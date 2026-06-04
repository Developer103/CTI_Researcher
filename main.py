"""
CTI Pipeline Orchestrator

Modes
─────
  --mode hourly  (default cron: every hour at :00)
      Ingest the past 1 hour of feeds, triage new items, store valuable findings
      in the `findings` DB table.  If any finding is Critical, High+CVE, or
      contains zero-day keywords, send an immediate compact alert via the
      requested delivery channels.

  --mode daily   (default cron: 06:30 daily)
      Read all findings stored by hourly scans over the past 26 hours, generate
      a full Daily Cyber Threat Brief with Qwen, and deliver it.

  --mode full    (manual / catch-up)
      Legacy full-cycle mode: 24-hour feed ingestion + triage + report in one
      shot.  Use when setting up for the first time or after an outage.

Usage examples
──────────────
  python3 main.py --mode hourly --discord
  python3 main.py --mode daily  --email-en you@example.com --email-ja you@example.com
  python3 main.py --mode full   --discord --email-en you@example.com
  python3 main.py --mode full   --start-date 2025-01-01 --end-date 2025-12-31 --output

At least one of --discord / --email-en / --email-ja / --output is required.
"""

import argparse
import logging
import sys
from datetime import date

import config  # noqa: F401 — side-effect: creates data/ dirs
import db_manager
import rag_manager
import agent_core
import ingestor
import notifier

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("cti.main")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sanity_check_config() -> None:
    """Warn about potentially mis-configured settings before doing real work."""
    if "localhost" not in config.OPENAI_API_BASE and "127.0.0.1" not in config.OPENAI_API_BASE:
        logger.warning(
            "OPENAI_API_BASE (%s) does not look like a local endpoint. "
            "Make sure Ollama/vLLM is running.",
            config.OPENAI_API_BASE,
        )


def _is_alertable(finding: dict) -> bool:
    """Return True if this finding should trigger an immediate alert."""
    sev = finding.get("severity", "").lower()
    cve = finding.get("cve", "")
    text = f"{finding.get('title', '')} {finding.get('summary', '')}".lower()

    if sev in [s.lower() for s in config.ALERT_SEVERITIES]:
        return True
    if config.ALERT_HIGH_WITH_CVE and sev == "high" and cve:
        return True
    if any(kw in text for kw in config.ALERT_ZERO_DAY_KEYWORDS):
        return True
    return False


# ── Hourly scan ───────────────────────────────────────────────────────────────

def run_hourly(
    lookback_hours: int | None = None,
    email_en: list[str] | None = None,
    email_ja: list[str] | None = None,
    discord: bool = False,
    output: bool = False,
) -> None:
    """Ingest last N hours, triage new items, store findings, alert on high-risk."""
    email_en = email_en or []
    email_ja = email_ja or []
    effective_lookback = lookback_hours if lookback_hours is not None else config.HOURLY_LOOKBACK_HOURS

    now_str = config.now_jst().strftime("%Y-%m-%d %H:%M JST")

    logger.info("=" * 60)
    logger.info("CTI Hourly Scan — %s (lookback: %dh)", now_str, effective_lookback)
    logger.info("=" * 60)

    _sanity_check_config()

    # Override lookback for this run
    config.LOOKBACK_HOURS = effective_lookback

    db_manager.init_db()
    logger.info("Fetching feeds for past %dh…", effective_lookback)

    all_items = ingestor.fetch_all_feeds()
    if not all_items:
        logger.info("No new items in past %dh — done.", effective_lookback)
        return

    alertable: list[dict] = []
    new_findings = 0

    for item in all_items:
        url = item["url"]
        if db_manager.check_if_processed(url):
            continue

        logger.info("Triaging: %s", item["title"][:80])

        triage = agent_core.triage_item_with_timeout(
            title=item["title"],
            url=url,
            content=item["content"],
            source=item["source"],
        )

        db_manager.mark_as_processed(url)

        if triage is None or not triage.is_valuable:
            continue

        finding = {
            "title": item["title"],
            "url": url,
            "source": item["source"],
            "published": item.get("published", ""),
            "cve": triage.cve,
            "summary": triage.summary,
            "severity": triage.severity,
            "affected_products": triage.affected_products,
        }

        intel_text = f"{item['title']}\n\n{triage.summary}"
        rag_manager.insert_intel(
            text=intel_text,
            metadata={
                "date": item.get("published", config.today_jst().isoformat()),
                "source": item["source"],
                "cve": triage.cve,
                "url": url,
                "severity": triage.severity,
            },
        )

        db_manager.save_finding(finding)
        new_findings += 1

        logger.info(
            "✓ [%s] %s | CVE: %s",
            triage.severity.upper(),
            item["title"][:60],
            triage.cve or "none",
        )

        if _is_alertable(finding):
            cve = finding.get("cve", "")
            title = finding.get("title", "")
            if db_manager.check_if_alerted(cve, title):
                logger.info(
                    "Suppressing duplicate alert (already sent within %dh): %s",
                    config.ALERT_DEDUP_WINDOW_HOURS,
                    title[:70],
                )
            else:
                alertable.append(finding)

    logger.info("Hourly scan complete — %d new finding(s), %d alert-threshold.", new_findings, len(alertable))

    if not alertable:
        return

    logger.info("Sending immediate alert for %d finding(s)…", len(alertable))

    # Mark these findings as alerted BEFORE delivery so a concurrent run
    # can't race and send the same alert twice.
    for f in alertable:
        db_manager.mark_as_alerted(f)

    if output:
        for f in alertable:
            print(f"[ALERT][{f['severity'].upper()}] {f['title']} — {f['url']}")

    if discord:
        notifier.send_immediate_alert(alertable)

    # Immediate alerts are English-only (speed > localisation).
    # Deduplicate across en+ja so addresses in both lists get one email.
    alert_emails = list(dict.fromkeys(email_en + email_ja))
    for addr in alert_emails:
        notifier.send_immediate_alert_email(alertable, addr, language="en")

    logger.info("CTI Hourly Scan finished.")


# ── Daily report (reads from findings table) ──────────────────────────────────

def run_daily(
    email_en: list[str] | None = None,
    email_ja: list[str] | None = None,
    discord: bool = False,
    output: bool = False,
) -> None:
    """Compile findings accumulated by hourly scans → generate and send daily report."""
    email_en = email_en or []
    email_ja = email_ja or []

    logger.info("=" * 60)
    logger.info("CTI Daily Report — %s", config.today_jst().isoformat())
    logger.info("=" * 60)

    _sanity_check_config()
    db_manager.init_db()

    daily_findings = db_manager.get_findings_since(hours=config.DAILY_REPORT_LOOKBACK_HOURS)

    if not daily_findings:
        msg = f"No findings stored in past {config.DAILY_REPORT_LOOKBACK_HOURS}h — no report generated."
        logger.info(msg)
        notifier.send_error_alert(msg)
        return

    logger.info("Generating Daily Brief from %d stored finding(s)…", len(daily_findings))
    report = agent_core.write_report(daily_findings)

    if not report:
        err = "Reporter returned no content — check LLM endpoint."
        logger.error(err)
        notifier.send_error_alert(err)
        return

    logger.info("Report generated (%d chars)", len(report))
    _save_report_to_disk(report)

    if output:
        print(report)

    if discord:
        ok = notifier.send_report(report)
        if ok:
            logger.info("Daily brief delivered to Discord.")
        else:
            logger.error("Discord delivery failed — report saved locally.")

    for addr in email_en:
        ok = notifier.send_report_email(report, addr, language="en")
        if ok:
            logger.info("English brief emailed to %s.", addr)
        else:
            logger.error("Email (en) to %s failed.", addr)

    if email_ja:
        logger.info("Translating report to Japanese (once for all %d recipient(s))…", len(email_ja))
        ja_report = notifier.translate_to_japanese(report)
        _save_report_to_disk(ja_report, suffix="_ja")
        for addr in email_ja:
            ok = notifier.send_report_email(ja_report, addr, language="ja", skip_translation=True)
            if ok:
                logger.info("Japanese brief emailed to %s.", addr)
            else:
                logger.error("Email (ja) to %s failed.", addr)

    logger.info("CTI Daily Report finished.")


# ── Full cycle (legacy / catch-up) ────────────────────────────────────────────

def run(
    start_date: str = "",
    end_date: str = "",
    lookback_hours: int | None = None,
    email_en: list[str] | None = None,
    email_ja: list[str] | None = None,
    discord: bool = False,
    output: bool = False,
) -> None:
    email_en = email_en or []
    email_ja = email_ja or []
    notify = discord or email_en or email_ja or output

    if lookback_hours is not None:
        config.LOOKBACK_HOURS = lookback_hours

    logger.info("=" * 60)
    logger.info("CTI Pipeline (full) — %s | lookback: %sh | date range: %s → %s",
                config.today_jst().isoformat(),
                config.LOOKBACK_HOURS,
                start_date or "—",
                end_date or "—")
    logger.info("=" * 60)

    _sanity_check_config()

    # ── 1. Initialise dedup store ─────────────────────────────────────────────
    db_manager.init_db()
    logger.info("SQLite dedup store: %d items already processed", db_manager.count_processed())

    # ── 2. Fetch feeds ────────────────────────────────────────────────────────
    all_items = ingestor.fetch_all_feeds(start_date=start_date, end_date=end_date)
    if not all_items:
        logger.info("No feed items retrieved — exiting early.")
        return

    rag_before = rag_manager.collection_count()
    logger.info("ChromaDB knowledge base: %d documents before this run", rag_before)

    # ── 3–4. Triage loop ──────────────────────────────────────────────────────
    daily_findings: list[dict] = []
    skipped_dedup = 0
    skipped_triage = 0
    skipped_low_value = 0
    skipped_rag_dedup = 0

    for item in all_items:
        url = item["url"]

        if db_manager.check_if_processed(url):
            skipped_dedup += 1
            continue

        logger.info("Triaging: %s", item["title"][:80])

        triage = agent_core.triage_item_with_timeout(
            title=item["title"],
            url=url,
            content=item["content"],
            source=item["source"],
        )

        db_manager.mark_as_processed(url)

        if triage is None:
            skipped_triage += 1
            logger.warning("Triage returned None or timed out for: %s", url)
            continue

        if not triage.is_valuable:
            skipped_low_value += 1
            logger.debug("Low-value item skipped: %s", item["title"][:60])
            continue

        finding = {
            "title": item["title"],
            "url": url,
            "source": item["source"],
            "published": item.get("published", ""),
            "cve": triage.cve,
            "summary": triage.summary,
            "severity": triage.severity,
            "affected_products": triage.affected_products,
        }

        intel_text = f"{item['title']}\n\n{triage.summary}"
        rag_inserted, rag_doc_id = rag_manager.insert_intel(
            text=intel_text,
            metadata={
                "date": item.get("published", config.today_jst().isoformat()),
                "source": item["source"],
                "cve": triage.cve,
                "url": url,
                "severity": triage.severity,
            },
        )
        if not rag_inserted:
            skipped_rag_dedup += 1

        db_manager.save_finding(finding)
        daily_findings.append(finding)
        logger.info(
            "✓ Valuable [%s] %s | CVE: %s | RAG: %s",
            triage.severity.upper(),
            item["title"][:60],
            triage.cve or "none",
            f"stored ({rag_doc_id[:8]}…)" if rag_inserted else "duplicate skipped",
        )

    # ── Summary stats ─────────────────────────────────────────────────────────
    rag_after = rag_manager.collection_count()
    logger.info(
        "Triage complete — valuable: %d | low-value: %d | "
        "triage-failed: %d | already-seen (SQLite): %d | RAG dup skipped: %d",
        len(daily_findings), skipped_low_value, skipped_triage,
        skipped_dedup, skipped_rag_dedup,
    )
    logger.info(
        "ChromaDB knowledge base: %d → %d documents (+%d new)",
        rag_before, rag_after, rag_after - rag_before,
    )

    # ── 5. Generate report (skipped when no delivery method requested) ────────
    logger.info(
        "Triage complete — %d finding(s) stored to DB.",
        len(daily_findings),
    )

    if not notify:
        logger.info("No delivery method specified — skipping report generation.")
        logger.info("CTI Pipeline (full) finished — findings stored to DB.")
        return

    if not daily_findings:
        logger.info("No valuable findings — no report generated.")
        notifier.send_error_alert(
            "CTI Pipeline ran successfully but found 0 high-value items today."
        )
        return

    logger.info("Generating Daily Cyber Threat Brief (%d findings)…", len(daily_findings))
    report = agent_core.write_report(daily_findings)

    if not report:
        err = "Reporter function returned no content — check LLM endpoint."
        logger.error(err)
        notifier.send_error_alert(err)
        return

    logger.info("Report generated (%d chars)", len(report))
    _save_report_to_disk(report)

    # ── 6. stdout ─────────────────────────────────────────────────────────────
    if output:
        print(report)

    # ── 7. Discord ────────────────────────────────────────────────────────────
    if discord:
        ok = notifier.send_report(report)
        if ok:
            logger.info("Brief delivered to Discord.")
        else:
            logger.error("Discord delivery failed — report saved locally.")

    # ── 8. Email (English) ────────────────────────────────────────────────────
    for addr in email_en:
        ok = notifier.send_report_email(report, addr, language="en")
        if ok:
            logger.info("English brief emailed to %s.", addr)
        else:
            logger.error("Email (en) to %s failed.", addr)

    # ── 9. Email (Japanese) — translate once, reuse for all recipients ────────
    if email_ja:
        logger.info("Translating report to Japanese (once for all %d recipient(s))…", len(email_ja))
        ja_report = notifier.translate_to_japanese(report)
        _save_report_to_disk(ja_report, suffix="_ja")
        for addr in email_ja:
            ok = notifier.send_report_email(ja_report, addr, language="ja", skip_translation=True)
            if ok:
                logger.info("Japanese brief emailed to %s.", addr)
            else:
                logger.error("Email (ja) to %s failed.", addr)

    logger.info("CTI Pipeline finished.")


def _save_report_to_disk(report: str, suffix: str = "") -> None:
    """Persist the report as a Markdown file under data/reports/."""
    reports_dir = config.BASE_DIR / "data" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    fname = reports_dir / f"brief_{config.today_jst().isoformat()}{suffix}.md"
    try:
        fname.write_text(report, encoding="utf-8")
        logger.info("Report saved to %s", fname)
    except OSError as exc:
        logger.warning("Could not save report to disk: %s", exc)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CTI Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  hourly  — 1h scan, store findings, immediate alert on critical/high\n"
            "  daily   — compile 26h of stored findings → full report\n"
            "  full    — legacy 24h full cycle (first run / catch-up)\n\n"
            "At least one delivery option is required:\n"
            "  --discord, --email-en, --email-ja, or --output"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["hourly", "daily", "full"],
        default="full",
        help="Run mode (default: full)",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=None,
        metavar="N",
        help="Override lookback window in hours (hourly default: 1, full default: 24)",
    )
    parser.add_argument(
        "--start-date",
        type=str,
        default=config.DEFAULT_START_DATE,
        metavar="YYYY-MM-DD",
        help="[full mode] Ingest items published on or after this date",
    )
    parser.add_argument(
        "--end-date",
        type=str,
        default=config.DEFAULT_END_DATE,
        metavar="YYYY-MM-DD",
        help="[full mode] Ingest items published on or before this date",
    )
    parser.add_argument(
        "--discord",
        action="store_true",
        help="Send report/alert to Discord",
    )
    parser.add_argument(
        "--email-en",
        action="append",
        default=None,
        dest="email_en",
        metavar="ADDRESS",
        help="Email English report to ADDRESS (repeatable)",
    )
    parser.add_argument(
        "--email-ja",
        action="append",
        default=None,
        dest="email_ja",
        metavar="ADDRESS",
        help="Email Japanese report to ADDRESS (repeatable)",
    )
    parser.add_argument(
        "--output",
        action="store_true",
        help="Print report to stdout",
    )

    args = parser.parse_args()

    has_delivery = args.discord or args.email_en or args.email_ja or args.output
    if not has_delivery and args.mode in ("hourly", "daily"):
        parser.error(
            f"--mode {args.mode} requires at least one delivery option:\n"
            "  --discord / --email-en / --email-ja / --output"
        )

    delivery = dict(
        email_en=args.email_en,
        email_ja=args.email_ja,
        discord=args.discord,
        output=args.output,
    )

    if args.mode == "hourly":
        run_hourly(lookback_hours=args.lookback_hours, **delivery)
    elif args.mode == "daily":
        run_daily(**delivery)
    else:  # full — delivery is optional (no flags = DB-only population)
        run(
            start_date=args.start_date,
            end_date=args.end_date,
            lookback_hours=args.lookback_hours,
            **delivery,
        )
