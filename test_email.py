#!/usr/bin/env python3
"""
Test email delivery — reads the most-recent on-disk report and emails it.
Does NOT run the research pipeline.

Usage:
  .venv/bin/python3 test_email.py
  .venv/bin/python3 test_email.py --lang en
  .venv/bin/python3 test_email.py --report data/reports/brief_2026-06-02.md --lang ja
  .venv/bin/python3 test_email.py --to someone@example.com --lang en
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config  # noqa: F401 — loads .env
import notifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("test_email")


def _latest_report() -> Path:
    reports_dir = Path(__file__).parent / "data" / "reports"
    reports = sorted(reports_dir.glob("brief_*.md"))
    if not reports:
        raise FileNotFoundError(f"No brief_*.md files found in {reports_dir}")
    return reports[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Email a saved CTI report (no pipeline run)")
    parser.add_argument(
        "--report",
        type=str,
        default="",
        help="Path to the .md report file (default: most recent in data/reports/)",
    )
    parser.add_argument(
        "--to",
        type=str,
        default="msky.ito@gmail.com,mizutai061213@gmail.com",
        help="Recipient email address (default: msky.ito@gmail.com,mizutai061213@gmail.com)",
    )
    parser.add_argument(
        "--lang",
        type=str,
        default="en",
        choices=["ja", "en"],
        help="Report language: 'ja' (translate to Japanese) or 'en' (send as-is) (default: en)",
    )
    args = parser.parse_args()

    report_path = Path(args.report) if args.report else _latest_report()

    if not report_path.exists():
        logger.error("Report file not found: %s", report_path)
        sys.exit(1)

    report_text = report_path.read_text(encoding="utf-8")
    logger.info("Loaded report: %s (%d chars)", report_path.name, len(report_text))
    logger.info("Sending to: %s  lang: %s  via %s:%d", args.to, args.lang, config.SMTP_HOST, config.SMTP_PORT)

    ok = notifier.send_report_email(report_text, args.to, language=args.lang)
    if ok:
        logger.info("Done — email sent successfully.")
    else:
        logger.error("Email failed — check SMTP_* settings in .env")
        sys.exit(1)


if __name__ == "__main__":
    main()
