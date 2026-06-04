#!/usr/bin/env python3
"""
Bulk PoC importer from nomi-sec/PoC-in-GitHub.

Downloads CVE PoC metadata from https://github.com/nomi-sec/PoC-in-GitHub and
writes it directly into the ChromaDB RAG store — bypassing the LLM triage loop
since every PoC entry is inherently valuable intelligence.

After running this, searching for any CVE ID (e.g. "CVE-2026-8732") via
query_rag.py returns the PoC description and all GitHub links.

Usage:
    # Ingest current year only (fast — default)
    python poc_ingestor.py

    # Ingest specific years
    python poc_ingestor.py --years 2024 2025 2026

    # Ingest all years since 1999 (slow — thousands of API calls)
    python poc_ingestor.py --all

    # Look up / re-ingest a single CVE
    python poc_ingestor.py --cve CVE-2026-8732

    # Force re-ingest even if already in SQLite dedup store
    python poc_ingestor.py --cve CVE-2026-8732 --force

    # Preview without writing
    python poc_ingestor.py --years 2026 --dry-run

Environment:
    GITHUB_TOKEN — optional; raises API rate limit from 60 → 5000 req/hour.
                   Strongly recommended when ingesting multiple years.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))

import config   # noqa: F401 — creates data/ dirs
import db_manager
import rag_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("poc_ingestor")

_REPO      = "nomi-sec/PoC-in-GitHub"
_RAW_BASE  = f"https://raw.githubusercontent.com/{_REPO}/master"
_API_BASE  = f"https://api.github.com/repos/{_REPO}"
_UA        = {"User-Agent": "CTI-Pipeline/1.0 (security research)"}
# Delay between raw-content fetches (not API calls) — no auth required for raw
_RAW_DELAY = 0.2   # seconds
# Delay between GitHub API calls (directory listings, commits)
_API_DELAY = 1.0   # seconds (keeps unauthenticated callers under 60 req/hour)


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _api_headers() -> dict:
    h = dict(_UA)
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"token {token}"
    else:
        logger.debug("No GITHUB_TOKEN set — rate limit is 60 req/hour")
    return h


# ── GitHub API helpers ─────────────────────────────────────────────────────────

def _list_cves_in_year(year: int) -> list[str]:
    """Return all CVE JSON filenames for *year* from the GitHub directory API."""
    url = f"{_API_BASE}/contents/{year}"
    time.sleep(_API_DELAY)
    try:
        resp = requests.get(url, headers=_api_headers(), timeout=30)
        resp.raise_for_status()
        return [f["name"] for f in resp.json() if f["name"].endswith(".json")]
    except requests.RequestException as exc:
        logger.warning("Failed to list year %d: %s", year, exc)
        return []


def _fetch_cve_pocs(year: int, filename: str) -> list[dict]:
    """Fetch the raw JSON array of PoC repos for one CVE file."""
    url = f"{_RAW_BASE}/{year}/{filename}"
    time.sleep(_RAW_DELAY)
    try:
        resp = requests.get(url, headers=_UA, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
    except requests.RequestException as exc:
        logger.warning("Failed to fetch %s/%s: %s", year, filename, exc)
        return []
    except ValueError as exc:
        logger.warning("Invalid JSON in %s/%s: %s", year, filename, exc)
        return []


# ── Document builder ───────────────────────────────────────────────────────────

def _build_document(cve_id: str, year: int, pocs: list[dict]) -> tuple[str, dict]:
    """
    Build a ChromaDB (text, metadata) pair from a list of PoC repo dicts.

    Captures every useful field from the JSON:
      html_url, name, full_name, description, topics, stargazers_count,
      forks_count, created_at, pushed_at, updated_at
    """
    # Best description = highest-starred repo that has one
    best_desc = ""
    for poc in sorted(pocs, key=lambda x: x.get("stargazers_count", 0), reverse=True):
        desc = (poc.get("description") or "").strip()
        if desc:
            best_desc = desc
            break

    # Aggregate topics across all repos (deduplicated, sorted)
    all_topics: list[str] = []
    seen_topics: set[str] = set()
    for poc in pocs:
        for t in (poc.get("topics") or []):
            t = t.strip().lower()
            if t and t not in seen_topics:
                seen_topics.add(t)
                all_topics.append(t)
    all_topics.sort()

    # Per-repo bullet lines — include every available field
    repo_lines = []
    for poc in pocs:
        html_url    = poc.get("html_url", "")
        repo_name   = poc.get("name", "")
        description = (poc.get("description") or "").strip()
        stars       = poc.get("stargazers_count", 0)
        forks       = poc.get("forks_count", 0)
        full_name   = poc.get("full_name", "")
        author      = full_name.split("/")[0] if full_name else ""
        created     = (poc.get("created_at") or "")[:10]
        updated     = (poc.get("updated_at") or "")[:10]
        pushed      = (poc.get("pushed_at") or "")[:10]
        topics      = poc.get("topics") or []

        line = f"  • {html_url}"
        if repo_name and repo_name != cve_id:
            line += f" [{repo_name}]"
        if description:
            line += f" — {description}"
        stats = f"★{stars}"
        if forks:
            stats += f", {forks} forks"
        if author:
            stats += f", by {author}"
        if created:
            stats += f", added {created}"
        if pushed and pushed != created:
            stats += f", last push {pushed}"
        if updated and updated != pushed:
            stats += f", updated {updated}"
        line += f" ({stats})"
        if topics:
            line += f"\n    tags: {', '.join(topics)}"
        repo_lines.append(line)

    text = (
        f"{cve_id} Proof-of-Concept Exploit\n\n"
        f"CVE ID: {cve_id}\n"
        f"Year: {year}\n"
        f"Public PoC repositories: {len(pocs)}\n"
    )
    if best_desc:
        text += f"Description: {best_desc}\n"
    if all_topics:
        text += f"Tags: {', '.join(all_topics)}\n"
    text += "\nPoC repositories on GitHub:\n" + "\n".join(repo_lines)
    text += (
        f"\n\nCatalogue: https://github.com/{_REPO}/blob/master/{year}/{cve_id}.json"
    )

    # Metadata — all string values for ChromaDB
    poc_urls   = " | ".join(p["html_url"] for p in pocs if p.get("html_url"))[:2000]
    max_stars  = max((p.get("stargazers_count", 0) for p in pocs), default=0)
    max_forks  = max((p.get("forks_count", 0) for p in pocs), default=0)
    topics_str = ", ".join(all_topics)[:500]

    # Latest push date across all repos
    latest_push = max(
        ((poc.get("pushed_at") or "")[:10] for poc in pocs),
        default="",
    )

    metadata = {
        "cve":        cve_id,
        "source":     "PoC-in-GitHub",
        "url":        f"https://github.com/search?q={cve_id}&type=repositories",
        "poc_urls":   poc_urls,
        "poc_count":  str(len(pocs)),
        "max_stars":  str(max_stars),
        "max_forks":  str(max_forks),
        "topics":     topics_str,
        "date":       latest_push or f"{year}-01-01",
        "severity":   "unknown",
        "year":       str(year),
    }
    return text, metadata


# ── Core ingest logic ──────────────────────────────────────────────────────────

def ingest_cve(year: int, filename: str, *, force: bool = False, dry_run: bool = False) -> bool:
    """
    Fetch and insert one CVE file into ChromaDB.

    Returns True if a new document was inserted.
    """
    cve_id    = filename.replace(".json", "")
    dedup_key = f"poc_github:{cve_id}"

    if not force and db_manager.check_if_processed(dedup_key):
        logger.debug("Already ingested — skipping: %s", cve_id)
        return False

    pocs = _fetch_cve_pocs(year, filename)
    if not pocs:
        db_manager.mark_as_processed(dedup_key)
        return False

    text, metadata = _build_document(cve_id, year, pocs)

    if dry_run:
        logger.info("[DRY RUN] %s — %d PoC repo(s)", cve_id, len(pocs))
        for poc in pocs:
            logger.info("           %s", poc.get("html_url", "?"))
        return True

    inserted, doc_id = rag_manager.insert_intel(text, metadata)
    db_manager.mark_as_processed(dedup_key)

    if inserted:
        logger.info(
            "✓ %s — %d PoC(s) | doc %s",
            cve_id, len(pocs), (doc_id or "")[:8],
        )
    else:
        logger.debug("~ %s — already in vector store (semantic dup)", cve_id)

    return inserted


def ingest_year(year: int, *, force: bool = False, dry_run: bool = False) -> int:
    """Ingest all CVEs for *year*. Returns the count of newly inserted documents."""
    logger.info("Listing CVEs for %d…", year)
    filenames = _list_cves_in_year(year)
    if not filenames:
        logger.warning("No JSON files found for %d — check API rate limits", year)
        return 0

    logger.info("%d CVE file(s) in %d — starting ingestion…", len(filenames), year)
    inserted = 0
    for i, filename in enumerate(filenames, 1):
        if i % 100 == 0:
            logger.info("  [%d/%d] year=%d", i, len(filenames), year)
        if ingest_cve(year, filename, force=force, dry_run=dry_run):
            inserted += 1

    logger.info("Year %d — %d/%d documents inserted", year, inserted, len(filenames))
    return inserted


def ingest_single(cve_id: str, *, force: bool = False, dry_run: bool = False) -> bool:
    """Look up and ingest one specific CVE (e.g. 'CVE-2026-8732')."""
    cve_id = cve_id.strip().upper()
    parts  = cve_id.split("-")
    if len(parts) < 3 or parts[0] != "CVE":
        logger.error("Invalid CVE ID: %s  (expected CVE-YYYY-NNNN)", cve_id)
        return False
    try:
        year = int(parts[1])
    except ValueError:
        logger.error("Cannot parse year from: %s", cve_id)
        return False

    filename = f"{cve_id}.json"
    return ingest_cve(year, filename, force=force, dry_run=dry_run)


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import PoC data from nomi-sec/PoC-in-GitHub into the CTI RAG store",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--years", nargs="+", type=int, metavar="YYYY",
        help="One or more years to ingest (e.g. --years 2024 2025 2026)",
    )
    group.add_argument(
        "--all", action="store_true",
        help="Ingest every year (1999 → now). Very slow without GITHUB_TOKEN.",
    )
    group.add_argument(
        "--cve", type=str, metavar="CVE-YYYY-NNNN",
        help="Ingest (or refresh) a single CVE",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-ingest even if the CVE is already in the SQLite dedup store",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be inserted without writing anything",
    )
    args = parser.parse_args()

    db_manager.init_db()
    rag_before = rag_manager.collection_count()
    logger.info("ChromaDB knowledge base: %d documents before this run", rag_before)

    if not os.environ.get("GITHUB_TOKEN"):
        logger.warning(
            "GITHUB_TOKEN not set — GitHub API rate limit is 60 req/hour. "
            "Set GITHUB_TOKEN in .env for bulk year imports."
        )

    if args.cve:
        ok = ingest_single(args.cve, force=args.force, dry_run=args.dry_run)
        if not ok and not args.dry_run:
            logger.info("Nothing new for %s (already ingested — use --force to refresh)", args.cve)
        return

    current_year = datetime.now(tz=timezone.utc).year
    if args.all:
        years = list(range(1999, current_year + 1))
    elif args.years:
        years = sorted(set(args.years))
    else:
        years = [current_year]

    total = 0
    for year in years:
        total += ingest_year(year, force=args.force, dry_run=args.dry_run)

    rag_after = rag_manager.collection_count()
    logger.info(
        "Done — %d new PoC record(s) inserted | ChromaDB: %d → %d documents",
        total, rag_before, rag_after,
    )


if __name__ == "__main__":
    main()
