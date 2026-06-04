"""
SQLite-backed exact-deduplication store.

Tables:
  processed_items — every URL seen (dedup across runs)
  findings        — valuable findings saved by hourly scans for daily report compilation
"""

import json
import re as _re
import sqlite3
import logging
from datetime import timedelta
from contextlib import contextmanager
from pathlib import Path

import config

logger = logging.getLogger(__name__)


# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS processed_items (
    url       TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL
);
"""

_CREATE_FINDINGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    url              TEXT NOT NULL UNIQUE,
    title            TEXT,
    source           TEXT,
    published        TEXT,
    cve              TEXT,
    summary          TEXT,
    severity         TEXT,
    affected_products TEXT,
    created_at       TEXT NOT NULL
);
"""

_CREATE_INSTANT_ALERTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS instant_alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    cve        TEXT NOT NULL DEFAULT '',
    title_key  TEXT NOT NULL DEFAULT '',
    alerted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_cve        ON instant_alerts (cve);
CREATE INDEX IF NOT EXISTS idx_alerts_title_key  ON instant_alerts (title_key);
CREATE INDEX IF NOT EXISTS idx_alerts_alerted_at ON instant_alerts (alerted_at);
"""

_ALERT_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "in", "on", "at", "to", "of", "and", "or",
    "for", "with", "by", "from", "as", "are", "was", "were", "has", "have",
    "had", "be", "been", "new", "via", "using", "that", "this", "its", "it",
    "about", "over", "after", "before", "which", "who", "how", "when",
})


# ── Internal helpers ──────────────────────────────────────────────────────────

@contextmanager
def _get_conn(db_path: Path = config.SQLITE_DB_PATH):
    """Yield a SQLite connection and commit/rollback on exit."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Public API ────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create the database schema if it does not exist yet."""
    with _get_conn() as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.execute(_CREATE_FINDINGS_TABLE_SQL)
        for stmt in _CREATE_INSTANT_ALERTS_TABLE_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
    logger.debug("SQLite DB initialised at %s", config.SQLITE_DB_PATH)


def check_if_processed(url: str) -> bool:
    """Return True if *url* has already been ingested."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM processed_items WHERE url = ?", (url,)
        ).fetchone()
    return row is not None


def mark_as_processed(url: str) -> None:
    """
    Record *url* as processed.

    Uses INSERT OR IGNORE so concurrent runs cannot raise a UNIQUE-constraint
    error for the same URL.
    """
    ts = config.now_jst().isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO processed_items (url, timestamp) VALUES (?, ?)",
            (url, ts),
        )
    logger.debug("Marked as processed: %s", url)


def count_processed() -> int:
    """Return the total number of URLs stored (useful for status logs)."""
    with _get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM processed_items").fetchone()
    return row["n"]


# ── Findings table (hourly → daily pipeline) ──────────────────────────────────

def save_finding(finding: dict) -> None:
    """Persist a valuable finding for daily report compilation. Ignores duplicates."""
    ts = config.now_jst().isoformat()
    with _get_conn() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO findings
               (url, title, source, published, cve, summary, severity, affected_products, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.get("url", ""),
                finding.get("title", ""),
                finding.get("source", ""),
                finding.get("published", ""),
                finding.get("cve", ""),
                finding.get("summary", ""),
                finding.get("severity", "unknown"),
                json.dumps(finding.get("affected_products", [])),
                ts,
            ),
        )
    logger.debug("Saved finding: %s", finding.get("url", ""))


def _title_fingerprint(title: str) -> str:
    """
    Normalise a finding title into a dedup key.

    Lowercases, strips punctuation, removes stop words and short tokens,
    sorts the remaining words so order differences don't matter, then returns
    the top 8 significant words joined by space.
    """
    words = _re.sub(r"[^a-z0-9 ]", " ", title.lower()).split()
    sig = sorted(w for w in words if w not in _ALERT_STOP_WORDS and len(w) > 2)[:8]
    return " ".join(sig)


def check_if_alerted(cve: str, title: str, window_hours: int | None = None) -> bool:
    """
    Return True if an immediate alert for this CVE or title was already sent
    within *window_hours* (default: config.ALERT_DEDUP_WINDOW_HOURS).

    Two dedup signals are checked independently:
      1. CVE match — any non-empty CVE that was already alerted.
      2. Title fingerprint — normalised word-sort of the title.
    Either match suppresses a repeat alert.
    """
    if window_hours is None:
        window_hours = config.ALERT_DEDUP_WINDOW_HOURS
    cutoff = (config.now_jst() - timedelta(hours=window_hours)).isoformat()
    title_key = _title_fingerprint(title)
    with _get_conn() as conn:
        if cve:
            row = conn.execute(
                "SELECT 1 FROM instant_alerts WHERE cve = ? AND alerted_at >= ?",
                (cve, cutoff),
            ).fetchone()
            if row:
                return True
        if title_key:
            row = conn.execute(
                "SELECT 1 FROM instant_alerts WHERE title_key = ? AND alerted_at >= ?",
                (title_key, cutoff),
            ).fetchone()
            if row:
                return True
    return False


def mark_as_alerted(finding: dict) -> None:
    """Record that an immediate alert was sent for *finding*."""
    ts = config.now_jst().isoformat()
    title_key = _title_fingerprint(finding.get("title", ""))
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO instant_alerts (url, cve, title_key, alerted_at) VALUES (?, ?, ?, ?)",
            (
                finding.get("url", ""),
                finding.get("cve", ""),
                title_key,
                ts,
            ),
        )
    logger.debug("Marked as alerted: %s", finding.get("url", ""))


def get_findings_since(hours: int = 26) -> list[dict]:
    """Return all findings created within the past *hours* hours, severity-ordered."""
    cutoff = (config.now_jst() - timedelta(hours=hours)).isoformat()
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT url, title, source, published, cve, summary, severity, affected_products
               FROM findings
               WHERE created_at >= ?
               ORDER BY
                 CASE severity
                   WHEN 'critical' THEN 0
                   WHEN 'high'     THEN 1
                   WHEN 'medium'   THEN 2
                   WHEN 'low'      THEN 3
                   ELSE 4
                 END,
                 created_at DESC""",
            (cutoff,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        try:
            d["affected_products"] = json.loads(d.get("affected_products") or "[]")
        except (json.JSONDecodeError, TypeError):
            d["affected_products"] = []
        result.append(d)
    return result
