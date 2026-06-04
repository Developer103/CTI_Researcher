"""
CTI Query API — FastAPI server for querying the CTI knowledge base.

Run:
  .venv/bin/uvicorn api:app --host 0.0.0.0 --port 8888 --reload

Interactive docs:
  http://localhost:8888/docs
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).parent))

import config
import db_manager
import rag_manager

# ── Optional API key auth ─────────────────────────────────────────────────────
# Set CTI_API_KEY in .env to require a key.  If unset, the API is open.
_API_KEY = os.environ.get("CTI_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _check_key(key: str = Security(_api_key_header)):
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI Query API",
    description="Query the local CTI findings database and RAG knowledge base.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

db_manager.init_db()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_iso(s: str) -> Optional[datetime]:
    """Parse an ISO date/datetime string. Returns None on failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _in_date_range(date_str: str, start: Optional[str], end: Optional[str]) -> bool:
    if not start and not end:
        return True
    dt = _parse_iso(date_str)
    if dt is None:
        return True
    # strip tz for naive comparison
    dt_naive = dt.replace(tzinfo=None)
    if start:
        s = _parse_iso(start)
        if s and dt_naive < s.replace(tzinfo=None):
            return False
    if end:
        e = _parse_iso(end)
        if e and dt_naive > e.replace(tzinfo=None):
            return False
    return True


# ── /findings ─────────────────────────────────────────────────────────────────

@app.get("/findings", summary="Query triage findings", dependencies=[Security(_check_key)])
def get_findings(
    hours: int = Query(26, description="How many hours back to look (default 26)"),
    severity: Optional[str] = Query(None, description="Comma-separated severities: critical,high,medium,low"),
    source: Optional[str] = Query(None, description="Filter by feed source name (partial match)"),
    cve: Optional[str] = Query(None, description="Filter by CVE ID (partial match, e.g. CVE-2024)"),
    q: Optional[str] = Query(None, description="Keyword search in title and summary"),
    start_date: Optional[str] = Query(None, description="Only items on or after this date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="Only items on or before this date (YYYY-MM-DD)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """
    Return triage findings from the SQLite findings table.

    Findings are items that the LLM triage deemed high-value. Apply any
    combination of filters to narrow results. Results are severity-ordered
    (critical first) then by recency.
    """
    rows = db_manager.get_findings_since(hours=hours)

    # severity filter
    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        rows = [r for r in rows if r.get("severity", "").lower() in allowed]

    # source filter (partial, case-insensitive)
    if source:
        src_lower = source.lower()
        rows = [r for r in rows if src_lower in r.get("source", "").lower()]

    # CVE filter (partial match)
    if cve:
        cve_upper = cve.upper()
        rows = [r for r in rows if cve_upper in r.get("cve", "").upper()]

    # keyword search
    if q:
        q_lower = q.lower()
        rows = [
            r for r in rows
            if q_lower in r.get("title", "").lower() or q_lower in r.get("summary", "").lower()
        ]

    # date range (uses published field)
    if start_date or end_date:
        rows = [r for r in rows if _in_date_range(r.get("published", ""), start_date, end_date)]

    total = len(rows)
    page = rows[offset: offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": page,
    }


# ── /findings/sources ─────────────────────────────────────────────────────────

@app.get("/findings/sources", summary="List all sources in findings", dependencies=[Security(_check_key)])
def get_sources(hours: int = Query(26, description="Look-back window in hours")):
    """Return unique source names and their finding counts within the window."""
    rows = db_manager.get_findings_since(hours=hours)
    counts: dict[str, int] = {}
    for r in rows:
        src = r.get("source", "unknown")
        counts[src] = counts.get(src, 0) + 1
    return {"sources": [{"source": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]}


# ── /search ───────────────────────────────────────────────────────────────────

@app.get("/search", summary="Semantic / CVE search over RAG knowledge base", dependencies=[Security(_check_key)])
def search_rag(
    q: Optional[str] = Query(None, description="Semantic search query (free text)"),
    cve: Optional[str] = Query(None, description="CVE mode: exact CVE ID metadata match (e.g. CVE-2024-21182). Bypasses vector search."),
    top: int = Query(10, ge=1, le=200, description="Number of results to return"),
    threshold: Optional[float] = Query(None, ge=0.0, le=2.0, description="Max distance to include (0=identical, 2=opposite). Typical useful range: 0.0–1.2"),
    start_date: Optional[str] = Query(None, description="Only docs with date >= this (YYYY-MM-DD or ISO datetime)"),
    end_date: Optional[str] = Query(None, description="Only docs with date <= this (YYYY-MM-DD or ISO datetime)"),
    source: Optional[str] = Query(None, description="Filter by source metadata (partial match)"),
    severity: Optional[str] = Query(None, description="Filter by severity metadata (exact: critical/high/medium/low)"),
):
    """
    Search the ChromaDB RAG knowledge base (~5000+ documents).

    **Two modes:**
    - **Semantic** (`q`): vector similarity search over all stored intel.
    - **CVE** (`cve`): exact metadata match — returns every document tagged
      with this CVE ID, bypassing vector search entirely.

    Use `threshold` to drop low-relevance semantic results (lower = stricter).
    Use `start_date` / `end_date` to restrict by document date.
    """
    if not q and not cve:
        raise HTTPException(status_code=422, detail="Provide either 'q' (semantic) or 'cve' (CVE mode)")

    if cve:
        items = rag_manager.query_by_cve(cve.strip())
    else:
        items = rag_manager.query_similar(q, n_results=top * 4)  # over-fetch for post-filtering

    # threshold filter (semantic only)
    if threshold is not None and not cve:
        items = [i for i in items if i["distance"] <= threshold]

    # date range filter
    if start_date or end_date:
        items = [
            i for i in items
            if _in_date_range(i["metadata"].get("date", ""), start_date, end_date)
        ]

    # source filter
    if source:
        src_lower = source.lower()
        items = [i for i in items if src_lower in i["metadata"].get("source", "").lower()]

    # severity filter
    if severity:
        sev_lower = severity.lower()
        items = [i for i in items if i["metadata"].get("severity", "").lower() == sev_lower]

    items = items[:top]

    return {
        "mode": "cve" if cve else "semantic",
        "query": cve if cve else q,
        "total_returned": len(items),
        "threshold": threshold,
        "results": [
            {
                "distance": round(i["distance"], 4),
                "keyword_match": i.get("keyword_match", False),
                "exact_cve_match": i.get("exact_cve_match", False),
                "metadata": i["metadata"],
                "text": i["text"],
            }
            for i in items
        ],
    }


# ── /stats ────────────────────────────────────────────────────────────────────

@app.get("/stats", summary="Database statistics", dependencies=[Security(_check_key)])
def get_stats():
    """Overall statistics for all three data stores."""
    # findings breakdown
    all_findings = db_manager.get_findings_since(hours=9999)
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # RAG stats
    rag_stats = rag_manager.collection_stats()

    # processed_items count
    processed_count = db_manager.count_processed()

    now = config.now_jst()

    return {
        "as_of": now.strftime("%Y-%m-%d %H:%M JST"),
        "findings": {
            "total": len(all_findings),
            "last_26h": len(db_manager.get_findings_since(hours=26)),
            "by_severity": sev_counts,
        },
        "rag": rag_stats,
        "processed_items": {
            "total": processed_count,
        },
    }


# ── /health ───────────────────────────────────────────────────────────────────

@app.get("/health", summary="Health check", include_in_schema=False)
def health():
    return {"status": "ok", "time": config.now_jst().strftime("%Y-%m-%d %H:%M JST")}
