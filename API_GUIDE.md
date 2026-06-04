# CTI Query API — Usage Guide

Base URL: http://localhost:8888

Interactive docs (try endpoints in browser): http://localhost:8888/docs

## Authentication

Optional. If CTI_API_KEY is set in .env, include this header on every request:

    X-API-Key: your_key_here

If CTI_API_KEY is not set, no header is needed.

---

## Endpoints

### GET /health

Simple liveness check. No parameters.

    curl http://localhost:8888/health

Response:
    {"status": "ok", "time": "2026-06-03 00:30 JST"}

---

### GET /stats

Overview of all three data stores: findings table, RAG knowledge base, and processed_items dedup table.
No parameters.

    curl http://localhost:8888/stats

Response fields:
    as_of               Current time in JST
    findings.total      Total findings ever stored
    findings.last_26h   Findings in the past 26 hours (what daily report will use)
    findings.by_severity  Counts broken down by critical/high/medium/low
    rag.total_documents   Total documents in ChromaDB
    processed_items.total Total URLs ever seen (dedup count)

---

### GET /findings

Query the SQLite findings table. These are LLM-triaged high-value items. Results are
sorted by severity (critical first) then by recency.

All parameters are optional and can be combined freely.

Parameters:

    hours         integer, default 26
                  How many hours back to look.
                  Example: hours=48 looks back 2 days.

    severity      string, comma-separated
                  Filter by severity level. Values: critical, high, medium, low
                  Example: severity=critical,high

    source        string, partial match, case-insensitive
                  Filter by feed source name.
                  Example: source=BleepingComputer
                  Example: source=threatfox  (matches ThreatFox)

    cve           string, partial match, case-insensitive
                  Filter by CVE ID. Partial match so CVE-2024 returns all 2024 CVEs.
                  Example: cve=CVE-2024-21182
                  Example: cve=CVE-2024  (all 2024 CVEs)

    q             string, keyword search
                  Searches in both title and summary fields.
                  Example: q=weblogic
                  Example: q=actively exploited

    start_date    string, YYYY-MM-DD
                  Only return items published on or after this date.
                  Uses the article's published date, not when it was ingested.
                  Example: start_date=2026-06-01

    end_date      string, YYYY-MM-DD
                  Only return items published on or before this date.
                  Example: end_date=2026-06-03

    limit         integer, default 100, max 1000
                  Maximum number of results to return.

    offset        integer, default 0
                  Pagination. Skip this many results before returning.

Response fields per result:
    title               Article title
    source              Feed source name
    url                 Original article URL
    published           Publication date/time
    cve                 CVE ID if identified, empty string if not
    severity            critical / high / medium / low
    affected_products   List of affected vendors/products
    summary             LLM-generated 1-3 sentence technical summary

Examples:

    # All critical and high findings from the past 48 hours
    curl "http://localhost:8888/findings?severity=critical,high&hours=48"

    # Everything related to WebLogic
    curl "http://localhost:8888/findings?q=weblogic&hours=9999"

    # All findings with a CVE ID from ThreatFox
    curl "http://localhost:8888/findings?source=threatfox&cve=CVE"

    # Paginate through all findings (page 2, 20 per page)
    curl "http://localhost:8888/findings?limit=20&offset=20"

    # Critical findings published in a specific date range
    curl "http://localhost:8888/findings?severity=critical&start_date=2026-06-01&end_date=2026-06-03"

---

### GET /findings/sources

List all feed sources that have findings in the window, with counts.

Parameters:

    hours         integer, default 26
                  Same as /findings — controls how far back to look.

    curl "http://localhost:8888/findings/sources?hours=48"

Response:
    {"sources": [{"source": "ThreatFox", "count": 24}, {"source": "BleepingComputer", "count": 8}, ...]}

---

### GET /search

Search the ChromaDB RAG knowledge base. This covers everything ever ingested
(5000+ documents) — much broader than /findings which only covers the 26h window.

Two mutually exclusive modes: semantic search (q) or CVE mode (cve).
Exactly one of q or cve must be provided.

Parameters:

    q             string
                  Free-text semantic search query. Uses vector similarity to find
                  conceptually related documents even if exact keywords don't match.
                  Example: q=botnet command and control infrastructure
                  Example: q=privilege escalation via kernel exploit

    cve           string
                  CVE mode. Provide an exact CVE ID. Bypasses vector search entirely
                  and returns every document in the knowledge base whose metadata
                  cve field exactly matches this ID.
                  Example: cve=CVE-2024-21182
                  Note: use /findings?cve= for partial matching. This is exact only.

    top           integer, default 10, max 200
                  Number of results to return.
                  In semantic mode, the engine fetches top*4 candidates internally
                  before filtering, so filters don't artificially cut off results.

    threshold     float, range 0.0 to 2.0, optional
                  Semantic mode only. Maximum distance to include.
                  Distance 0.0 = identical vector, 2.0 = opposite.
                  Practical guide:
                    0.0 - 0.5   very high similarity, near-duplicates
                    0.5 - 0.8   strong topical match
                    0.8 - 1.2   related topic, broader match
                    1.2+        weak or coincidental match
                  If not set, all results up to top are returned regardless of score.
                  Example: threshold=0.8 returns only strongly relevant results.

    start_date    string, YYYY-MM-DD or ISO datetime
                  Only return documents with a date metadata field on or after this.
                  Example: start_date=2026-05-01

    end_date      string, YYYY-MM-DD or ISO datetime
                  Only return documents with a date metadata field on or before this.
                  Example: end_date=2026-06-03

    source        string, partial match, case-insensitive
                  Filter results by source metadata field.
                  Example: source=mandiant
                  Example: source=kaspersky

    severity      string, exact match
                  Filter results by severity metadata field.
                  Values: critical, high, medium, low
                  Note: unlike /findings, this is exact (no comma-separated list).
                  Example: severity=critical

Response fields per result:
    distance          Similarity score (lower = more similar). 0.0 for CVE mode.
    keyword_match     true if the query text appeared literally in the document
                      (these are promoted above pure vector matches)
    exact_cve_match   true when using CVE mode
    metadata          Object with: source, url, cve, severity, date
    text              The full stored document text (title + LLM summary)

Examples:

    # Semantic search for Mirai botnet activity, top 10 most relevant
    curl "http://localhost:8888/search?q=mirai+botnet+iot&top=10"

    # Same but only high-confidence results
    curl "http://localhost:8888/search?q=mirai+botnet+iot&top=10&threshold=0.8"

    # Everything ever stored for a specific CVE
    curl "http://localhost:8888/search?cve=CVE-2024-21182"

    # Ransomware activity from the past month
    curl "http://localhost:8888/search?q=ransomware+encryption&start_date=2026-05-01&top=20"

    # Critical findings from Mandiant only
    curl "http://localhost:8888/search?q=apt+campaign&source=mandiant&severity=critical&top=5"

    # Broad historical search with date range (no threshold = return all top results)
    curl "http://localhost:8888/search?q=supply+chain+attack&start_date=2026-01-01&end_date=2026-06-01&top=50"

---

## Key Differences: /findings vs /search

    /findings
      - Source: SQLite findings table only
      - Scope: 26 hours by default (configurable with hours=)
      - Search: keyword match in title/summary
      - CVE: partial match
      - Use when: you want recent triaged items, structured filtering, pagination

    /search
      - Source: ChromaDB RAG knowledge base
      - Scope: everything ever ingested (5000+ documents, no time limit by default)
      - Search: vector similarity (semantic) or exact CVE metadata match
      - CVE: exact match only
      - Use when: you want historical context, conceptual similarity, or all
        records for a specific CVE across all time

---

## Response Envelope (/findings)

    {
      "total": 42,        Total matching results before pagination
      "offset": 0,        Current offset
      "limit": 100,       Current limit
      "results": [...]    Array of finding objects
    }

## Response Envelope (/search)

    {
      "mode": "semantic",       or "cve"
      "query": "weblogic rce",  The query string used
      "total_returned": 10,     Number of results after all filters
      "threshold": 0.8,         The threshold applied (null if not set)
      "results": [...]          Array of result objects
    }
