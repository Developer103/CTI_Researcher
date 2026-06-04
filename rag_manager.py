"""
ChromaDB-backed vector store for long-term threat intelligence memory.

Design guarantees
─────────────────
* **Accumulates across runs** — uses PersistentClient + get_or_create_collection,
  so the collection grows every time the pipeline runs; nothing is ever wiped.

* **Semantic deduplication** — before inserting, the nearest stored document is
  checked.  If the cosine distance falls below DEDUP_DISTANCE_THRESHOLD the
  item is considered a near-duplicate and skipped, so the model never learns
  the same threat twice.

* **Agent-readable** — format_results_for_agent() produces clean, structured
  text that the hermes-agent tool (defined in agent_core.py) returns directly
  to the LLM's context window.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

import chromadb
from chromadb.utils import embedding_functions

import config

logger = logging.getLogger(__name__)

# ── Deduplication threshold ───────────────────────────────────────────────────
#
# ChromaDB returns *cosine distance* (0 = identical, 1 = orthogonal).
# Typical interpretation for all-MiniLM-L6-v2:
#   < 0.10  →  near-duplicate / paraphrase of the same event
#   0.10–0.25 →  same topic, different details  (we still allow these in)
#   > 0.25  →  clearly different item
#
# We block only true near-duplicates so the knowledge base grows meaningfully
# on each run while preventing dozens of outlets reporting the same CVE from
# flooding the store.
DEDUP_DISTANCE_THRESHOLD: float = 0.10


# ── Singleton client & collection ─────────────────────────────────────────────

_client: Optional[chromadb.PersistentClient] = None
_collection: Optional[chromadb.Collection] = None


def _get_collection() -> chromadb.Collection:
    """
    Lazily open (or create) the persistent ChromaDB collection.

    The PersistentClient writes to CHROMA_PERSIST_DIR on disk so all data
    survives process restarts.  get_or_create_collection means multiple runs
    always append to the same collection — never replace it.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    _client = chromadb.PersistentClient(path=str(config.CHROMA_PERSIST_DIR))

    # Default embedding: all-MiniLM-L6-v2 via sentence-transformers.
    # No API key required; runs fully local.
    ef = embedding_functions.DefaultEmbeddingFunction()

    _collection = _client.get_or_create_collection(
        name=config.CHROMA_COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
    logger.info(
        "ChromaDB collection '%s' opened — current size: %d documents",
        config.CHROMA_COLLECTION_NAME,
        _collection.count(),
    )
    return _collection


# ── Semantic deduplication ────────────────────────────────────────────────────

def is_near_duplicate(text: str, threshold: float = DEDUP_DISTANCE_THRESHOLD) -> bool:
    """
    Return True if *text* is semantically very close to something already stored.

    Works by querying the single nearest neighbour and comparing the cosine
    distance against *threshold*.  Returns False immediately when the collection
    is empty (first run always inserts).
    """
    collection = _get_collection()
    if collection.count() == 0:
        return False

    results = collection.query(
        query_texts=[text],
        n_results=1,
        include=["distances", "documents"],
    )

    distances = results.get("distances", [[]])[0]
    if not distances:
        return False

    nearest_dist = distances[0]
    is_dup = nearest_dist < threshold

    if is_dup:
        nearest_doc = results["documents"][0][0] if results["documents"][0] else ""
        logger.debug(
            "Near-duplicate detected (distance=%.4f < %.4f). Existing: %.80s…",
            nearest_dist,
            threshold,
            nearest_doc,
        )
    else:
        logger.debug("Novelty check passed (distance=%.4f)", nearest_dist)

    return is_dup


# ── Public API ────────────────────────────────────────────────────────────────

def insert_intel(text: str, metadata: dict) -> tuple[bool, Optional[str]]:
    """
    Embed *text* and append it to the persistent vector store — unless a
    near-duplicate already exists.

    Parameters
    ----------
    text:
        The intelligence text to embed (title + triage summary recommended).
    metadata:
        Key-value pairs stored alongside the embedding.
        Recommended keys: ``date``, ``source``, ``cve``, ``url``, ``severity``.

    Returns
    -------
    (inserted, doc_id)
        inserted=True  + doc_id string  → new document was appended.
        inserted=False + None           → skipped because a near-duplicate exists.
    """
    # ── Semantic dedup check ──────────────────────────────────────────────────
    if is_near_duplicate(text):
        logger.info(
            "RAG insert SKIPPED — near-duplicate already in store: %.70s…", text
        )
        return False, None

    collection = _get_collection()
    doc_id = str(uuid.uuid4())

    # ChromaDB requires all metadata values to be strings
    safe_meta = {k: str(v) for k, v in metadata.items()}
    import config as _cfg
    safe_meta.setdefault("date", _cfg.now_jst().isoformat())

    collection.add(documents=[text], metadatas=[safe_meta], ids=[doc_id])

    logger.info(
        "RAG insert OK — doc %s | collection now %d documents",
        doc_id,
        collection.count(),
    )
    return True, doc_id


def query_similar(query_text: str, n_results: int = 5) -> list[dict]:
    """
    Return the *n_results* most semantically similar stored intel items.

    Also injects any documents whose text contains the query as a literal
    keyword (case-insensitive) but ranked below the threshold — useful for
    product names, CVE IDs, and other identifiers that are poor vector queries.

    Each result dict contains ``text``, ``metadata``, and ``distance``.
    """
    collection = _get_collection()
    if collection.count() == 0:
        return []

    # Fetch a wider pool so keyword hits that fall outside the caller's
    # threshold can still be surfaced as exact-match bonuses.
    # When the caller already requests the full collection, skip the multiplier.
    total = collection.count()
    fetch_n = total if n_results >= total else min(max(n_results * 4, 20), total)
    results = collection.query(
        query_texts=[query_text],
        n_results=fetch_n,
        include=["documents", "metadatas", "distances"],
    )

    items = []
    seen_ids: set[str] = set()
    keyword = query_text.lower()

    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        item = {"text": doc, "metadata": meta, "distance": dist}
        # Promote keyword hits: override distance so they survive any threshold
        if keyword in doc.lower():
            item["distance"] = min(dist, 0.50)
            item["keyword_match"] = True
        items.append(item)
        seen_ids.add(doc[:40])  # rough dedup key

    # Sort: keyword matches first, then by ascending distance
    items.sort(key=lambda x: (not x.get("keyword_match"), x["distance"]))
    return items[:n_results]


def format_results_for_agent(results: list[dict]) -> str:
    """
    Render query results as clean, structured text suitable for an LLM context window.

    Called by the hermes-agent RAG tool in agent_core.py so the model
    receives consistently formatted intelligence history.
    """
    if not results:
        return "No relevant past intelligence found in the knowledge base."

    lines = [f"Retrieved {len(results)} relevant past intelligence item(s):\n"]
    for i, r in enumerate(results, 1):
        meta = r["metadata"]

        date_str   = meta.get("date", "")[:10] or "unknown date"
        source     = meta.get("source", "unknown source")
        cve        = meta.get("cve", "")
        severity   = meta.get("severity", "")
        url        = meta.get("url", "")
        poc_urls   = meta.get("poc_urls", "")
        poc_count  = meta.get("poc_count", "")
        max_stars  = meta.get("max_stars", "")
        max_forks  = meta.get("max_forks", "")
        topics     = meta.get("topics", "")
        similarity = f"{(1 - r['distance']) * 100:.0f}% similar"

        # Build a compact header line
        tags = [date_str, source, similarity]
        if cve:
            tags.append(f"CVE: {cve}")
        if severity and severity not in ("unknown", ""):
            tags.append(f"Severity: {severity.upper()}")
        if poc_count:
            poc_header = f"PoCs: {poc_count}"
            if max_stars and max_stars != "0":
                poc_header += f" (top ★{max_stars}"
                if max_forks and max_forks != "0":
                    poc_header += f", {max_forks} forks"
                poc_header += ")"
            tags.append(poc_header)

        lines.append(f"[{i}] {' | '.join(tags)}")
        lines.append(r["text"])
        if url:
            lines.append(f"Source URL: {url}")
        if topics:
            lines.append(f"Topics: {topics}")
        # Surface individual PoC links for exploit entries
        if poc_urls:
            lines.append("PoC GitHub links:")
            for poc_url in poc_urls.split(" | "):
                poc_url = poc_url.strip()
                if poc_url:
                    lines.append(f"  {poc_url}")
        lines.append("")   # blank separator between entries

    return "\n".join(lines)


def query_by_cve(cve_id: str) -> list[dict]:
    """
    Return all documents whose ``cve`` metadata field exactly matches *cve_id*.

    Bypasses vector search entirely — useful when you want every entry for a
    specific CVE without the noise of semantically similar vulnerability docs.
    The CVE ID is normalised to uppercase before matching.
    """
    collection = _get_collection()
    if collection.count() == 0:
        return []

    normalised = cve_id.strip().upper()
    result = collection.get(
        where={"cve": {"$eq": normalised}},
        include=["documents", "metadatas"],
    )

    docs = result.get("documents") or []
    metas = result.get("metadatas") or []

    items = []
    for doc, meta in zip(docs, metas):
        items.append({"text": doc, "metadata": meta, "distance": 0.0, "exact_cve_match": True})

    # Sort by date descending so the newest entry is first
    items.sort(key=lambda x: x["metadata"].get("date", ""), reverse=True)
    return items


def collection_count() -> int:
    """Return the total number of documents in the collection."""
    return _get_collection().count()


def collection_stats() -> dict:
    """
    Return rich statistics about the collection by scanning all metadata.

    Keys returned:
      total           – total document count
      by_source       – {source_name: count} sorted by count desc
      by_severity     – {severity: count} sorted by count desc
      with_cve        – number of documents that have a CVE ID
      with_poc        – number of documents that have at least one PoC
      date_range      – {"oldest": "YYYY-MM-DD", "newest": "YYYY-MM-DD"} or None
      recent          – {"last_7_days": n, "last_30_days": n}
      top_cves        – list of (cve_id, count) for CVEs appearing more than once
      avg_poc_stars   – average max_stars across documents that have PoCs (float)
    """
    from collections import Counter
    from datetime import datetime, timezone

    collection = _get_collection()
    total = collection.count()
    if total == 0:
        return {"total": 0}

    # Fetch all metadatas without loading embeddings or document text
    result = collection.get(include=["metadatas"])
    metadatas = result.get("metadatas") or []

    sources: Counter = Counter()
    severities: Counter = Counter()
    cves: Counter = Counter()
    with_cve = 0
    with_poc = 0
    poc_stars: list[int] = []
    dates: list[str] = []
    now = datetime.now(timezone.utc)
    last_7 = 0
    last_30 = 0

    for meta in metadatas:
        # source
        sources[meta.get("source") or "unknown"] += 1

        # severity – normalise to lowercase
        sev = (meta.get("severity") or "unknown").lower().strip() or "unknown"
        severities[sev] += 1

        # CVE
        cve = meta.get("cve", "").strip()
        if cve:
            with_cve += 1
            cves[cve] += 1

        # PoC
        poc_n = meta.get("poc_count", "0")
        try:
            if int(poc_n) > 0:
                with_poc += 1
                stars = int(meta.get("max_stars", 0) or 0)
                poc_stars.append(stars)
        except (ValueError, TypeError):
            pass

        # Date
        date_str = (meta.get("date") or "")[:10]
        if len(date_str) == 10:
            dates.append(date_str)
            try:
                pub = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                delta = (now - pub).days
                if delta <= 7:
                    last_7 += 1
                if delta <= 30:
                    last_30 += 1
            except ValueError:
                pass

    return {
        "total": total,
        "by_source": dict(sources.most_common()),
        "by_severity": dict(severities.most_common()),
        "with_cve": with_cve,
        "with_poc": with_poc,
        "date_range": {
            "oldest": min(dates) if dates else None,
            "newest": max(dates) if dates else None,
        },
        "recent": {
            "last_7_days": last_7,
            "last_30_days": last_30,
        },
        "top_cves": [(cve, cnt) for cve, cnt in cves.most_common(10) if cnt > 1],
        "avg_poc_stars": round(sum(poc_stars) / len(poc_stars), 1) if poc_stars else 0.0,
    }
