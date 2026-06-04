#!/usr/bin/env python3
"""
CTI RAG query CLI.

Usage:
  python3 query_rag.py "Log4Shell exploitation"        # all results (semantic)
  python3 query_rag.py "ransomware healthcare" --top 10
  python3 query_rag.py "CVE-2024-12345" --cve          # exact metadata match
  python3 query_rag.py --stats

Hermes can call this directly via the terminal tool:
  terminal("python3 /home/kei/llm_vault/hermes_qwen_cti/query_rag.py 'your query'")
"""

import sys
import argparse
from pathlib import Path

# Make sure the project modules are importable regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

import config  # noqa: F401 — creates data/ dirs
import rag_manager


def main():
    parser = argparse.ArgumentParser(
        description="Query the CTI ChromaDB knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "query",
        nargs="?",
        help="Natural-language search query",
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=None,
        metavar="N",
        help="Number of results to return (default: all results)",
    )
    parser.add_argument(
        "--cve",
        action="store_true",
        help="Treat QUERY as an exact CVE ID and match against metadata only (no vector search)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show knowledge base statistics only",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.6,
        metavar="T",
        help="Max cosine distance to include (0=identical, 1=unrelated; default: 0.6)",
    )
    parser.add_argument(
        "--start-date",
        type=str,
        default="",
        metavar="YYYY-MM-DD",
        help="Only show results published on or after this date",
    )
    parser.add_argument(
        "--end-date",
        type=str,
        default="",
        metavar="YYYY-MM-DD",
        help="Only show results published on or before this date",
    )

    args = parser.parse_args()

    count = rag_manager.collection_count()

    if args.stats or not args.query:
        print("CTI Knowledge Base")
        print(f"  Location : {config.CHROMA_PERSIST_DIR}")
        print(f"  Documents: {count}")
        if count == 0:
            print("  (empty — run main.py to populate it)")
            return

        stats = rag_manager.collection_stats()

        # ── Date range & recency ──────────────────────────────────────────────
        dr = stats["date_range"]
        if dr["oldest"]:
            print(f"  Date range: {dr['oldest']}  →  {dr['newest']}")
        recent = stats["recent"]
        print(f"  Added last 7 days : {recent['last_7_days']}")
        print(f"  Added last 30 days: {recent['last_30_days']}")

        # ── CVE / PoC coverage ────────────────────────────────────────────────
        print(f"\n  With CVE ID : {stats['with_cve']} "
              f"({stats['with_cve'] * 100 // count}%)")
        print(f"  With PoC    : {stats['with_poc']} "
              f"({stats['with_poc'] * 100 // count}%)", end="")
        if stats["avg_poc_stars"]:
            print(f"  [avg top ★ {stats['avg_poc_stars']}]", end="")
        print()

        # ── By severity ───────────────────────────────────────────────────────
        sev_order = ["critical", "high", "medium", "low", "unknown"]
        by_sev = stats["by_severity"]
        present = [s for s in sev_order if s in by_sev]
        remaining = [s for s in by_sev if s not in sev_order]
        ordered_sev = present + remaining
        if ordered_sev:
            print("\n  By severity:")
            for sev in ordered_sev:
                bar = "█" * (by_sev[sev] * 20 // count)
                print(f"    {sev.upper():8s} {by_sev[sev]:>5}  {bar}")

        # ── By source ─────────────────────────────────────────────────────────
        by_src = stats["by_source"]
        if by_src:
            print(f"\n  By source ({len(by_src)} distinct):")
            for src, n in list(by_src.items())[:15]:
                bar = "█" * (n * 20 // count)
                print(f"    {src[:35]:35s} {n:>5}  {bar}")
            if len(by_src) > 15:
                print(f"    … and {len(by_src) - 15} more sources")

        # ── Top recurring CVEs ────────────────────────────────────────────────
        top_cves = stats["top_cves"]
        if top_cves:
            print("\n  CVEs with multiple entries:")
            for cve, n in top_cves:
                print(f"    {cve}  ×{n}")

        return

    if count == 0:
        print("Knowledge base is empty. Run main.py first to populate it.")
        sys.exit(1)

    if args.cve:
        # Exact metadata match — skip vector search entirely
        results = rag_manager.query_by_cve(args.query)
        if args.top is not None:
            results = results[: args.top]
        if not results:
            print(f'No entries found for CVE ID: "{args.query.strip().upper()}"')
            print(f"(Knowledge base has {count} documents total)")
            sys.exit(0)
        print(f'CTI Knowledge Base — {len(results)} exact match(es) for CVE: "{args.query.strip().upper()}"\n')
        print(rag_manager.format_results_for_agent(results))
        return

    # Semantic / keyword search
    fetch_n = args.top if args.top is not None else count
    results = rag_manager.query_similar(args.query, n_results=fetch_n)

    # Filter by distance threshold
    results = [r for r in results if r["distance"] <= args.threshold]

    # Filter by date range if specified
    if args.start_date or args.end_date:
        from datetime import datetime, timezone
        filtered = []
        for r in results:
            date_str = r.get("metadata", {}).get("date", "")
            if not date_str:
                filtered.append(r)  # unknown date passes through
                continue
            try:
                pub_date = date_str[:10]  # YYYY-MM-DD
                if args.start_date and pub_date < args.start_date:
                    continue
                if args.end_date and pub_date > args.end_date:
                    continue
                filtered.append(r)
            except Exception:
                filtered.append(r)
        results = filtered

    if not results:
        print(f'No results within distance {args.threshold} for: "{args.query}"')
        print(f"(Knowledge base has {count} documents total)")
        sys.exit(0)

    print(f'CTI Knowledge Base — {len(results)} result(s) for: "{args.query}"\n')
    print(rag_manager.format_results_for_agent(results))


if __name__ == "__main__":
    main()
