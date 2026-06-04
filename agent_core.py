"""
Hermes-Agent / Qwen brain for the CTI pipeline.

Timeout handling strategy:
  - Each triage_item call has a 200s timeout (allows 10 items/hour even in worst case)
  - If timeout occurs, logging.warning is called and TriageResult=None returned
  - Timeout items are tracked by main.py and included in final report memo

Real hermes-agent API (v0.15.1):
  - AIAgent(base_url=, api_key=, model=, ephemeral_system_prompt=,
            enabled_toolsets=[...], quiet_mode=True)
  - agent.run_conversation(user_message, system_message=None) -> dict
  - agent.chat(message) -> str   [wrapper around run_conversation]

RAG integration strategy (two layers):
  1. Pre-fetch: rag_manager.query_similar() is called before every agent
     call and its results are embedded directly in the message so the model
     always sees relevant history without needing a tool.
  2. Live tool: the agent is given the `code_execution` toolset so it can
     run Python to call rag_manager.query_similar() for additional searches
     during its reasoning loop.  The system prompts describe exactly how.
     This also means a standalone `hermes` CLI session with qwen3.5:35b
     can query the knowledge base by running the provided Python snippet.

Public functions
─────  ───────────
  triage_item()  — decide if a raw news item is high-value intel
  write_report() — synthesise a list of findings into a Daily Cyber Brief
"""

import json
import logging
import re
from datetime import date
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

import config

logger = logging.getLogger(__name__)

# Timeout per triage_item call (200s = 3.3 min, allows 10 items/hour max)
TRIAGE_TIMEOUT_SECONDS = 200

# Module-level globals for timeout tracking — declared here so all functions
# can reference them without fragile 'if key not in globals()' guards.
_TRIAGE_TIMEOUT_COUNT: int = 0
_TIMEOUT_URLS: list = []

# Absolute path to the project root — embedded in system prompts so the
# agent can construct the correct sys.path.insert call.
_PROJECT_ROOT = str(Path(__file__).parent.resolve())

# Python snippet the agent can run to query the RAG knowledge base.
# Written into both system prompts so a standalone hermes CLI session
# with qwen3.5:35b also has the capability.
_RAG_PYTHON_SNIPPET = f"""\
import sys
sys.path.insert(0, {repr(_PROJECT_ROOT)})
from rag_manager import query_similar, format_results_for_agent
results = query_similar("YOUR QUERY HERE", n_results=5)
print(format_results_for_agent(results))\
"""


# ── Pydantic schemas ────────────────────────────────────────  ──  ──  ──  ──  ──  ──

class TriageResult(BaseModel):
    """Structured output from the triage agent call."""

    is_valuable: bool = Field(
        description="True if this item contains actionable threat intelligence."
    )
    cve: str = Field(
        default="",
        description="CVE identifier if present, e.g. 'CVE-2024-12345', else empty string.",
    )
    summary: str = Field(
        description="One-to-three sentence technical summary of the threat.",
    )
    severity: str = Field(
        default="unknown",
        description="Estimated severity: critical | high | medium | low | unknown.",
    )
    affected_products: list[str] = Field(
        default_factory=list,
        description="List of affected vendors/products, if mentioned.",
    )


# ── Agent initialisation ───────────  ──  ─────────────────  ──  ───  ─────── ────

def _build_agent(system_prompt: str):
    """
    Instantiate a hermes-agent AIAgent with the given persistent system prompt
    and the ``code_execution`` toolset enabled for live RAG queries.
    """
    try:
        from run_agent import AIAgent  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "hermes-agent is not installed. Run:\n"
            "  pip install git+https://github.com/NousResearch/hermes-agent.git"
        ) from exc

    agent = AIAgent(
        model=config.MODEL_NAME,
        base_url=config.OPENAI_API_BASE,
        api_key=config.OPENAI_API_KEY,
        quiet_mode=True,
        ephemeral_system_prompt=system_prompt,
        # code_execution lets Qwen call rag_manager directly during reasoning.
        # file toolset gives read_file for context; all others suppressed.
        enabled_toolsets=["code_execution", "file"],
    )
    return agent


# Lazily-created singletons — separate instances because ephemeral_system_prompt
# is fixed at construction time.
_triage_agent = None
_reporter_agent = None


def _get_triage_agent():
    global _triage_agent
    if _triage_agent is None:
        _triage_agent = _build_agent(_TRIAGE_SYSTEM)
    return _triage_agent


def _get_reporter_agent():
    global _reporter_agent
    if _reporter_agent is None:
        _reporter_agent = _build_agent(_REPORTER_SYSTEM)
    return _reporter_agent


# ── System prompts ──────── ────────── ──────────────────────  ────────  ───  ───  ───


_TRIAGE_SYSTEM = f"""\
You are a senior offensive security researcher and threat intelligence analyst.
Your ONLY task is to evaluate raw security news items and decide whether they \
contain actionable, high-value threat intelligence worth distributing to a \
security operations team.

═══ KNOWLEDGE BASE ACCESS ═══
You have access to a local CTI knowledge base via the execute_code tool.
To check if a threat has already been analysed, run this Python snippet
(replace the query string as needed):

{_RAG_PYTHON_SNIPPET}

Before rating an item, call execute_code with the title as the query to avoid
marking already-covered events as new and valuable.

═══ RATING CRITERIA ═══
HIGH VALUE — set is_valuable=true:
  • Active exploitation of vulnerabilities (0-day, 1-day, in-the-wild)
  • New ransomware / APT TTPs or campaigns
  • Critical CVEs with PoC or confirmed exploitation
  • Large-scale data breaches (enterprise / government targets)
  • Malware campaigns targeting enterprise infrastructure

LOW VALUE — set is_valuable=false:
  • Marketing content, vendor press releases, awareness posts
  • Old CVEs with no new exploitation activity
  • Opinion pieces without specific threat data
  • Duplicate coverage already in the knowledge base

═══ OUTPUT FORMAT ═══
After any tool use, output ONLY a valid JSON object — no markdown fences, \
no extra text, nothing else:
{{
  "is_valuable": <bool>,
  "cve": "<CVE-ID or empty string>",
  "summary": "<1-3 sentence technical summary>",
  "severity": "<critical|high|medium|low|unknown>",
  "affected_products": ["<product1>", ...]
}}\
"""

_REPORTER_SYSTEM = f"""\
You are a principal threat intelligence analyst writing a classified daily \
cyber threat brief for a security operations team. Output will be distributed \
via Discord and must use Markdown formatting.

═══ KNOWLEDGE BASE ACCESS ═══
You have access to a persistent CTI knowledge base — use it to enrich the brief \
with historical context, recurring actor patterns, and CVE series data.
Run this Python snippet via execute_code (replace query as needed):

{_RAG_PYTHON_SNIPPET}

Use execute_code once or twice during writing to pull context for the most \
significant findings. Include any useful historical patterns in the \
"Historical Context" section.

═══ REQUIRED STRUCTURE ═══
# 🛡 Daily Cyber Threat Brief — {{DATE}}

## Executive Summary
(2-3 sentences on the day's most critical themes)

## Critical Findings
(Bulleted list: severity tag · affected product · one-sentence impact)

## CVE Spotlight
(Named CVEs with estimated CVSS, affected versions, exploitation status)

## Historical Context
(Relevant past intelligence from the knowledge base — skip if nothing found)

## Recommended Actions
(Concrete, prioritised mitigations for today)

## Full Intelligence Feed
(Numbered list of all findings with summaries and URLs)

---
*Brief generated by the local CTI pipeline · Knowledge base: {{KB_COUNT}} documents.*\
"""


# ── Prompt helpers ──────── ──────────  ──────────────────    ────────    ───    ───


_TRIAGE_MESSAGE_TEMPLATE = """\
ITEM TO EVALUATE:
Title:   {title}
Source:  {source}
URL:     {url}
Content:
{content}

RELEVANT PAST INTELLIGENCE (pre-fetched from knowledge base):
{rag_context}

Output the JSON triage result now.\
"""

_REPORTER_MESSAGE_TEMPLATE = """\
Today's date: {date}
Knowledge base size: {kb_count} documents

Here are today's {count} validated threat intelligence findings:

{findings_block}
{timeout_section}{timeout_note}
Write the complete Daily Cyber Threat Brief now.\
"""


# ── Public functions ─────────── ───  ───  ───  ────────────  ───  ─────── ────


def triage_item(
    title: str,
    url: str,
    content: str,
    source: str = "unknown",
) -> Optional[TriageResult]:
    """
    Ask Qwen (via hermes-agent) to assess a single news item.

    RAG context is pre-fetched and embedded in the message so the model sees
    relevant history immediately.  The agent may also call execute_code for
    additional knowledge base queries during its reasoning loop.

    Returns a TriageResult or None on LLM/parse failure.
    """
    # Pre-fetch RAG context for this item
    rag_context = _pre_fetch_rag(f"{title} {content[:300]}")

    message = _TRIAGE_MESSAGE_TEMPLATE.format(
        title=title,
        source=source,
        url=url,
        content=content[:4000],
        rag_context=rag_context,
    )

    agent = _get_triage_agent()
    try:
        raw = agent.run_conversation(
            user_message=message,
        )["final_response"]
    except Exception as exc:
        logger.error("LLM triage call failed for '%s': %s", url, exc)
        return None

    return _parse_triage_response(raw, url)


def triage_item_with_timeout(
    title: str,
    url: str,
    content: str,
    source: str = "unknown",
):
    """
    Wrapper around triage_item that handles timeouts gracefully.
    Uses ThreadPoolExecutor with timeout to avoid crashing the pipeline.

    Returns TriageResult or None (on timeout/failure).
    Tracks timeout events for inclusion in final report memo.

    Side effect: Updates global _TRIAGE_TIMEOUT_COUNT and _TIMEOUT_URLS list.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
    import sys

    # Import tracking globals from module level (hack to access from function scope)
    # These are in the global namespace of this module
    global _TRIAGE_TIMEOUT_COUNT, _TIMEOUT_URLS

    result_holder = {"result": None, "exception": None}
    lock = threading.Lock()

    def _run_trage():
        try:
            result_holder["result"] = triage_item(title, url, content, source)
        except Exception as e:
            logger.error("Triage execution failed for '%s': %s", url, e)
            result_holder["exception"] = e

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_trage)
            future.result(timeout=TRIAGE_TIMEOUT_SECONDS)
        return result_holder["result"]
    except FuturesTimeoutError:
        with lock:
            _TRIAGE_TIMEOUT_COUNT += 1
            _TIMEOUT_URLS.append(url)
        logger.warning(f"Triage timeout for '{url}' (exceeded {TRIAGE_TIMEOUT_SECONDS}s)")
        return None
    except Exception as e:
        logger.error("Unexpected error in triage for '%s': %s", url, e)
        return None


def _get_timeout_summary() -> str:
    """Return formatted timeout summary for inclusion in the daily report."""
    if _TRIAGE_TIMEOUT_COUNT == 0:
        return ""
    count = _TRIAGE_TIMEOUT_COUNT
    urls = _TIMEOUT_URLS

    summary = [f"\n{'─' * 60}"]
    summary.append(f"⚠️  TIMEOUT SUMMARY — {len(urls)} items failed to process within {TRIAGE_TIMEOUT_SECONDS}s")
    summary.append(f"{'─' * 60}\n")
    for i, url in enumerate(urls, 1):
        summary.append(f"{i}. {url}")
    summary.append(f"\n*These items were skipped to maintain pipeline throughput.*")
    return "".join(summary)


def write_report(findings: list[dict]) -> Optional[str]:
    """
    Ask Qwen to write a cohesive Daily Cyber Threat Brief in Markdown.

    The agent is given the code_execution tool so it can query the knowledge
    base autonomously during writing to surface historical patterns.

    Returns the Markdown report string, or None on failure.
    """
    if not findings:
        logger.warning("write_report called with empty findings list")
        return None

    import rag_manager
    import config as _cfg
    kb_count = rag_manager.collection_count()
    today = _cfg.now_jst().strftime("%Y-%m-%d")
    findings_block = _format_findings_for_prompt(findings)
    timeout_summary = _get_timeout_summary()

    message = _REPORTER_MESSAGE_TEMPLATE.format(
        date=today,
        kb_count=kb_count,
        count=len(findings),
        findings_block=findings_block,
        timeout_section=timeout_summary if timeout_summary else "",
        timeout_note="\n\n*Pipeline completed with timeout events—review notes above.*" if (timeout_summary and "TIMEOUT SUMMARY" in timeout_summary) else "",
    )

    agent = _get_reporter_agent()
    try:
        report = agent.run_conversation(
            user_message=message,
        )["final_response"]
    except Exception as exc:
        logger.error("LLM reporter call failed: %s", exc)
        return None

    return report.strip() if report else None


# ── Internal helpers ─────────────────────────────────  ──────── ───    ───    ───


def _pre_fetch_rag(query: str) -> str:
    """
    Query ChromaDB and return formatted results for prompt injection.
    Returns a "not yet populated" notice when the store is empty.
    """
    try:
        import rag_manager
        results = rag_manager.query_similar(query, n_results=3)
        return rag_manager.format_results_for_agent(results)
    except Exception as exc:
        logger.warning("RAG pre-fetch failed: %s", exc)
        return "(Knowledge base unavailable — ChromaDB error)"


def _parse_triage_response(raw: str, url: str) -> Optional[TriageResult]:
    """Extract and validate JSON from the model's raw reply."""
    if not raw:
        logger.warning("Empty triage response for %s", url)
        return None

    # Strip any accidental markdown code fences (```json … ``` or plain ```)
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1 or end == 0:
        logger.warning("No JSON found in triage response for %s | raw=%.200s", url, cleaned)
        return None

    json_str = cleaned[start:end]
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning(f"JSON decode error for {url}: {exc} | raw={json_str[:200]}")
        return None

    try:
        return TriageResult(**data)
    except ValidationError as exc:
        logger.warning("TriageResult validation error for %s: %s", url, exc)
        return None


def _format_findings_for_prompt(findings: list[dict]) -> str:
    """Render findings as a numbered text block for the reporter prompt."""
    lines = []
    for i, f in enumerate(findings, start=1):
        products = ", ".join(f.get("affected_products", [])) or "N/A"
        lines.append(
            f"{i}. [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Untitled')}\n"
            f"   CVE: {f.get('cve', 'N/A')} | Products: {products}\n"
            f"   Summary: {f.get('summary', '')}\n"
            f"   URL: {f.get('url', '')}\n"
        )
    return "\n".join(lines)