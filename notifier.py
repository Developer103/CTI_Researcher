"""
Discord notifier for the CTI pipeline.

Delivery strategy (tried in order):
  1. Discord REST API via the Unleash bot token from ~/.hermes/.env
     Posts directly to the target channel (DISCORD_CHANNEL_ID).
     No gateway process required — works from standalone cron.
  2. Webhook fallback — plain POST to DISCORD_WEBHOOK_URL if set.

The bot token (DISCORD_BOT_TOKEN) is read from ~/.hermes/.env, the same
credential the hermes gateway uses, so no extra secrets are needed here.
"""

import logging
import os
import smtplib
import time
from datetime import date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
from dotenv import load_dotenv

import config

logger = logging.getLogger(__name__)

# Load the hermes env to get the bot token (only read on first use)
_hermes_env_loaded = False
_DISCORD_API = "https://discord.com/api/v10"

# Target channel — override DISCORD_CHANNEL_ID in .env or it falls back to
# the hermes-unleash channel discovered during setup.
_DEFAULT_CHANNEL_ID = "1507293382509072474"   # #hermes-unleash in Stack guild

_INTER_MESSAGE_DELAY = 0.8   # Seconds between sequential Discord messages


# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_bot_token() -> str:
    """Read DISCORD_BOT_TOKEN from ~/.hermes/.env (cached after first call)."""
    global _hermes_env_loaded
    if not _hermes_env_loaded:
        hermes_env = Path.home() / ".hermes" / ".env"
        if hermes_env.exists():
            load_dotenv(hermes_env, override=False)
        _hermes_env_loaded = True
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    return token


def _bot_headers() -> dict:
    token = _get_bot_token()
    if not token:
        raise RuntimeError(
            "DISCORD_BOT_TOKEN not found in ~/.hermes/.env. "
            "Set DISCORD_WEBHOOK_URL in .env as a fallback."
        )
    return {"Authorization": f"Bot {token}", "Content-Type": "application/json"}


# ── Text chunking ─────────────────────────────────────────────────────────────

def _chunk_text(text: str, max_chars: int = config.DISCORD_MAX_CHARS) -> list[str]:
    """
    Split *text* into ≤*max_chars* chunks, breaking on newlines where possible
    so Markdown formatting is not severed mid-block.
    """
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > max_chars:
            if current:
                chunks.append(current)
            while len(line) > max_chars:
                chunks.append(line[:max_chars])
                line = line[max_chars:]
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks


# ── Primary: REST API via bot token ──────────────────────────────────────────

def _post_to_channel(channel_id: str, content: str) -> bool:
    """POST *content* to a Discord channel via the bot REST API."""
    url = f"{_DISCORD_API}/channels/{channel_id}/messages"
    try:
        resp = requests.post(
            url,
            headers=_bot_headers(),
            json={"content": content},
            timeout=10,
        )
        if resp.status_code in (200, 201):
            return True
        if resp.status_code == 429:
            retry_after = resp.json().get("retry_after", 5)
            logger.warning("Discord rate-limited; retrying after %.1fs", retry_after)
            time.sleep(retry_after)
            resp2 = requests.post(url, headers=_bot_headers(),
                                   json={"content": content}, timeout=10)
            return resp2.status_code in (200, 201)
        logger.error("Discord REST returned %d: %s", resp.status_code, resp.text[:300])
        return False
    except requests.RequestException as exc:
        logger.error("Discord REST request failed: %s", exc)
        return False


def _send_via_bot(report_markdown: str) -> bool:
    """
    Deliver *report_markdown* to DISCORD_CHANNEL_ID using the bot REST API.
    Long reports are chunked and posted sequentially.
    """
    channel_id = os.environ.get("DISCORD_CHANNEL_ID", _DEFAULT_CHANNEL_ID)

    try:
        headers = _bot_headers()   # raises if token missing
    except RuntimeError as exc:
        logger.error("%s", exc)
        return False

    chunks = _chunk_text(report_markdown)
    logger.info(
        "Posting %d message(s) to Discord channel %s via bot REST API",
        len(chunks), channel_id,
    )

    all_ok = True
    for i, chunk in enumerate(chunks, 1):
        ok = _post_to_channel(channel_id, chunk)
        if not ok:
            logger.error("Failed to post chunk %d/%d", i, len(chunks))
            all_ok = False
        if i < len(chunks):
            time.sleep(_INTER_MESSAGE_DELAY)

    return all_ok


# ── Fallback: plain webhook ───────────────────────────────────────────────────

def _send_via_webhook(report_markdown: str) -> bool:
    """Deliver via DISCORD_WEBHOOK_URL (fallback if bot delivery fails)."""
    webhook_url = config.DISCORD_WEBHOOK_URL
    if not webhook_url:
        return False

    today = config.now_jst().strftime("%Y-%m-%d")
    header = f"📡 **CTI Pipeline Daily Brief — {today}**\n{'─' * 40}"
    chunks = [header] + _chunk_text(report_markdown)

    all_ok = True
    for i, chunk in enumerate(chunks, 1):
        try:
            resp = requests.post(webhook_url, json={"content": chunk}, timeout=10)
            if resp.status_code not in (200, 204):
                logger.error("Webhook chunk %d failed: %d", i, resp.status_code)
                all_ok = False
        except requests.RequestException as exc:
            logger.error("Webhook chunk %d error: %s", i, exc)
            all_ok = False
        if i < len(chunks):
            time.sleep(_INTER_MESSAGE_DELAY)

    return all_ok


# ── Public API ────────────────────────────────────────────────────────────────

def send_report(report_markdown: str) -> bool:
    """
    Deliver *report_markdown* to Discord.

    Tries the Unleash bot REST API first, then falls back to a webhook URL
    if bot delivery fails and DISCORD_WEBHOOK_URL is configured.
    """
    if _send_via_bot(report_markdown):
        logger.info("Report delivered to Discord via bot REST API.")
        return True

    logger.warning("Bot delivery failed — trying webhook fallback…")
    if config.DISCORD_WEBHOOK_URL and _send_via_webhook(report_markdown):
        logger.info("Report delivered to Discord via webhook fallback.")
        return True

    logger.error("All Discord delivery methods failed.")
    return False


# ── Email helpers ─────────────────────────────────────────────────────────────

# Border colour for each consecutive ## section in the report (cycles)
_SECTION_COLORS = [
    "#2563eb",  # Executive Summary — blue
    "#dc2626",  # Critical Findings — red
    "#ea580c",  # CVE Spotlight — orange
    "#7c3aed",  # Historical Context — purple
    "#16a34a",  # Recommended Actions — green
    "#475569",  # Full Intelligence Feed — slate
]

_HTML_CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1b2a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Arial,'Hiragino Sans','Meiryo',sans-serif;font-size:14px;line-height:1.65;color:#1e293b}
.wrap{max-width:800px;margin:0 auto;padding:20px}
.eh{background:linear-gradient(135deg,#0d1b2a 0%,#1a3a5c 100%);border:1px solid #1e4080;border-radius:8px 8px 0 0;padding:28px 32px;text-align:center}
.eh h1{font-size:20px;font-weight:700;color:#e2e8f0;margin-bottom:8px;letter-spacing:.3px}
.db{display:inline-block;background:rgba(37,99,235,.25);border:1px solid rgba(37,99,235,.6);color:#93c5fd;padding:3px 14px;border-radius:12px;font-size:12px;font-weight:600;letter-spacing:1px}
.content{background:#fff}
.sec{padding:22px 28px;border-bottom:1px solid #e2e8f0;border-left:4px solid #94a3b8}
.sec:last-child{border-bottom:none}
h2{font-size:15px;font-weight:700;color:#0f172a;margin-bottom:12px;padding-bottom:7px;border-bottom:1px solid #f1f5f9}
h3{font-size:13px;font-weight:700;color:#1e3a8a;margin:14px 0 6px}
h4{font-size:13px;font-weight:600;color:#334155;margin:10px 0 4px}
p{margin-bottom:9px;color:#334155}
p:last-child{margin-bottom:0}
ul,ol{margin:6px 0 8px 22px;color:#334155}
li{margin-bottom:4px}
strong{font-weight:700;color:#0f172a}
em{font-style:italic;color:#64748b}
code{background:#f1f5f9;color:#be185d;padding:1px 5px;border-radius:3px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px}
pre{background:#0f172a;color:#94a3b8;padding:14px 16px;border-radius:6px;margin:8px 0;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:11.5px;line-height:1.6;white-space:pre-wrap;word-wrap:break-word}
pre code{background:none;color:#94a3b8;padding:0;font-size:inherit}
blockquote{border-left:3px solid #2563eb;background:#eff6ff;padding:9px 14px;margin:8px 0;border-radius:0 4px 4px 0;color:#1d4ed8}
hr{border:none;border-top:1px solid #e2e8f0;margin:12px 0}
a{color:#2563eb;text-decoration:none}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th{background:#f8fafc;padding:8px 12px;text-align:left;font-weight:700;color:#0f172a;border:1px solid #e2e8f0;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td{padding:8px 12px;border:1px solid #e2e8f0;color:#334155;vertical-align:top}
tr:nth-child(even) td{background:#f8fafc}
.b{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:800;letter-spacing:.5px;vertical-align:middle}
.bc{background:#dc2626;color:#fff}
.bh{background:#ea580c;color:#fff}
.bm{background:#ca8a04;color:#fff}
.bl{background:#16a34a;color:#fff}
.bi{background:#6b7280;color:#fff}
.ef{text-align:center;padding:12px 16px;color:#64748b;font-size:11px;background:#0d1b2a;border-radius:0 0 8px 8px}
"""


def translate_to_japanese(report_markdown: str) -> str:
    """Public wrapper — translate once, cache/reuse the result yourself."""
    return _translate_to_japanese(report_markdown)


def _translate_to_japanese(report_markdown: str) -> str:
    """Translate the Markdown report to Japanese via the local Qwen model."""
    try:
        from openai import OpenAI
    except ImportError:
        logger.warning("openai package not available — skipping translation")
        return report_markdown

    client = OpenAI(base_url=config.OPENAI_API_BASE, api_key=config.OPENAI_API_KEY)

    system = (
        "あなたは日本語ネイティブのサイバーセキュリティアナリストです。\n"
        "以下のレポートを、日本のセキュリティ専門家が自分で書いたように自然な日本語に訳してください。\n\n"
        "【文体について】\n"
        "- 直訳ではなく、意味を保ちながら自然な日本語表現を使うこと\n"
        "- 英語の語順や構文をそのまま日本語に置き換えない\n"
        "- カタカナは本当に必要な場合のみ使用する。日本語や漢字で自然に表現できる言葉は日本語を使う\n"
        "  （例：「攻撃者」「脆弱性」「認証回避」「権限昇格」「実行」「悪用」「感染」「侵害」「検出」「対策」など）\n"
        "- 文末は「〜した」「〜される」「〜が確認された」「〜に注意が必要」などの自然な体言止め・です/ます調を状況に応じて使う\n"
        "- セキュリティレポートとして読み手に伝わる、簡潔で明確な文章にすること\n\n"
        "【変更しないもの】\n"
        "- すべてのMarkdown書式（# 見出し、**太字**、- リスト、> 引用、表、コードブロックなど）\n"
        "- CVE ID（例: CVE-2024-12345）\n"
        "- 製品名・ベンダー名・マルウェア名（Windows, Apache, Palo Alto, Mirai, Cobalt Strike など）\n"
        "- 技術略語（CVSS, PoC, APT, TTP, RCE, SQLi, XSS, LPE, DDoS, IoC, C2, EDR, MFA, SYSTEM など）\n"
        "- 深刻度ラベル [CRITICAL]、[HIGH]、[MEDIUM]、[LOW]\n"
        "- URL、IPアドレス、ハッシュ値、バージョン番号\n"
        "- 絵文字（🛡🔴🟠🟡🔗 など）\n\n"
        "翻訳後のMarkdownのみ出力すること。説明・前置き・コメントは不要。"
    )

    logger.info("Translating report to Japanese via %s…", config.MODEL_NAME)
    try:
        response = client.chat.completions.create(
            model=config.MODEL_NAME,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": report_markdown},
            ],
            temperature=0.1,
            timeout=360,
        )
        translated = response.choices[0].message.content or ""
        # Strip Qwen3 thinking blocks if present
        import re as _re
        translated = _re.sub(r"<think>.*?</think>", "", translated, flags=_re.DOTALL).strip()
        if translated:
            logger.info("Translation complete (%d chars)", len(translated))
            return translated
        logger.warning("Translation returned empty — using English report")
        return report_markdown
    except Exception as exc:
        logger.warning("Translation failed (%s) — using English report", exc)
        return report_markdown


def _inline_md(text: str) -> str:
    """Convert inline Markdown to HTML-safe text with formatting."""
    import re as _re

    # Split on inline code spans first so their content is only HTML-escaped
    parts = _re.split(r"(`[^`]+`)", text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 2:
            inner = part[1:-1].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            out.append(f"<code>{inner}</code>")
            continue

        # HTML-escape the non-code portion
        p = part.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Severity badges
        p = p.replace("[CRITICAL]", '<span class="b bc">CRITICAL</span>')
        p = p.replace("[HIGH]",     '<span class="b bh">HIGH</span>')
        p = p.replace("[MEDIUM]",   '<span class="b bm">MEDIUM</span>')
        p = p.replace("[LOW]",      '<span class="b bl">LOW</span>')

        # Links [text](url) — after escaping, url may contain &amp;
        p = _re.sub(
            r"\[([^\]]+)\]\(([^)]+)\)",
            lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>',
            p,
        )

        # Bold **text** before italic *text*
        p = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", p)

        # Italic *text* (not part of **)
        p = _re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", p)

        out.append(p)
    return "".join(out)


def _body_to_html(md: str) -> str:
    """Convert a Markdown section body to HTML (handles tables, lists, code, blockquotes)."""
    import re as _re

    lines = md.splitlines()
    html: list[str] = []
    in_ul = in_ol = in_table = in_code = in_bq = False
    pending: list[str] = []

    def flush_para():
        nonlocal pending
        if pending:
            t = " ".join(pending).strip()
            if t:
                html.append(f"<p>{_inline_md(t)}</p>")
            pending = []

    def close_list():
        nonlocal in_ul, in_ol
        if in_ul:
            html.append("</ul>"); in_ul = False
        if in_ol:
            html.append("</ol>"); in_ol = False

    def close_table():
        nonlocal in_table
        if in_table:
            html.append("</tbody></table>"); in_table = False

    def close_bq():
        nonlocal in_bq
        if in_bq:
            html.append("</blockquote>"); in_bq = False

    def reset_blocks():
        flush_para(); close_list(); close_table(); close_bq()

    for line in lines:
        # ── Code block ──────────────────────────────────────────────────────────
        if line.strip().startswith("```"):
            if in_code:
                html.append("</code></pre>"); in_code = False
            else:
                reset_blocks()
                html.append('<pre><code>'); in_code = True
            continue
        if in_code:
            html.append(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + "\n")
            continue

        # ── Blank line ───────────────────────────────────────────────────────────
        if not line.strip():
            if pending:
                flush_para()
            else:
                close_list(); close_table(); close_bq()
            continue

        # ── H3 / H4 ─────────────────────────────────────────────────────────────
        if line.startswith("#### "):
            reset_blocks()
            html.append(f"<h4>{_inline_md(line[5:].strip())}</h4>"); continue
        if line.startswith("### "):
            reset_blocks()
            html.append(f"<h3>{_inline_md(line[4:].strip())}</h3>"); continue

        # ── HR ───────────────────────────────────────────────────────────────────
        if _re.match(r"^[-*_]{3,}$", line.strip()):
            reset_blocks(); html.append("<hr>"); continue

        # ── Table ────────────────────────────────────────────────────────────────
        if line.strip().startswith("|"):
            flush_para(); close_bq(); close_list()
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(_re.match(r"^[-: ]+$", c) for c in cells if c):
                # Separator row — transition from thead to tbody already done
                continue
            if not in_table:
                row = "".join(f"<th>{_inline_md(c)}</th>" for c in cells)
                html.append(f"<table><thead><tr>{row}</tr></thead><tbody>")
                in_table = True
            else:
                row = "".join(f"<td>{_inline_md(c)}</td>" for c in cells)
                html.append(f"<tr>{row}</tr>")
            continue
        else:
            close_table()

        # ── Blockquote ───────────────────────────────────────────────────────────
        if line.startswith("> "):
            flush_para(); close_list()
            if not in_bq:
                html.append("<blockquote>"); in_bq = True
            html.append(f"<p>{_inline_md(line[2:].strip())}</p>"); continue
        else:
            close_bq()

        # ── Unordered list ───────────────────────────────────────────────────────
        ul = _re.match(r"^\s*[-*]\s+(.+)", line)
        if ul:
            flush_para(); close_table()
            if in_ol:
                html.append("</ol>"); in_ol = False
            if not in_ul:
                html.append("<ul>"); in_ul = True
            html.append(f"<li>{_inline_md(ul.group(1))}</li>"); continue

        # ── Ordered list ─────────────────────────────────────────────────────────
        ol = _re.match(r"^\s*\d+[.)]\s+(.+)", line)
        if ol:
            flush_para(); close_table()
            if in_ul:
                html.append("</ul>"); in_ul = False
            if not in_ol:
                html.append("<ol>"); in_ol = True
            html.append(f"<li>{_inline_md(ol.group(1))}</li>"); continue

        # Fallthrough — close lists then accumulate as paragraph text
        if in_ul or in_ol:
            close_list()
        pending.append(line)

    # Flush any trailing state
    flush_para(); close_list(); close_table(); close_bq()
    if in_code:
        html.append("</code></pre>")

    return "\n".join(html)


def _render_html_email(report_markdown: str, language: str = "ja") -> str:
    """Convert a Markdown CTI brief into a styled HTML email."""
    import re as _re

    lines = report_markdown.splitlines()
    h1_title = ""
    sections: list[tuple[str, list[str]]] = []
    cur_head: str | None = None
    cur_body: list[str] = []

    for line in lines:
        if line.startswith("# ") and not line.startswith("## "):
            h1_title = line[2:].strip()
        elif line.startswith("## "):
            if cur_head is not None:
                sections.append((cur_head, cur_body))
            cur_head = line[3:].strip()
            cur_body = []
        elif cur_head is not None:
            cur_body.append(line)

    if cur_head is not None:
        sections.append((cur_head, cur_body))

    # Extract date from H1 title (e.g. "🛡 Daily Cyber Threat Brief — 2026-06-02")
    date_m = _re.search(r"\d{4}-\d{2}-\d{2}", h1_title)
    date_str = date_m.group(0) if date_m else config.today_jst().isoformat()

    # Pull the pipeline footer line (*Brief generated by…*) out of the last section
    # so it renders in the email footer bar, not inside a content card.
    pipeline_footer = ""
    if sections:
        last_head, last_body = sections[-1]
        # Walk backwards, skip blank lines, grab the first italic-only line
        for i in range(len(last_body) - 1, -1, -1):
            stripped = last_body[i].strip()
            if not stripped:
                continue
            if _re.match(r"^\*[^*].+[^*]\*$", stripped):
                pipeline_footer = stripped[1:-1]  # strip the surrounding *
                last_body = last_body[:i] + last_body[i + 1:]
                sections[-1] = (last_head, last_body)
            break

    if language == "ja":
        header_title = "🛡 CTI デイリー脅威ブリーフ"
        footer_text = pipeline_footer or "CTI Pipeline &nbsp;·&nbsp; ローカル知識ベース &nbsp;·&nbsp; 自動生成レポート"
    else:
        header_title = "🛡 CTI Daily Threat Brief"
        footer_text = pipeline_footer or "CTI Pipeline &nbsp;·&nbsp; Local Knowledge Base &nbsp;·&nbsp; Auto-generated Report"

    # Build section divs — strip trailing --- dividers from each body
    # (they are Markdown section separators, not needed inside HTML cards)
    section_html_parts: list[str] = []
    for idx, (heading, body_lines) in enumerate(sections):
        # Drop trailing blank lines and --- / *** / ___ dividers
        trimmed = list(body_lines)
        while trimmed and _re.match(r"^[-*_]{3,}$", trimmed[-1].strip()) or (trimmed and not trimmed[-1].strip()):
            trimmed.pop()
        color = _SECTION_COLORS[idx % len(_SECTION_COLORS)]
        body_html = _body_to_html("\n".join(trimmed))
        section_html_parts.append(
            f'<div class="sec" style="border-left-color:{color}">'
            f"<h2>{_inline_md(heading)}</h2>"
            f"{body_html}"
            f"</div>"
        )

    body_html = "\n".join(section_html_parts)

    lang_attr = "ja" if language == "ja" else "en"
    return f"""\
<!DOCTYPE html>
<html lang="{lang_attr}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CTI Brief — {date_str}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="eh" style="background:linear-gradient(135deg,#0d1b2a 0%,#1a3a5c 100%);border:1px solid #1e4080;border-radius:8px 8px 0 0;padding:28px 32px;text-align:center">
    <h1>{header_title}</h1>
    <span class="db">{date_str}</span>
  </div>
  <div class="content">
{body_html}
  </div>
  <div class="ef">{footer_text}</div>
</div>
</body>
</html>"""


def send_report_email(
    report_markdown: str,
    to_email: str,
    language: str = "ja",
    skip_translation: bool = False,
) -> bool:
    """
    Render *report_markdown* as a styled HTML email and deliver to *to_email*.

    language="ja"              — translate then send (Japanese subject/header)
    language="ja" + skip_translation=True — content is already translated; skip LLM call
    language="en"              — send as-is (English subject/header)
    """
    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        logger.error("Email delivery skipped — SMTP_USER or SMTP_PASSWORD not set in .env")
        return False

    today = config.now_jst().strftime("%Y-%m-%d")

    # ── Translate if needed ───────────────────────────────────────────────────
    if language == "ja" and not skip_translation:
        content_md = _translate_to_japanese(report_markdown)
        subject = f"CTI デイリー脅威ブリーフ — {today}"
    elif language == "ja":
        content_md = report_markdown  # already translated by caller
        subject = f"CTI デイリー脅威ブリーフ — {today}"
    else:
        content_md = report_markdown
        subject = f"CTI Daily Brief — {today}"

    # ── Render HTML ───────────────────────────────────────────────────────────
    html_body = _render_html_email(content_md, language=language)

    # ── Assemble MIME message ─────────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM or config.SMTP_USER
    recipients = [addr.strip() for addr in to_email.split(",")]
    msg["To"] = ", ".join(recipients)
    # plain first (lowest priority), html second (preferred by mail clients)
    msg.attach(MIMEText(content_md, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # ── Send ──────────────────────────────────────────────────────────────────
    try:
        # Gmail app passwords are issued with spaces; strip them before login
        password = config.SMTP_PASSWORD.replace(" ", "")
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(config.SMTP_USER, password)
            smtp.sendmail(config.SMTP_FROM or config.SMTP_USER, recipients, msg.as_string())
        logger.info("Report emailed to %s via %s:%d", to_email, config.SMTP_HOST, config.SMTP_PORT)
        return True
    except smtplib.SMTPAuthenticationError as exc:
        logger.error(
            "SMTP auth failed (%s). "
            "For Gmail, use an App Password — https://myaccount.google.com/apppasswords",
            exc,
        )
        return False
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Email delivery failed: %s", exc)
        return False


def send_immediate_alert(findings: list[dict]) -> bool:
    """
    Post a compact immediate-alert message to Discord for high-risk findings.

    Translation is intentionally skipped — speed matters for immediate alerts.
    """
    now = config.now_jst().strftime("%Y-%m-%d %H:%M JST")
    lines = [f"🚨 **IMMEDIATE CTI ALERT** — {now}\n{'─' * 40}"]
    for f in findings:
        sev = f.get("severity", "unknown").upper()
        title = f.get("title", "Untitled")
        cve = f.get("cve", "")
        source = f.get("source", "")
        summary = f.get("summary", "")[:300]
        products = ", ".join(f.get("affected_products", []))
        url = f.get("url", "")
        block = [f"**[{sev}]** {title}"]
        if cve:
            block.append(f"CVE: `{cve}`")
        if products:
            block.append(f"Affected: {products}")
        if source:
            block.append(f"Source: {source}")
        if summary:
            block.append(summary)
        if url:
            block.append(f"🔗 {url}")
        lines.append("\n".join(block))
        lines.append("─" * 30)
    message = "\n\n".join(lines)

    ok = _send_via_bot(message)
    if not ok and config.DISCORD_WEBHOOK_URL:
        ok = _send_via_webhook(message)
    if ok:
        logger.info("Immediate alert delivered to Discord (%d findings).", len(findings))
    else:
        logger.error("Immediate alert Discord delivery failed.")
    return ok


def send_immediate_alert_email(findings: list[dict], to_email: str, language: str = "en") -> bool:
    """Send a compact HTML immediate-alert email for high-risk findings."""
    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        logger.error("Email delivery skipped — SMTP_USER or SMTP_PASSWORD not set")
        return False

    now = config.now_jst().strftime("%Y-%m-%d %H:%M JST")
    today = config.now_jst().strftime("%Y-%m-%d")

    if language == "ja":
        subject = f"🚨 CTI 即時アラート — {today} ({len(findings)}件)"
    else:
        subject = f"🚨 CTI Immediate Alert — {today} ({len(findings)} finding(s))"

    # Build compact HTML
    sev_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}
    cards = []
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        color = sev_color.get(sev, "#475569")
        title = f.get("title", "Untitled").replace("<", "&lt;").replace(">", "&gt;")
        cve = f.get("cve", "")
        source = f.get("source", "").replace("<", "&lt;")
        summary = f.get("summary", "")[:400].replace("<", "&lt;").replace(">", "&gt;")
        products = ", ".join(f.get("affected_products", [])).replace("<", "&lt;")
        url = f.get("url", "")
        meta = []
        if cve:
            meta.append(f"CVE: <code>{cve}</code>")
        if products:
            meta.append(f"Affected: {products}")
        if source:
            meta.append(f"Source: {source}")
        meta_html = " &nbsp;·&nbsp; ".join(meta)
        cards.append(f"""
<div style="border-left:4px solid {color};padding:14px 18px;margin:10px 0;background:#fff;border-radius:0 6px 6px 0">
  <div style="font-size:11px;font-weight:800;color:{color};text-transform:uppercase;letter-spacing:.8px">{sev}</div>
  <div style="font-size:15px;font-weight:700;color:#0f172a;margin:4px 0 6px">{title}</div>
  <div style="font-size:11px;color:#64748b;margin-bottom:8px">{meta_html}</div>
  <div style="font-size:13px;color:#334155">{summary}</div>
  {'<div style="margin-top:8px"><a href="' + url + '" style="color:#2563eb;font-size:12px">Read more →</a></div>' if url else ''}
</div>""")

    cards_html = "\n".join(cards)
    html = f"""\
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>CTI Alert — {today}</title></head>
<body style="background:#0d1b2a;margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif">
<div style="max-width:700px;margin:0 auto">
  <div style="background:linear-gradient(135deg,#7f1d1d,#450a0a);border:1px solid #dc2626;border-radius:8px 8px 0 0;padding:22px 28px;text-align:center">
    <div style="font-size:22px;font-weight:800;color:#fef2f2">🚨 IMMEDIATE CTI ALERT</div>
    <div style="display:inline-block;background:rgba(220,38,38,.3);border:1px solid rgba(220,38,38,.7);color:#fca5a5;padding:3px 14px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:1px;margin-top:8px">{now} &nbsp;·&nbsp; {len(findings)} FINDING(S)</div>
  </div>
  <div style="background:#f8fafc;padding:16px 20px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px">
    {cards_html}
  </div>
</div>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM or config.SMTP_USER
    recipients = [addr.strip() for addr in to_email.split(",")]
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(
        "\n\n".join(
            f"[{f.get('severity','?').upper()}] {f.get('title','')} — {f.get('url','')}"
            for f in findings
        ),
        "plain", "utf-8",
    ))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        password = config.SMTP_PASSWORD.replace(" ", "")
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo(); smtp.starttls(); smtp.ehlo()
            smtp.login(config.SMTP_USER, password)
            smtp.sendmail(config.SMTP_FROM or config.SMTP_USER, recipients, msg.as_string())
        logger.info("Immediate alert emailed to %s.", to_email)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Immediate alert email failed: %s", exc)
        return False


def send_error_alert(message: str) -> None:
    """Post a short error alert to Discord. Failure is logged but not re-raised."""
    short = f"⚠️ **CTI Pipeline Alert**\n```\n{message[:1800]}\n```"
    try:
        _send_via_bot(short)
    except Exception:
        if config.DISCORD_WEBHOOK_URL:
            try:
                requests.post(config.DISCORD_WEBHOOK_URL, json={"content": short}, timeout=10)
            except Exception:
                pass
