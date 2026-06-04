"""
Feed ingestor for the CTI pipeline.

Supported feed types (set via the ``type`` key in config.RSS_FEEDS):
  rss           — standard Atom/RSS via feedparser (default)
  threatfox     — abuse.ch ThreatFox IOC export (JSON, no auth)
  urlhaus       — abuse.ch URLhaus malware URL export (ZIP → JSON, no auth)
  feodo         — abuse.ch Feodo Tracker botnet C2 blocklist (JSON, no auth)
  poc_github    — nomi-sec/PoC-in-GitHub: new CVE PoC repos added in last N hours

All items are normalised to:
  {
    "title":     str,
    "url":       str,      # canonical link — used as the SQLite dedup key
    "content":   str,      # best available body text (HTML stripped)
    "source":    str,      # feed name from config
    "published": str,      # ISO-8601 UTC string or empty
  }

Only items published within the last ``config.LOOKBACK_HOURS`` hours are
returned.  Unreachable feeds are logged and skipped gracefully.
"""

import html
import io
import json
import logging
import os
import re
import time
import zipfile
from datetime import datetime, timezone, timedelta
from typing import Optional

import feedparser
import requests

import config

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "CTI-Pipeline/1.0 (security research)"}


# Shared helpers ───────────────────────────────────────────────────────────────

def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parse a date string (YYYY-MM-DD) to midnight UTC."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
    except ValueError:
        logger.warning("Invalid date format: %s (expected YYYY-MM-DD)", date_str)
        return None


def _cutoff_dt() -> datetime:
    """Return the 24-hour lookback cutoff (legacy default)."""
    return datetime.now(tz=timezone.utc) - timedelta(hours=config.LOOKBACK_HOURS)


def _filter_by_date(
    pub_dt: Optional[datetime],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> bool:
    """
    Return True if pub_dt falls within the requested range.

    - Neither provided → legacy 24-hour lookback.
    - start_date only  → pub_dt ≥ start_date.
    - end_date only    → pub_dt ≤ end_date (inclusive, end of day).
    - Both provided    → start_date ≤ pub_dt ≤ end_date.
    - pub_dt is None   → always pass through (unknown publication date).
    """
    if pub_dt is None:
        return True

    if not start_date and not end_date:
        return pub_dt >= _cutoff_dt()

    if start_date:
        start_dt = _parse_date(start_date)
        if start_dt and pub_dt < start_dt:
            return False

    if end_date:
        end_dt = _parse_date(end_date)
        if end_dt:
            end_of_day = end_dt.replace(hour=23, minute=59, second=59)
            if pub_dt > end_of_day:
                return False

    return True


def _parse_utc(s: str, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> Optional[datetime]:
    """Parse a UTC timestamp string. Returns None on failure."""
    if not s:
        return None
    for f in (fmt, "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ── RSS / Atom ─────────────────────────────────────────────────────────────────

def _entry_published_dt(entry) -> Optional[datetime]:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=timezone.utc)
            except Exception:
                pass
    return None


def _best_content(entry) -> str:
    if hasattr(entry, "content") and entry.content:
        return _strip_html(entry.content[0].value)
    return _strip_html(getattr(entry, "summary", "") or "")


def _fetch_rss_feed(feed_cfg: dict) -> list[dict]:
    """Fetch and parse a single RSS/Atom feed."""
    name, url = feed_cfg["name"], feed_cfg["url"]
    headers = {**_HEADERS, **feed_cfg.get("headers", {})}
    try:
        resp = requests.get(url, timeout=config.REQUEST_TIMEOUT, headers=headers)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("Failed to fetch feed '%s': %s", name, exc)
        return []

    parsed = feedparser.parse(resp.text)
    items = []
    for entry in parsed.entries:
        link = getattr(entry, "link", "") or ""
        if not link:
            continue
        pub_dt = _entry_published_dt(entry)
        if not _filter_by_date(pub_dt, feed_cfg.get("start_date"), feed_cfg.get("end_date")):
            continue
        items.append({
            "title":     _strip_html(getattr(entry, "title", "") or ""),
            "url":       link,
            "content":   _best_content(entry),
            "source":    name,
            "published": pub_dt.isoformat() if pub_dt else "",
        })

    _range = f"{feed_cfg.get('start_date')} → {feed_cfg.get('end_date')}" if (feed_cfg.get("start_date") or feed_cfg.get("end_date")) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d items (%s)", name, len(items), _range)
    return items


# ── abuse.ch: ThreatFox IOC feed ──────────────────────────────────────────────
# Free JSON export — dict keyed by IOC ID, value is a list of IOC records.
# We filter to the last 24h and deduplicate by (malware_family, ioc_type) so
# the triage loop sees one representative IOC per active family rather than
# hundreds of C2 IPs for the same botnet.

def _fetch_threatfox(feed_cfg: dict) -> list[dict]:
    """Ingest ThreatFox IOC export: one entry per active malware family."""
    name = feed_cfg["name"]
    url  = feed_cfg["url"]

    try:
        resp = requests.get(url, timeout=30, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("ThreatFox fetch failed: %s", exc)
        return []
    except (ValueError, KeyError) as exc:
        logger.warning("ThreatFox parse failed: %s", exc)
        return []

    _start = feed_cfg.get("start_date")
    _end   = feed_cfg.get("end_date")
    items: list[dict] = []
    seen: set[str] = set()   # (family, ioc_type) dedup key

    for _ioc_id, records in data.items():
        for rec in (records if isinstance(records, list) else [records]):
            pub_dt = _parse_utc(rec.get("first_seen_utc", ""), "%Y-%m-%d %H:%M:%S")
            if not _filter_by_date(pub_dt, _start, _end):
                continue

            # Confidence filter — skip low-confidence noise
            if int(rec.get("confidence_level", 0)) < 75:
                continue

            family   = rec.get("malware_printable") or rec.get("malware") or "Unknown Malware"
            ioc_type = rec.get("ioc_type", "unknown")
            ioc_val  = rec.get("ioc_value", "")
            dedup    = f"{family.lower()}:{ioc_type}"

            if dedup in seen:
                continue
            seen.add(dedup)

            aliases = rec.get("malware_alias", "") or ""
            tags    = rec.get("tags", "") or ""
            ref     = rec.get("reference", "") or ""
            threat  = rec.get("threat_type", "") or ""

            content = (
                f"Active {threat} IOC. Malware family: {family}"
                + (f" (aliases: {aliases})" if aliases else "")
                + f". IOC type: {ioc_type}, value: {ioc_val}."
                + f" Confidence: {rec.get('confidence_level', 0)}%."
                + (f" Tags: {tags}." if tags else "")
                + (f" Reference: {ref}." if ref else "")
            )

            items.append({
                "title":     f"[ThreatFox] {family} — new {ioc_type} IOC ({threat})",
                "url":       f"https://threatfox.abuse.ch/browse.php?search=ioc:{ioc_val}",
                "content":   content,
                "source":    name,
                "published": pub_dt.isoformat() if pub_dt else "",
            })

            if len(items) >= 30:
                break
        if len(items) >= 30:
            break

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d items (%s)", name, len(items), _range)
    return items


# ── abuse.ch: URLhaus malware URL feed ────────────────────────────────────────
# Free ZIP download → JSON dict.  We filter to "online" URLs from the last 24h
# and deduplicate by malware family tag so 400+ Mozi/Mirai entries collapse to
# one representative item the model can assess.

def _fetch_urlhaus(feed_cfg: dict) -> list[dict]:
    """Ingest URLhaus malware URL export: one entry per active malware family."""
    name = feed_cfg["name"]
    url  = feed_cfg["url"]

    try:
        resp = requests.get(url, timeout=30, headers=_HEADERS)
        resp.raise_for_status()
        zf   = zipfile.ZipFile(io.BytesIO(resp.content))
        with zf.open(zf.namelist()[0]) as f:
            data = json.loads(f.read())
    except requests.RequestException as exc:
        logger.warning("URLhaus fetch failed: %s", exc)
        return []
    except Exception as exc:
        logger.warning("URLhaus parse failed: %s", exc)
        return []

    _start = feed_cfg.get("start_date")
    _end   = feed_cfg.get("end_date")
    items: list[dict] = []
    seen: set[str] = set()  # malware family dedup

    for _uid, entries in data.items():
        for entry in (entries if isinstance(entries, list) else [entries]):
            # Only currently-active URLs
            if entry.get("url_status") != "online":
                continue

            pub_dt = _parse_utc(entry.get("dateadded", ""))
            if not _filter_by_date(pub_dt, _start, _end):
                continue

            raw_tags = entry.get("tags") or []
            tags     = raw_tags if isinstance(raw_tags, list) else [raw_tags]
            family   = tags[0] if tags else "untagged"
            dedup    = family.lower()

            if dedup in seen and dedup != "untagged":
                continue
            seen.add(dedup)

            tag_str     = ", ".join(tags) if tags else "none"
            sample_url  = entry.get("url", "")
            threat      = entry.get("threat", "malware_download")
            urlhaus_lnk = entry.get("urlhaus_link", "https://urlhaus.abuse.ch/")

            content = (
                f"Actively serving malware ({threat}). "
                f"URL: {sample_url}. "
                f"Tags/family: {tag_str}. "
                f"Reporter: {entry.get('reporter', 'anonymous')}."
            )

            items.append({
                "title":     f"[URLhaus] Live malware URL — {tag_str[:50]}",
                "url":       urlhaus_lnk,
                "content":   content,
                "source":    name,
                "published": pub_dt.isoformat() if pub_dt else "",
            })

            if len(items) >= 25:
                break
        if len(items) >= 25:
            break

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d items (%s)", name, len(items), _range)
    return items


# ── abuse.ch: Feodo Tracker botnet C2 blocklist ───────────────────────────────
# Tiny JSON (~2 KB) — no ZIP, no auth — listing known botnet C2 IPs.
# We surface the IPs added in the last 24h only.

def _fetch_feodo(feed_cfg: dict) -> list[dict]:
    """Ingest Feodo Tracker recommended C2 blocklist."""
    name = feed_cfg["name"]
    url  = feed_cfg["url"]

    try:
        resp = requests.get(url, timeout=15, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("Feodo Tracker fetch failed: %s", exc)
        return []
    except ValueError as exc:
        logger.warning("Feodo Tracker parse failed: %s", exc)
        return []

    _start = feed_cfg.get("start_date")
    _end   = feed_cfg.get("end_date")
    items: list[dict] = []
    seen_malware: set[str] = set()

    for entry in data:
        pub_dt = _parse_utc(entry.get("first_seen_utc", "") or entry.get("first_seen", ""),
                            "%Y-%m-%d %H:%M:%S")
        if not _filter_by_date(pub_dt, _start, _end):
            continue

        malware = entry.get("malware", "Unknown")
        ip      = entry.get("ip_address", "")
        port    = entry.get("port", "")
        status  = entry.get("status", "")
        country = entry.get("country", "")

        dedup = malware.lower()
        if dedup in seen_malware:
            continue
        seen_malware.add(dedup)

        content = (
            f"New botnet C2 server tracked by Feodo Tracker. "
            f"Malware family: {malware}. C2 IP: {ip}:{port}. "
            f"Status: {status}. Country: {country}."
        )

        items.append({
            "title":     f"[Feodo] {malware} botnet — new C2 server ({ip})",
            "url":       f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            "content":   content,
            "source":    name,
            "published": pub_dt.isoformat() if pub_dt else "",
        })

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d items (%s)", name, len(items), _range)
    return items


# ── nomi-sec/PoC-in-GitHub: daily new-PoC monitor ────────────────────────────
#
# Uses the GitHub commits API to find CVE JSON files added/modified in the last
# N hours, then downloads only those files.  This is the incremental complement
# to poc_ingestor.py (which bulk-imports entire years).
#
# Required config key: feed_cfg["url"] should be
#   "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits"
#
# Optional env var: GITHUB_TOKEN — raises rate limit 60 → 5000 req/hour.

_POC_REPO    = "nomi-sec/PoC-in-GitHub"
_POC_RAW     = f"https://raw.githubusercontent.com/{_POC_REPO}/master"
_POC_UA      = {"User-Agent": "CTI-Pipeline/1.0 (security research)"}


def _poc_api_headers() -> dict:
    h = dict(_POC_UA)
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _poc_raw_fetch(year: int, filename: str) -> list[dict]:
    """Download one CVE JSON file from the raw GitHub URL."""
    url = f"{_POC_RAW}/{year}/{filename}"
    try:
        resp = requests.get(url, headers=_POC_UA, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
    except Exception as exc:
        logger.debug("PoC raw fetch failed %s/%s: %s", year, filename, exc)
        return []


def _poc_build_item(cve_id: str, year: int, pocs: list[dict], source: str) -> dict:
    """Turn a list of PoC repo dicts into a normalised feed item with all fields."""
    # Best description = highest-starred repo that has one
    best_desc = ""
    for poc in sorted(pocs, key=lambda x: x.get("stargazers_count", 0), reverse=True):
        if poc.get("description"):
            best_desc = poc["description"].strip()
            break

    # Aggregate topics across all repos
    all_topics: list[str] = []
    seen_topics: set[str] = set()
    for poc in pocs:
        for t in (poc.get("topics") or []):
            t = t.strip().lower()
            if t and t not in seen_topics:
                seen_topics.add(t)
                all_topics.append(t)
    all_topics.sort()

    repo_lines = []
    for poc in pocs:
        html_url    = poc.get("html_url", "")
        repo_name   = poc.get("name", "")
        desc        = (poc.get("description") or "").strip()
        stars       = poc.get("stargazers_count", 0)
        forks       = poc.get("forks_count", 0)
        full_name   = poc.get("full_name", "")
        author      = full_name.split("/")[0] if full_name else ""
        created     = (poc.get("created_at") or "")[:10]
        pushed      = (poc.get("pushed_at") or "")[:10]
        updated     = (poc.get("updated_at") or "")[:10]
        topics      = poc.get("topics") or []

        line = f"  • {html_url}"
        if repo_name and repo_name != cve_id:
            line += f" [{repo_name}]"
        if desc:
            line += f" — {desc}"
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

    content = f"{cve_id} — {len(pocs)} public PoC exploit repo(s) newly published.\n"
    if best_desc:
        content += f"Description: {best_desc}\n"
    if all_topics:
        content += f"Tags: {', '.join(all_topics)}\n"
    content += "\nPoC repositories:\n" + "\n".join(repo_lines)
    content += f"\n\nSource: https://github.com/{_POC_REPO}/blob/master/{year}/{cve_id}.json"

    # published = most recent created_at among the new PoC repos
    pub_dt = None
    for poc in sorted(pocs, key=lambda x: x.get("created_at", ""), reverse=True):
        raw_ts = poc.get("created_at", "")
        if raw_ts:
            try:
                pub_dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass
            break

    return {
        "title":     f"[PoC] New exploit released for {cve_id} ({len(pocs)} repo(s))",
        "url":       f"https://github.com/{_POC_REPO}/blob/master/{year}/{cve_id}.json",
        "content":   content,
        "source":    source,
        "published": pub_dt.isoformat() if pub_dt else "",
    }


def _fetch_poc_github(feed_cfg: dict) -> list[dict]:
    """
    Find CVE PoC JSON files added/modified in the last LOOKBACK_HOURS and
    return them as normalised feed items.

    Strategy:
      1. GET /commits?since=<cutoff> → list of recent commit SHAs
      2. GET /commits/{sha}           → files changed per commit
      3. For each changed *.json file in a year/ directory, download the raw
         content and build a feed item.

    Without GITHUB_TOKEN, the unauthenticated rate limit (60 req/hour) can be
    a constraint on very active days.  Set GITHUB_TOKEN to raise it to 5000/hour.
    """
    name    = feed_cfg["name"]
    api_url = feed_cfg["url"]  # https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits
    _start  = feed_cfg.get("start_date")
    _end    = feed_cfg.get("end_date")

    # Determine the since-cutoff
    if _start:
        since_dt = _parse_date(_start) or _cutoff_dt()
    else:
        since_dt = _cutoff_dt()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Step 1: list recent commits ───────────────────────────────────────────
    try:
        resp = requests.get(
            api_url,
            headers=_poc_api_headers(),
            params={"since": since_iso, "per_page": 100},
            timeout=20,
        )
        resp.raise_for_status()
        commits = resp.json()
    except requests.RequestException as exc:
        logger.warning("PoC-in-GitHub commits API failed: %s", exc)
        return []
    except ValueError as exc:
        logger.warning("PoC-in-GitHub commits parse failed: %s", exc)
        return []

    if not commits:
        logger.info("Feed '%s': no commits since %s", name, since_iso)
        return []

    logger.info("Feed '%s': %d recent commit(s) to inspect", name, len(commits))

    # ── Step 2: collect changed CVE JSON filenames ────────────────────────────
    changed_files: dict[str, int] = {}  # filename → year (deduped)

    for commit in commits:
        sha        = commit.get("sha", "")
        commit_url = commit.get("url", "")
        if not sha or not commit_url:
            continue
        time.sleep(0.5)
        try:
            det = requests.get(commit_url, headers=_poc_api_headers(), timeout=15)
            det.raise_for_status()
            detail = det.json()
        except requests.RequestException:
            continue

        for file_info in detail.get("files", []):
            path = file_info.get("filename", "")
            # Matches e.g. "2026/CVE-2026-8732.json"
            parts = path.split("/")
            if len(parts) == 2 and parts[1].startswith("CVE-") and parts[1].endswith(".json"):
                try:
                    year = int(parts[0])
                    changed_files[parts[1]] = year
                except ValueError:
                    pass

    if not changed_files:
        logger.info("Feed '%s': 0 new CVE PoC files in recent commits", name)
        return []

    logger.info("Feed '%s': %d unique CVE file(s) changed — fetching…", name, len(changed_files))

    # ── Step 3: download and build items ──────────────────────────────────────
    items: list[dict] = []
    for filename, year in changed_files.items():
        cve_id = filename.replace(".json", "")
        pocs   = _poc_raw_fetch(year, filename)
        if not pocs:
            continue

        item    = _poc_build_item(cve_id, year, pocs, name)
        pub_dt  = None
        if item["published"]:
            try:
                pub_dt = datetime.fromisoformat(item["published"])
            except ValueError:
                pass

        if not _filter_by_date(pub_dt, _start, _end):
            continue
        items.append(item)

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d PoC item(s) (%s)", name, len(items), _range)
    return items


# ── CISA Known Exploited Vulnerabilities (KEV) ────────────────────────────────
# Official CISA catalog of CVEs confirmed actively exploited in the wild.
# Filters to entries whose `dateAdded` falls within the lookback window.
# Ransomware-linked entries are flagged in the title.

def _fetch_cisa_kev(feed_cfg: dict) -> list[dict]:
    """Ingest CISA KEV JSON catalog — return entries added within lookback."""
    name = feed_cfg["name"]
    url  = feed_cfg["url"]

    try:
        resp = requests.get(url, timeout=20, headers=_HEADERS)
        resp.raise_for_status()
        catalog = resp.json()
    except requests.RequestException as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return []
    except (ValueError, KeyError) as exc:
        logger.warning("CISA KEV parse failed: %s", exc)
        return []

    _start = feed_cfg.get("start_date")
    _end   = feed_cfg.get("end_date")
    items: list[dict] = []

    for vuln in catalog.get("vulnerabilities", []):
        date_added = vuln.get("dateAdded", "")
        pub_dt = _parse_date(date_added)
        if not _filter_by_date(pub_dt, _start, _end):
            continue

        cve_id       = vuln.get("cveID", "")
        vendor       = vuln.get("vendorProject", "")
        product      = vuln.get("product", "")
        vuln_name    = vuln.get("vulnerabilityName", "")
        description  = vuln.get("shortDescription", "")
        action       = vuln.get("requiredAction", "")
        due_date     = vuln.get("dueDate", "")
        ransomware   = vuln.get("knownRansomwareCampaignUse", "Unknown")

        ransomware_flag = " [RANSOMWARE]" if ransomware == "Known" else ""
        title = f"[CISA KEV{ransomware_flag}] {cve_id} — {vendor} {product}: {vuln_name}"

        content = (
            f"CISA confirmed actively exploited in the wild. "
            f"CVE: {cve_id}. Vendor: {vendor}. Product: {product}. "
            f"Vulnerability: {vuln_name}. "
            + (f"Description: {description} " if description else "")
            + (f"Required action: {action} " if action else "")
            + (f"Remediation due: {due_date}. " if due_date else "")
            + f"Known ransomware campaign use: {ransomware}."
        )

        items.append({
            "title":     title,
            "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "content":   content,
            "source":    name,
            "published": pub_dt.isoformat() if pub_dt else "",
        })

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d item(s) (%s)", name, len(items), _range)
    return items


# ── abuse.ch: MalwareBazaar sample repository ─────────────────────────────────
# Free JSON export of recently-submitted malware samples.
# We filter to samples added in the last 24h and deduplicate by signature
# (malware family) so the model sees one representative sample per active family.

def _fetch_bazaar(feed_cfg: dict) -> list[dict]:
    """Ingest MalwareBazaar recent samples: one entry per malware family.

    Uses the mb-api POST endpoint (the old GET export URL was removed).
    """
    name = feed_cfg["name"]
    url  = feed_cfg.get("url", "https://mb-api.abuse.ch/api/v1/")

    try:
        resp = requests.post(
            url,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
            headers=_HEADERS,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("MalwareBazaar fetch failed: %s", exc)
        return []
    except ValueError as exc:
        logger.warning("MalwareBazaar parse failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        logger.warning("MalwareBazaar returned non-ok status: %s", data.get("query_status"))
        return []

    _start = feed_cfg.get("start_date")
    _end   = feed_cfg.get("end_date")
    items: list[dict] = []
    seen: set[str] = set()

    for sample in data.get("data", []):
        pub_dt = _parse_utc(sample.get("first_seen", ""))
        if not _filter_by_date(pub_dt, _start, _end):
            continue

        signature = (sample.get("signature") or "unknown").strip()
        dedup_key = signature.lower()
        if dedup_key in seen and dedup_key != "unknown":
            continue
        seen.add(dedup_key)

        sha256    = sample.get("sha256_hash", "")
        file_type = sample.get("file_type", "")
        mime_type = sample.get("file_type_mime", "")
        reporter  = sample.get("reporter", "anonymous")
        tags      = sample.get("tags") or []
        tag_str   = ", ".join(tags) if isinstance(tags, list) else str(tags)
        origin    = sample.get("origin_country", "")

        content = (
            f"New {signature} malware sample submitted to MalwareBazaar. "
            f"File type: {file_type} ({mime_type}). "
            f"SHA256: {sha256}. "
            + (f"Tags: {tag_str}. " if tag_str else "")
            + (f"Origin country: {origin}. " if origin else "")
            + f"Reporter: {reporter}."
        )

        items.append({
            "title":     f"[MalwareBazaar] {signature} sample — {file_type}",
            "url":       f"https://bazaar.abuse.ch/sample/{sha256}/",
            "content":   content,
            "source":    name,
            "published": pub_dt.isoformat() if pub_dt else "",
        })

        if len(items) >= 20:
            break

    _range = f"{_start} → {_end}" if (_start or _end) else f"last {config.LOOKBACK_HOURS}h"
    logger.info("Feed '%s': %d item(s) (%s)", name, len(items), _range)
    return items


# ── Dispatch table ─────────────────────────────────────────────────────────────

_FEED_HANDLERS = {
    "rss":        _fetch_rss_feed,
    "threatfox":  _fetch_threatfox,
    "urlhaus":    _fetch_urlhaus,
    "feodo":      _fetch_feodo,
    "bazaar":     _fetch_bazaar,
    "cisa_kev":   _fetch_cisa_kev,
    "poc_github": _fetch_poc_github,
}


# ── Public API ─────────────────────────────────────────────────────────────────

def fetch_all_feeds(start_date: str = "", end_date: str = "") -> list[dict]:
    """
    Pull every configured feed and return a deduplicated flat list of items.

    Cross-feed URL deduplication is handled here.  Per-run URL deduplication
    (across pipeline runs) is handled by the SQLite db_manager layer.
    
    Date range filtering can be applied globally or on a per-feed basis.
    """
    all_items: list[dict] = []
    seen_urls: set[str] = set()

    for feed_cfg in config.RSS_FEEDS:
        feed_type = feed_cfg.get("type", "rss")
        handler   = _FEED_HANDLERS.get(feed_type)

        if handler is None:
            logger.warning("Unknown feed type '%s' for '%s' — skipping",
                           feed_type, feed_cfg.get("name", "?"))
            continue

        # Override per-feed date ranges with global args if provided
        if start_date:
            feed_cfg = dict(feed_cfg)
            feed_cfg["start_date"] = start_date
        if end_date:
            feed_cfg = dict(feed_cfg)
            feed_cfg["end_date"] = end_date

        for item in handler(feed_cfg):
            url = item["url"]
            if url not in seen_urls:
                seen_urls.add(url)
                all_items.append(item)

    logger.info("Total unique items fetched across all feeds: %d", len(all_items))
    return all_items
