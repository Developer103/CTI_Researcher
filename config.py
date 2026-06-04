"""
Configuration loader for the CTI pipeline.
Reads from .env and defines static constants (feed URLs, DB paths, etc.).
"""

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

# ── Timezone ──────────────────────────────────────────────────────────────────
JST = timezone(timedelta(hours=9))


def now_jst() -> datetime:
    return datetime.now(JST)


def today_jst():
    return now_jst().date()

# Load .env from the project root (same directory as this file)
load_dotenv(dotenv_path=Path(__file__).parent / ".env")


# ── LLM / API ────────────────────────────────────────────────────────────────
OPENAI_API_BASE: str = os.environ.get("OPENAI_API_BASE", "http://localhost:11434/v1")
OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "sk-local")
MODEL_NAME: str = os.environ.get("MODEL_NAME", "qwen3.5:35b")

# ── Email delivery ───────────────────────────────────────────────────────────
# Uses STARTTLS on port 587.  For Gmail, generate an App Password at:
#   https://myaccount.google.com/apppasswords  (2FA must be enabled)
SMTP_HOST: str = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER: str = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM: str = os.environ.get("SMTP_FROM", SMTP_USER)

# ── Discord delivery ──────────────────────────────────────────────────────────
# Primary: hermes-agent send_message tool (uses the bot already connected to
# the guild).  Set DISCORD_CHANNEL to the target channel name or ID.
# Fallback: plain webhook POST if DISCORD_WEBHOOK_URL is set.
DISCORD_CHANNEL: str = os.environ.get("DISCORD_CHANNEL", "hermes-unleash")
DISCORD_WEBHOOK_URL: str = os.environ.get("DISCORD_WEBHOOK_URL", "")
DISCORD_MAX_CHARS: int = 1900  # Leave headroom below Discord's 2000-char hard limit

# ── Persistence paths ─────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
SQLITE_DB_PATH: Path = BASE_DIR / "data" / "cti_state.db"
CHROMA_PERSIST_DIR: Path = BASE_DIR / "data" / "chroma"

# Create data dirs on import so nothing else has to worry about it
SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

# ── Date Range Configuration ───────────────────────────────────────────────
DEFAULT_START_DATE: str = ""  # Empty = disable, ISO format (YYYY-MM-DD) if set
DEFAULT_END_DATE: str = ""    # Empty = disable, ISO format (YYYY-MM-DD) if set

# ── Ingestion ─────────────────────────────────────────────────────────────
LOOKBACK_HOURS: int = 24  # Active lookback window; overridden to 1 in hourly mode
REQUEST_TIMEOUT: int = 15

# ── Hourly scan / immediate alert ─────────────────────────────────────────────
HOURLY_LOOKBACK_HOURS: int = 1       # Each hourly scan covers the past 1 hour
DAILY_REPORT_LOOKBACK_HOURS: int = 26  # Read 26h of findings to cover any overlap

# Findings that trigger an immediate alert during hourly scans:
#   - Any finding whose severity is in ALERT_SEVERITIES
#   - Any HIGH severity finding that also has a CVE ID (if ALERT_HIGH_WITH_CVE)
#   - Any finding whose title/summary contains a zero-day keyword
ALERT_SEVERITIES: list[str] = ["critical"]
ALERT_HIGH_WITH_CVE: bool = True
ALERT_ZERO_DAY_KEYWORDS: list[str] = [
    "zero-day", "0-day", "zeroday", "actively exploited",
    "in the wild", "exploit in the wild",
]
# Don't send a repeat immediate alert for the same CVE or topic within this window.
ALERT_DEDUP_WINDOW_HOURS: int = 72

RSS_FEEDS: list[dict] = [
    # ── General security news ─────────────────────────────────────────────────
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
    {
        "name": "TheHackerNews",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
    },
    {
        "name": "DarkReading",
        "url": "https://www.darkreading.com/rss.xml",
    },
    {
        "name": "KrebsOnSecurity",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "name": "SANS ISC",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
    },
    {
        "name": "Full Disclosure",
        "url": "https://seclists.org/rss/fulldisclosure.rss",
    },
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
    },
    {
        # Recorded Future's newsroom — investigative cyber journalism
        "name": "The Record",
        "url": "https://therecord.media/feed",
    },
    {
        # Pierluigi Paganini — high-volume threat news, IOC-heavy
        "name": "SecurityAffairs",
        "url": "https://securityaffairs.com/feed",
    },
    {
        # Schneier on Security — expert analysis, policy commentary
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
    },
    {
        # PoCs, advisories, and tools — complements Exploit-DB
        "name": "Packet Storm Security",
        "url": "https://packetstormsecurity.com/headlines.xml",
    },
    # ── Government CERTs & advisories ────────────────────────────────────────
    {
        # UK National Cyber Security Centre advisories and threat intelligence
        "name": "UK NCSC",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    },
    {
        # JVN iPedia (IPA + JPCERT/CC) English — authoritative Japanese CVE/advisory
        # feed. Replaced jpcert.or.jp/english/at/rss.xml which returned 404 after
        # JPCERT restructured their English publications in 2024.
        "name": "JVN (JPCERT/CC + IPA)",
        "url": "https://jvndb.jvn.jp/en/feed/",
    },
    # ── Malware research & threat actor blogs ─────────────────────────────────
    {
        # In-depth malware PCAP analysis with IOCs — updated on every incident
        "name": "Malware Traffic Analysis",
        "url": "https://www.malware-traffic-analysis.net/blog-entries.rss",
    },
    {
        # Malwarebytes research team — malware families, campaigns, TTPs
        "name": "Malwarebytes Labs",
        "url": "https://www.malwarebytes.com/blog/feed",
    },
    {
        # Cisco Talos — world's largest commercial threat intelligence team
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss",
    },
    {
        # ESET — malware family deep dives, APT campaign reports
        "name": "ESET WeLiveSecurity",
        "url": "https://www.welivesecurity.com/en/rss/",
    },
    {
        # Kaspersky GReAT — APT & malware research, SecureList
        "name": "Kaspersky SecureList",
        "url": "https://securelist.com/feed/",
    },
    {
        # Microsoft Threat Intelligence — nation-state actors, ransomware
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
    },
    {
        # Mandiant (Google) — APT attributions, incident response findings
        "name": "Mandiant Blog",
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
    },
    {
        # Google Project Zero — original 0-day research, browser/kernel/sandbox
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    },
    {
        # Palo Alto Unit 42 — APT campaigns, malware family deep dives
        "name": "Unit 42 (Palo Alto)",
        "url": "https://unit42.paloaltonetworks.com/feed/",
    },
    {
        # CrowdStrike — nation-state actors, big-game hunting, eCrime
        "name": "CrowdStrike Blog",
        "url": "https://www.crowdstrike.com/blog/feed/",
    },
    {
        # Check Point Research — malware, APT, mobile/IoT vulnerability research
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/",
    },
    {
        # Volexity — APT attribution, memory forensics, network intrusions
        "name": "Volexity",
        "url": "https://www.volexity.com/blog/feed/",
    },
    {
        # Proofpoint — threat research, email threats, APT phishing, TA tracking
        "name": "Proofpoint",
        "url": "https://www.proofpoint.com/us/rss.xml",
    },
    {
        # Sophos X-Ops / Threat Research — malware, ransomware, APT deep dives
        # (Secureworks CTU was acquired by Sophos; research now published here)
        "name": "Sophos Threat Research",
        "url": "https://www.sophos.com/en-us/blog/feed",
    },
    {
        # Elastic Security Labs — detection research, SIEM rules, malware analysis
        "name": "Elastic Security Labs",
        "url": "https://www.elastic.co/security-labs/rss/feed.xml",
    },
    {
        # Red Canary — threat detection, ATT&CK mapping, threat hunting
        "name": "Red Canary",
        "url": "https://redcanary.com/blog/feed/",
    },
    # ── CISA Known Exploited Vulnerabilities (KEV) ────────────────────────────
    # Official CISA catalog of CVEs confirmed actively exploited in the wild.
    # Custom handler (type "cisa_kev") filters to entries added in the last
    # LOOKBACK_HOURS and surfaces ransomware-linked KEVs prominently.
    {
        "name": "CISA KEV",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "cisa_kev",
    },
    # ── abuse.ch live malware databases (no API key required) ────────────────
    # These are placed LAST intentionally: they produce the highest item volume
    # and each item is cheap to triage. If the pipeline hits a timeout, it's
    # better to lose IOC entries than editorial news.
    {
        # Feodo Tracker: botnet C2 IP blocklist (Emotet, QakBot, BazarLoader…)
        # Tiny feed (~2 KB), instant parse — processed first among abuse.ch feeds.
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "type": "feodo",
    },
    {
        # URLhaus: actively-serving malware download URLs, submitted in real time.
        # Deduped to one entry per malware family — ~25 items max.
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/json/",
        "type": "urlhaus",
    },
    {
        # ThreatFox: community-submitted IOCs (C2 IPs, domains, URLs, hashes).
        # Deduped to one entry per malware family per day — ~30 items max.
        # Processed last because it has the highest per-item triage latency.
        "name": "ThreatFox",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "threatfox",
    },
    # MalwareBazaar removed: mb-api.abuse.ch now requires auth for get_recent.
    # ThreatFox and URLhaus already provide abuse.ch IOC coverage.
    # ── PoC-in-GitHub: ongoing monitor for new exploit releases ─────────────
    # Checks the GitHub commits API for CVE JSON files added/modified in the
    # last LOOKBACK_HOURS.  For historical bulk import use:
    #   python poc_ingestor.py --years 2024 2025 2026
    # Set GITHUB_TOKEN in .env for 5000 req/hour instead of 60.
    {
        "name": "PoC-in-GitHub",
        "url":  "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits",
        "type": "poc_github",
    },
]

# ── ChromaDB ─────────────────────────────────────────────────────────────────
CHROMA_COLLECTION_NAME: str = "cti_intel"
