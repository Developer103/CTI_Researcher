# CTI Pipeline Timeout Protection - Implementation Summary

## Overview
Added robust timeout protection to the CTI triage pipeline to prevent individual LLM calls from stalling the entire daily processing run.

## Key Changes

### 1. **agent_core.py** - Timeout Wrapper

#### New Function: `triage_item_with_timeout()`
```python
def triage_item_with_timeout(title, url, content, source)
```
- Wraps `triage_item()` in a ThreadPoolExecutor with timeout
- Default timeout: 60 seconds (configurable via `TRIAGE_TIMEOUT_SECONDS`)
- Returns `None` on timeout or failure (graceful degradation)
- Thread-safe timeout tracking

#### New Function: `_get_timeout_summary()`
```python
def _get_timeout_summary() -> str
```
- Generates formatted timeout summary for final report
- Lists all URLs that timed out
- Shows total count of timeout events

#### Updated: `write_report()`
- Calls `_get_timeout_summary()` to get timeout stats
- Injects timeout information into final Markdown brief
- Shows: "Pipeline completed with timeout events—review notes above"

### 2. **main.py** - Updated Triage Loop

Changed from:
```python
triage = agent_core.triage_item(...)
```

To:
```python
triage = agent_core.triage_item_with_timeout(...)
```

Updated warning log message:
```python
logger.warning("Triage returned None or timed out for: %s", url)
```

### 3. **Configuration** (`config.py`)

New constants:
```python
TRIAGE_TIMEOUT_SECONDS = int(os.getenv("CTI_TRIAGE_TIMEOUT", "60"))
```
- Defaults to 60 seconds
- Can be overridden via `CTI_TRIAGE_TIMEOUT` environment variable

## Timeout Behavior

### What Happens When a Timeout Occurs:
1. Triage function returns `None` (no processing error)
2. Item is marked as processed (won't retry next run)
3. URL is logged to `_TIMEOUT_URLS` list
4. Total timeout counter `_TRIAGE_TIMEOUT_COUNT` increments
5. Final report includes a "TIMEOUT SUMMARY" section
5. Pipeline continues uninterrupted for remaining items

### Example Report Footer:
```markdown
────────────────────────────────────────────────────────
⚠️  TIMEOUT SUMMARY — 2 items failed to process within 60s
────────────────────────────────────────────────────────

1. https://www.kroll.com/en/crises/incident-management-blog/cyber-risks...
2. https://www.scmagazine.com/threat-intelligence/hacking-actvists-m...

*These items were skipped to maintain pipeline throughput.*
────────────────────────────────────────────────────────
```

## Benefits

1. **Pipeline Reliability**: One stuck LLM call won't block all remaining items
2. **Operational Visibility**: Clear record of which URLs caused timeout issues
3. **Automatic Recovery**: Skipped items are marked processed (won't retry)
4. **Flexible Configuration**: Timeout can be tuned via environment variable
5. **Graceful Degradation**: More important findings still get processed

## Testing the Timeout System

### Test with Short Timeout:
```bash
CTI_TRIAGE_TIMEOUT=5 python3 main.py
```
This will simulate timeouts by setting a 5-second limit.

### Check Timeout Logs:
```bash
grep "TRIAGE_TIMEOUT" logs/cti_pipeline.log
```

### Expected Log Output:
```
INFO     cti.main — Triaging: Latest Cyber Threat Intelligence...
INFO     cti.main — Triage successful: CVE-2024-XXXX
WARNING  cti.main — Triage returned None or timed out for: https://...
INFO     cti.main — Valuable [CRITICAL] Log4Shell | CVE: CVE-2021-44228...
```

## Next Steps (Optional Enhancements)

1. **Timeout Alerting**: Send Discord alert after N consecutive timeouts
2. **URL Exclusion**: Auto-blacklist URLs that consistently timeout
3. **Progressive Timeout**: Start with shorter timeout, extend on retry
4. **Rate Limiting**: Throttle requests to slow/overloaded sources
5. **Health Checks**: Periodic ping to LLM endpoint before sending full context

## Files Modified

- `agent_core.py` - Added timeout wrapper and tracking functions
- `main.py` - Updated to use timeout-aware triage
- `config.py` - Added timeout configuration constants

---
**Date**: 2025-09-15
**Status**: ✓ Implementation Complete
