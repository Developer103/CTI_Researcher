"""
CTI Web UI — human-friendly interface that queries the JSON API on port 8888.

Run:
  .venv/bin/python3 ui.py

Serves on port 8889.  The JSON API must be running on port 8889.
"""

import os
import sys
from pathlib import Path
import requests
from flask import Flask, request

sys.path.insert(0, str(Path(__file__).parent))
import config
import db_manager
import rag_manager

app = Flask(__name__)

API_BASE = os.environ.get("CTI_API_BASE", "http://localhost:8888")
API_KEY  = os.environ.get("CTI_API_KEY", "")

_HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}

def _api(path: str, params: dict = None):
    try:
        r = requests.get(f"{API_BASE}{path}", params=params, headers=_HEADERS, timeout=15)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)


# ── Base CSS + layout ─────────────────────────────────────────────────────────

_BASE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}CTI{% endblock %}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1b2a;--surface:#112236;--border:#1e3a5f;
  --text:#cbd5e1;--text-dim:#64748b;--text-bright:#e2e8f0;
  --blue:#3b82f6;--red:#ef4444;--orange:#f97316;--yellow:#eab308;
  --green:#22c55e;--slate:#94a3b8;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Hiragino Sans',sans-serif;font-size:14px;line-height:1.6}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}

/* nav */
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:0}
nav .brand{font-weight:800;font-size:15px;color:var(--text-bright);padding:14px 20px 14px 0;border-right:1px solid var(--border);margin-right:8px}
nav a{color:var(--text-dim);padding:14px 14px;display:inline-block;font-size:13px;transition:color .15s}
nav a:hover,nav a.active{color:var(--text-bright);text-decoration:none}

/* page */
.page{max-width:1200px;margin:0 auto;padding:28px 24px}
h1{font-size:18px;font-weight:700;color:var(--text-bright);margin-bottom:6px}
h2{font-size:14px;font-weight:700;color:var(--text-bright);margin-bottom:12px}
.subtitle{color:var(--text-dim);font-size:13px;margin-bottom:24px}

/* cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px;margin-bottom:12px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 18px}
.stat-val{font-size:28px;font-weight:800;color:var(--text-bright);line-height:1}
.stat-label{font-size:12px;color:var(--text-dim);margin-top:4px}

/* severity badges */
.badge{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:800;letter-spacing:.5px;vertical-align:middle}
.badge-critical{background:#7f1d1d;color:#fca5a5;border:1px solid #ef4444}
.badge-high{background:#7c2d12;color:#fdba74;border:1px solid #f97316}
.badge-medium{background:#713f12;color:#fde68a;border:1px solid #eab308}
.badge-low{background:#14532d;color:#86efac;border:1px solid #22c55e}
.badge-unknown{background:#1e293b;color:#94a3b8;border:1px solid #475569}

/* finding card */
.finding{border-left:3px solid var(--border);padding:14px 16px;margin-bottom:10px;background:var(--surface);border-radius:0 6px 6px 0}
.finding-critical{border-left-color:#ef4444}
.finding-high{border-left-color:#f97316}
.finding-medium{border-left-color:#eab308}
.finding-low{border-left-color:#22c55e}
.finding-title{font-size:14px;font-weight:600;color:var(--text-bright);margin:6px 0 4px}
.finding-meta{font-size:12px;color:var(--text-dim);margin-bottom:6px}
.finding-meta span{margin-right:14px}
.finding-summary{font-size:13px;color:var(--text);line-height:1.6}
.finding-products{font-size:12px;color:var(--blue);margin-top:4px}

/* form */
.form-row{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:4px}
.form-group label{font-size:12px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
input[type=text],input[type=number],input[type=date],select{
  background:#0d1b2a;border:1px solid var(--border);color:var(--text-bright);
  padding:7px 10px;border-radius:5px;font-size:13px;width:100%
}
input:focus,select:focus{outline:none;border-color:var(--blue)}
.checkbox-group{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
.checkbox-group label{display:flex;align-items:center;gap:5px;font-size:13px;color:var(--text);cursor:pointer;padding:5px 10px;background:#0d1b2a;border:1px solid var(--border);border-radius:4px}
.checkbox-group input[type=checkbox]{accent-color:var(--blue)}
button{background:var(--blue);color:#fff;border:none;padding:8px 20px;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}
.btn-secondary{background:var(--surface);border:1px solid var(--border);color:var(--text)}

/* distance bar */
.dist-bar{display:inline-block;width:80px;height:6px;background:#1e293b;border-radius:3px;vertical-align:middle;margin-right:6px;overflow:hidden}
.dist-fill{height:100%;border-radius:3px;background:var(--blue)}

/* table */
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#0d1b2a;color:var(--text-dim);text-align:left;padding:9px 12px;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-bottom:1px solid var(--border);color:var(--text)}
tr:last-child td{border-bottom:none}
tr:hover td{background:#0d1b2a33}

/* misc */
.error{background:#7f1d1d22;border:1px solid #ef444466;color:#fca5a5;padding:12px 16px;border-radius:6px;margin-bottom:16px}
.empty{color:var(--text-dim);text-align:center;padding:40px;font-size:13px}
.pagination{display:flex;gap:8px;align-items:center;margin-top:16px;font-size:13px}
.page-info{color:var(--text-dim)}
.tag{display:inline-block;background:#1e3a5f;color:#93c5fd;padding:1px 7px;border-radius:3px;font-size:11px;margin:1px}
.mode-toggle{display:flex;gap:0;margin-bottom:16px}
.mode-btn{padding:7px 18px;border:1px solid var(--border);background:#0d1b2a;color:var(--text-dim);cursor:pointer;font-size:13px;transition:all .15s}
.mode-btn:first-child{border-radius:5px 0 0 5px}
.mode-btn:last-child{border-radius:0 5px 5px 0;border-left:none}
.mode-btn.active{background:var(--blue);color:#fff;border-color:var(--blue)}
</style>
<script>
function setMode(mode){
  document.getElementById('semantic-fields').style.display = mode==='semantic'?'':'none';
  document.getElementById('cve-fields').style.display = mode==='cve'?'':'none';
  document.getElementById('mode-semantic').classList.toggle('active', mode==='semantic');
  document.getElementById('mode-cve').classList.toggle('active', mode==='cve');
  document.getElementById('mode-val').value = mode;
}
</script>
</head>
<body>
<nav>
  <div class="brand">🛡 CTI</div>
  <a href="/" class="__ACTIVE_home__">ダッシュボード</a>
  <a href="/findings" class="__ACTIVE_findings__">Findings</a>
  <a href="/search" class="__ACTIVE_search__">RAG検索</a>
  <a href="/sources" class="__ACTIVE_sources__">ソース</a>
</nav>
__CONTENT__
</body>
</html>"""


db_manager.init_db()


def _render(body: str, active: str) -> str:
    pages = ["home", "findings", "search", "sources"]
    html = _BASE.replace("__CONTENT__", body)
    for p in pages:
        html = html.replace(f"__ACTIVE_{p}__", "active" if p == active else "")
    return html


def _badge(sev):
    s = (sev or "unknown").lower()
    return f'<span class="badge badge-{s}">{s.upper()}</span>'

def _finding_card(f):
    sev = (f.get("severity") or "unknown").lower()
    cve = f.get("cve") or ""
    products = f.get("affected_products") or []
    published = (f.get("published") or "")[:16].replace("T", " ")
    cve_html = f' &nbsp;·&nbsp; <span style="color:#93c5fd">{cve}</span>' if cve else ""
    prod_html = ""
    if products:
        tags = "".join(f'<span class="tag">{p}</span>' for p in products[:6])
        prod_html = f'<div class="finding-products">{tags}</div>'
    url = f.get("url") or "#"
    title = f.get("title") or "Untitled"
    return f"""
<div class="finding finding-{sev}">
  <div>{_badge(sev)}{cve_html}</div>
  <div class="finding-title"><a href="{url}" target="_blank">{title}</a></div>
  <div class="finding-meta">
    <span>📡 {f.get('source','')}</span>
    <span>🕐 {published}</span>
  </div>
  <div class="finding-summary">{f.get('summary','')}</div>
  {prod_html}
</div>"""


# ── Home / Stats ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    stats, err = _api("/stats")
    recent, _ = _api("/findings", {"hours": 26, "limit": 10})

    stat_cards = ""
    if stats:
        f = stats.get("findings", {})
        r = stats.get("rag", {})
        p = stats.get("processed_items", {})
        sev = f.get("by_severity", {})
        stat_cards = f"""
<div class="card-grid">
  <div class="stat-card"><div class="stat-val">{f.get('last_26h',0)}</div><div class="stat-label">直近26時間のFindings</div></div>
  <div class="stat-card"><div class="stat-val">{f.get('total',0)}</div><div class="stat-label">累計Findings</div></div>
  <div class="stat-card"><div class="stat-val">{r.get('total_documents',0):,}</div><div class="stat-label">RAK ドキュメント数</div></div>
  <div class="stat-card"><div class="stat-val">{p.get('total',0):,}</div><div class="stat-label">処理済みURL数</div></div>
</div>
<div class="card" style="margin-bottom:24px">
  <h2>脅威度内訳（全期間）</h2>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px">
    {''.join(f'<span>{_badge(s)} <b style="color:var(--text-bright)">{n}</b></span>' for s,n in sorted(sev.items(), key=lambda x:['critical','high','medium','low'].index(x[0]) if x[0] in ['critical','high','medium','low'] else 99))}
  </div>
</div>"""

    findings_html = ""
    if recent and recent.get("results"):
        findings_html = "".join(_finding_card(f) for f in recent["results"])
    else:
        findings_html = '<div class="empty">直近26時間のFindingsなし</div>'

    err_html = f'<div class="error">APIエラー: {err}</div>' if err else ""

    body = f"""
<div class="page">
  <h1>ダッシュボード</h1>
  <p class="subtitle">{stats.get('as_of','') if stats else ''}</p>
  {err_html}
  {stat_cards}
  <h2>直近26時間の Findings（上位10件）</h2>
  {findings_html}
</div>"""
    return _render(body, "home")


# ── Findings ──────────────────────────────────────────────────────────────────

@app.route("/findings")
def findings():
    # collect params
    hours       = request.args.get("hours", "26")
    severity    = request.args.getlist("severity")
    source      = request.args.get("source", "")
    cve         = request.args.get("cve", "")
    q           = request.args.get("q", "")
    start_date  = request.args.get("start_date", "")
    end_date    = request.args.get("end_date", "")
    limit       = int(request.args.get("limit", "50"))
    offset      = int(request.args.get("offset", "0"))
    submitted   = any([severity, source, cve, q, start_date, end_date,
                       request.args.get("submitted")])

    results_html = ""
    total = 0
    error_html = ""

    if submitted:
        params = {
            "hours": hours, "limit": limit, "offset": offset,
        }
        if severity:
            params["severity"] = ",".join(severity)
        if source:
            params["source"] = source
        if cve:
            params["cve"] = cve
        if q:
            params["q"] = q
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        data, err = _api("/findings", params)
        if err:
            error_html = f'<div class="error">APIエラー: {err}</div>'
        elif data:
            total = data.get("total", 0)
            items = data.get("results", [])
            if items:
                results_html = "".join(_finding_card(f) for f in items)
                # pagination
                prev_off = max(0, offset - limit)
                next_off = offset + limit
                prev_btn = f'<a href="?{_qs(request.args, offset=prev_off)}"><button class="btn-secondary">← 前へ</button></a>' if offset > 0 else ""
                next_btn = f'<a href="?{_qs(request.args, offset=next_off)}"><button class="btn-secondary">次へ →</button></a>' if next_off < total else ""
                results_html += f'<div class="pagination"><span class="page-info">{offset+1}–{min(offset+limit,total)} / {total}件</span>{prev_btn}{next_btn}</div>'
            else:
                results_html = '<div class="empty">条件に合うFindingsが見つかりませんでした</div>'

    sev_options = ["critical","high","medium","low"]
    sev_checks = "".join(f"""
      <label><input type="checkbox" name="severity" value="{s}"{'checked' if s in severity else ''}> {_badge(s)}</label>
    """ for s in sev_options)

    body = f"""
<div class="page">
  <h1>Findings 検索</h1>
  <p class="subtitle">LLMトリアージ済みの高価値アイテムをSQLiteから検索します</p>
  {error_html}
  <div class="card">
    <form method="get">
      <input type="hidden" name="submitted" value="1">
      <div class="form-row">
        <div class="form-group" style="width:100px">
          <label>過去N時間</label>
          <input type="number" name="hours" value="{hours}" min="1" max="9999">
        </div>
        <div class="form-group">
          <label>深刻度</label>
          <div class="checkbox-group">{sev_checks}</div>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:200px">
          <label>キーワード（タイトル・サマリー）</label>
          <input type="text" name="q" value="{q}" placeholder="例: weblogic, actively exploited">
        </div>
        <div class="form-group" style="width:200px">
          <label>CVE ID（部分一致）</label>
          <input type="text" name="cve" value="{cve}" placeholder="例: CVE-2024-21182">
        </div>
        <div class="form-group" style="width:180px">
          <label>ソース（部分一致）</label>
          <input type="text" name="source" value="{source}" placeholder="例: BleepingComputer">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="width:160px">
          <label>公開日 From</label>
          <input type="date" name="start_date" value="{start_date}">
        </div>
        <div class="form-group" style="width:160px">
          <label>公開日 To</label>
          <input type="date" name="end_date" value="{end_date}">
        </div>
        <div class="form-group" style="width:100px">
          <label>表示件数</label>
          <select name="limit">
            {''.join(f'<option value="{n}"{"selected" if str(n)==str(limit) else ""}>{n}件</option>' for n in [20,50,100,200])}
          </select>
        </div>
        <div class="form-group" style="align-self:flex-end">
          <button type="submit">検索</button>
        </div>
      </div>
    </form>
  </div>
  {'<p style="color:var(--text-dim);font-size:13px;margin-bottom:12px">'+str(total)+'件ヒット</p>' if submitted and not error_html else ''}
  {results_html}
</div>"""
    return _render(body, "findings")


# ── Search (RAG) ──────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    mode        = request.args.get("mode", "semantic")
    q           = request.args.get("q", "")
    cve         = request.args.get("cve", "")
    top         = request.args.get("top", "10")
    threshold   = request.args.get("threshold", "")
    start_date  = request.args.get("start_date", "")
    end_date    = request.args.get("end_date", "")
    source      = request.args.get("source", "")
    severity    = request.args.get("severity", "")
    submitted   = request.args.get("submitted")

    results_html = ""
    error_html = ""

    if submitted:
        params = {"top": top}
        if mode == "cve":
            params["cve"] = cve
        else:
            params["q"] = q
        if threshold:
            params["threshold"] = threshold
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        if source:
            params["source"] = source
        if severity:
            params["severity"] = severity

        data, err = _api("/search", params)
        if err:
            error_html = f'<div class="error">APIエラー: {err}</div>'
        elif data:
            items = data.get("results", [])
            total_ret = data.get("total_returned", 0)
            if items:
                cards = []
                for item in items:
                    meta = item.get("metadata", {})
                    dist = item.get("distance", 0)
                    fill = max(0, min(100, int((1 - dist/2)*100)))
                    sev = meta.get("severity","unknown")
                    cve_m = meta.get("cve","")
                    date_m = (meta.get("date","") or "")[:16].replace("T"," ")
                    src_m = meta.get("source","")
                    url_m = meta.get("url","#")
                    text = item.get("text","")
                    km = ' <span style="color:#fde68a;font-size:11px">★キーワード一致</span>' if item.get("keyword_match") else ""
                    exact = ' <span style="color:#86efac;font-size:11px">✓ CVE完全一致</span>' if item.get("exact_cve_match") else ""
                    dist_html = f'<div class="dist-bar"><div class="dist-fill" style="width:{fill}%"></div></div><span style="font-size:11px;color:var(--text-dim)">dist {dist:.4f}</span>' if not item.get("exact_cve_match") else ""
                    cve_tag = f'<span class="tag">{cve_m}</span>' if cve_m else ""
                    cards.append(f"""
<div class="finding finding-{sev.lower()}">
  <div style="margin-bottom:6px">{_badge(sev)} {cve_tag} {dist_html}{km}{exact}</div>
  <div class="finding-meta">
    <span>📡 <a href="{url_m}" target="_blank">{src_m}</a></span>
    <span>🕐 {date_m}</span>
  </div>
  <div class="finding-summary" style="font-size:13px;margin-top:6px">{text}</div>
</div>""")
                results_html = f'<p style="color:var(--text-dim);font-size:13px;margin-bottom:12px">{total_ret}件返却</p>' + "".join(cards)
            else:
                results_html = '<div class="empty">条件に合うドキュメントが見つかりませんでした</div>'

    sev_sel = "".join(f'<option value="{s}"{"selected" if s==severity else ""}>{s.upper()}</option>' for s in ["","critical","high","medium","low"])

    semantic_display = "" if mode == "semantic" else "none"
    cve_display = "" if mode == "cve" else "none"

    body = f"""
<div class="page">
  <h1>RAG 知識ベース検索</h1>
  <p class="subtitle">ChromaDB全履歴（5,000件超）をベクトル検索またはCVE完全一致で検索します</p>
  {error_html}
  <div class="card">
    <form method="get">
      <input type="hidden" name="submitted" value="1">
      <input type="hidden" name="mode" value="{mode}" id="mode-val">
      <div style="margin-bottom:16px">
        <div class="mode-toggle">
          <button type="button" class="mode-btn {'active' if mode=='semantic' else ''}" id="mode-semantic" onclick="setMode('semantic')">🔍 ベクトル検索</button>
          <button type="button" class="mode-btn {'active' if mode=='cve' else ''}" id="mode-cve" onclick="setMode('cve')">🎯 CVEモード</button>
        </div>
      </div>
      <div id="semantic-fields" style="display:{semantic_display}">
        <div class="form-row">
          <div class="form-group" style="flex:1;min-width:300px">
            <label>検索クエリ（自然言語可）</label>
            <input type="text" name="q" value="{q}" placeholder="例: mirai botnet iot infrastructure, supply chain attack">
          </div>
          <div class="form-group" style="width:120px">
            <label>threshold（距離上限）</label>
            <input type="text" name="threshold" value="{threshold}" placeholder="例: 0.8">
          </div>
        </div>
      </div>
      <div id="cve-fields" style="display:{cve_display}">
        <div class="form-row">
          <div class="form-group" style="width:280px">
            <label>CVE ID（完全一致）</label>
            <input type="text" name="cve" value="{cve}" placeholder="例: CVE-2024-21182">
          </div>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="width:160px">
          <label>日付 From</label>
          <input type="date" name="start_date" value="{start_date}">
        </div>
        <div class="form-group" style="width:160px">
          <label>日付 To</label>
          <input type="date" name="end_date" value="{end_date}">
        </div>
        <div class="form-group" style="width:160px">
          <label>ソース（部分一致）</label>
          <input type="text" name="source" value="{source}" placeholder="例: mandiant">
        </div>
        <div class="form-group" style="width:130px">
          <label>深刻度（完全一致）</label>
          <select name="severity"><option value="">すべて</option>{sev_sel}</select>
        </div>
        <div class="form-group" style="width:90px">
          <label>件数上限</label>
          <input type="number" name="top" value="{top}" min="1" max="200">
        </div>
        <div class="form-group" style="align-self:flex-end">
          <button type="submit">検索</button>
        </div>
      </div>
    </form>
  </div>
  {results_html}
  <div class="card" style="margin-top:16px;font-size:12px;color:var(--text-dim)">
    <b>thresholdの目安：</b>
    0.0–0.5 ほぼ同一 &nbsp;·&nbsp;
    0.5–0.8 強い類似 &nbsp;·&nbsp;
    0.8–1.2 関連トピック &nbsp;·&nbsp;
    1.2以上 弱い関連
  </div>
</div>"""
    return _render(body, "search")


# ── Sources ───────────────────────────────────────────────────────────────────

@app.route("/sources")
def sources():
    hours = request.args.get("hours", "26")
    data, err = _api("/findings/sources", {"hours": hours})

    error_html = f'<div class="error">APIエラー: {err}</div>' if err else ""
    table_rows = ""
    if data:
        srcs = data.get("sources", [])
        max_count = srcs[0]["count"] if srcs else 1
        for s in srcs:
            pct = int(s["count"] / max_count * 100)
            table_rows += f"""
<tr>
  <td>{s['source']}</td>
  <td>{s['count']}</td>
  <td style="width:200px">
    <div style="background:#1e293b;height:8px;border-radius:4px;overflow:hidden">
      <div style="width:{pct}%;height:100%;background:var(--blue);border-radius:4px"></div>
    </div>
  </td>
</tr>"""

    body = f"""
<div class="page">
  <h1>フィードソース別 Findings 数</h1>
  <p class="subtitle">直近N時間のFindings件数をソース別に表示します</p>
  {error_html}
  <div class="card" style="margin-bottom:16px">
    <form method="get" style="display:flex;align-items:flex-end;gap:12px">
      <div class="form-group" style="width:140px">
        <label>過去N時間</label>
        <input type="number" name="hours" value="{hours}" min="1">
      </div>
      <button type="submit">更新</button>
    </form>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>ソース</th><th>件数</th><th>割合</th></tr></thead>
      <tbody>{table_rows or '<tr><td colspan="3" style="text-align:center;color:var(--text-dim);padding:24px">データなし</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
    return _render(body, "sources")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _qs(args, **override):
    """Rebuild query string with overrides."""
    from urllib.parse import urlencode
    d = dict(args)
    d.update({k: [str(v)] for k, v in override.items()})
    return urlencode(d, doseq=True)


if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    port = int(os.environ.get("CTI_UI_PORT", 8889))
    print(f"CTI UI running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
