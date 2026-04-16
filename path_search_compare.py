#!/usr/bin/env python3
"""
Forward Networks — Path Search Comparison Tool
Runs a matrix of parameter combinations across src/dst pairs
and identifies which combination most reliably surfaces firewall hops.

Author: Robert Tavoularis — Forward Networks Customer Success Engineering
"""

import sys
import http.server
import webbrowser
import threading
import json
import os
import urllib.request
import urllib.error
import urllib.parse
import base64
import time
import importlib.util

def _load_helpers():
    import importlib.util as _ilu
    _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_helpers.py")
    _s = _ilu.spec_from_file_location("fwd_helpers", _p)
    _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
    return _m
_helpers = _load_helpers()


PORT = 8766
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_search_config.json")

CREDENTIALS   = {}
BASE_URL      = "https://fwd.app"
NETWORKS_DATA = []


def _load_discovery():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_discovery.py")
    spec = importlib.util.spec_from_file_location("fwd_discovery", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"networks": [], "savedSearches": []}
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"networks": [], "savedSearches": []}

def run_path_search(base_url, network_id, snapshot_id, src_ip, dst_ip,
                    intent, max_candidates, ip_proto, dst_port, max_seconds=300):
    """Run a single path search and return (status, body, elapsed_ms)."""
    params = {
        "srcIp":         src_ip,
        "dstIp":         dst_ip,
        "intent":        intent,
        "maxCandidates": str(max_candidates),
        "maxResults":    str(max_candidates),
        "maxSeconds":    str(max_seconds),
    }
    if ip_proto:
        params["ipProto"] = str(ip_proto)
    if dst_port:
        params["dstPort"] = str(dst_port)
    if snapshot_id:
        params["snapshotId"] = snapshot_id

    qs   = urllib.parse.urlencode(params)
    url  = f"{base_url.rstrip('/')}/api/networks/{network_id}/paths?{qs}"

    if network_id not in CREDENTIALS:
        return None, f"No credentials for network {network_id}", 0

    req = urllib.request.Request(url)
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Accept", "application/json")

    t0 = time.time()
    last_err = None
    for attempt in range(2):
        if attempt > 0:
            time.sleep(3)
        try:
            with urllib.request.urlopen(req, timeout=max_seconds + 120) as resp:
                body   = resp.read().decode("utf-8")
                status = resp.status
            return status, body, round((time.time() - t0) * 1000)
        except urllib.error.HTTPError as e:
            body   = e.read().decode("utf-8")
            status = e.code
            return status, body, round((time.time() - t0) * 1000)
        except Exception as ex:
            last_err = str(ex)

    return None, last_err, round((time.time() - t0) * 1000)


def analyze_paths(body, consensus_threshold):
    """Parse path search response and return analysis dict."""
    try:
        parsed = json.loads(body)
    except Exception:
        return {"error": "Invalid JSON response"}

    paths      = (parsed.get("info") or {}).get("paths") or []
    total_hits = (parsed.get("info") or {}).get("totalHits", {})
    timed_out  = parsed.get("timedOut", False)

    fw_fingerprints = []
    for p in paths:
        hops    = p.get("hops", [])
        fw_hops = [h for h in hops if h.get("deviceType") == "FIREWALL"]
        fw_names= sorted(set(h.get("deviceName", "(unnamed)") for h in fw_hops))
        fw_fingerprints.append(fw_names)

    paths_with_fw  = sum(1 for fp in fw_fingerprints if fp)
    all_fw_devices = sorted(set(n for fp in fw_fingerprints for n in fp))

    fp_map = {}
    for fp in fw_fingerprints:
        key = "|".join(fp) if fp else ""
        fp_map[key] = fp_map.get(key, 0) + 1

    fw_fp_map      = {k: v for k, v in fp_map.items() if k != ""}
    unique_fw_sets = len(fw_fp_map)

    if paths_with_fw == 0:
        consensus = "NO_FIREWALL"
    elif unique_fw_sets == 1:
        consensus = "CLEAN"
    else:
        dominant_count = max(fw_fp_map.values()) if fw_fp_map else 0
        dominant_pct   = (dominant_count / paths_with_fw * 100) if paths_with_fw else 0
        consensus = "SOFT" if dominant_pct >= consensus_threshold else "SPLIT"

    dominant_fp = []
    if fw_fp_map:
        dominant_key = max(fw_fp_map, key=fw_fp_map.get)
        dominant_fp  = dominant_key.split("|") if dominant_key else []

    result1_has_fw            = False
    result1_matches_consensus = None
    result1_fw_devices        = []
    if paths:
        first_fp           = fw_fingerprints[0]
        result1_has_fw     = bool(first_fp)
        result1_fw_devices = first_fp
        if result1_has_fw and dominant_fp:
            result1_matches_consensus = (sorted(first_fp) == sorted(dominant_fp))

    return {
        "total_paths":               len(paths),
        "total_hits":                total_hits,
        "timed_out":                 timed_out,
        "paths_with_fw":             paths_with_fw,
        "all_fw_devices":            all_fw_devices,
        "unique_fw_sets":            unique_fw_sets,
        "fp_map":                    fp_map,
        "dominant_fp":               dominant_fp,
        "consensus":                 consensus,
        "result1_has_fw":            result1_has_fw,
        "result1_fw_devices":        result1_fw_devices,
        "result1_matches_consensus": result1_matches_consensus,
    }


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forward Networks · Path Search Comparison</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #0d1117; --surface: #161b22; --border: #30363d;
    --accent:  #00b4d8; --accent2: #90e0ef; --text: #e6edf3;
    --muted:   #8b949e; --success: #3fb950; --error: #f85149;
    --warn:    #d29922; --radius: 6px;
  }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'JetBrains Mono','Courier New',monospace;
    min-height: 100vh; padding: 24px;
  }
  header { display:flex; align-items:baseline; gap:10px; margin-bottom:6px; }
  .home-link { margin-left:auto; font-size:0.67rem; color:var(--muted); text-decoration:none; letter-spacing:.04em; }
  .home-link:hover { color:var(--accent); }
  .logo   { color:var(--accent); font-size:1.3rem; font-weight:700; }
  .title  { font-size:1.2rem; font-weight:700; letter-spacing:0.05em; }
  .sub    { color:var(--muted); font-size:0.82rem; }
  .divider{ height:1px; background:var(--accent); margin:10px 0 20px; }

  .layout { display:flex; gap:16px; align-items:flex-start; }
  .left   { width:340px; flex-shrink:0; display:flex; flex-direction:column; gap:12px; }
  .right  { flex:1; min-width:0; }

  .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px 18px; }
  .card-title { font-size:0.68rem; font-weight:700; color:var(--muted); letter-spacing:0.12em; margin-bottom:12px; }
  .card-sep   { height:1px; background:var(--border); margin:12px 0; }
  .row  { display:flex; align-items:center; gap:10px; margin-bottom:8px; flex-wrap:wrap; }
  .row:last-child { margin-bottom:0; }
  label { font-size:0.74rem; font-weight:600; color:var(--muted); min-width:110px; flex-shrink:0; }
  label span { color:var(--error); }
  input[type="text"], select, textarea {
    background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
    color:var(--text); font-family:inherit; font-size:0.8rem;
    padding:6px 9px; outline:none; transition:border-color 0.15s;
  }
  input[type="text"] { flex:1; min-width:80px; }
  input[type="text"]:focus, select:focus, textarea:focus { border-color:var(--accent); }
  input[type="text"]::placeholder { color:var(--muted); }
  select { cursor:pointer; min-width:160px; }
  select option { background:var(--surface); }
  textarea { flex:1; min-height:80px; resize:vertical; font-size:0.75rem; line-height:1.6; }

  button {
    font-family:inherit; font-size:0.76rem; font-weight:700;
    border:none; border-radius:var(--radius); padding:8px 16px;
    cursor:pointer; transition:opacity 0.15s, transform 0.1s;
  }
  button:active { transform:scale(0.97); }
  button:disabled { opacity:0.35; cursor:not-allowed; }
  .btn-primary   { background:var(--accent);  color:var(--bg); }
  .btn-secondary { background:var(--surface); color:var(--text); border:1px solid var(--border); }
  .btn-primary:not(:disabled):hover   { opacity:0.85; }
  .btn-secondary:not(:disabled):hover { border-color:var(--muted); }
  .btn-sm { padding:5px 12px; font-size:0.7rem; }
  .btn-row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }

  .progress-wrap { background:var(--border); border-radius:2px; height:6px; margin:8px 0; }
  .progress-fill { background:var(--accent); border-radius:2px; height:6px; transition:width 0.3s; }
  .progress-label { font-size:0.7rem; color:var(--muted); }

  .results-table-wrap { overflow-x:auto; margin-top:12px; }
  table { width:100%; border-collapse:collapse; font-size:0.72rem; }
  th {
    background:var(--surface); color:var(--muted); font-weight:700;
    padding:7px 10px; text-align:left; border-bottom:2px solid var(--border);
    white-space:nowrap; position:sticky; top:0; z-index:1;
  }
  td { padding:6px 10px; border-bottom:1px solid var(--border); vertical-align:middle; }
  tr:hover td { background:#1c2330; }

  .badge { display:inline-block; font-size:0.62rem; font-weight:700; padding:2px 7px; border-radius:3px; white-space:nowrap; }
  .badge-ok   { background:var(--success); color:var(--bg); }
  .badge-warn { background:var(--warn);    color:var(--bg); }
  .badge-err  { background:var(--error);   color:var(--bg); }
  .badge-muted{ background:var(--border);  color:var(--muted); }

  .fw-tag { display:inline-block; background:var(--bg); border:1px solid var(--border); border-radius:3px; padding:1px 5px; margin:1px 2px 1px 0; font-size:0.65rem; color:var(--accent2); }

  .summary-panel { margin-top:16px; }
  .summary-title { font-size:0.72rem; font-weight:700; color:var(--accent); letter-spacing:0.12em; margin-bottom:10px; }
  .summary-row {
    display:flex; align-items:center; gap:10px; padding:8px 12px;
    margin-bottom:6px; border:1px solid var(--border); border-radius:var(--radius);
    background:var(--surface);
  }
  .summary-rank { font-size:0.8rem; font-weight:700; color:var(--accent); min-width:24px; }
  .summary-combo { flex:1; font-size:0.72rem; }
  .summary-score { font-size:0.72rem; font-weight:700; }
  .hint { font-size:0.66rem; color:var(--muted); }

  .spinner { display:inline-block; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .empty-state { font-size:0.78rem; color:var(--muted); padding:24px; text-align:center; }

  /* Cred indicator */
  .cred-dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:5px; }
  .cred-dot.has  { background:var(--success); }
  .cred-dot.none { background:var(--error); }
  .net-id-hint { font-size:0.66rem; color:var(--accent2); }
</style>
</head>
<body>

<header>
  <span class="logo">⬡</span>
  <span class="title">PATH SEARCH COMPARISON</span>
  <span class="sub">Parameter Matrix Analyzer</span>
  <a href="http://localhost:8760" class="home-link" title="Back to launcher">⌂ Home</a>
</header>
<div class="divider"></div>

<div class="layout">

  <!-- ── LEFT ── -->
  <div class="left">

    <div class="card">
      <div class="card-title">── NETWORK</div>
      <div class="row">
        <label>Network <span>*</span></label>
        <select id="network-select" onchange="onNetworkSelect()" autocomplete="off" data-lpignore="true">
          <option value="">— select —</option>
        </select>
        <span id="cred-indicator"></span>
      </div>
      <div class="row">
        <label></label>
        <span id="net-id-display" class="net-id-hint"></span>
      </div>
      <div class="row">
        <label>Snapshot</label>
        <select id="snapshot-select" autocomplete="off" data-lpignore="true">
          <option value="">latestProcessed</option>
        </select>
      </div>
      <div class="row">
        <label>Instance URL</label>
        <input type="text" id="base-url" value="https://fwd.app">
      </div>
    </div>

    <div class="card">
      <div class="card-title">── SOURCE / DESTINATION PAIRS</div>
      <div class="row" style="align-items:flex-start">
        <label style="padding-top:6px">Pairs <span>*</span></label>
        <div style="flex:1">
          <textarea id="pairs-input" placeholder="srcIp,dstIp (one per line)&#10;10.0.0.1,192.168.1.1&#10;10.0.0.2,192.168.1.2"></textarea>
          <div class="hint" style="margin-top:4px">One srcIp,dstIp per line. CIDR ok.</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">── PARAMETER MATRIX</div>
      <div class="row">
        <label>maxCandidates</label>
        <input type="text" id="cfg-candidates" value="50,5000,10000" placeholder="comma-separated">
      </div>
      <div class="row">
        <label>Ports (TCP)</label>
        <input type="text" id="cfg-ports" value="none,80,443" placeholder="none,80,443">
        <span class="hint">TCP only; "none" = no port/proto filter</span>
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label>maxSeconds</label>
        <input type="text" id="cfg-seconds" value="300" style="max-width:60px">
      </div>
      <div class="row">
        <label>Consensus %</label>
        <input type="text" id="cfg-consensus" value="80" style="max-width:60px">
        <span class="hint">threshold for "SOFT" consensus</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title">── RUN</div>
      <div id="progress-label" class="progress-label" style="margin-bottom:6px">Ready.</div>
      <div class="progress-wrap"><div class="progress-fill" id="progress-bar" style="width:0%"></div></div>
      <div class="btn-row" style="margin-top:10px">
        <button class="btn-primary" id="run-btn" onclick="runMatrix()">▶ Run Matrix</button>
        <button class="btn-secondary" id="stop-btn" onclick="stopMatrix()" disabled>■ Stop</button>
        <button class="btn-secondary btn-sm" id="export-btn" onclick="exportCsv()" disabled>↓ CSV</button>
      </div>
      <div id="run-status" style="font-size:0.7rem;color:var(--muted);margin-top:8px"></div>
    </div>

  </div>

  <!-- ── RIGHT ── -->
  <div class="right">

    <div class="card" style="padding:12px 16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <span style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.12em">── RESULTS MATRIX</span>
        <span id="total-badge" style="font-size:0.68rem;color:var(--muted)"></span>
      </div>
      <div class="results-table-wrap">
        <table id="results-table">
          <thead>
            <tr>
              <th>src → dst</th>
              <th>maxCand</th>
              <th>intent</th>
              <th>port</th>
              <th>time</th>
              <th>paths</th>
              <th>w/ FW</th>
              <th>FW sets</th>
              <th>consensus</th>
              <th>#1 has FW</th>
              <th>#1 matches</th>
              <th>FW devices</th>
            </tr>
          </thead>
          <tbody id="results-body">
            <tr><td colspan="12" class="empty-state">Select a network and click ▶ Run Matrix</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card summary-panel" id="summary-panel" style="display:none">
      <div class="summary-title">── COMBINATION RANKING</div>
      <div style="font-size:0.7rem;color:var(--muted);margin-bottom:12px">
        Scored: #1 has FW (50 pts) · consensus ok (30 pts) · #1 matches dominant fingerprint (20 pts)
      </div>
      <div id="summary-rows"></div>
    </div>

  </div>
</div>

<script>
let discoveredNetworks   = [];
let credentialedNetworks = new Set();
let running = false;
let stopped = false;
let allResults = [];

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  try {
    const r = await fetch('/instance-url');
    const d = await r.json();
    if (d.baseUrl) document.getElementById('base-url').value = d.baseUrl;
  } catch(e) {}
  try {
    const r    = await fetch('/networks-data');
    const data = await r.json();
    discoveredNetworks   = Array.isArray(data) ? data : (data.networks || []);
    credentialedNetworks = new Set(discoveredNetworks.map(n => n.id));
  } catch(e) { discoveredNetworks = []; }
  setTimeout(() => { renderNetworkDropdown(); }, 300);
}

function renderNetworkDropdown() {
  const sel = document.getElementById('network-select');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— select —</option>';
  discoveredNetworks.forEach((n, i) => {
    const opt = document.createElement('option');
    opt.value = i; opt.textContent = n.name;
    sel.appendChild(opt);
  });
  if (cur !== '') sel.value = cur;
  updateCredIndicator();
}

function onNetworkSelect() {
  const idx = document.getElementById('network-select').value;
  const sel = document.getElementById('snapshot-select');
  sel.innerHTML = '<option value="">latestProcessed</option>';

  if (idx !== '') {
    const net = discoveredNetworks[parseInt(idx)];
    document.getElementById('net-id-display').textContent = `ID: ${net.id}`;
    (net.snapshots || []).forEach(s => {
      const opt = document.createElement('option');
      opt.value = s.id; opt.textContent = s.label || s.id;
      sel.appendChild(opt);
    });
  } else {
    document.getElementById('net-id-display').textContent = '';
  }
  updateCredIndicator();
}

function updateCredIndicator() {
  const idx = document.getElementById('network-select').value;
  const el  = document.getElementById('cred-indicator');
  if (idx === '') { el.innerHTML = ''; return; }
  const netId   = discoveredNetworks[parseInt(idx)].id;
  const hasCred = credentialedNetworks.has(netId);
  el.innerHTML  = `<span class="cred-dot ${hasCred ? 'has' : 'none'}" title="${hasCred ? 'Credentials loaded' : 'No credentials for this network'}"></span>`;
}

// ── Config parsing ────────────────────────────────────────────────────────────
function parsePairs() {
  return document.getElementById('pairs-input').value.trim().split('\n')
    .map(l => l.trim()).filter(Boolean)
    .map(l => { const [src, dst] = l.split(',').map(s => s.trim()); return { src, dst }; })
    .filter(p => p.src && p.dst);
}

function parseCandidates() {
  return document.getElementById('cfg-candidates').value.split(',')
    .map(s => parseInt(s.trim())).filter(n => !isNaN(n));
}

function parsePorts() {
  return document.getElementById('cfg-ports').value.split(',')
    .map(s => s.trim()).filter(Boolean);
}

function buildMatrix(pairs, candidates, ports) {
  const intents = ['PREFER_DELIVERED', 'PREFER_VIOLATIONS'];
  const combos  = [];
  pairs.forEach(pair => {
    candidates.forEach(mc => {
      intents.forEach(intent => {
        ports.forEach(port => {
          combos.push({ src: pair.src, dst: pair.dst, maxCandidates: mc, intent,
                        port: port === 'none' ? null : port, portLabel: port });
        });
      });
    });
  });
  return combos;
}

// ── Run matrix ────────────────────────────────────────────────────────────────
async function runMatrix() {
  const netIdx = document.getElementById('network-select').value;
  if (netIdx === '') { alert('Please select a network.'); return; }

  const net        = discoveredNetworks[parseInt(netIdx)];
  const networkId  = net.id;
  const snapshotId = document.getElementById('snapshot-select').value;
  const baseUrl    = document.getElementById('base-url').value.trim();
  const maxSeconds = parseInt(document.getElementById('cfg-seconds').value) || 300;
  const consPct    = parseFloat(document.getElementById('cfg-consensus').value) || 80;

  const pairs      = parsePairs();
  const candidates = parseCandidates();
  const ports      = parsePorts();

  if (!pairs.length)      { alert('Enter at least one src,dst pair.'); return; }
  if (!candidates.length) { alert('Enter at least one maxCandidates value.'); return; }
  if (!ports.length)      { alert('Enter at least one port value (use "none" for no port filter).'); return; }

  const matrix = buildMatrix(pairs, candidates, ports);
  const total  = matrix.length;

  running = true; stopped = false; allResults = [];
  document.getElementById('run-btn').disabled    = true;
  document.getElementById('stop-btn').disabled   = false;
  document.getElementById('export-btn').disabled = true;
  document.getElementById('summary-panel').style.display = 'none';
  document.getElementById('total-badge').textContent = `0 / ${total} complete`;
  document.getElementById('results-body').innerHTML =
    `<tr><td colspan="12" class="empty-state"><span class="spinner">⟳</span> Running ${total} combinations...</td></tr>`;

  let done = 0;
  let firstRow = true;

  for (const combo of matrix) {
    if (stopped) break;
    setProgress(done, total,
      `Running: ${combo.src} → ${combo.dst} · maxCand=${combo.maxCandidates} · ${combo.intent.replace('PREFER_','')} · port:${combo.portLabel}`);

    const resp = await fetch('/run-search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl, networkId, snapshotId,
        srcIp: combo.src, dstIp: combo.dst,
        intent: combo.intent, maxCandidates: combo.maxCandidates,
        ipProto: combo.port ? 6 : null,
        dstPort: combo.port ? parseInt(combo.port) : null,
        maxSeconds, consensusPct: consPct
      })
    });
    const result = await resp.json();
    result.combo = combo;
    allResults.push(result);
    done++;

    if (firstRow) {
      document.getElementById('results-body').innerHTML = '';
      firstRow = false;
    }
    appendRow(result);
    document.getElementById('total-badge').textContent = `${done} / ${total} complete`;
    setProgress(done, total, done === total ? `✓ Complete — ${total} combinations` : `${done} of ${total} done`);
  }

  running = false;
  document.getElementById('run-btn').disabled   = false;
  document.getElementById('stop-btn').disabled  = true;
  document.getElementById('export-btn').disabled = allResults.length === 0;
  if (allResults.length > 0) buildSummary(candidates, ports);
}

function stopMatrix() {
  stopped = true;
  document.getElementById('run-status').textContent = 'Stopped by user.';
}

function setProgress(done, total, label) {
  document.getElementById('progress-bar').style.width  = (total > 0 ? Math.round(done/total*100) : 0) + '%';
  document.getElementById('progress-label').textContent = label;
}

// ── Render result row ─────────────────────────────────────────────────────────
function appendRow(r) {
  const tbody = document.getElementById('results-body');
  const tr    = document.createElement('tr');
  const c     = r.combo;

  if (r.error) {
    tr.innerHTML = `
      <td>${esc(c.src)} → ${esc(c.dst)}</td>
      <td>${c.maxCandidates}</td>
      <td style="font-size:0.66rem">${c.intent.replace('PREFER_','')}</td>
      <td>${c.portLabel}</td>
      <td colspan="8"><span class="badge badge-err">ERROR: ${esc(r.error)}</span></td>`;
    tbody.appendChild(tr); return;
  }

  const a = r.analysis;
  const fwPct  = a.total_paths > 0 ? Math.round(a.paths_with_fw / a.total_paths * 100) : 0;
  const elapsed= r.elapsed_ms < 1000 ? `${r.elapsed_ms}ms` : `${(r.elapsed_ms/1000).toFixed(2)}s`;
  const pathsCell = (a.total_hits && a.total_hits.type === 'LOWER_BOUND')
    ? `${a.total_paths}<span style="color:var(--warn)">+</span>` : `${a.total_paths}`;
  const fwTags = (a.all_fw_devices || []).map(n =>
    `<span class="fw-tag">${esc(n)}</span>`).join('') || '<span style="color:var(--muted)">—</span>';

  const consBadge = { CLEAN:'<span class="badge badge-ok">✓ clean</span>',
    SOFT:'<span class="badge badge-warn">⚠ soft</span>',
    SPLIT:'<span class="badge badge-err">⚠ split</span>',
    NO_FIREWALL:'<span class="badge badge-err">✗ no FW</span>' }[a.consensus]
    || '<span class="badge badge-muted">—</span>';
  const r1Badge = a.result1_has_fw
    ? '<span class="badge badge-ok">✓ yes</span>'
    : '<span class="badge badge-err">✗ no</span>';
  const matchBadge = a.result1_matches_consensus === null
    ? '<span class="badge badge-muted">n/a</span>'
    : a.result1_matches_consensus
      ? '<span class="badge badge-ok">✓</span>'
      : '<span class="badge badge-err">✗</span>';

  tr.innerHTML = `
    <td style="white-space:nowrap">${esc(c.src)} → ${esc(c.dst)}</td>
    <td>${c.maxCandidates.toLocaleString()}</td>
    <td style="font-size:0.66rem">${c.intent.replace('PREFER_','')}</td>
    <td>${c.portLabel}</td>
    <td style="white-space:nowrap">${elapsed}</td>
    <td>${pathsCell}</td>
    <td>${a.paths_with_fw} <span style="color:var(--muted)">(${fwPct}%)</span></td>
    <td>${a.unique_fw_sets}</td>
    <td>${consBadge}</td>
    <td>${r1Badge}</td>
    <td>${matchBadge}</td>
    <td style="max-width:220px">${fwTags}</td>`;
  tbody.appendChild(tr);
}

// ── Combination ranking ───────────────────────────────────────────────────────
function buildSummary(candidates, ports) {
  const intents = ['PREFER_DELIVERED', 'PREFER_VIOLATIONS'];
  const combos  = [];
  candidates.forEach(mc => {
    intents.forEach(intent => {
      ports.forEach(port => {
        const rows = allResults.filter(r =>
          !r.error && r.combo.maxCandidates === mc &&
          r.combo.intent === intent && r.combo.portLabel === port);
        if (!rows.length) return;
        const n          = rows.length;
        const r1HasFw    = rows.filter(r => r.analysis.result1_has_fw).length;
        const consOk     = rows.filter(r => ['CLEAN','SOFT'].includes(r.analysis.consensus)).length;
        const r1Matches  = rows.filter(r => r.analysis.result1_matches_consensus === true).length;
        const noFw       = rows.filter(r => r.analysis.consensus === 'NO_FIREWALL').length;
        const score      = (r1HasFw / n) * 50 + (consOk / n) * 30 + (r1Matches / n) * 20;
        combos.push({ mc, intent, port, n, r1HasFw, consOk, r1Matches, noFw, score });
      });
    });
  });
  combos.sort((a, b) => b.score - a.score);

  const panel = document.getElementById('summary-panel');
  const rowsEl = document.getElementById('summary-rows');
  rowsEl.innerHTML = '';

  combos.forEach((c, i) => {
    const pct = t => c.n > 0 ? Math.round(t / c.n * 100) : 0;
    const portLabel = c.port === 'none' ? 'no port' : `TCP/${c.port}`;
    const scoreColor = c.score >= 70 ? 'var(--success)' : c.score >= 40 ? 'var(--warn)' : 'var(--error)';
    const div = document.createElement('div');
    div.className = 'summary-row';
    div.innerHTML = `
      <div class="summary-rank">#${i+1}</div>
      <div class="summary-combo">
        <strong>maxCandidates=${c.mc.toLocaleString()}</strong> · ${c.intent.replace('PREFER_','')} · ${portLabel}
        <div style="margin-top:4px;font-size:0.66rem;color:var(--muted)">
          #1 has FW: ${c.r1HasFw}/${c.n} (${pct(c.r1HasFw)}%) &nbsp;·&nbsp;
          consensus ok: ${c.consOk}/${c.n} (${pct(c.consOk)}%) &nbsp;·&nbsp;
          no FW: ${c.noFw}/${c.n} &nbsp;·&nbsp;
          #1 matches: ${c.r1Matches}/${c.n} (${pct(c.r1Matches)}%)
        </div>
      </div>
      <div class="summary-score" style="color:${scoreColor}">${Math.round(c.score)}/100</div>`;
    rowsEl.appendChild(div);
  });

  // Verdict
  const best = combos[0];
  const verdict = document.createElement('div');
  verdict.style.cssText = 'margin-top:14px;padding-top:12px;border-top:1px solid var(--border);font-size:0.72rem;line-height:1.8';
  if (best && best.score >= 70) {
    verdict.innerHTML = `<span style="color:var(--success);font-weight:700">✓ Winning combination found</span> — maxCandidates=${best.mc.toLocaleString()}, ${best.intent.replace('PREFER_','')}, ${best.port === 'none' ? 'no port' : 'TCP/' + best.port} scores ${Math.round(best.score)}/100.`;
  } else if (best && best.score >= 40) {
    verdict.innerHTML = `<span style="color:var(--warn);font-weight:700">⚠ No clear winner</span> — best combination scores ${Math.round(best.score)}/100. Multiple searches may be needed to guarantee firewall visibility.`;
  } else {
    verdict.innerHTML = `<span style="color:var(--error);font-weight:700">✗ No reliable combination found</span> — firewall hops are inconsistently surfaced across all tested parameters.`;
  }
  rowsEl.appendChild(verdict);
  panel.style.display = 'block';
}

// ── CSV export ────────────────────────────────────────────────────────────────
function exportCsv() {
  const hdrs = ['src','dst','maxCandidates','intent','port','elapsed_ms',
                'total_paths','paths_with_fw','fw_pct','unique_fw_sets',
                'consensus','result1_has_fw','result1_matches','all_fw_devices'];
  const rows = [hdrs.join(',')];
  allResults.forEach(r => {
    if (r.error) {
      rows.push([r.combo.src,r.combo.dst,r.combo.maxCandidates,r.combo.intent,
                 r.combo.portLabel,'','','','','','ERROR','','',csv(r.error)].join(',')); return;
    }
    const a = r.analysis;
    rows.push([
      csv(r.combo.src), csv(r.combo.dst),
      r.combo.maxCandidates, r.combo.intent, r.combo.portLabel,
      r.elapsed_ms, a.total_paths, a.paths_with_fw,
      a.total_paths > 0 ? Math.round(a.paths_with_fw/a.total_paths*100) : 0,
      a.unique_fw_sets, a.consensus,
      a.result1_has_fw ? 'yes' : 'no',
      a.result1_matches_consensus === null ? 'n/a' : a.result1_matches_consensus ? 'yes' : 'no',
      csv((a.all_fw_devices||[]).join('; '))
    ].join(','));
  });
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `path_compare_${Date.now()}.csv`; a.click();
  URL.revokeObjectURL(a.href);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function csv(s) {
  s = String(s||'');
  return (s.includes(',') || s.includes('"') || s.includes('\n'))
    ? '"' + s.replace(/"/g,'""') + '"' : s;
}

boot();
</script>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/networks-data':
            body = json.dumps(NETWORKS_DATA).encode('utf-8')
            self._respond(200, 'application/json', body)
        elif self.path == '/instance-url':
            body = json.dumps({'baseUrl': BASE_URL}).encode('utf-8')
            self._respond(200, 'application/json', body)
        else:
            self._respond(200, 'text/html; charset=utf-8', HTML.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw    = self.rfile.read(length)

        if self.path == '/run-search':
            try:
                req         = json.loads(raw)
                status, body, elapsed_ms = run_path_search(
                    req['baseUrl'], req['networkId'], req.get('snapshotId', ''),
                    req['srcIp'], req['dstIp'], req['intent'], req['maxCandidates'],
                    req.get('ipProto'), req.get('dstPort'), req.get('maxSeconds', 300)
                )
                if status is None:
                    result = {'error': body, 'elapsed_ms': elapsed_ms}
                else:
                    result = {
                        'status':     status,
                        'elapsed_ms': elapsed_ms,
                        'analysis':   analyze_paths(body, req.get('consensusPct', 80))
                    }
                self._respond(200, 'application/json', json.dumps(result).encode('utf-8'))
            except Exception as e:
                self._respond(200, 'application/json',
                    json.dumps({'error': str(e), 'elapsed_ms': 0}).encode('utf-8'))
        else:
            self._respond(404, 'application/json', b'{"ok":false}')

    def _respond(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def run():
    print('\n  ⬡  Forward Networks — Path Search Comparison Tool')
    print('  ' + '─' * 50)
    global NETWORKS_DATA, BASE_URL
    args = _helpers.parse_args()
    BASE_URL, NETWORKS_DATA = _helpers.collect_credentials(
        CREDENTIALS, args, _load_discovery().discover_all)

    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)

    if not args['no_browser']:
        def open_browser():
            time.sleep(0.4)
            webbrowser.open(f'http://localhost:{PORT}')
        threading.Thread(target=open_browser, daemon=True).start()

    print(f'     Running at: http://localhost:{PORT}')
    print(f'     Press Ctrl+C to quit\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n  Shutting down. Goodbye.\n')
        server.shutdown()


if __name__ == '__main__':
    run()