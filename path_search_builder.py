#!/usr/bin/env python3
"""
Forward Networks — Path Search URL Builder
Runs a local web server and opens the tool in your browser.
No external dependencies required.
"""

import http.server
import webbrowser
import threading
import json
import os
import urllib.request
import urllib.error
import base64
import sys
import importlib.util

def _load_discovery():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_discovery.py")
    spec = importlib.util.spec_from_file_location("fwd_discovery", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

PORT = 8765
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_search_config.json")
DEFAULT_CONFIG = {"networks": [], "savedSearches": []}

# In-memory credentials store: { networkId: "Basic base64string" }
CREDENTIALS = {}
# Discovered networks: [{ id, name, snapshots: [{id, label, timestamp}] }]
NETWORKS_DATA = []

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()

def write_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

def collect_credentials(base_url="https://fwd.app"):
    """Load credentials from env vars and discover networks/snapshots via API."""
    global NETWORKS_DATA
    prefix = "FWD_CREDS_"
    found  = 0
    for key, val in os.environ.items():
        if key.startswith(prefix):
            net_id = key[len(prefix):]
            token  = base64.b64encode(val.encode()).decode()
            CREDENTIALS[net_id] = f"Basic {token}"
            found += 1
    if found == 0:
        print("  ⚠  No FWD_CREDS_* environment variables found.")
        print("     Add them to ~/.zshrc like:")
        print('       export FWD_CREDS_123456="accessKey:secretKey"')
        print("     Then run: source ~/.zshrc\n")
        return
    print(f"  ✓ {found} network credential(s) loaded from environment.")
    print("  Discovering networks and snapshots...\n")
    try:
        disc = _load_discovery()
        NETWORKS_DATA = disc.discover_all(base_url, CREDENTIALS)
        print()
    except Exception as e:
        print(f"  ⚠  Discovery failed: {e}\n")
        NETWORKS_DATA = [{"id": nid, "name": nid, "snapshots": []}
                         for nid in CREDENTIALS]

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forward Networks · Path Search Builder</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --accent:  #00b4d8;
    --accent2: #90e0ef;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --success: #3fb950;
    --error:   #f85149;
    --warn:    #d29922;
    --radius:  6px;
  }

  html, body { height: 100%; }

  body {
    background: var(--bg); color: var(--text);
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    height: 100vh; overflow: hidden;
    display: flex; flex-direction: column;
  }

  /* ── Top bar ── */
  .topbar {
    flex-shrink: 0;
    padding: 16px 24px 0;
    background: var(--bg);
  }
  header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 6px; }
  .logo     { color: var(--accent); font-size: 1.3rem; font-weight: 700; }
  .title    { font-size: 1.2rem; font-weight: 700; letter-spacing: 0.05em; }
  .subtitle { color: var(--muted); font-size: 0.82rem; }
  .divider  { height: 1px; background: var(--accent); margin: 10px 0 0; }

  /* ── Split layout ── */
  .split {
    flex: 1; display: flex; overflow: hidden;
    gap: 0;
  }

  /* LEFT PANE */
  .left-pane {
    width: 38%; min-width: 320px; flex-shrink: 0;
    overflow-y: auto; padding: 16px 16px 24px 24px;
    border-right: 1px solid var(--border);
  }

  /* RIGHT PANE */
  .right-pane {
    flex: 1; display: flex; flex-direction: column;
    overflow: hidden; padding: 16px 24px 24px 16px;
  }
  .right-pane-header {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 10px; flex-shrink: 0;
  }
  .right-title { font-size: 0.7rem; font-weight: 700; color: var(--accent); letter-spacing: 0.12em; }
  .badge { background: var(--accent); color: var(--bg); font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: 3px; }
  .status-badge {
    margin-left: auto; font-size: 0.7rem; font-weight: 700;
    padding: 2px 10px; border-radius: 3px;
  }
  .status-badge.ok  { background: var(--success); color: var(--bg); }
  .status-badge.err { background: var(--error);   color: var(--bg); }
  .status-badge.run { background: var(--warn);    color: var(--bg); }

  #json-output {
    flex: 1; overflow-y: auto;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px; font-size: 0.78rem; line-height: 1.7;
    white-space: pre-wrap; word-break: break-all;
  }
  /* JSON syntax highlighting */
  .j-key    { color: #79c0ff; }
  .j-str    { color: #a5d6a7; }
  .j-num    { color: #f0c27f; }
  .j-bool   { color: var(--accent); }
  .j-null   { color: var(--muted); }
  .j-empty  { color: var(--muted); font-style: italic; }

  /* ── Collapsible panels ── */
  .panel { margin-bottom: 10px; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .panel-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 16px; background: var(--surface);
    cursor: pointer; user-select: none; transition: background 0.15s;
  }
  .panel-header:hover { background: #1c2330; }
  .panel-header-left { display: flex; align-items: center; gap: 10px; }
  .panel-title { font-size: 0.68rem; font-weight: 700; color: var(--muted); letter-spacing: 0.12em; }
  .panel-chevron { color: var(--muted); font-size: 0.7rem; transition: transform 0.2s; }
  .panel.open .panel-chevron { transform: rotate(90deg); }
  .panel-body { display: none; padding: 16px 18px; background: var(--surface); border-top: 1px solid var(--border); }
  .panel.open .panel-body { display: block; }

  /* ── Cards ── */
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 14px 18px; margin-bottom: 10px;
  }
  .card-title { font-size: 0.65rem; font-weight: 700; color: var(--muted); letter-spacing: 0.12em; margin-bottom: 12px; }
  .card-sep   { height: 1px; background: var(--border); margin: 12px 0; }

  .row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  .row:last-child { margin-bottom: 0; }

  label { font-size: 0.74rem; font-weight: 600; color: var(--muted); min-width: 90px; flex-shrink: 0; }
  label span { color: var(--error); margin-left: 2px; }

  input[type="text"], select {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text);
    font-family: inherit; font-size: 0.8rem;
    padding: 6px 9px; outline: none; transition: border-color 0.15s;
  }
  input[type="text"] { flex: 1; min-width: 100px; }
  input[type="text"]:focus, select:focus { border-color: var(--accent); }
  input[type="text"]::placeholder { color: var(--muted); }
  select { cursor: pointer; min-width: 160px; }
  select option { background: var(--surface); }

  .hint { font-size: 0.66rem; color: var(--muted); flex-shrink: 0; white-space: nowrap; }

  /* URL display */
  .url-box {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--accent2);
    font-size: 0.75rem; padding: 10px; min-height: 56px;
    word-break: break-all; white-space: pre-wrap;
    line-height: 1.6; cursor: text; user-select: all;
    margin-bottom: 10px;
  }

  /* ── Pills ── */
  .pills { display: flex; gap: 6px; flex-wrap: wrap; }
  .pill input[type="radio"] { display: none; }
  .pill label {
    display: inline-block; padding: 4px 11px;
    border: 1px solid var(--border); border-radius: 999px;
    font-size: 0.68rem; font-weight: 600; color: var(--muted);
    cursor: pointer; transition: all 0.15s; min-width: unset;
  }
  .pill input[type="radio"]:checked + label { background: var(--accent); border-color: var(--accent); color: var(--bg); }
  .pill label:hover { border-color: var(--accent); color: var(--accent); }
  .pill input[type="radio"]:checked + label:hover { color: var(--bg); }

  /* ── Buttons ── */
  .btn-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }
  button {
    font-family: inherit; font-size: 0.76rem; font-weight: 700;
    border: none; border-radius: var(--radius);
    padding: 8px 16px; cursor: pointer;
    transition: opacity 0.15s, transform 0.1s;
  }
  button:disabled { opacity: 0.35; cursor: not-allowed; }
  button:not(:disabled):active { transform: scale(0.97); }
  .btn-primary   { background: var(--accent);   color: var(--bg); }
  .btn-run       { background: var(--success);  color: var(--bg); }
  .btn-secondary { background: var(--surface);  color: var(--text); border: 1px solid var(--border); }
  .btn-danger    { background: var(--surface);  color: var(--error); border: 1px solid var(--error); }
  .btn-primary:not(:disabled):hover   { opacity: 0.85; }
  .btn-run:not(:disabled):hover       { opacity: 0.85; }
  .btn-secondary:not(:disabled):hover { border-color: var(--muted); }
  .btn-danger:not(:disabled):hover    { background: var(--error); color: var(--bg); }
  .btn-sm { padding: 4px 10px; font-size: 0.68rem; }

  .toolbar {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 8px 12px;
  }
  .toolbar-sep {
    width: 1px; height: 18px; background: var(--border); flex-shrink: 0;
  }
  #copy-status { font-size: 0.72rem; color: var(--success); opacity: 0; transition: opacity 0.2s; }
  #copy-status.visible { opacity: 1; }
  .save-status { font-size: 0.72rem; opacity: 0; transition: opacity 0.2s; }
  .save-status.visible { opacity: 1; }

  #validation { font-size: 0.7rem; color: var(--error); line-height: 1.7; white-space: pre; margin-bottom: 6px; }

  /* ── Saved Searches ── */
  .ss-row { display: flex; align-items: center; gap: 8px; }
  .ss-row select { flex: 1; }

  /* ── Manage panel ── */
  .network-list { display: flex; flex-direction: column; gap: 6px; }
  .network-item { border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .network-item-header {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 12px; background: var(--bg); cursor: pointer;
  }
  .network-item-header:hover { background: #0d1117cc; }
  .network-item-chevron { color: var(--muted); font-size: 0.65rem; transition: transform 0.2s; flex-shrink: 0; }
  .network-item.open .network-item-chevron { transform: rotate(90deg); }
  .network-item-name { font-size: 0.78rem; font-weight: 600; flex: 1; }
  .network-item-id   { font-size: 0.7rem; color: var(--muted); }
  .network-item-body { display: none; padding: 10px 12px 12px; background: var(--bg); border-top: 1px solid var(--border); }
  .network-item.open .network-item-body { display: block; }

  .snapshot-list { margin-bottom: 8px; display: flex; flex-direction: column; gap: 5px; }
  .snapshot-row  { display: flex; align-items: center; gap: 6px; }
  .snapshot-row input { flex: 1; min-width: 60px; }
  .snap-label { font-size: 0.65rem; color: var(--muted); min-width: 50px; }

  .add-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
  .add-row input { flex: 1; min-width: 80px; }

  .manage-add-network { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
  .manage-add-network input { flex: 1; min-width: 100px; }

  .empty-state { font-size: 0.74rem; color: var(--muted); padding: 6px 0; }

  /* ── Results toolbar ── */
  .results-toolbar {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 7px 12px;
    margin-bottom: 8px; font-size: 0.72rem;
  }
  .results-toolbar-row2 {
    display: flex; align-items: flex-start; gap: 10px; flex-wrap: wrap;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 8px 12px;
    margin-bottom: 8px; font-size: 0.72rem;
  }
  .nav-btn {
    font-family: inherit; font-size: 0.72rem; font-weight: 700;
    background: var(--surface); color: var(--text);
    border: 1px solid var(--border); border-radius: var(--radius);
    padding: 3px 10px; cursor: pointer; transition: border-color 0.15s;
  }
  .nav-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
  .nav-btn:disabled { opacity: 0.3; cursor: not-allowed; }
  .nav-label { color: var(--muted); }
  .nav-current { color: var(--text); font-weight: 700; }
  .filter-group { display: flex; flex-direction: column; gap: 5px; }
  .filter-group-label { font-size: 0.65rem; font-weight: 700; color: var(--muted); letter-spacing: 0.1em; }
  .filter-pills { display: flex; gap: 5px; flex-wrap: wrap; }
  .filter-pill {
    padding: 3px 10px; border: 1px solid var(--border); border-radius: 999px;
    font-size: 0.68rem; font-weight: 600; color: var(--muted);
    cursor: pointer; transition: all 0.15s; user-select: none;
  }
  .filter-pill:hover  { border-color: var(--accent); color: var(--accent); }
  .filter-pill.active { background: var(--accent); border-color: var(--accent); color: var(--bg); }
  .hit-bound { font-size: 0.68rem; color: var(--warn); margin-left: 4px; }

  /* ── Hop filter autocomplete ── */
  .hop-filter-input-wrap { position: relative; }
  .hop-filter-input {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text);
    font-family: inherit; font-size: 0.72rem;
    padding: 3px 8px; outline: none; width: 160px;
    transition: border-color 0.15s;
  }
  .hop-filter-input:focus { border-color: var(--accent); }
  .hop-filter-input::placeholder { color: var(--muted); }
  .autocomplete-list {
    position: absolute; top: 100%; left: 0; z-index: 100;
    background: var(--surface); border: 1px solid var(--accent);
    border-radius: var(--radius); min-width: 200px; max-height: 180px;
    overflow-y: auto; margin-top: 2px;
  }
  .autocomplete-item {
    padding: 5px 10px; font-size: 0.72rem; cursor: pointer;
    transition: background 0.1s;
  }
  .autocomplete-item:hover { background: var(--border); }

  /* ── Envelope toggle ── */
  .envelope-btn { font-size: 0.68rem; }

  /* ── Firewall summary panel ── */
  .fw-summary {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 8px; overflow: hidden;
  }
  .fw-summary-header {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 12px; cursor: pointer; user-select: none;
    transition: background 0.15s;
  }
  .fw-summary-header:hover { background: #1c2330; }
  .fw-summary-title { font-size: 0.68rem; font-weight: 700; color: var(--accent); letter-spacing: 0.12em; flex: 1; }
  .fw-summary-body { padding: 10px 12px; border-top: 1px solid var(--border); }
  .fw-warn { font-size: 0.7rem; color: var(--warn); font-weight: 700; margin-bottom: 8px; }
  .fw-clean { font-size: 0.7rem; color: var(--success); font-weight: 700; margin-bottom: 8px; }
  .fw-row {
    display: flex; align-items: center; gap: 10px;
    padding: 6px 8px; margin-bottom: 4px; border-radius: var(--radius);
    border: 1px solid var(--border); cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }
  .fw-row:hover { border-color: var(--accent); background: #1c2330; }
  .fw-row.active { border-color: var(--accent); background: #0d2030; }
  .fw-row-names { flex: 1; font-size: 0.72rem; color: var(--text); }
  .fw-row-name-tag {
    display: inline-block; background: var(--bg); border: 1px solid var(--border);
    border-radius: 3px; padding: 1px 6px; margin: 2px 3px 2px 0;
    font-size: 0.68rem; color: var(--accent2);
  }
  .fw-row-count { font-size: 0.7rem; color: var(--muted); flex-shrink: 0; min-width: 70px; text-align: right; }
  .fw-bar-wrap { width: 80px; flex-shrink: 0; }
  .fw-bar-bg { background: var(--border); border-radius: 2px; height: 6px; }
  .fw-bar-fill { background: var(--accent); border-radius: 2px; height: 6px; transition: width 0.3s; }
  .fw-none { font-size: 0.72rem; color: var(--muted); font-style: italic; }
  .fw-controls { display: flex; gap: 6px; margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--border); flex-wrap: wrap; align-items: center; }

  /* ── App search / URL boxes ── */
  .app-box-wrap { margin-bottom: 8px; }
  .app-box-header {
    display: flex; align-items: center; gap: 8px; margin-bottom: 4px;
  }
  .app-box-label { font-size: 0.68rem; font-weight: 700; color: var(--accent); letter-spacing: 0.12em; }
  .app-box {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--accent2);
    font-size: 0.75rem; padding: 8px 10px;
    word-break: break-all; white-space: pre-wrap;
    line-height: 1.5; cursor: text; user-select: all;
    flex: 1;
  }
  .app-box-row { display: flex; align-items: center; gap: 8px; }
  .copy-inline {
    font-family: inherit; font-size: 0.68rem; font-weight: 700;
    background: var(--surface); color: var(--text);
    border: 1px solid var(--border); border-radius: var(--radius);
    padding: 4px 10px; cursor: pointer; flex-shrink: 0;
    transition: border-color 0.15s;
  }
  .copy-inline:hover { border-color: var(--accent); color: var(--accent); }

  /* ── Cred indicator ── */
  .cred-dot {
    display: inline-block; width: 7px; height: 7px;
    border-radius: 50%; margin-right: 5px;
  }
  .cred-dot.has  { background: var(--success); }
  .cred-dot.none { background: var(--error); }
</style>
</head>
<body>

<div class="topbar">
  <header>
    <span class="logo">⬡</span>
    <span class="title">PATH SEARCH</span>
    <span class="subtitle">URL Builder</span>
  </header>
  <div class="divider"></div>
</div>

<div class="split">

  <!-- ════════════════════════════════
       LEFT PANE — controls
       ════════════════════════════════ -->
  <div class="left-pane">

    <!-- Saved Searches -->
    <div class="panel" id="panel-saved">
      <div class="panel-header" onclick="togglePanel('panel-saved')">
        <div class="panel-header-left"><span class="panel-title">── SAVED SEARCHES</span></div>
        <span class="panel-chevron">▶</span>
      </div>
      <div class="panel-body">
        <div class="ss-row">
          <select id="saved-select" onchange="loadSavedSearch()">
            <option value="">— select a saved search —</option>
          </select>
          <button class="btn-secondary btn-sm" onclick="saveCurrentSearch()">Save as...</button>
          <button class="btn-danger btn-sm" onclick="deleteSavedSearch()">Delete</button>
        </div>
        <div id="save-status" class="save-status" style="margin-top:6px;color:var(--success)"></div>
      </div>
    </div>

    <!-- Base -->
    <div class="card">
      <div class="card-title">── BASE</div>
      <div class="row">
        <label>Instance URL <span>*</span></label>
        <input type="text" id="base" placeholder="https://fwd.app" value="https://fwd.app">
      </div>
      <div class="row">
        <label>Network <span>*</span></label>
        <select id="network-select" onchange="onNetworkSelect()" autocomplete="off" data-form-type="other" data-lpignore="true">
          <option value="">— select —</option>
        </select>
        <span class="hint" id="network-id-display" style="color:var(--accent2)"></span>
        <span id="cred-indicator" title="Credential status"></span>
      </div>
      <div class="row">
        <label>Snapshot</label>
        <select id="snapshot-select" onchange="onSnapshotSelect()">
          <option value="">latestProcessed</option>
        </select>
        <span class="hint" id="snapshot-id-display" style="color:var(--accent2)"></span>
      </div>
    </div>

    <!-- Required params -->
    <div class="card">
      <div class="card-title">── REQUIRED PARAMETERS</div>
      <div class="row">
        <label>srcIp <span>*</span></label>
        <input type="text" id="srcIp" placeholder="e.g. 10.0.0.1">
      </div>
      <div class="row">
        <label>dstIp <span>*</span></label>
        <input type="text" id="dstIp" placeholder="e.g. 192.168.1.1">
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label>intent</label>
        <div class="pills">
          <div class="pill"><input type="radio" id="i0" name="intent" value="" checked><label for="i0">default</label></div>
          <div class="pill"><input type="radio" id="i1" name="intent" value="PREFER_DELIVERED"><label for="i1">PREFER_DELIVERED</label></div>
          <div class="pill"><input type="radio" id="i2" name="intent" value="PREFER_VIOLATIONS"><label for="i2">PREFER_VIOLATIONS</label></div>
          <div class="pill"><input type="radio" id="i3" name="intent" value="VIOLATIONS_ONLY"><label for="i3">VIOLATIONS_ONLY</label></div>
        </div>
      </div>
    </div>

    <!-- Optional params -->
    <div class="card">
      <div class="card-title">── OPTIONAL PARAMETERS</div>
      <div class="row">
        <label>ipProto</label>
        <input type="text" id="ipProto" placeholder="6" style="max-width:70px">
        <span class="hint">6=TCP · 17=UDP · 1=ICMP</span>
      </div>
      <div class="row">
        <label>dstPort</label>
        <input type="text" id="dstPort" placeholder="443" style="max-width:70px">
        <span class="hint">0–65535</span>
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label>maxCandidates</label>
        <input type="text" id="maxCandidates" placeholder="5000" style="max-width:70px">
      </div>
      <div class="row">
        <label>maxResults</label>
        <input type="text" id="maxResults" placeholder="1" style="max-width:70px">
      </div>
      <div class="row">
        <label>maxSeconds</label>
        <input type="text" id="maxSeconds" placeholder="30" style="max-width:70px">
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label style="min-width:90px">includeNetworkFunctions</label>
        <div class="pills">
          <div class="pill"><input type="radio" id="inf0" name="includeNF" value="" checked><label for="inf0">default</label></div>
          <div class="pill"><input type="radio" id="inf1" name="includeNF" value="true"><label for="inf1">true</label></div>
          <div class="pill"><input type="radio" id="inf2" name="includeNF" value="false"><label for="inf2">false</label></div>
        </div>
      </div>
    </div>

  </div><!-- /left-pane -->

  <!-- ════════════════════════════════
       RIGHT PANE — results
       ════════════════════════════════ -->
  <div class="right-pane">

    <!-- Collapsible URL panel -->
    <div id="url-panel" style="display:none;margin-bottom:8px">
      <!-- API URL -->
      <div style="margin-bottom:8px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
          <span style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.12em">── GENERATED URL</span>
          <span class="badge">GET</span>
        </div>
        <div class="url-box" id="url-display"></div>
      </div>
      <!-- App search string -->
      <div class="app-box-wrap">
        <div class="app-box-header">
          <span class="app-box-label">── APP SEARCH STRING</span>
        </div>
        <div class="app-box-row">
          <div class="app-box" id="app-search-display"></div>
          <button class="copy-inline" onclick="copyAppBox('app-search-display', this)">&#x2398; Copy</button>
        </div>
      </div>
      <!-- App URL -->
      <div class="app-box-wrap">
        <div class="app-box-header">
          <span class="app-box-label">── APP URL</span>
        </div>
        <div class="app-box-row">
          <div class="app-box" id="app-url-display"></div>
          <button class="copy-inline" onclick="copyAppBox('app-url-display', this)">&#x2398; Copy</button>
        </div>
      </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar" style="margin-bottom:10px">
      <button class="btn-run btn-sm"       id="run-btn"        onclick="runQuery()">&#x25B6; Run</button>
      <div class="toolbar-sep"></div>
      <button class="btn-primary btn-sm"   onclick="copyUrl()">&#x2398; API URL</button>
      <button class="btn-primary btn-sm"   onclick="copyAppUrlDirect()">&#x2398; App URL</button>
      <button class="btn-primary btn-sm"   onclick="copyAppStringDirect()">&#x2398; App String</button>
      <div class="toolbar-sep"></div>
      <button class="btn-secondary btn-sm" id="view-urls-btn"  onclick="toggleUrlPanel()">&#x25BC; URLs</button>
      <div class="toolbar-sep"></div>
      <button class="btn-secondary btn-sm" onclick="clearAll()">&#x21BA; Clear</button>
      <div class="toolbar-sep"></div>
      <span id="resp-status" class="status-badge" style="display:none"></span>
      <span id="resp-time"   class="status-badge" style="display:none;background:var(--surface);color:var(--muted);border:1px solid var(--border)"></span>
      <div class="toolbar-sep" id="resp-sep" style="display:none"></div>
      <button class="btn-secondary btn-sm" id="copy-resp-btn" onclick="copyResponse()" disabled>&#x2398; Copy Response</button>
      <button class="btn-secondary btn-sm" id="dl-raw-btn"    onclick="downloadRaw()"  disabled>&#x2193; Download Raw</button>
      <span id="copy-status" style="font-size:0.72rem;color:var(--success);opacity:0;transition:opacity 0.2s">&#x2713; Copied!</span>
    </div>

    <div id="validation" style="margin-bottom:6px"></div>

    <!-- Results toolbar row 1: totals + navigation -->
    <div class="results-toolbar" id="results-toolbar" style="display:none">
      <span class="nav-label">results:</span>
      <span id="nav-total" class="nav-current"></span>
      <div class="toolbar-sep"></div>
      <button class="nav-btn" id="nav-prev" onclick="navStep(-1)">&#x25C0; prev</button>
      <span id="nav-pos" class="nav-current" style="min-width:140px;text-align:center"></span>
      <button class="nav-btn" id="nav-next" onclick="navStep(1)">next &#x25B6;</button>
      <span id="nav-hops" style="font-size:0.68rem;color:var(--accent2);margin-left:2px"></span>
      <div class="toolbar-sep"></div>
      <button class="nav-btn" id="rank-hops-btn" onclick="toggleRankByHops()" title="Sort current filtered set by most hops">&#x2195; hops: off</button>
      <div class="toolbar-sep"></div>
      <button class="nav-btn" onclick="resetFilters()" title="Clear all filters, keep results">&#x21BA; reset filters</button>
      <div class="toolbar-sep"></div>
      <button class="nav-btn envelope-btn" id="envelope-btn" onclick="toggleEnvelope()" title="Show/hide top-level response fields">&#x2709; envelope: off</button>
    </div>

    <!-- Results toolbar row 2: filters -->
    <div class="results-toolbar-row2" id="filter-toolbar" style="display:none">
      <div class="filter-group">
        <div class="filter-group-label">forwardingOutcome</div>
        <div class="filter-pills" id="filter-forwarding"></div>
      </div>
      <div class="toolbar-sep" style="height:auto;align-self:stretch"></div>
      <div class="filter-group">
        <div class="filter-group-label">securityOutcome</div>
        <div class="filter-pills" id="filter-security"></div>
      </div>
      <div class="toolbar-sep" style="height:auto;align-self:stretch"></div>
      <span id="filter-count" style="color:var(--accent2);align-self:center"></span>
    </div>

    <!-- Results toolbar row 3: hop filters -->
    <div class="results-toolbar-row2" id="hop-filter-toolbar" style="display:none">
      <div class="filter-group">
        <div class="filter-group-label">deviceType</div>
        <div class="filter-pills" id="filter-devicetype"></div>
      </div>
      <div class="toolbar-sep" style="height:auto;align-self:stretch"></div>
      <div class="filter-group">
        <div class="filter-group-label">deviceName</div>
        <div class="hop-filter-input-wrap">
          <input class="hop-filter-input" id="filter-devicename-input" placeholder="type to search..." oninput="onHopInput('deviceName',this.value)" autocomplete="off">
          <div class="autocomplete-list" id="ac-devicename" style="display:none"></div>
        </div>
        <div class="filter-pills" id="filter-devicename-pills" style="margin-top:4px"></div>
      </div>
      <div class="toolbar-sep" style="height:auto;align-self:stretch"></div>
      <div class="filter-group">
        <div class="filter-group-label">displayName</div>
        <div class="hop-filter-input-wrap">
          <input class="hop-filter-input" id="filter-displayname-input" placeholder="type to search..." oninput="onHopInput('displayName',this.value)" autocomplete="off">
          <div class="autocomplete-list" id="ac-displayname" style="display:none"></div>
        </div>
        <div class="filter-pills" id="filter-displayname-pills" style="margin-top:4px"></div>
      </div>
    </div>

    <!-- Firewall Summary -->
    <div class="fw-summary" id="fw-summary" style="display:none">
      <div class="fw-summary-header" onclick="toggleFwSummary()">
        <span class="fw-summary-title">── FIREWALL SUMMARY</span>
        <span id="fw-summary-badge" class="status-badge" style="font-size:0.65rem"></span>
        <span id="fw-summary-chevron" style="color:var(--muted);font-size:0.7rem;transition:transform 0.2s">▶</span>
      </div>
      <div class="fw-summary-body" id="fw-summary-body" style="display:none">
        <div id="fw-status-line"></div>
        <div id="fw-rows"></div>
        <div class="fw-controls">
          <button class="nav-btn" id="fw-only-btn" onclick="toggleFwOnly()">&#x1F6E1; FW paths only: off</button>
          <button class="nav-btn" id="fw-rank-btn" onclick="toggleFwRank()">&#x2195; rank by FW count: off</button>
          <button class="nav-btn" onclick="clearFwFilter()" style="margin-left:auto">&#x21BA; clear FW filter</button>
        </div>
      </div>
    </div>

    <!-- Envelope display -->
    <div id="envelope-display" style="display:none;margin-bottom:8px">
      <div style="font-size:0.65rem;color:var(--muted);letter-spacing:0.1em;margin-bottom:4px">── ENVELOPE</div>
      <div id="envelope-content" style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:0.75rem;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:120px;overflow-y:auto"></div>
    </div>

    <!-- Response label -->
    <div style="font-size:0.68rem;font-weight:700;color:var(--muted);letter-spacing:0.12em;margin-bottom:6px">── API RESPONSE</div>
    <div id="json-output" style="flex:1"><span class="j-empty">Hit &#x25B6; Run to execute the query against the API.</span></div>
  </div>

</div><!-- /split -->

<script>
// ── State ──────────────────────────────────────────────────────────────────────
let config             = { savedSearches: [] };
let discoveredNetworks = [];          // [{ id, name, snapshots:[{id,label}] }]
let credentialedNetworks = new Set();

// ── Boot ───────────────────────────────────────────────────────────────────────
async function boot() {
  // Load saved searches from config
  try {
    const r = await fetch('/config');
    const c = await r.json();
    config.savedSearches = c.savedSearches || [];
  } catch(e) {}

  // Load live network/snapshot data from API discovery
  try {
    const r    = await fetch('/networks-data');
    const data = await r.json();
    discoveredNetworks   = Array.isArray(data) ? data : (data.networks || []);
    credentialedNetworks = new Set(discoveredNetworks.map(n => n.id));
  } catch(e) { discoveredNetworks = []; }

  // Small delay to let password managers (Dashlane etc) finish injecting
  // before we populate dropdowns
  setTimeout(() => {
    renderNetworkDropdown();
    renderSavedSearchDropdown();
    bindInputs();
    update();
  }, 300);
}

// ── Persist config ─────────────────────────────────────────────────────────────
async function persist() {
  await fetch('/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
}

// ── Panel toggle ───────────────────────────────────────────────────────────────
function togglePanel(id) {
  document.getElementById(id).classList.toggle('open');
}

// ── Network dropdown ───────────────────────────────────────────────────────────
function renderNetworkDropdown() {
  const sel = document.getElementById('network-select');
  const current = sel.value;
  sel.innerHTML = '<option value="">— select —</option>';
  discoveredNetworks.forEach((n, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = n.name;
    sel.appendChild(opt);
  });
  if (current !== '') sel.value = current;
  renderSnapshotDropdown();
  updateCredIndicator();
}

function onNetworkSelect() {
  const idx = document.getElementById('network-select').value;
  const net = idx !== '' ? discoveredNetworks[parseInt(idx)] : null;
  document.getElementById('network-id-display').textContent = net ? `ID: ${net.id}` : '';
  renderSnapshotDropdown();
  updateCredIndicator();
  update();
}

function updateCredIndicator() {
  const idx = document.getElementById('network-select').value;
  const el  = document.getElementById('cred-indicator');
  const runBtn = document.getElementById('run-btn');
  if (idx === '') {
    el.innerHTML = '';
    runBtn.disabled = true;
    return;
  }
  const netId = discoveredNetworks[parseInt(idx)].id;
  const hasCred = credentialedNetworks.has(netId);
  el.innerHTML = `<span class="cred-dot ${hasCred ? 'has' : 'none'}" title="${hasCred ? 'Credentials loaded' : 'No credentials for this network'}"></span>`;
  runBtn.disabled = !hasCred;
}

function renderSnapshotDropdown(selectedSnapId) {
  const netIdx = document.getElementById('network-select').value;
  const sel = document.getElementById('snapshot-select');
  sel.innerHTML = '<option value="">latestProcessed</option>';
  if (netIdx !== '') {
    const net = discoveredNetworks[parseInt(netIdx)];
    (net.snapshots || []).forEach(s => {
      const opt = document.createElement('option');
      opt.value = s.id;
      opt.textContent = s.label || s.id;
      if (selectedSnapId && s.id === selectedSnapId) opt.selected = true;
      sel.appendChild(opt);
    });
  }
  onSnapshotSelect();
}

function onSnapshotSelect() {
  const sel = document.getElementById('snapshot-select');
  document.getElementById('snapshot-id-display').textContent = sel.value ? `ID: ${sel.value}` : '';
  update();
}

// ── Saved Searches ─────────────────────────────────────────────────────────────
function renderSavedSearchDropdown() {
  const sel = document.getElementById('saved-select');
  const current = sel.value;
  sel.innerHTML = '<option value="">— select a saved search —</option>';
  config.savedSearches.forEach((s, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = s.name;
    sel.appendChild(opt);
  });
  if (current !== '') sel.value = current;
}

function loadSavedSearch() {
  const idx = document.getElementById('saved-select').value;
  if (idx === '') return;
  const p = config.savedSearches[parseInt(idx)].params;

  document.getElementById('base').value = p.base || 'https://fwd.app';

  const netSel = document.getElementById('network-select');
  netSel.value = p.networkIdx !== undefined ? p.networkIdx : '';
  document.getElementById('network-id-display').textContent =
    netSel.value !== '' ? `ID: ${discoveredNetworks[parseInt(netSel.value)].id}` : '';

  renderSnapshotDropdown(p.snapshotId);
  updateCredIndicator();

  document.getElementById('srcIp').value = p.srcIp || '';
  document.getElementById('dstIp').value = p.dstIp || '';

  document.querySelectorAll('input[name="intent"]').forEach(r => {
    r.checked = r.value === (p.intent || '');
  });

  document.getElementById('ipProto').value       = p.ipProto       || '';
  document.getElementById('dstPort').value       = p.dstPort       || '';
  document.getElementById('maxCandidates').value = p.maxCandidates || '';
  document.getElementById('maxResults').value    = p.maxResults    || '';
  document.getElementById('maxSeconds').value    = p.maxSeconds    || '';
  document.querySelectorAll('input[name="includeNF"]').forEach(r => {
    r.checked = r.value === (p.includeNF || '');
  });

  update();
}

function currentParams() {
  return {
    base:          document.getElementById('base').value.trim(),
    networkIdx:    document.getElementById('network-select').value,
    snapshotId:    document.getElementById('snapshot-select').value,
    srcIp:         document.getElementById('srcIp').value.trim(),
    dstIp:         document.getElementById('dstIp').value.trim(),
    intent:        document.querySelector('input[name="intent"]:checked').value,
    ipProto:       document.getElementById('ipProto').value.trim(),
    dstPort:       document.getElementById('dstPort').value.trim(),
    maxCandidates: document.getElementById('maxCandidates').value.trim(),
    maxResults:    document.getElementById('maxResults').value.trim(),
    maxSeconds:    document.getElementById('maxSeconds').value.trim(),
    includeNF:     document.querySelector('input[name="includeNF"]:checked').value,
  };
}

async function saveCurrentSearch() {
  const name = prompt('Name this saved search:');
  if (!name || !name.trim()) return;
  const trimmed = name.trim();
  const existing = config.savedSearches.findIndex(s => s.name === trimmed);
  const entry = { name: trimmed, params: currentParams() };
  if (existing >= 0) {
    if (!confirm(`"${trimmed}" already exists. Overwrite?`)) return;
    config.savedSearches[existing] = entry;
  } else {
    config.savedSearches.push(entry);
  }
  await persist();
  renderSavedSearchDropdown();
  const idx = config.savedSearches.findIndex(s => s.name === trimmed);
  document.getElementById('saved-select').value = idx;
  flashStatus('save-status', `✓ Saved "${trimmed}"`);
}

async function deleteSavedSearch() {
  const idx = document.getElementById('saved-select').value;
  if (idx === '') return;
  const name = config.savedSearches[parseInt(idx)].name;
  if (!confirm(`Delete "${name}"?`)) return;
  config.savedSearches.splice(parseInt(idx), 1);
  await persist();
  renderSavedSearchDropdown();
}

// ── Manage panel removed — networks/snapshots discovered live from API ──────────

// ── URL builder ────────────────────────────────────────────────────────────────
function bindInputs() {
  ['base','srcIp','dstIp','ipProto','dstPort','maxCandidates','maxResults','maxSeconds']
    .forEach(id => document.getElementById(id).addEventListener('input', update));
  document.querySelectorAll('input[name="intent"]').forEach(r => r.addEventListener('change', update));
  document.querySelectorAll('input[name="includeNF"]').forEach(r => r.addEventListener('change', update));
}

function update() {
  const base        = document.getElementById('base').value.trim().replace(/\/$/, '');
  const netIdx      = document.getElementById('network-select').value;
  const networkId   = netIdx !== '' && discoveredNetworks[parseInt(netIdx)]
    ? discoveredNetworks[parseInt(netIdx)].id : '';
  const snapshotId  = document.getElementById('snapshot-select').value;
  const srcIp       = document.getElementById('srcIp').value.trim();
  const dstIp       = document.getElementById('dstIp').value.trim();
  const intent      = document.querySelector('input[name="intent"]:checked').value;
  const ipProto     = document.getElementById('ipProto').value.trim();
  const dstPort     = document.getElementById('dstPort').value.trim();
  const maxCandidates = document.getElementById('maxCandidates').value.trim();
  const maxResults    = document.getElementById('maxResults').value.trim();
  const maxSeconds    = document.getElementById('maxSeconds').value.trim();
  const includeNF     = document.querySelector('input[name="includeNF"]:checked').value;

  const errors = [];
  if (!base)      errors.push('• Instance URL is required');
  if (!networkId) errors.push('• Network is required');
  if (!srcIp)     errors.push('• srcIp is required');
  if (!dstIp)     errors.push('• dstIp is required');
  if (ipProto && !/^\d+$/.test(ipProto)) errors.push('• ipProto must be a number');
  if (dstPort) {
    const p = parseInt(dstPort, 10);
    if (isNaN(p) || p < 0 || p > 65535) errors.push('• dstPort must be 0–65535');
  }
  document.getElementById('validation').textContent = errors.join('\n');

  const path = `/api/networks/${networkId || '{networkId}'}/paths`;
  const params = new URLSearchParams();
  if (srcIp)         params.set('srcIp',         srcIp);
  if (dstIp)         params.set('dstIp',         dstIp);
  if (intent)        params.set('intent',        intent);
  if (ipProto)       params.set('ipProto',       ipProto);
  if (dstPort)       params.set('dstPort',       dstPort);
  if (snapshotId)    params.set('snapshotId',    snapshotId);
  if (maxCandidates) params.set('maxCandidates', maxCandidates);
  if (maxResults)    params.set('maxResults',    maxResults);
  if (maxSeconds)    params.set('maxSeconds',    maxSeconds);
  if (includeNF !== '') params.set('includeNetworkFunctions', includeNF);

  const qs  = params.toString();
  const url = `${base || 'https://fwd.app'}${path}${qs ? '?' + qs : ''}`;
  document.getElementById('url-display').textContent = url;
  buildAppStrings();
}

// ── Raw response store (for copy/download) ────────────────────────────────────
let lastRawResponse  = null;
let allPaths         = [];      // all paths from info.paths
let filteredPaths    = [];      // paths after filter applied
let currentPathIdx   = 0;       // index into filteredPaths
let activeForwarding  = new Set();
let activeSecurity    = new Set();
let activeDeviceTypes = new Set();
let activeDeviceNames = new Set();
let activeDisplayNames= new Set();
let allHopValues      = { deviceType: new Set(), deviceName: new Set(), displayName: new Set() };
let showEnvelope      = false;
let lastParsedBody    = null;
let rankByHops        = false;
let fwOnly            = false;
let rankByFwCount     = false;
let activeFwFingerprint = null;   // null = no FW filter, Set = selected fingerprint
let fwSummaryOpen     = false;

// ── Run query (via Python proxy) ───────────────────────────────────────────────
async function runQuery() {
  const url = document.getElementById('url-display').textContent.trim();
  const netIdx = document.getElementById('network-select').value;
  if (netIdx === '') return;
  const networkId = discoveredNetworks[parseInt(netIdx)].id;

  const out       = document.getElementById('json-output');
  const badge     = document.getElementById('resp-status');
  const timeBadge = document.getElementById('resp-time');
  const copyBtn   = document.getElementById('copy-resp-btn');
  const dlBtn     = document.getElementById('dl-raw-btn');

  out.innerHTML = '<span class="j-empty">Running...</span>';
  badge.style.display = 'none';
  timeBadge.style.display = 'none';
  copyBtn.disabled = true;
  dlBtn.disabled   = true;
  lastRawResponse  = null;

  const t0 = performance.now();

  try {
    const r = await fetch('/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, networkId })
    });
    const d = await r.json();
    const elapsed = performance.now() - t0;

    // Timing badge
    const secs = elapsed / 1000;
    timeBadge.textContent = secs < 1 ? `${Math.round(elapsed)}ms` : `${secs.toFixed(2)}s`;
    timeBadge.style.display = 'inline-block';

    badge.style.display = 'inline-block';
    document.getElementById('resp-sep').style.display = 'block';
    if (d.error) {
      badge.className = 'status-badge err';
      badge.textContent = 'ERROR';
      out.innerHTML = `<span style="color:var(--error)">${escHtml(d.error)}</span>`;
    } else {
      badge.className = d.status >= 200 && d.status < 300 ? 'status-badge ok' : 'status-badge err';
      badge.textContent = `${d.status}`;
      lastRawResponse = d;
      copyBtn.disabled = false;
      dlBtn.disabled   = false;
      // Parse paths and initialise navigator
      try {
        const parsed = JSON.parse(d.body);
        lastParsedBody = parsed;
        allPaths = (parsed.info && parsed.info.paths) ? parsed.info.paths : [];
        const hits = parsed.info && parsed.info.totalHits;
        initNavigator(hits);
      } catch(e) {
        allPaths = [];
        out.innerHTML = syntaxHighlight(d.body);
        hideNavigator();
      }
    }
  } catch(e) {
    const elapsed = performance.now() - t0;
    timeBadge.textContent = `${((elapsed)/1000).toFixed(2)}s`;
    timeBadge.style.display = 'inline-block';
    badge.style.display = 'inline-block';
    document.getElementById('resp-sep').style.display = 'block';
    badge.className = 'status-badge err';
    badge.textContent = 'ERROR';
    out.innerHTML = `<span style="color:var(--error)">Request failed: ${escHtml(String(e))}</span>`;
  }
}

// ── Copy pretty response ───────────────────────────────────────────────────────
function copyResponse() {
  if (!lastRawResponse) return;
  let text;
  if (filteredPaths.length > 0) {
    // Copy the currently displayed single path
    text = JSON.stringify(filteredPaths[currentPathIdx], null, 2);
  } else {
    try { text = JSON.stringify(JSON.parse(lastRawResponse.body), null, 2); }
    catch(e) { text = lastRawResponse.body; }
  }
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('copy-resp-btn');
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = orig, 2000);
  });
}

// ── Download raw response ──────────────────────────────────────────────────────
function downloadRaw() {
  if (!lastRawResponse) return;
  const url      = document.getElementById('url-display').textContent.trim();
  const srcIp    = document.getElementById('srcIp').value.trim().replace(/[^a-zA-Z0-9._-]/g, '_');
  const dstIp    = document.getElementById('dstIp').value.trim().replace(/[^a-zA-Z0-9._-]/g, '_');
  const filename = `path_search_${srcIp}_to_${dstIp}_${Date.now()}.txt`;

  // Build raw text: request line + status + headers + body
  const raw = [
    `REQUEST`,
    `GET ${url}`,
    ``,
    `RESPONSE`,
    `Status: ${lastRawResponse.status}`,
    `Time:   ${document.getElementById('resp-time').textContent}`,
    ``,
    `Headers:`,
    ...(lastRawResponse.headers || []).map(([k,v]) => `  ${k}: ${v}`),
    ``,
    `Body:`,
    lastRawResponse.body
  ].join('\n');

  const blob = new Blob([raw], { type: 'text/plain' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Navigator & filter ────────────────────────────────────────────────────────
function initNavigator(totalHits) {
  // Build unique outcome sets from allPaths
  const fwdSet = new Set(allPaths.map(p => p.forwardingOutcome).filter(Boolean));
  const secSet = new Set(allPaths.map(p => p.securityOutcome).filter(Boolean));

  // Build unique hop value sets
  allHopValues = { deviceType: new Set(), deviceName: new Set(), displayName: new Set() };
  allPaths.forEach(p => (p.hops || []).forEach(h => {
    if (h.deviceType)   allHopValues.deviceType.add(h.deviceType);
    if (h.deviceName)   allHopValues.deviceName.add(h.deviceName);
    if (h.displayName)  allHopValues.displayName.add(h.displayName);
  }));

  // Total hits label
  const totalEl = document.getElementById('nav-total');
  if (totalHits) {
    const bound = totalHits.type === 'LOWER_BOUND' ? '+' : '';
    totalEl.innerHTML = `<strong>${totalHits.value}${bound}</strong>`;
    if (bound) totalEl.innerHTML += `<span class="hit-bound">(lower bound)</span>`;
  } else {
    totalEl.textContent = allPaths.length;
  }

  // Reset all active filters
  activeForwarding   = new Set();
  activeSecurity     = new Set();
  activeDeviceTypes  = new Set();
  activeDeviceNames  = new Set();
  activeDisplayNames = new Set();
  document.getElementById('filter-devicename-input').value  = '';
  document.getElementById('filter-displayname-input').value = '';
  document.getElementById('filter-devicename-pills').innerHTML  = '';
  document.getElementById('filter-displayname-pills').innerHTML = '';

  // Render outcome filter pills
  renderFilterPills('filter-forwarding', fwdSet, activeForwarding, applyFilters);
  renderFilterPills('filter-security',   secSet, activeSecurity,   applyFilters);

  // Render deviceType pills (dropdown style since usually bounded)
  renderFilterPills('filter-devicetype', allHopValues.deviceType, activeDeviceTypes, applyFilters);

  // Rank by hops — reset
  rankByHops = false;
  const rankBtn = document.getElementById('rank-hops-btn');
  rankBtn.textContent   = '↕ hops: off';
  rankBtn.style.color   = '';
  rankBtn.style.borderColor = '';

  // Envelope
  showEnvelope = false;
  document.getElementById('envelope-btn').textContent = '✉ envelope: off';
  document.getElementById('envelope-display').style.display = 'none';

  document.getElementById('results-toolbar').style.display    = 'flex';
  document.getElementById('filter-toolbar').style.display     = allPaths.length ? 'flex' : 'none';
  document.getElementById('hop-filter-toolbar').style.display = allPaths.length ? 'flex' : 'none';

  // FW state reset
  fwOnly            = false;
  rankByFwCount     = false;
  activeFwFingerprint = null;
  fwSummaryOpen     = false;
  document.getElementById('fw-summary').style.display = 'none';
  document.getElementById('fw-summary-body').style.display = 'none';
  document.getElementById('fw-summary-chevron').style.transform = '';

  applyFilters();
  buildFwSummary();
}

function renderFilterPills(containerId, valueSet, activeSet, onChange) {
  const container = document.getElementById(containerId);
  container.innerHTML = '';
  if (valueSet.size === 0) {
    container.innerHTML = '<span style="color:var(--muted);font-size:0.68rem">none</span>';
    return;
  }
  valueSet.forEach(val => {
    const pill = document.createElement('span');
    pill.className = 'filter-pill' + (activeSet.has(val) ? ' active' : '');
    pill.textContent = val;
    pill.onclick = () => {
      if (activeSet.has(val)) activeSet.delete(val);
      else activeSet.add(val);
      pill.classList.toggle('active');
      onChange();
    };
    container.appendChild(pill);
  });
}

function applyFilters() {
  filteredPaths = allPaths.filter(p => {
    const fwdOk = activeForwarding.size  === 0 || activeForwarding.has(p.forwardingOutcome);
    const secOk = activeSecurity.size    === 0 || activeSecurity.has(p.securityOutcome);
    const hops  = p.hops || [];
    const hopOk = (activeDeviceTypes.size === 0 && activeDeviceNames.size === 0 && activeDisplayNames.size === 0)
      || hops.some(h => {
          const dtOk  = activeDeviceTypes.size  === 0 || activeDeviceTypes.has(h.deviceType);
          const dnOk  = activeDeviceNames.size  === 0 || activeDeviceNames.has(h.deviceName);
          const dispOk= activeDisplayNames.size === 0 || activeDisplayNames.has(h.displayName);
          return dtOk && dnOk && dispOk;
        });
    // FW only filter
    const fwHops = hops.filter(h => h.deviceType === 'FIREWALL');
    const fwOnlyOk = !fwOnly || fwHops.length > 0;
    // FW fingerprint filter
    const fwFingerprintOk = !activeFwFingerprint || fingerprintMatches(fwHops, activeFwFingerprint);
    return fwdOk && secOk && hopOk && fwOnlyOk && fwFingerprintOk;
  });
  currentPathIdx = 0;

  // Sort
  if (rankByFwCount) {
    filteredPaths.sort((a, b) => {
      const aFw = (a.hops || []).filter(h => h.deviceType === 'FIREWALL').length;
      const bFw = (b.hops || []).filter(h => h.deviceType === 'FIREWALL').length;
      return bFw - aFw;
    });
  } else if (rankByHops) {
    filteredPaths.sort((a, b) => (b.hops || []).length - (a.hops || []).length);
  }

  const anyFilter = activeForwarding.size > 0 || activeSecurity.size > 0
                 || activeDeviceTypes.size > 0 || activeDeviceNames.size > 0 || activeDisplayNames.size > 0;
  const countEl = document.getElementById('filter-count');
  countEl.textContent = anyFilter ? `${filteredPaths.length} of ${allPaths.length} match` : '';

  renderCurrentPath();
}

function navStep(dir) {
  currentPathIdx = Math.max(0, Math.min(filteredPaths.length - 1, currentPathIdx + dir));
  renderCurrentPath();
}

function renderCurrentPath() {
  const out     = document.getElementById('json-output');
  const prevBtn = document.getElementById('nav-prev');
  const nextBtn = document.getElementById('nav-next');
  const posEl   = document.getElementById('nav-pos');

  if (filteredPaths.length === 0) {
    out.innerHTML = '<span class="j-empty">No results match the current filter.</span>';
    posEl.textContent = '0 of 0';
    prevBtn.disabled  = true;
    nextBtn.disabled  = true;
    return;
  }

  const currentPath = filteredPaths[currentPathIdx];
  const globalIdx   = allPaths.indexOf(currentPath) + 1;
  const anyFilter   = activeForwarding.size > 0 || activeSecurity.size > 0;
  const filterNote  = anyFilter ? ` (filtered: ${filteredPaths.length})` : '';
  posEl.textContent = `Result ${globalIdx} of ${allPaths.length}${filterNote}`;

  const hopCount = (currentPath.hops || []).length;
  document.getElementById('nav-hops').textContent = hopCount ? `· ${hopCount} hops` : '';

  prevBtn.disabled  = currentPathIdx === 0;
  nextBtn.disabled  = currentPathIdx === filteredPaths.length - 1;
  out.innerHTML     = syntaxHighlight(currentPath);
}

// ── Hop autocomplete ──────────────────────────────────────────────────────────
function onHopInput(field, query) {
  const acId     = field === 'deviceName' ? 'ac-devicename' : 'ac-displayname';
  const activeSet= field === 'deviceName' ? activeDeviceNames : activeDisplayNames;
  const acEl     = document.getElementById(acId);
  const allVals  = allHopValues[field];

  if (!query.trim()) { acEl.style.display = 'none'; return; }

  const matches = [...allVals].filter(v =>
    v.toLowerCase().includes(query.toLowerCase()) && !activeSet.has(v)
  );

  if (matches.length === 0) { acEl.style.display = 'none'; return; }

  acEl.innerHTML = matches.slice(0, 30).map(v =>
    `<div class="autocomplete-item" onclick="selectHopValue('${field}','${v.replace(/'/g,"\'")}')">
      ${escHtml(v)}
    </div>`
  ).join('');
  acEl.style.display = 'block';
}

function selectHopValue(field, value) {
  const activeSet  = field === 'deviceName' ? activeDeviceNames : activeDisplayNames;
  const pillsId    = field === 'deviceName' ? 'filter-devicename-pills' : 'filter-displayname-pills';
  const inputId    = field === 'deviceName' ? 'filter-devicename-input' : 'filter-displayname-input';
  const acId       = field === 'deviceName' ? 'ac-devicename' : 'ac-displayname';

  activeSet.add(value);
  document.getElementById(inputId).value = '';
  document.getElementById(acId).style.display = 'none';

  // Add pill
  const pillsEl = document.getElementById(pillsId);
  const pill = document.createElement('span');
  pill.className = 'filter-pill active';
  pill.textContent = value + ' ✕';
  pill.onclick = () => {
    activeSet.delete(value);
    pill.remove();
    applyFilters();
  };
  pillsEl.appendChild(pill);
  applyFilters();
}

// Close autocomplete when clicking outside
document.addEventListener('click', e => {
  ['ac-devicename','ac-displayname'].forEach(id => {
    const el = document.getElementById(id);
    if (el && !el.contains(e.target)) el.style.display = 'none';
  });
});

// ── Envelope toggle ────────────────────────────────────────────────────────────
function toggleEnvelope() {
  showEnvelope = !showEnvelope;
  const btn     = document.getElementById('envelope-btn');
  const display = document.getElementById('envelope-display');
  btn.textContent = `✉ envelope: ${showEnvelope ? 'on' : 'off'}`;
  if (showEnvelope && lastParsedBody) {
    // Show everything except info.paths and returnPathInfo.paths (too large)
    const envelope = {};
    Object.keys(lastParsedBody).forEach(k => {
      if (k === 'info') {
        envelope.info = { ...lastParsedBody.info };
        delete envelope.info.paths;
      } else if (k === 'returnPathInfo') {
        // skip
      } else {
        envelope[k] = lastParsedBody[k];
      }
    });
    document.getElementById('envelope-content').innerHTML = syntaxHighlight(envelope);
    display.style.display = 'block';
  } else {
    display.style.display = 'none';
  }
}

// ── Rank by hops toggle ───────────────────────────────────────────────────────
function toggleRankByHops() {
  rankByHops = !rankByHops;
  const btn = document.getElementById('rank-hops-btn');
  btn.textContent = `↕ hops: ${rankByHops ? 'on' : 'off'}`;
  btn.style.color = rankByHops ? 'var(--accent)' : '';
  btn.style.borderColor = rankByHops ? 'var(--accent)' : '';
  applyFilters();
}

// ── Reset filters (keep results) ──────────────────────────────────────────────
function resetFilters() {
  // Clear outcome filter pills
  activeForwarding  = new Set();
  activeSecurity    = new Set();
  activeDeviceTypes = new Set();
  activeDeviceNames = new Set();
  activeDisplayNames= new Set();

  // Turn off rank by hops
  rankByHops = false;
  const rankBtn = document.getElementById('rank-hops-btn');
  rankBtn.textContent   = '↕ hops: off';
  rankBtn.style.color   = '';
  rankBtn.style.borderColor = '';

  // Re-render outcome pills (deselect all)
  const fwdSet = new Set(allPaths.map(p => p.forwardingOutcome).filter(Boolean));
  const secSet = new Set(allPaths.map(p => p.securityOutcome).filter(Boolean));
  renderFilterPills('filter-forwarding', fwdSet, activeForwarding, applyFilters);
  renderFilterPills('filter-security',   secSet, activeSecurity,   applyFilters);
  renderFilterPills('filter-devicetype', allHopValues.deviceType, activeDeviceTypes, applyFilters);

  // Clear autocomplete inputs and pills
  ['filter-devicename-input','filter-displayname-input'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['filter-devicename-pills','filter-displayname-pills'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });

  document.getElementById('filter-count').textContent = '';
  // Reset FW filters
  fwOnly              = false;
  rankByFwCount       = false;
  activeFwFingerprint = null;
  document.getElementById('fw-only-btn').textContent = '🛡 FW paths only: off';
  document.getElementById('fw-only-btn').style.color = '';
  document.getElementById('fw-only-btn').style.borderColor = '';
  document.getElementById('fw-rank-btn').textContent = '↕ rank by FW count: off';
  document.getElementById('fw-rank-btn').style.color = '';
  document.getElementById('fw-rank-btn').style.borderColor = '';
  buildFwSummary();
  applyFilters();
}

// ── Firewall helpers ──────────────────────────────────────────────────────────
function getFwNames(path) {
  return (path.hops || [])
    .filter(h => h.deviceType === 'FIREWALL')
    .map(h => h.deviceName || '(unnamed)')
    .sort();
}

function fingerprintKey(names) { return names.join('|'); }

function fingerprintMatches(fwHops, activeSet) {
  const names = fwHops.map(h => h.deviceName || '(unnamed)').sort();
  const key   = fingerprintKey(names);
  return key === [...activeSet].join('|');
}

// ── Build firewall summary ─────────────────────────────────────────────────────
function buildFwSummary() {
  if (allPaths.length === 0) {
    document.getElementById('fw-summary').style.display = 'none';
    return;
  }

  // Build fingerprint map: key → { names[], count, paths[] }
  const fpMap = new Map();
  allPaths.forEach(p => {
    const names = getFwNames(p);
    const key   = fingerprintKey(names);
    if (!fpMap.has(key)) fpMap.set(key, { names, count: 0, paths: [] });
    fpMap.get(key).count++;
    fpMap.get(key).paths.push(p);
  });

  // Sort by count desc
  const fingerprints = [...fpMap.values()].sort((a,b) => b.count - a.count);
  const uniqueFw     = fingerprints.filter(f => f.names.length > 0);
  const noFwCount    = (fpMap.get('') || { count: 0 }).count;
  const hasAsymmetry = uniqueFw.length > 1;

  // Badge
  const badge = document.getElementById('fw-summary-badge');
  if (hasAsymmetry) {
    badge.textContent  = '⚠ asymmetry';
    badge.className    = 'status-badge err';
    badge.style.display = 'inline-block';
  } else if (uniqueFw.length === 1) {
    badge.textContent  = '✓ consistent';
    badge.className    = 'status-badge ok';
    badge.style.display = 'inline-block';
  } else {
    badge.textContent  = 'no FW hops';
    badge.className    = 'status-badge';
    badge.style.background = 'var(--muted)';
    badge.style.display = 'inline-block';
  }

  // Status line
  const statusEl = document.getElementById('fw-status-line');
  if (hasAsymmetry) {
    statusEl.innerHTML = `<div class="fw-warn">⚠ ${uniqueFw.length} distinct firewall sets detected across ${allPaths.length} paths — possible asymmetric routing</div>`;
  } else if (uniqueFw.length === 1) {
    statusEl.innerHTML = `<div class="fw-clean">✓ Consistent firewall set across all paths with FW hops</div>`;
  } else {
    statusEl.innerHTML = `<div class="fw-none">No FIREWALL hops found in any path</div>`;
  }

  // Rows
  const rowsEl = document.getElementById('fw-rows');
  rowsEl.innerHTML = '';
  const maxCount = fingerprints[0] ? fingerprints[0].count : 1;

  fingerprints.forEach(fp => {
    const row = document.createElement('div');
    row.className = 'fw-row';
    const pct = Math.round((fp.count / allPaths.length) * 100);
    const barW = Math.round((fp.count / maxCount) * 100);
    const key  = fingerprintKey(fp.names);
    const isActive = activeFwFingerprint && fingerprintKey([...activeFwFingerprint]) === key;
    if (isActive) row.classList.add('active');

    const nameTags = fp.names.length > 0
      ? fp.names.map(n => `<span class="fw-row-name-tag">${escHtml(n)}</span>`).join('')
      : `<span class="fw-none">no firewall hops</span>`;

    row.innerHTML = `
      <div class="fw-row-names">${nameTags}</div>
      <div class="fw-bar-wrap"><div class="fw-bar-bg"><div class="fw-bar-fill" style="width:${barW}%"></div></div></div>
      <div class="fw-row-count">${fp.count} paths (${pct}%)</div>`;

    row.onclick = () => {
      if (fp.names.length === 0) return; // can't filter on "no FW"
      if (isActive) {
        activeFwFingerprint = null;
      } else {
        activeFwFingerprint = new Set(fp.names);
      }
      buildFwSummary();
      applyFilters();
    };
    rowsEl.appendChild(row);
  });

  document.getElementById('fw-summary').style.display = 'block';
  // Auto-open if there's asymmetry
  if (hasAsymmetry && !fwSummaryOpen) {
    fwSummaryOpen = true;
    document.getElementById('fw-summary-body').style.display = 'block';
    document.getElementById('fw-summary-chevron').style.transform = 'rotate(90deg)';
  }
}

function toggleFwSummary() {
  fwSummaryOpen = !fwSummaryOpen;
  document.getElementById('fw-summary-body').style.display = fwSummaryOpen ? 'block' : 'none';
  document.getElementById('fw-summary-chevron').style.transform = fwSummaryOpen ? 'rotate(90deg)' : '';
}

function toggleFwOnly() {
  fwOnly = !fwOnly;
  const btn = document.getElementById('fw-only-btn');
  btn.textContent   = `🛡 FW paths only: ${fwOnly ? 'on' : 'off'}`;
  btn.style.color   = fwOnly ? 'var(--accent)' : '';
  btn.style.borderColor = fwOnly ? 'var(--accent)' : '';
  applyFilters();
}

function toggleFwRank() {
  rankByFwCount = !rankByFwCount;
  if (rankByFwCount) { rankByHops = false; document.getElementById('rank-hops-btn').textContent = '↕ hops: off'; document.getElementById('rank-hops-btn').style.color=''; document.getElementById('rank-hops-btn').style.borderColor=''; }
  const btn = document.getElementById('fw-rank-btn');
  btn.textContent   = `↕ rank by FW count: ${rankByFwCount ? 'on' : 'off'}`;
  btn.style.color   = rankByFwCount ? 'var(--accent)' : '';
  btn.style.borderColor = rankByFwCount ? 'var(--accent)' : '';
  applyFilters();
}

function clearFwFilter() {
  activeFwFingerprint = null;
  fwOnly              = false;
  rankByFwCount       = false;
  document.getElementById('fw-only-btn').textContent = '🛡 FW paths only: off';
  document.getElementById('fw-only-btn').style.color = '';
  document.getElementById('fw-only-btn').style.borderColor = '';
  document.getElementById('fw-rank-btn').textContent = '↕ rank by FW count: off';
  document.getElementById('fw-rank-btn').style.color = '';
  document.getElementById('fw-rank-btn').style.borderColor = '';
  buildFwSummary();
  applyFilters();
}

function hideNavigator() {
  document.getElementById('results-toolbar').style.display    = 'none';
  document.getElementById('filter-toolbar').style.display     = 'none';
  document.getElementById('hop-filter-toolbar').style.display = 'none';
  document.getElementById('envelope-display').style.display   = 'none';
  document.getElementById('fw-summary').style.display         = 'none';
}

// ── JSON syntax highlighter ────────────────────────────────────────────────────
function syntaxHighlight(json) {
  if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
  else {
    try { json = JSON.stringify(JSON.parse(json), null, 2); } catch(e) {}
  }
  return json.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
      if (/^"/.test(match)) {
        if (/:$/.test(match)) return `<span class="j-key">${match}</span>`;
        return `<span class="j-str">${match}</span>`;
      }
      if (/true|false/.test(match)) return `<span class="j-bool">${match}</span>`;
      if (/null/.test(match))       return `<span class="j-null">${match}</span>`;
      return `<span class="j-num">${match}</span>`;
    });
}

// ── Protocol number → app name map ───────────────────────────────────────────
const PROTO_MAP = {
  '1':  'ICMP',  '3':  'GGP',   '6':  'TCP',   '8':  'EGP',
  '12': 'PUP',   '17': 'UDP',   '20': 'HMP',   '27': 'RDP',
  '46': 'RSVP',  '47': 'GRE',   '50': 'ESP',   '51': 'AH',
  '58': 'ICMPv6','66': 'RVD',   '88': 'IGMP',  '89': 'OSPF'
};

function buildAppStrings() {
  const base       = document.getElementById('base').value.trim().replace(/\/$/, '');
  const netIdx     = document.getElementById('network-select').value;
  const networkId  = netIdx !== '' && discoveredNetworks[parseInt(netIdx)]
    ? discoveredNetworks[parseInt(netIdx)].id : '';
  const snapshotId = document.getElementById('snapshot-select').value;
  const srcIp      = document.getElementById('srcIp').value.trim();
  const dstIp      = document.getElementById('dstIp').value.trim();
  const ipProto    = document.getElementById('ipProto').value.trim();
  const dstPort    = document.getElementById('dstPort').value.trim();

  // ── Search string: f(src)(ipv4_dst.dst)(ip_proto.NAME)(tp_dst.port)m(permit_all)
  let searchStr = '';
  if (srcIp) {
    searchStr += `f(${srcIp})`;
    if (dstIp)    searchStr += `(ipv4_dst.${dstIp})`;
    if (ipProto)  searchStr += `(ip_proto.${PROTO_MAP[ipProto] || ipProto})`;
    if (dstPort)  searchStr += `(tp_dst.${dstPort})`;
    searchStr += `m(permit_all)`;
  }
  document.getElementById('app-search-display').textContent =
    searchStr || '— fill in srcIp to generate —';

  // ── App URL: base/?/search?networkId=...&snapshotId=...&q=...
  let appUrl = '';
  if (base && networkId && searchStr) {
    const params = new URLSearchParams();
    params.set('networkId', networkId);
    if (snapshotId) params.set('snapshotId', snapshotId);
    params.set('q', searchStr);
    appUrl = `${base}/?/search?${params.toString()}`;
  }
  document.getElementById('app-url-display').textContent =
    appUrl || '— select a network and fill in srcIp to generate —';
}

function copyAppBox(id, btn) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 2000);
  });
}

// ── URL panel toggle ──────────────────────────────────────────────────────────
let urlPanelOpen = false;
function toggleUrlPanel() {
  urlPanelOpen = !urlPanelOpen;
  document.getElementById('url-panel').style.display = urlPanelOpen ? 'block' : 'none';
  document.getElementById('view-urls-btn').textContent = urlPanelOpen ? '▲ URLs' : '▼ URLs';
}

// ── Direct copy from toolbar (no need to expand panel) ────────────────────────
function copyAppUrlDirect() {
  const text = document.getElementById('app-url-display').textContent;
  navigator.clipboard.writeText(text).then(() => flashCopyStatus('✓ App URL copied!'));
}

function copyAppStringDirect() {
  const text = document.getElementById('app-search-display').textContent;
  navigator.clipboard.writeText(text).then(() => flashCopyStatus('✓ App String copied!'));
}

function flashCopyStatus(msg) {
  const el = document.getElementById('copy-status');
  el.textContent = msg;
  el.style.opacity = '1';
  setTimeout(() => { el.style.opacity = '0'; el.textContent = '✓ Copied!'; }, 2000);
}

function copyUrl() {
  const url = document.getElementById('url-display').textContent;
  navigator.clipboard.writeText(url).then(() => flashCopyStatus('✓ API URL copied!'));
}

function clearAll() {
  document.getElementById('base').value = 'https://fwd.app';
  document.getElementById('network-select').value = '';
  document.getElementById('network-id-display').textContent = '';
  document.getElementById('snapshot-id-display').textContent = '';
  document.getElementById('saved-select').value = '';
  document.getElementById('cred-indicator').innerHTML = '';
  document.getElementById('run-btn').disabled = true;
  renderSnapshotDropdown();
  ['srcIp','dstIp','ipProto','dstPort','maxCandidates','maxResults','maxSeconds']
    .forEach(id => document.getElementById(id).value = '');
  document.getElementById('i0').checked   = true;
  document.getElementById('inf0').checked = true;
  document.getElementById('json-output').innerHTML = '<span class="j-empty">Hit ▶ Run to execute the query against the API.</span>';
  document.getElementById('resp-status').style.display = 'none';
  update();
}

function flashStatus(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.add('visible');
  setTimeout(() => { el.classList.remove('visible'); el.textContent = ''; }, 3000);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

boot();
</script>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/config':
            data = read_config()
            body = json.dumps(data).encode('utf-8')
            self._respond(200, 'application/json', body)

        elif self.path == '/credentialed':
            body = json.dumps({'networkIds': list(CREDENTIALS.keys())}).encode('utf-8')
            self._respond(200, 'application/json', body)

        elif self.path == '/networks-data':
            body = json.dumps(NETWORKS_DATA).encode('utf-8')
            self._respond(200, 'application/json', body)

        else:
            body = HTML.encode('utf-8')
            self._respond(200, 'text/html; charset=utf-8', body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)

        if self.path == '/config':
            try:
                data = json.loads(raw)
                write_config(data)
                self._respond(200, 'application/json', b'{"ok":true}')
            except Exception:
                self._respond(400, 'application/json', b'{"ok":false}')

        elif self.path == '/proxy':
            try:
                req_data = json.loads(raw)
                url       = req_data['url']
                network_id = req_data['networkId']

                if network_id not in CREDENTIALS:
                    self._respond(200, 'application/json',
                        json.dumps({'error': f'No credentials loaded for network {network_id}. Restart and enter credentials.'}).encode())
                    return

                req = urllib.request.Request(url)
                req.add_header('Authorization', CREDENTIALS[network_id])
                req.add_header('Accept', 'application/json')

                try:
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        status  = resp.status
                        headers = list(resp.headers.items())
                        body    = resp.read().decode('utf-8')
                except urllib.error.HTTPError as e:
                    status  = e.code
                    headers = list(e.headers.items()) if e.headers else []
                    body    = e.read().decode('utf-8')

                result = json.dumps({'status': status, 'headers': headers, 'body': body})
                self._respond(200, 'application/json', result.encode('utf-8'))

            except Exception as e:
                self._respond(200, 'application/json',
                    json.dumps({'error': str(e)}).encode('utf-8'))
        else:
            self._respond(404, 'application/json', b'{"ok":false}')

    def _respond(self, code, content_type, body):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def run():
    print(f'\n  ⬡  Forward Networks — Path Search URL Builder')
    print(f'  ' + '─' * 50)
    # Read base URL from env or use default
    base_url = os.environ.get('FWD_BASE_URL', 'https://fwd.app')
    collect_credentials(base_url)

    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)

    def open_browser():
        import time
        time.sleep(0.4)
        webbrowser.open(f'http://localhost:{PORT}')

    threading.Thread(target=open_browser, daemon=True).start()

    print(f'  Running at: http://localhost:{PORT}')
    print(f'  Config:     {CONFIG_FILE}')
    print(f'  Press Ctrl+C to quit\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n  Shutting down. Goodbye.\n')
        server.shutdown()


if __name__ == '__main__':
    run()