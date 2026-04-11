#!/usr/bin/env python3
"""
Forward Networks — Path Search History Tool
Runs the same path search across historical snapshots going back a configurable
number of days and reports how firewall visibility changes over time.

Uses the Forward Networks API:
  GET /api/networks/{networkId}/snapshots?state=PROCESSED
  GET /api/networks/{networkId}/paths?snapshotId=...

Author: Robert Tavoularis — Forward Networks Customer Success Engineering
"""

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
from datetime import datetime, timezone, timedelta

PORT        = 8767
CREDENTIALS   = {}
NETWORKS_DATA = []
CONFIG_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_search_config.json")


def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"savedSearches": []}
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"savedSearches": []}


def write_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Device types the API considers "firewall" across all platforms
FIREWALL_TYPES = frozenset([
    "FIREWALL",
    "AWS_NETWORK_FIREWALL",
    "AZURE_FIREWALL",
])


def _load_discovery():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_discovery.py")
    spec = importlib.util.spec_from_file_location("fwd_discovery", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect_credentials(base_url="https://fwd.app"):
    global NETWORKS_DATA
    prefix = "FWD_CREDS_"
    found  = 0
    for k, v in os.environ.items():
        if k.startswith(prefix):
            net_id = k[len(prefix):]
            token  = base64.b64encode(v.encode()).decode()
            CREDENTIALS[net_id] = f"Basic {token}"
            found += 1
    if found == 0:
        print("  ⚠  No FWD_CREDS_* environment variables found.")
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


def api_get(base_url, network_id, path, params=None):
    """
    Make an authenticated GET to the Forward API.
    path should start with /api/...
    Returns (status_code, parsed_json_or_None, error_string_or_None)
    """
    if network_id not in CREDENTIALS:
        return None, None, f"No credentials for network {network_id}"
    qs  = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{base_url.rstrip('/')}{path}{qs}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            msg = json.loads(body).get("message", body)
        except Exception:
            msg = body
        return e.code, None, msg
    except Exception as ex:
        return None, None, str(ex)


def list_processed_snapshots(base_url, network_id, days_back):
    """
    Fetch all PROCESSED snapshots for a network within the last `days_back` days.
    Returns list of SnapshotInfo dicts, newest first, filtered to the date window.
    The API returns snapshots newest-first natively.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    params = {"state": "PROCESSED", "limit": "500"}
    status, data, err = api_get(base_url, network_id,
                                f"/api/networks/{network_id}/snapshots", params)
    if err or data is None:
        return [], err or f"HTTP {status}"

    snapshots = data.get("snapshots", [])

    # Filter to date window using processedAt (ISO 8601 string)
    result = []
    for s in snapshots:
        ts_str = s.get("processedAt") or s.get("createdAt")
        if not ts_str:
            continue
        try:
            # Python 3.7+ fromisoformat doesn't handle trailing Z
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts >= cutoff:
            result.append({
                "id":          s["id"],
                "processedAt": ts_str,
                "ts":          ts.isoformat(),
                "label":       ts.strftime("%Y-%m-%d %H:%M UTC"),
                "date":        ts.strftime("%Y-%m-%d"),
            })

    # Oldest first — baseline at top, each row compared to the one above
    result.sort(key=lambda x: x["ts"], reverse=False)
    return result, None


def run_path_search(base_url, network_id, snapshot_id, src_ip, dst_ip,
                    intent, max_candidates, max_results, ip_proto, dst_port, max_seconds=30):
    """
    Run a path search for a specific snapshot.
    Returns (status, parsed_body_dict_or_None, elapsed_ms, error_or_None)
    """
    params = {
        "srcIp":         src_ip,
        "dstIp":         dst_ip,
        "intent":        intent,
        "maxCandidates": str(max_candidates),
        "maxResults":    str(max_results),
        "maxSeconds":    str(max_seconds),
        "snapshotId":    snapshot_id,
    }
    if ip_proto:
        params["ipProto"] = str(ip_proto)
    if dst_port:
        params["dstPort"] = str(dst_port)

    if network_id not in CREDENTIALS:
        return None, None, 0, f"No credentials for network {network_id}"

    qs  = urllib.parse.urlencode(params)
    url = f"{base_url.rstrip('/')}/api/networks/{network_id}/paths?{qs}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Accept", "application/json")

    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=max_seconds + 120) as resp:
            body   = json.loads(resp.read().decode("utf-8"))
            status = resp.status
    except urllib.error.HTTPError as e:
        raw  = e.read().decode("utf-8")
        elapsed = round((time.time() - t0) * 1000)
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw}
        return e.code, body, elapsed, f"HTTP {e.code}"
    except Exception as ex:
        return None, None, round((time.time() - t0) * 1000), str(ex)

    return status, body, round((time.time() - t0) * 1000), None


def normalize_fw_name(name, normalize_peers):
    """
    When normalize_peers is True, strip a trailing single letter or digit
    (e.g. fw-cluster-a → fw-cluster, fw01 → fw) so that active/standby
    device pairs that differ only by a suffix compare as equal.
    """
    if not normalize_peers or not name:
        return name
    # Strip trailing -a, -b, -1, -2, _a, _b etc.
    import re
    return re.sub(r'[-_][a-zA-Z0-9]$', '', name)


def extract_fw_fingerprint(paths, normalize_peers):
    """
    From a list of Path objects (from info.paths), extract a canonical
    firewall fingerprint: a sorted frozenset of normalized device names
    across ALL firewall hops in ALL returned paths.

    We use the union across all paths rather than per-path because the
    question for history is "what firewalls are reachable on this date",
    not "which specific path was chosen". This makes the comparison robust
    to ECMP path selection changing day-to-day.
    """
    fw_names = set()
    for path in paths:
        for hop in path.get("hops", []):
            if hop.get("deviceType") in FIREWALL_TYPES:
                raw_name = hop.get("deviceName") or hop.get("displayName") or "(unnamed)"
                fw_names.add(normalize_fw_name(raw_name, normalize_peers))
    return frozenset(fw_names)


def build_urls(base_url, network_id, snapshot_id, src_ip, dst_ip,
               intent, max_candidates, max_results, ip_proto, dst_port, max_seconds):
    """Build the API URL and app search string/URL for display."""
    params = {
        "srcIp":         src_ip,
        "dstIp":         dst_ip,
        "intent":        intent,
        "maxCandidates": str(max_candidates),
        "maxResults":    str(max_results),
        "maxSeconds":    str(max_seconds),
        "snapshotId":    snapshot_id,
    }
    if ip_proto:
        params["ipProto"] = str(ip_proto)
    if dst_port:
        params["dstPort"] = str(dst_port)

    api_url = f"{base_url.rstrip('/')}/api/networks/{network_id}/paths?{urllib.parse.urlencode(params)}"

    PROTO_MAP = {"1":"ICMP","6":"TCP","17":"UDP","47":"GRE","50":"ESP","51":"AH","58":"ICMPv6"}
    search = f"f({src_ip})(ipv4_dst.{dst_ip})"
    if ip_proto:
        search += f"(ip_proto.{PROTO_MAP.get(str(ip_proto), str(ip_proto))})"
    if dst_port:
        search += f"(tp_dst.{dst_port})"
    search += "m(permit_all)"

    app_params = {"networkId": network_id, "snapshotId": snapshot_id, "q": search}
    app_url    = f"{base_url.rstrip('/')}/?/search?{urllib.parse.urlencode(app_params)}"

    return api_url, search, app_url


def extract_hop_device_set(paths, normalize_peers):
    """
    Extract the union of all non-synthetic device names across all paths
    that share the same forwardingOutcome and hop count as the top path.
    Used for hop-set change detection.
    """
    if not paths:
        return []
    top = paths[0]
    top_fo  = top.get("forwardingOutcome", "")
    top_len = len(top.get("hops", []))
    names = set()
    for p in paths:
        if (p.get("forwardingOutcome") == top_fo and
                len(p.get("hops", [])) == top_len):
            for h in p.get("hops", []):
                name = h.get("deviceName") or h.get("displayName") or ""
                if name and not any(name.startswith(pfx)
                                    for pfx in ("internet ", "MPLS-", "MPLS_")):
                    if normalize_peers:
                        name = re.sub(r"[-_][a-zA-Z]$", "", name)
                    names.add(name)
    return sorted(names)


def analyze_snapshot_result(body, normalize_peers):
    """
    Parse a PathSearchResponse and return a summary dict.
    """
    if body is None:
        return {"error": "No response body", "fw_fingerprint": [], "total_paths": 0}

    paths     = (body.get("info") or {}).get("paths") or []
    timed_out = body.get("timedOut", False)
    query_url = body.get("queryUrl", "")

    fingerprint   = extract_fw_fingerprint(paths, normalize_peers)
    paths_with_fw = sum(
        1 for p in paths
        if any(h.get("deviceType") in FIREWALL_TYPES for h in p.get("hops", []))
    )

    outcomes = {}
    for p in paths:
        o = p.get("forwardingOutcome", "UNKNOWN")
        outcomes[o] = outcomes.get(o, 0) + 1

    hop_counts = [len(p.get("hops", [])) for p in paths]
    max_hops   = max(hop_counts) if hop_counts else 0
    min_hops   = min(hop_counts) if hop_counts else 0

    hop_device_set = extract_hop_device_set(paths, normalize_peers)

    # Use totalHits for path count — accurate even when maxResults=1
    total_hits_data = (body.get("info") or {}).get("totalHits") or {}
    total_hits      = total_hits_data.get("value", len(paths))
    total_hits_type = total_hits_data.get("type", "EXACT")

    return {
        "fw_fingerprint":  sorted(fingerprint),
        "has_fw":          len(fingerprint) > 0,
        "total_paths":     total_hits,
        "total_hits_type": total_hits_type,
        "paths_returned":  len(paths),
        "paths_with_fw":   paths_with_fw,
        "timed_out":       timed_out,
        "query_url":       query_url,
        "outcomes":        outcomes,
        "max_hops":        max_hops,
        "min_hops":        min_hops,
        "hop_device_set":  hop_device_set,
    }


def _levenshtein_ratio(a, b):
    """Normalised edit distance: 1.0 = identical, 0.0 = nothing in common."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    # Standard DP Levenshtein
    prev_row = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr_row = [i]
        for j, cb in enumerate(b, 1):
            curr_row.append(min(
                prev_row[j] + 1,          # deletion
                curr_row[j - 1] + 1,      # insertion
                prev_row[j - 1] + (ca != cb),  # substitution
            ))
        prev_row = curr_row
    dist = prev_row[lb]
    return 1.0 - dist / max(la, lb)


FUZZY_SIMILAR_THRESHOLD = 0.6   # names with ratio >= this are "similar peer" changes


def diff_hop_sets(prev_set, curr_set):
    """
    Compare two device name sets and return a structured diff:
      {
        "added":    [names present in curr but not prev],
        "removed":  [names present in prev but not curr],
        "similar":  [(removed, added, ratio), ...],  # fuzzy-matched peer swaps
        "replaced": [(removed, added), ...],          # clear replacements (no fuzzy match)
        "net_added":   [names in added with no fuzzy match],
        "net_removed": [names in removed with no fuzzy match],
      }
    Similar = ratio >= FUZZY_SIMILAR_THRESHOLD.
    Each name participates in at most one pairing (greedy best-match).
    """
    prev_s = set(prev_set or [])
    curr_s = set(curr_set or [])
    added   = sorted(curr_s - prev_s)
    removed = sorted(prev_s - curr_s)

    if not added or not removed:
        return {
            "added": added, "removed": removed,
            "similar": [], "replaced": [],
            "net_added": added, "net_removed": removed,
        }

    # Score all (removed, added) pairs
    scores = []
    for r in removed:
        for a in added:
            ratio = _levenshtein_ratio(r, a)
            if ratio >= FUZZY_SIMILAR_THRESHOLD:
                scores.append((ratio, r, a))
    scores.sort(reverse=True)

    matched_r, matched_a = set(), set()
    similar, replaced = [], []
    for ratio, r, a in scores:
        if r not in matched_r and a not in matched_a:
            similar.append((r, a, round(ratio, 2)))
            matched_r.add(r)
            matched_a.add(a)

    # Unmatched pairs are genuine replacements
    unmatched_r = [r for r in removed if r not in matched_r]
    unmatched_a = [a for a in added   if a not in matched_a]
    # Pair remaining by position for display (best we can do without context)
    for i in range(max(len(unmatched_r), len(unmatched_a))):
        r = unmatched_r[i] if i < len(unmatched_r) else None
        a = unmatched_a[i] if i < len(unmatched_a) else None
        replaced.append((r, a))

    return {
        "added":       added,
        "removed":     removed,
        "similar":     similar,
        "replaced":    replaced,
        "net_added":   [a for a in added   if a not in matched_a],
        "net_removed": [r for r in removed if r not in matched_r],
    }


def detect_change(prev, curr):
    """
    Compare two analysis dicts and return a change classification string.

    Returns one of:
      NO_CHANGE          — identical device set and path count
      FW_SET_CHANGED     — different firewall devices (meaningful change)
      FW_APPEARED        — prev had no FW, curr does
      FW_DISAPPEARED     — prev had FW, curr has none
      HOP_SET_CHANGED    — non-FW device set changed (new/removed hops)
      HOP_SET_SIMILAR    — device set changed but all diffs are fuzzy peer swaps
      PATH_COUNT_ONLY    — same device set, different path count (ECMP variation)
      BASELINE           — first snapshot, no previous to compare
    """
    if prev is None:
        return "BASELINE"

    prev_fp = frozenset(prev.get("fw_fingerprint") or [])
    curr_fp = frozenset(curr.get("fw_fingerprint") or [])

    # FW changes take priority
    if prev_fp != curr_fp:
        if not prev_fp and curr_fp:
            return "FW_APPEARED"
        if prev_fp and not curr_fp:
            return "FW_DISAPPEARED"
        return "FW_SET_CHANGED"

    # Hop-set changes
    prev_hops = frozenset(prev.get("hop_device_set") or [])
    curr_hops = frozenset(curr.get("hop_device_set") or [])
    if prev_hops != curr_hops and prev_hops and curr_hops:
        hop_diff = diff_hop_sets(list(prev_hops), list(curr_hops))
        # If every change has a fuzzy peer match, it's SIMILAR (warn-level)
        if hop_diff["replaced"] or hop_diff["net_added"] or hop_diff["net_removed"]:
            return "HOP_SET_CHANGED"
        return "HOP_SET_SIMILAR"

    if prev.get("total_paths") != curr.get("total_paths"):
        return "PATH_COUNT_ONLY"
    return "NO_CHANGE"


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forward Networks · Path Search History</title>
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
  .logo   { color:var(--accent); font-size:1.3rem; font-weight:700; }
  .title  { font-size:1.2rem; font-weight:700; letter-spacing:0.05em; }
  .sub    { color:var(--muted); font-size:0.82rem; }
  .divider{ height:1px; background:var(--accent); margin:10px 0 20px; }

  .layout { display:flex; gap:16px; align-items:flex-start; }
  .left   { width:340px; flex-shrink:0; display:flex; flex-direction:column; gap:12px; }
  .right  { flex:1; min-width:0; display:flex; flex-direction:column; gap:12px; }

  .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px 18px; }
  .card-title { font-size:0.68rem; font-weight:700; color:var(--muted); letter-spacing:0.12em; margin-bottom:12px; }
  .card-sep   { height:1px; background:var(--border); margin:12px 0; }
  .row  { display:flex; align-items:center; gap:10px; margin-bottom:8px; flex-wrap:wrap; }
  .row:last-child { margin-bottom:0; }
  label { font-size:0.74rem; font-weight:600; color:var(--muted); min-width:110px; flex-shrink:0; }
  label span { color:var(--error); }
  input[type="text"], input[type="number"], select {
    background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
    color:var(--text); font-family:inherit; font-size:0.8rem;
    padding:6px 9px; outline:none; transition:border-color 0.15s;
  }
  input[type="text"] { flex:1; min-width:80px; }
  input[type="number"] { width:70px; }
  input[type="text"]:focus, input[type="number"]:focus, select:focus { border-color:var(--accent); }
  input::placeholder { color:var(--muted); }
  select { cursor:pointer; min-width:160px; }
  select option { background:var(--surface); }

  /* Toggle switch */
  .toggle-row { display:flex; align-items:center; gap:10px; }
  .toggle-label { font-size:0.74rem; font-weight:600; color:var(--muted); flex:1; }
  .toggle { position:relative; width:36px; height:20px; flex-shrink:0; }
  .toggle input { opacity:0; width:0; height:0; }
  .toggle-slider {
    position:absolute; inset:0; background:var(--border); border-radius:20px;
    cursor:pointer; transition:background 0.2s;
  }
  .toggle-slider::before {
    content:''; position:absolute; width:14px; height:14px; left:3px; top:3px;
    background:var(--muted); border-radius:50%; transition:transform 0.2s, background 0.2s;
  }
  .toggle input:checked + .toggle-slider { background:var(--accent); }
  .toggle input:checked + .toggle-slider::before { transform:translateX(16px); background:#fff; }
  .toggle-hint { font-size:0.65rem; color:var(--muted); margin-top:4px; }

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
  .btn-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }

  .progress-wrap  { background:var(--border); border-radius:2px; height:6px; margin:8px 0; }
  .progress-fill  { background:var(--accent); border-radius:2px; height:6px; transition:width 0.3s; }
  .progress-label { font-size:0.7rem; color:var(--muted); }

  /* ── Timeline ── */
  .timeline { display:flex; flex-direction:column; gap:6px; }
  .tl-row {
    display:flex; align-items:stretch; gap:0;
    border:1px solid var(--border); border-radius:var(--radius);
    overflow:hidden; transition:border-color 0.15s;
  }
  .tl-row:hover { border-color:var(--accent); }

  /* Left gutter: status color bar */
  .tl-gutter { width:5px; flex-shrink:0; }
  .tl-gutter.no-change       { background:var(--muted); }
  .tl-gutter.fw-set-changed  { background:var(--error); }
  .tl-gutter.fw-appeared     { background:var(--accent); }
  .tl-gutter.fw-disappeared  { background:var(--error); }
  .tl-gutter.hop-set-changed { background:var(--warn); }
  .tl-gutter.hop-set-similar { background:var(--accent2); opacity:0.7; }
  .tl-gutter.path-count-only { background:var(--muted); }
  .tl-gutter.baseline        { background:var(--accent2); }
  .tl-gutter.error           { background:var(--warn); }
  .tl-gutter.no-results      { background:var(--muted); }

  .tl-body { flex:1; padding:10px 14px; background:var(--surface); }
  .tl-header { display:flex; align-items:center; gap:10px; margin-bottom:6px; flex-wrap:wrap; }
  .tl-date { font-size:0.78rem; font-weight:700; color:var(--text); min-width:160px; }
  .tl-snap-id { font-size:0.65rem; color:var(--muted); }

  .badge { display:inline-block; font-size:0.62rem; font-weight:700; padding:2px 8px; border-radius:3px; white-space:nowrap; }
  .badge-ok    { background:var(--success); color:var(--bg); }
  .badge-err    { background:var(--error);   color:var(--bg); }
  .badge-warn   { background:var(--warn);    color:var(--bg); }
  .badge-info   { background:var(--accent);  color:var(--bg); }
  .badge-peer   { background:var(--accent2); color:var(--bg); }
  .badge-muted { background:var(--border);  color:var(--muted); }
  .badge-accent2{ background:#1a3a45; color:var(--accent2); border:1px solid var(--accent2); }

  .tl-fw { display:flex; gap:6px; flex-wrap:wrap; margin-top:5px; }
  .fw-tag { display:inline-block; background:var(--bg); border:1px solid var(--border); border-radius:3px; padding:1px 6px; font-size:0.68rem; color:var(--accent2); }
  .fw-tag.new { border-color:var(--success); color:var(--success); }
  .fw-tag.removed { border-color:var(--error); color:var(--error); text-decoration:line-through; }

  .tl-meta { display:flex; gap:12px; flex-wrap:wrap; margin-top:5px; font-size:0.66rem; color:var(--muted); }
  .tl-meta a { color:var(--accent); text-decoration:none; }
  .tl-meta a:hover { text-decoration:underline; }

  .tl-change-note { font-size:0.7rem; margin-top:4px; }
  .change-fw-set      { color:var(--error); font-weight:700; }
  .change-appeared    { color:var(--accent); font-weight:700; }
  .change-gone        { color:var(--error); font-weight:700; }
  .change-hop-changed { color:var(--warn); font-weight:700; }
  .change-hop-similar { color:var(--accent2); }
  .change-count       { color:var(--muted); }
  .change-baseline    { color:var(--accent2); }
  .hop-change-peer    { font-size:0.68rem; color:var(--accent2); font-style:italic; }
  .hop-change-replace { font-size:0.68rem; color:var(--warn); }
  .hop-change-remove  { font-size:0.68rem; color:var(--error); }
  .hop-change-add     { font-size:0.68rem; color:var(--success); }

  /* Summary bar */
  .summary-bar {
    display:flex; gap:16px; flex-wrap:wrap; align-items:center;
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:12px 16px;
  }
  .sum-item { display:flex; flex-direction:column; gap:3px; }
  .sum-label { font-size:0.62rem; color:var(--muted); letter-spacing:0.1em; }
  .sum-val   { font-size:0.9rem; font-weight:700; }
  .sum-val.ok   { color:var(--success); }
  .sum-val.err  { color:var(--error); }
  .sum-val.warn { color:var(--warn); }
  .sum-val.info { color:var(--accent); }
  .sep-v { width:1px; background:var(--border); align-self:stretch; }

  .empty-state { font-size:0.78rem; color:var(--muted); padding:24px; text-align:center; }

  .cred-dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:5px; }
  .cred-dot.has  { background:var(--success); }
  .cred-dot.none { background:var(--error); }
  .net-id-hint { font-size:0.66rem; color:var(--accent2); }

  .spinner { display:inline-block; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .hint { font-size:0.66rem; color:var(--muted); }

  /* ── Saved searches ── */
  .ss-row { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
  .ss-row select { flex:1; min-width:120px; }
  .save-status { font-size:0.7rem; color:var(--success); opacity:0; transition:opacity 0.2s; }
  .save-status.visible { opacity:1; }

  /* ── Expand panel ── */
  .tl-expand-btn {
    font-family:inherit; font-size:0.65rem; font-weight:700;
    background:var(--bg); color:var(--muted);
    border:1px solid var(--border); border-radius:var(--radius);
    padding:2px 8px; cursor:pointer; margin-left:auto;
    transition:border-color 0.15s, color 0.15s;
  }
  .tl-expand-btn:hover { border-color:var(--accent); color:var(--accent); }
  .tl-detail {
    display:none; margin-top:8px; padding-top:8px;
    border-top:1px solid var(--border);
  }
  .tl-detail.open { display:block; }
  .detail-section { margin-bottom:8px; }
  .detail-label { font-size:0.62rem; font-weight:700; color:var(--muted); letter-spacing:0.1em; margin-bottom:3px; }
  .detail-box {
    background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
    padding:6px 8px; font-size:0.7rem; color:var(--accent2);
    word-break:break-all; white-space:pre-wrap; line-height:1.5;
    cursor:text; user-select:all;
  }
  .detail-copy-row { display:flex; align-items:flex-start; gap:6px; }
  .detail-copy-row .detail-box { flex:1; }
  .copy-sm {
    font-family:inherit; font-size:0.62rem; font-weight:700;
    background:var(--surface); color:var(--muted);
    border:1px solid var(--border); border-radius:var(--radius);
    padding:3px 7px; cursor:pointer; flex-shrink:0; margin-top:0;
    transition:border-color 0.15s;
  }
  .copy-sm:hover { border-color:var(--accent); color:var(--accent); }
  .json-scroll {
    max-height:300px; overflow-y:auto;
    background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
    padding:8px; font-size:0.68rem; line-height:1.6;
    white-space:pre-wrap; word-break:break-all;
  }
  .j-key  { color:#79c0ff; }
  .j-str  { color:#a5d6a7; }
  .j-num  { color:#f0c27f; }
  .j-bool { color:var(--accent); }
  .j-null { color:var(--muted); }
</style>
</head>
<body>

<header>
  <span class="logo">⬡</span>
  <span class="title">PATH SEARCH HISTORY</span>
  <span class="sub">Snapshot Audit — Path Search Results Over Time</span>
</header>
<div class="divider"></div>

<div class="layout">

  <!-- ── LEFT ── -->
  <div class="left">

    <div class="card">
      <div class="card-title">── SAVED SEARCHES</div>
      <div class="ss-row">
        <select id="saved-select" onchange="loadSavedSearch()" autocomplete="off" data-lpignore="true">
          <option value="">— select a saved search —</option>
        </select>
      </div>
      <div class="ss-row" style="margin-top:8px">
        <button class="btn-secondary btn-sm" onclick="saveCurrentSearch()">Save as...</button>
        <button class="btn-secondary btn-sm" onclick="deleteSavedSearch()">Delete</button>
      </div>
      <div id="save-status" class="save-status" style="margin-top:6px"></div>
    </div>

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
        <label>Instance URL</label>
        <input type="text" id="base-url" value="https://fwd.app">
      </div>
    </div>

    <div class="card">
      <div class="card-title">── QUERY</div>
      <div class="row">
        <label>srcIp <span>*</span></label>
        <input type="text" id="src-ip" placeholder="10.0.0.1">
      </div>
      <div class="row">
        <label>dstIp <span>*</span></label>
        <input type="text" id="dst-ip" placeholder="192.168.1.1">
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label>ipProto</label>
        <input type="text" id="ip-proto" placeholder="6" style="max-width:60px">
        <span class="hint">6=TCP 17=UDP</span>
      </div>
      <div class="row">
        <label>dstPort</label>
        <input type="text" id="dst-port" placeholder="443" style="max-width:60px">
      </div>
      <div class="card-sep"></div>
      <div class="row">
        <label>intent</label>
        <select id="intent">
          <option value="PREFER_DELIVERED">PREFER_DELIVERED</option>
          <option value="PREFER_VIOLATIONS">PREFER_VIOLATIONS</option>
          <option value="VIOLATIONS_ONLY">VIOLATIONS_ONLY</option>
        </select>
      </div>
      <div class="row">
        <label>maxCandidates</label>
        <input type="number" id="max-cand" value="5000" min="1" max="10000">
        <span class="hint">1–10000</span>
      </div>
      <div class="row">
        <label>maxResults</label>
        <input type="number" id="max-results" value="1" min="1" max="10000">
        <span class="hint">paths returned (totalHits always shown)</span>
      </div>
      <div class="row">
        <label>maxSeconds</label>
        <input type="number" id="max-sec" value="30" min="1" max="300">
        <span class="hint">per snapshot</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title">── HISTORY SETTINGS</div>
      <div class="row">
        <label>Days back</label>
        <input type="number" id="days-back" value="7" min="1" max="365">
        <span class="hint">all snapshots in this window are queried</span>
      </div>
      <div class="card-sep"></div>
      <div class="toggle-row" style="margin-bottom:8px">
        <span class="toggle-label">Normalize peer names</span>
        <label class="toggle">
          <input type="checkbox" id="normalize-peers">
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="toggle-hint">
        Strip trailing letters/digits from device names before comparing
        (e.g. fw-a / fw-b → fw). Prevents failover events from being
        flagged as firewall set changes.
      </div>
    </div>

  </div><!-- /left -->

  <!-- ── RIGHT ── -->
  <div class="right">

    <!-- Summary bar — shown after run completes, sits above run bar -->
    <div id="summary-bar" style="display:none">
      <div class="summary-bar">
        <div class="sum-item">
          <span class="sum-label">SNAPSHOTS AUDITED</span>
          <span class="sum-val info" id="sum-total">—</span>
        </div>
        <div class="sep-v"></div>
        <div class="sum-item">
          <span class="sum-label">WITH FIREWALL</span>
          <span class="sum-val ok" id="sum-fw">—</span>
        </div>
        <div class="sum-item">
          <span class="sum-label">WITHOUT FIREWALL</span>
          <span class="sum-val err" id="sum-no-fw">—</span>
        </div>
        <div class="sep-v"></div>
        <div class="sum-item">
          <span class="sum-label">FW SET CHANGES</span>
          <span class="sum-val err" id="sum-changes">—</span>
        </div>
        <div class="sum-item">
          <span class="sum-label">ECMP-ONLY VARIATIONS</span>
          <span class="sum-val" style="color:var(--muted)" id="sum-ecmp">—</span>
        </div>
        <div class="sep-v"></div>
        <div class="sum-item">
          <span class="sum-label">ERRORS / TIMEOUTS</span>
          <span class="sum-val warn" id="sum-err">—</span>
        </div>
        <div class="sep-v"></div>
        <div class="sum-item" style="justify-content:center">
          <button class="btn-secondary btn-sm" id="export-btn" onclick="exportCsv()" disabled>↓ Export CSV</button>
        </div>
      </div>
    </div>

    <!-- Run bar -->
    <div style="display:flex;align-items:center;gap:10px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;flex-wrap:wrap">
      <button class="btn-primary" id="run-btn" onclick="runHistory()">▶ Run Audit</button>
      <button class="btn-secondary" id="stop-btn" onclick="stopAudit()" disabled>■ Stop</button>
      <div style="flex:1;min-width:160px">
        <div id="progress-label" class="progress-label" style="margin-bottom:4px">Ready.</div>
        <div class="progress-wrap" style="margin:0"><div class="progress-fill" id="progress-bar" style="width:0%"></div></div>
      </div>
    </div>

    <!-- Timeline -->
    <div class="card" style="padding:12px 16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.12em">── TIMELINE</span>
        <span style="font-size:0.68rem;color:var(--muted)">oldest first</span>
        <span id="timeline-count" style="font-size:0.68rem;color:var(--muted);margin-left:auto"></span>
      </div>
      <div class="timeline" id="timeline">
        <div class="empty-state">Select a network, enter src/dst, and click ▶ Run Audit</div>
      </div>
    </div>

  </div><!-- /right -->
</div>

<script>
let discoveredNetworks   = [];
let credentialedNetworks = new Set();
let stopped = false;
let allRows = [];   // { snapshot, analysis, change, elapsed_ms }

// ── Boot ──────────────────────────────────────────────────────────────────────
let savedSearches = [];

async function boot() {
  try {
    const r    = await fetch('/networks-data');
    const data = await r.json();
    discoveredNetworks   = Array.isArray(data) ? data : (data.networks || []);
    credentialedNetworks = new Set(discoveredNetworks.map(n => n.id));
  } catch(e) { discoveredNetworks = []; }
  try {
    const r = await fetch('/config');
    const c = await r.json();
    savedSearches = c.savedSearches || [];
  } catch(e) { savedSearches = []; }
  setTimeout(() => {
    renderNetworkDropdown();
    renderSavedSearchDropdown();
  }, 300);
}

// ── Saved Searches ────────────────────────────────────────────────────────────
function renderSavedSearchDropdown() {
  const sel = document.getElementById('saved-select');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— select a saved search —</option>';
  savedSearches.forEach((s, i) => {
    const opt = document.createElement('option');
    opt.value = i; opt.textContent = s.name;
    sel.appendChild(opt);
  });
  if (cur !== '') sel.value = cur;
}

function loadSavedSearch() {
  const idx = document.getElementById('saved-select').value;
  if (idx === '') return;
  const p = savedSearches[parseInt(idx)].params;

  document.getElementById('base-url').value  = p.base || 'https://fwd.app';
  document.getElementById('src-ip').value    = p.srcIp    || '';
  document.getElementById('dst-ip').value    = p.dstIp    || '';
  document.getElementById('ip-proto').value  = p.ipProto  || '';
  document.getElementById('dst-port').value  = p.dstPort  || '';
  document.getElementById('max-cand').value     = p.maxCandidates || 5000;
  document.getElementById('max-results').value  = p.maxResults    || 1;
  document.getElementById('max-sec').value      = p.maxSeconds    || 30;

  const intentSel = document.getElementById('intent');
  intentSel.value = p.intent || 'PREFER_DELIVERED';

  // Restore network selection by network ID
  if (p.networkId) {
    const idx = discoveredNetworks.findIndex(n => n.id === p.networkId);
    if (idx >= 0) {
      document.getElementById('network-select').value = idx;
      onNetworkSelect();
    }
  }
}

function currentParams() {
  const netIdx  = document.getElementById('network-select').value;
  const networkId = netIdx !== '' ? discoveredNetworks[parseInt(netIdx)].id : '';
  return {
    base:          document.getElementById('base-url').value.trim(),
    networkId,
    srcIp:         document.getElementById('src-ip').value.trim(),
    dstIp:         document.getElementById('dst-ip').value.trim(),
    ipProto:       document.getElementById('ip-proto').value.trim(),
    dstPort:       document.getElementById('dst-port').value.trim(),
    intent:        document.getElementById('intent').value,
    maxCandidates: document.getElementById('max-cand').value,
    maxResults:    document.getElementById('max-results').value,
    maxSeconds:    document.getElementById('max-sec').value,
  };
}

async function saveCurrentSearch() {
  const name = prompt('Name this saved search:');
  if (!name || !name.trim()) return;
  const trimmed = name.trim();
  const existing = savedSearches.findIndex(s => s.name === trimmed);
  const entry = { name: trimmed, params: currentParams() };
  if (existing >= 0) {
    if (!confirm(`"${trimmed}" already exists. Overwrite?`)) return;
    savedSearches[existing] = entry;
  } else {
    savedSearches.push(entry);
  }
  await fetch('/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ savedSearches })
  });
  renderSavedSearchDropdown();
  const newIdx = savedSearches.findIndex(s => s.name === trimmed);
  document.getElementById('saved-select').value = newIdx;
  flashStatus('save-status', `✓ Saved "${trimmed}"`);
}

async function deleteSavedSearch() {
  const idx = document.getElementById('saved-select').value;
  if (idx === '') return;
  const name = savedSearches[parseInt(idx)].name;
  if (!confirm(`Delete "${name}"?`)) return;
  savedSearches.splice(parseInt(idx), 1);
  await fetch('/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ savedSearches })
  });
  renderSavedSearchDropdown();
}

function flashStatus(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.add('visible');
  setTimeout(() => { el.classList.remove('visible'); el.textContent = ''; }, 3000);
}

function renderNetworkDropdown() {
  const sel = document.getElementById('network-select');
  sel.innerHTML = '<option value="">— select —</option>';
  discoveredNetworks.forEach((n, i) => {
    const opt = document.createElement('option');
    opt.value = i; opt.textContent = n.name;
    sel.appendChild(opt);
  });
  updateCredIndicator();
}

function onNetworkSelect() {
  const idx = document.getElementById('network-select').value;
  document.getElementById('net-id-display').textContent =
    idx !== '' ? `ID: ${discoveredNetworks[parseInt(idx)].id}` : '';
  updateCredIndicator();
}

function updateCredIndicator() {
  const idx = document.getElementById('network-select').value;
  const el  = document.getElementById('cred-indicator');
  if (idx === '') { el.innerHTML = ''; return; }
  const netId   = discoveredNetworks[parseInt(idx)].id;
  const hasCred = credentialedNetworks.has(netId);
  el.innerHTML  = `<span class="cred-dot ${hasCred?'has':'none'}" title="${hasCred?'Credentials loaded':'No credentials'}"></span>`;
}

// ── Run ───────────────────────────────────────────────────────────────────────
async function runHistory() {
  const netIdx = document.getElementById('network-select').value;
  if (netIdx === '') { alert('Please select a network.'); return; }

  const networkId     = discoveredNetworks[parseInt(netIdx)].id;
  const baseUrl       = document.getElementById('base-url').value.trim();
  const srcIp         = document.getElementById('src-ip').value.trim();
  const dstIp         = document.getElementById('dst-ip').value.trim();
  const ipProto       = document.getElementById('ip-proto').value.trim() || null;
  const dstPort       = document.getElementById('dst-port').value.trim() || null;
  const intent        = document.getElementById('intent').value;
  const maxCand       = parseInt(document.getElementById('max-cand').value) || 5000;
  const maxResults    = parseInt(document.getElementById('max-results').value) || 1;
  const maxSec        = parseInt(document.getElementById('max-sec').value) || 30;
  const daysBack      = parseInt(document.getElementById('days-back').value) || 7;
  const normPeers     = document.getElementById('normalize-peers').checked;

  if (!srcIp || !dstIp) { alert('srcIp and dstIp are required.'); return; }

  stopped = false; allRows = [];
  document.getElementById('run-btn').disabled    = true;
  document.getElementById('stop-btn').disabled   = false;
  document.getElementById('export-btn').disabled = true;
  document.getElementById('summary-bar').style.display = 'none';
  document.getElementById('timeline').innerHTML =
    '<div class="empty-state"><span class="spinner">⟳</span> Fetching snapshot list...</div>';
  setProgress(0, 1, 'Fetching snapshots...');

  // Step 1: get snapshot list
  const listResp = await fetch('/list-snapshots', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseUrl, networkId, daysBack })
  });
  const listData = await listResp.json();

  if (listData.error) {
    document.getElementById('timeline').innerHTML =
      `<div class="empty-state" style="color:var(--error)">Failed to fetch snapshots: ${esc(listData.error)}</div>`;
    document.getElementById('run-btn').disabled  = false;
    document.getElementById('stop-btn').disabled = true;
    return;
  }

  const snapshots = listData.snapshots || [];
  if (snapshots.length === 0) {
    document.getElementById('timeline').innerHTML =
      `<div class="empty-state">No processed snapshots found in the last ${daysBack} days.</div>`;
    document.getElementById('run-btn').disabled  = false;
    document.getElementById('stop-btn').disabled = true;
    return;
  }

  document.getElementById('timeline-count').textContent = `${snapshots.length} snapshots`;
  document.getElementById('timeline').innerHTML = '';

  // Step 2: run path search for each snapshot (list is oldest-first)
  // Uses a concurrency pool — up to CONCURRENCY requests in-flight at once.
  // Results are rendered in snapshot order regardless of completion order:
  // we buffer completed results and flush as many consecutive ones as possible
  // from the front each time any result arrives.

  const CONCURRENCY = 5;
  const total       = snapshots.length;
  const results     = new Array(total).fill(null);  // indexed buffer
  let nextToLaunch  = 0;   // next snapshot index to start
  let nextToRender  = 0;   // next snapshot index to render
  let inFlight      = 0;
  let doneCount     = 0;

  function buildRow(i, row) {
    const snap    = snapshots[i];
    const isFirst = (i === 0);
    row.snapshot  = snap;

    // For change detection, look back through already-rendered rows
    let prevAnalysis = null;
    for (let j = i - 1; j >= 0; j--) {
      if (results[j] && results[j].analysis && !results[j].error) {
        prevAnalysis = results[j].analysis;
        break;
      }
    }

    if (isFirst && !row.error) {
      row.change = 'BASELINE';
    } else {
      row.change = row.error ? 'error' : detectChange(prevAnalysis, row.analysis);
    }
    return row;
  }

  function flushRendered() {
    // Render as many consecutive completed rows as possible from nextToRender
    while (nextToRender < total && results[nextToRender] !== null) {
      const row = results[nextToRender];
      allRows.push(row);
      appendTimelineRow(row, nextToRender === 0, nextToRender === 0);
      nextToRender++;
    }
  }

  async function launchOne(i) {
    if (stopped) { inFlight--; doneCount++; flushRendered(); return; }
    const snap = snapshots[i];
    setProgress(doneCount, total,
      `[${doneCount}/${total} done · ${inFlight} in flight] ${snap.label}`);

    try {
      const resp = await fetch('/run-search-snap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baseUrl, networkId, snapshotId: snap.id,
          srcIp, dstIp, intent, maxCandidates: maxCand, maxResults,
          ipProto: ipProto ? parseInt(ipProto) : null,
          dstPort: dstPort ? parseInt(dstPort) : null,
          maxSeconds: maxSec, normalizePeers: normPeers
        })
      });
      const row = await resp.json();
      results[i] = buildRow(i, row);
    } catch(e) {
      results[i] = buildRow(i, { error: String(e), elapsed_ms: 0, analysis: null,
                                  api_url: '', app_search: '', app_url: '', raw_body: null });
    }

    inFlight--;
    doneCount++;
    setProgress(doneCount, total,
      `[${doneCount}/${total} done · ${inFlight} in flight]`);
    flushRendered();

    // Start the next one if any remain
    if (nextToLaunch < total && !stopped) {
      inFlight++;
      const next = nextToLaunch++;
      launchOne(next);
    }
  }

  // Seed the pool
  await new Promise(r => setTimeout(r, 0)); // yield before starting
  while (nextToLaunch < total && inFlight < CONCURRENCY) {
    inFlight++;
    const i = nextToLaunch++;
    launchOne(i);
  }

  // Wait for all in-flight requests to complete
  await new Promise(resolve => {
    const check = setInterval(() => {
      if (doneCount >= total) { clearInterval(check); resolve(); }
    }, 100);
  });

  setProgress(snapshots.length, snapshots.length,
    stopped ? 'Stopped.' : `✓ Complete — ${allRows.length} snapshots audited`);
  document.getElementById('run-btn').disabled    = false;
  document.getElementById('stop-btn').disabled   = true;
  document.getElementById('export-btn').disabled = allRows.length === 0;
  buildSummary();
}

function stopAudit() {
  stopped = true;
}

function setProgress(done, total, label) {
  document.getElementById('progress-bar').style.width  = (total > 0 ? Math.round(done/total*100) : 0) + '%';
  document.getElementById('progress-label').textContent = label;
}

// ── Client-side change detection (mirrors Python logic) ───────────────────────
const FUZZY_THRESHOLD = 0.6;

function levenshteinRatio(a, b) {
  a = a.toLowerCase(); b = b.toLowerCase();
  if (a === b) return 1.0;
  const la = a.length, lb = b.length;
  if (!la || !lb) return 0.0;
  let prev = Array.from({length: lb + 1}, (_, i) => i);
  for (let i = 1; i <= la; i++) {
    const curr = [i];
    for (let j = 1; j <= lb; j++) {
      curr.push(Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i-1] !== b[j-1] ? 1 : 0)
      ));
    }
    prev = curr;
  }
  return 1.0 - prev[lb] / Math.max(la, lb);
}

function diffHopSets(prevSet, currSet) {
  const ps = new Set(prevSet || []);
  const cs = new Set(currSet || []);
  const added   = [...cs].filter(x => !ps.has(x)).sort();
  const removed = [...ps].filter(x => !cs.has(x)).sort();
  if (!added.length || !removed.length) {
    return { added, removed, similar: [], replaced: [], netAdded: added, netRemoved: removed };
  }
  const scores = [];
  for (const r of removed) for (const a of added) {
    const ratio = levenshteinRatio(r, a);
    if (ratio >= FUZZY_THRESHOLD) scores.push({ ratio, r, a });
  }
  scores.sort((x, y) => y.ratio - x.ratio);
  const matchedR = new Set(), matchedA = new Set();
  const similar = [], replaced = [];
  for (const { ratio, r, a } of scores) {
    if (!matchedR.has(r) && !matchedA.has(a)) {
      similar.push({ removed: r, added: a, ratio: Math.round(ratio * 100) / 100 });
      matchedR.add(r); matchedA.add(a);
    }
  }
  const unmR = removed.filter(r => !matchedR.has(r));
  const unmA = added.filter(a => !matchedA.has(a));
  for (let i = 0; i < Math.max(unmR.length, unmA.length); i++) {
    replaced.push({ removed: unmR[i] || null, added: unmA[i] || null });
  }
  return {
    added, removed, similar, replaced,
    netAdded:   added.filter(a => !matchedA.has(a)),
    netRemoved: removed.filter(r => !matchedR.has(r)),
  };
}

function detectChange(prev, curr) {
  if (!prev) return 'BASELINE';
  if (!curr)  return 'error';
  const pf = new Set(prev.fw_fingerprint || []);
  const cf = new Set(curr.fw_fingerprint || []);
  const fwEq = pf.size === cf.size && [...pf].every(v => cf.has(v));
  if (!fwEq) {
    if (pf.size === 0 && cf.size > 0) return 'FW_APPEARED';
    if (pf.size > 0 && cf.size === 0) return 'FW_DISAPPEARED';
    return 'FW_SET_CHANGED';
  }
  const ph = new Set(prev.hop_device_set || []);
  const ch = new Set(curr.hop_device_set || []);
  const hopEq = ph.size === ch.size && [...ph].every(v => ch.has(v));
  if (!hopEq && ph.size > 0 && ch.size > 0) {
    const d = diffHopSets([...ph], [...ch]);
    if (d.replaced.length || d.netAdded.length || d.netRemoved.length)
      return 'HOP_SET_CHANGED';
    return 'HOP_SET_SIMILAR';
  }
  return prev.total_paths !== curr.total_paths ? 'PATH_COUNT_ONLY' : 'NO_CHANGE';
}

// ── Timeline rendering ────────────────────────────────────────────────────────
const CHANGE_META = {
  NO_CHANGE:        { gutterClass:'no-change',       badge:'<span class="badge badge-muted">— no change</span>' },
  FW_SET_CHANGED:   { gutterClass:'fw-set-changed',  badge:'<span class="badge badge-err">⚠ FW set changed</span>' },
  FW_APPEARED:      { gutterClass:'fw-appeared',     badge:'<span class="badge badge-info">↑ FW appeared</span>' },
  FW_DISAPPEARED:   { gutterClass:'fw-disappeared',  badge:'<span class="badge badge-err">↓ FW disappeared</span>' },
  HOP_SET_CHANGED:  { gutterClass:'hop-set-changed', badge:'<span class="badge badge-warn">⚠ path hops changed</span>' },
  HOP_SET_SIMILAR:  { gutterClass:'hop-set-similar', badge:'<span class="badge badge-peer">~ peer swap</span>' },
  PATH_COUNT_ONLY:  { gutterClass:'path-count-only', badge:'<span class="badge badge-muted">~ path count only</span>' },
  BASELINE:         { gutterClass:'baseline',         badge:'<span class="badge badge-accent2">● baseline</span>' },
  error:            { gutterClass:'error',             badge:'<span class="badge badge-warn">⚠ error</span>' },
  NO_RESULTS:       { gutterClass:'no-results',        badge:'<span class="badge badge-muted">— no results</span>' },
};

function appendTimelineRow(row, isFirst, isLast) {
  const tl       = document.getElementById('timeline');
  const snap     = row.snapshot;
  const analysis = row.analysis || {};
  const change   = row.change || 'error';
  const meta     = CHANGE_META[change] || CHANGE_META['error'];
  const rowId    = `row-${snap.id}`;

  // FW device tags + hop diff — compare to the nearest previous non-error row
  let prevFp = new Set();
  let prevAnalysis = null;
  for (let j = allRows.length - 2; j >= 0; j--) {
    if (allRows[j].analysis && !allRows[j].error) {
      prevAnalysis = allRows[j].analysis;
      prevFp = new Set(prevAnalysis.fw_fingerprint || []);
      break;
    }
  }
  const currFp = new Set(analysis.fw_fingerprint || []);

  let fwHtml = '';
  if (currFp.size > 0) {
    fwHtml = '<div class="tl-fw">';
    currFp.forEach(name => {
      const isNew = prevFp.size > 0 && !prevFp.has(name);
      fwHtml += `<span class="fw-tag${isNew?' new':''}">${esc(name)}</span>`;
    });
    prevFp.forEach(name => {
      if (!currFp.has(name))
        fwHtml += `<span class="fw-tag removed">${esc(name)}</span>`;
    });
    fwHtml += '</div>';
  } else if (!row.error) {
    fwHtml = '<div class="tl-fw"><span style="font-size:0.68rem;color:var(--muted)">no firewall hops found</span></div>';
  }

  // Change note
  let changeNote = '';
  if (change === 'FW_SET_CHANGED')
    changeNote = `<div class="tl-change-note change-fw-set">⚠ Firewall set differs from previous snapshot</div>`;
  else if (change === 'FW_APPEARED')
    changeNote = `<div class="tl-change-note change-appeared">↑ Firewall hops newly visible in this snapshot</div>`;
  else if (change === 'FW_DISAPPEARED')
    changeNote = `<div class="tl-change-note change-gone">↓ Firewall hops missing — were visible in previous snapshot</div>`;
  else if (change === 'HOP_SET_CHANGED' || change === 'HOP_SET_SIMILAR') {
    const prevHops = new Set((prevAnalysis ? prevAnalysis.hop_device_set : null) || []);
    const currHops = new Set(analysis.hop_device_set || []);
    const d = diffHopSets([...prevHops], [...currHops]);
    const noteCls = change === 'HOP_SET_SIMILAR' ? 'change-hop-similar' : 'change-hop-changed';
    const notePrefix = change === 'HOP_SET_SIMILAR'
      ? '~ Path hops changed (likely peer swap)'
      : '⚠ Path hops changed';
    let parts = [];
    d.similar.forEach(s => {
      parts.push(`<span class="hop-change-peer">${esc(s.removed)} → ${esc(s.added)}</span>`);
    });
    d.replaced.forEach(r => {
      if (r.removed && r.added)
        parts.push(`<span class="hop-change-replace">${esc(r.removed)} → ${esc(r.added)}</span>`);
      else if (r.removed)
        parts.push(`<span class="hop-change-remove">− ${esc(r.removed)}</span>`);
      else if (r.added)
        parts.push(`<span class="hop-change-add">+ ${esc(r.added)}</span>`);
    });
    changeNote = `<div class="tl-change-note ${noteCls}">${notePrefix}${parts.length ? ': ' + parts.join(', ') : ''}</div>`;
  }
  else if (change === 'PATH_COUNT_ONLY')
    changeNote = `<div class="tl-change-note change-count">Path count changed (${analysis.total_paths||0} paths) — same device set, likely ECMP variation</div>`;
  else if (change === 'BASELINE')
    changeNote = `<div class="tl-change-note change-baseline">Oldest snapshot in window — used as baseline for comparison</div>`;

  // Meta line
  const elapsed   = row.elapsed_ms < 1000 ? `${row.elapsed_ms}ms` : `${(row.elapsed_ms/1000).toFixed(1)}s`;
  const hitsBound = analysis.total_hits_type === 'LOWER_BOUND' ? '+' : '';
  const pathStr   = analysis.total_paths !== undefined ? `${analysis.total_paths}${hitsBound} total hits` : '';
  const hopStr    = analysis.max_hops ? (analysis.min_hops === analysis.max_hops ? `${analysis.max_hops} hops` : `${analysis.min_hops}–${analysis.max_hops} hops`) : '';
  const fwPathStr = analysis.paths_with_fw ? `${analysis.paths_with_fw} w/ FW` : '';
  // analysis.timed_out = API returned partial results with timedOut:true (still useful)
  // row.error with no analysis = socket-level timeout, no results at all
  const apiTimedOut    = analysis.timed_out && !row.error;
  const socketTimedOut = row.error && row.error.toLowerCase().includes('timed out');

  const timedOutBadge = apiTimedOut
    ? `<span class="badge badge-warn" style="font-size:0.6rem">timedOut: true</span>`
    : socketTimedOut
      ? `<span class="badge badge-err" style="font-size:0.6rem">socket timeout</span>`
      : '';

  // Two distinct timeout notes
  const timeoutNote = apiTimedOut
    ? `<div style="font-size:0.68rem;color:var(--warn);margin-top:4px">
        API response included <code>timedOut: true</code>. Results shown are what was returned.
       </div>`
    : socketTimedOut
      ? `<div style="font-size:0.68rem;color:var(--error);margin-top:4px">
          Socket timeout — no response received within maxSeconds + 120s. The Forward API may still be processing.
          Use the API URL copy button to test this snapshot directly.
         </div>`
      : '';

  // Expand button ID
  const detailId = `detail-${snap.id}`;

  const div = document.createElement('div');
  div.className = 'tl-row';
  // Store copy values on the container — avoids inline onclick escaping issues
  div.dataset.appSearch = row.app_search || '';
  div.dataset.appUrl    = row.app_url    || '';
  div.dataset.apiUrl    = row.api_url    || '';
  div.dataset.rawJson   = row.raw_body ? JSON.stringify(row.raw_body, null, 2) : '';
  div.innerHTML = `
    <div class="tl-gutter ${meta.gutterClass}"></div>
    <div class="tl-body">
      <div class="tl-header">
        <span class="tl-date">${esc(snap.label)}</span>
        ${meta.badge}
        ${timedOutBadge}
        <span class="tl-snap-id">ID: ${esc(snap.id)}</span>
        <button class="tl-expand-btn" onclick="toggleDetail('${detailId}', this)">▶ detail</button>
      </div>
      ${row.error ? `<div style="font-size:0.7rem;color:var(--error);margin-top:4px">Error: ${esc(row.error)}</div>` : ''}
      ${timeoutNote}
      ${!row.error ? fwHtml : ''}
      ${changeNote}
      <div class="tl-meta">
        ${pathStr ? `<span>${pathStr}</span>` : ''}
        ${hopStr  ? `<span>${hopStr}</span>`  : ''}
        ${fwPathStr ? `<span>${fwPathStr}</span>` : ''}
        <span>${elapsed}</span>
        ${row.app_search ? `<button class="copy-sm" style="margin-left:4px" data-copy="app_search" title="Copy app search string">⎘ Search</button>` : ''}
        ${row.app_url    ? `<button class="copy-sm" data-copy="app_url" title="Copy app URL">⎘ App URL</button>` : ''}
        ${row.api_url    ? `<button class="copy-sm" data-copy="api_url" title="Copy API URL">⎘ API URL</button>` : ''}
      </div>

      <!-- Expandable detail panel — full URLs + JSON -->
      <div class="tl-detail" id="${detailId}">
        <div class="detail-section">
          <div class="detail-label">APP SEARCH STRING</div>
          <div class="detail-copy-row">
            <div class="detail-box">${esc(row.app_search || '—')}</div>
            <button class="copy-sm" data-copy="app_search">⎘ Copy</button>
          </div>
        </div>
        <div class="detail-section">
          <div class="detail-label">APP URL</div>
          <div class="detail-copy-row">
            <div class="detail-box">${esc(row.app_url || '—')}</div>
            <button class="copy-sm" data-copy="app_url">⎘ Copy</button>
          </div>
        </div>
        <div class="detail-section">
          <div class="detail-label">API URL</div>
          <div class="detail-copy-row">
            <div class="detail-box">${esc(row.api_url || '—')}</div>
            <button class="copy-sm" data-copy="api_url">⎘ Copy</button>
          </div>
        </div>
        ${row.raw_body ? `
        <div class="detail-section">
          <div class="detail-label" style="display:flex;align-items:center;gap:8px">
            API RESPONSE
            <button class="copy-sm" data-copy="raw_json">⎘ Copy JSON</button>
          </div>
          <div class="json-scroll">${syntaxHL(row.raw_body)}</div>
        </div>` : ''}
      </div>
    </div>`;
  tl.appendChild(div);
}

function toggleDetail(id, btn) {
  const el = document.getElementById(id);
  const open = el.classList.toggle('open');
  btn.textContent = open ? '▼ detail' : '▶ detail';
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 2000);
  });
}

// Delegated handler for all data-copy buttons — reads value from nearest .tl-row
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  const key    = btn.dataset.copy;
  const tlRow  = btn.closest('.tl-row');
  if (!tlRow) return;
  const keyMap = {
    app_search: tlRow.dataset.appSearch,
    app_url:    tlRow.dataset.appUrl,
    api_url:    tlRow.dataset.apiUrl,
    raw_json:   tlRow.dataset.rawJson,
  };
  const text = keyMap[key] || '';
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 2000);
  });
});

function syntaxHL(obj) {
  let s = JSON.stringify(obj, null, 2);
  s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return s.replace(/("(\u[a-zA-Z0-9]{4}|\[^u]|[^\"])*"(\s*:)?|(true|false|null)|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, m => {
    if (/^"/.test(m)) return /:$/.test(m) ? `<span class="j-key">${m}</span>` : `<span class="j-str">${m}</span>`;
    if (/true|false/.test(m)) return `<span class="j-bool">${m}</span>`;
    if (/null/.test(m)) return `<span class="j-null">${m}</span>`;
    return `<span class="j-num">${m}</span>`;
  });
}

// ── Summary bar ───────────────────────────────────────────────────────────────
function buildSummary() {
  const total   = allRows.length;
  const withFw  = allRows.filter(r => !r.error && r.analysis && r.analysis.has_fw).length;
  const noFw    = allRows.filter(r => !r.error && r.analysis && !r.analysis.has_fw).length;
  const changes = allRows.filter(r => ['FW_SET_CHANGED','FW_APPEARED','FW_DISAPPEARED','HOP_SET_CHANGED'].includes(r.change)).length;
  const ecmp    = allRows.filter(r => r.change === 'PATH_COUNT_ONLY').length;
  const errors  = allRows.filter(r => r.error || (r.analysis?.timed_out && !r.analysis?.total_paths)).length;

  document.getElementById('sum-total').textContent   = total;
  document.getElementById('sum-fw').textContent      = withFw;
  document.getElementById('sum-no-fw').textContent   = noFw;
  document.getElementById('sum-changes').textContent = changes;
  document.getElementById('sum-ecmp').textContent    = ecmp;
  document.getElementById('sum-err').textContent     = errors;
  document.getElementById('summary-bar').style.display = 'block';
}

// ── CSV export ────────────────────────────────────────────────────────────────
function exportCsv() {
  const hdrs = [
    'snapshot_id',
    'processed_at',
    'change',
    'fw_devices',
    'total_hits',
    'total_hits_type',
    'paths_with_fw',
    'hops_min',
    'hops_max',
    'timed_out',
    'elapsed_ms',
    'error',
    'api_url'
  ];
  const rows = [hdrs.join(',')];
  allRows.forEach(r => {
    const a = r.analysis || {};
    rows.push([
      csv(r.snapshot.id),
      csv(r.snapshot.ts),
      r.change || '',
      csv((a.fw_fingerprint || []).join('; ')),
      a.total_paths   ?? '',
      a.total_hits_type || '',
      a.paths_with_fw ?? '',
      a.min_hops      ?? '',
      a.max_hops      ?? '',
      a.timed_out ? 'yes' : 'no',
      r.elapsed_ms    ?? '',
      csv(r.error     || ''),
      csv(r.api_url   || '')
    ].join(','));
  });
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `path_history_${Date.now()}.csv`;
  a.click();
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
        elif self.path == '/config':
            body = json.dumps(read_config()).encode('utf-8')
            self._respond(200, 'application/json', body)
        else:
            self._respond(200, 'text/html; charset=utf-8', HTML.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw    = self.rfile.read(length)

        if self.path == '/config':
            try:
                data = json.loads(raw)
                write_config(data)
                self._respond(200, 'application/json', b'{"ok":true}')
            except Exception:
                self._respond(400, 'application/json', b'{"ok":false}')

        elif self.path == '/list-snapshots':
            try:
                req      = json.loads(raw)
                base_url = req['baseUrl']
                net_id   = req['networkId']
                days     = int(req.get('daysBack', 30))
                snaps, err = list_processed_snapshots(base_url, net_id, days)
                if err:
                    result = {'error': err, 'snapshots': []}
                else:
                    result = {'snapshots': snaps}
                self._respond(200, 'application/json', json.dumps(result).encode('utf-8'))
            except Exception as e:
                self._respond(200, 'application/json',
                    json.dumps({'error': str(e), 'snapshots': []}).encode('utf-8'))

        elif self.path == '/run-search-snap':
            try:
                req           = json.loads(raw)
                base_url      = req['baseUrl']
                net_id        = req['networkId']
                snap_id       = req['snapshotId']
                norm_peers    = req.get('normalizePeers', False)
                src_ip        = req['srcIp']
                dst_ip        = req['dstIp']
                intent        = req.get('intent', 'PREFER_DELIVERED')
                max_cand      = req.get('maxCandidates', 5000)
                max_results   = req.get('maxResults', 1)
                ip_proto      = req.get('ipProto')
                dst_port      = req.get('dstPort')
                max_sec       = req.get('maxSeconds', 30)

                api_url, app_search, app_url = build_urls(
                    base_url, net_id, snap_id, src_ip, dst_ip,
                    intent, max_cand, max_results, ip_proto, dst_port, max_sec
                )

                status, body, elapsed_ms, err = run_path_search(
                    base_url, net_id, snap_id, src_ip, dst_ip,
                    intent, max_cand, max_results, ip_proto, dst_port, max_sec
                )

                # Retry once on socket-level errors (timeout, connection reset, etc.)
                # These are transient — the API runs fine when called individually.
                if err and body is None:
                    time.sleep(3)
                    status2, body2, elapsed_ms2, err2 = run_path_search(
                        base_url, net_id, snap_id, src_ip, dst_ip,
                        intent, max_cand, max_results, ip_proto, dst_port, max_sec
                    )
                    if body2 is not None:
                        status, body, elapsed_ms, err = status2, body2, elapsed_ms + elapsed_ms2, err2
                    else:
                        err = f"{err} (retried: {err2})"

                if err and body is None:
                    result = {
                        'error': err, 'elapsed_ms': elapsed_ms, 'analysis': None,
                        'api_url': api_url, 'app_search': app_search, 'app_url': app_url,
                        'raw_body': None
                    }
                else:
                    analysis = analyze_snapshot_result(body, norm_peers)
                    result   = {
                        'status':     status,
                        'elapsed_ms': elapsed_ms,
                        'analysis':   analysis,
                        'error':      err if status and status >= 400 else None,
                        'api_url':    api_url,
                        'app_search': app_search,
                        'app_url':    app_url,
                        'raw_body':   body,
                    }
                self._respond(200, 'application/json', json.dumps(result).encode('utf-8'))
            except Exception as e:
                self._respond(200, 'application/json',
                    json.dumps({'error': str(e), 'elapsed_ms': 0, 'analysis': None,
                                'api_url': '', 'app_search': '', 'app_url': '', 'raw_body': None}).encode('utf-8'))

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
    print('\n  ⬡  Forward Networks — Path Search History Tool')
    print('  ' + '─' * 50)
    base_url = os.environ.get('FWD_BASE_URL', 'https://fwd.app')
    collect_credentials(base_url)

    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)

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