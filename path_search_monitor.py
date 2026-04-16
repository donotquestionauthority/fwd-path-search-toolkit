#!/usr/bin/env python3
"""
Forward Networks Path Search Monitor
Watchlist-based regression monitor for resolved path search issues.
Port 8769
"""

import base64
import importlib.util
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
import http.server
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

PORT         = 8769
MONITOR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_search_monitor.json")
FIREWALL_TYPES = {"FIREWALL", "AWS_NETWORK_FIREWALL", "AZURE_FIREWALL"}

CREDENTIALS  = {}
NETWORKS_DATA = []
BASE_URL     = "https://fwd.app"
JIRA_BASE_URL = ""
EVIDENCE_DIR  = ""


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def _load_discovery():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_discovery.py")
    spec = importlib.util.spec_from_file_location("fwd_discovery", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod



def _prompt_for_credentials():
    """Prompt operator for network ID and credentials at runtime.
    Called when no FWD_CREDS_* environment variables are found.
    Credentials are held in memory only — never written to disk.
    """
    import getpass
    print("  No FWD_CREDS_* environment variables found.")
    print("  Enter credentials manually (held in memory for this session only).\n")
    while True:
        net_id = input("  Network ID (leave blank to finish): ").strip()
        if not net_id:
            break
        access_key = input(f"  Access key for network {net_id}: ").strip()
        secret_key = getpass.getpass(f"  Secret key for network {net_id}: ")
        if access_key and secret_key:
            val   = f"{access_key}:{secret_key}"
            token = base64.b64encode(val.encode()).decode()
            CREDENTIALS[net_id] = f"Basic {token}"
            print(f"  ✓  Network {net_id} credential stored.\n")
        else:
            print("  ⚠  Both access key and secret key are required. Try again.\n")
    if not CREDENTIALS:
        print("  ⚠  No credentials entered. Exiting.\n")
        sys.exit(1)


def collect_credentials(base_url):
    global NETWORKS_DATA, BASE_URL, JIRA_BASE_URL, EVIDENCE_DIR
    BASE_URL      = base_url
    JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    EVIDENCE_DIR  = os.environ.get("EVIDENCE_DIR", "").strip()

    prefix = "FWD_CREDS_"
    found  = 0
    for k, v in os.environ.items():
        if k.startswith(prefix):
            net_id = k[len(prefix):]
            token  = base64.b64encode(v.encode()).decode()
            CREDENTIALS[net_id] = f"Basic {token}"
            found += 1
    if found == 0:
        _prompt_for_credentials()
    print(f"  ✓  {found} network credential(s) loaded.")
    if JIRA_BASE_URL:
        print(f"  ✓  Jira base URL: {JIRA_BASE_URL}")
    else:
        print("  ⚠  JIRA_BASE_URL not set — Jira IDs will not be hyperlinked.")
    if EVIDENCE_DIR:
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        print(f"  ✓  Evidence directory: {EVIDENCE_DIR}")
    else:
        print("  ⚠  EVIDENCE_DIR not set — archived evidence will save to working directory.")
    print("  Discovering networks and snapshots...\n")
    try:
        disc = _load_discovery()
        NETWORKS_DATA = disc.discover_all(base_url, CREDENTIALS)
        print()
    except Exception as e:
        print(f"  ⚠  Discovery failed: {e}\n")
        NETWORKS_DATA = [{"id": nid, "name": nid, "snapshots": []} for nid in CREDENTIALS]


# ─────────────────────────────────────────────────────────────────────────────
# Config persistence
# ─────────────────────────────────────────────────────────────────────────────

def read_monitor_data():
    if not os.path.exists(MONITOR_FILE):
        return {"entries": []}
    try:
        with open(MONITOR_FILE) as f:
            data = json.load(f)
        if "entries" not in data:
            data["entries"] = []
        return data
    except Exception:
        return {"entries": []}


def write_monitor_data(data):
    with open(MONITOR_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Path search
# ─────────────────────────────────────────────────────────────────────────────

def run_path_search(network_id, snapshot_id, src_ip, dst_ip,
                    intent=None, ip_proto=None, dst_port=None,
                    max_candidates=None, max_results=1, max_seconds=30):
    params = {
        "srcIp":      src_ip,
        "dstIp":      dst_ip,
        "maxResults": str(max_results),
        "maxSeconds": str(max_seconds),
        "snapshotId": snapshot_id,
    }
    if max_candidates:  params["maxCandidates"] = str(max_candidates)
    if intent:          params["intent"]         = intent
    if ip_proto:        params["ipProto"]        = str(ip_proto)
    if dst_port:        params["dstPort"]        = str(dst_port)

    if network_id not in CREDENTIALS:
        return None, None, 0, f"No credentials for network {network_id}"

    qs  = urllib.parse.urlencode(params)
    url = f"{BASE_URL.rstrip('/')}/api/networks/{network_id}/paths?{qs}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Accept", "application/json")

    t0 = time.time()
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=max_seconds + 120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body, round((time.time() - t0) * 1000), None
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            elapsed = round((time.time() - t0) * 1000)
            try:    body = json.loads(raw)
            except: body = {"_raw": raw}
            return e.code, body, elapsed, f"HTTP {e.code}"
        except Exception as ex:
            if attempt == 0:
                time.sleep(3)
                continue
            return None, None, round((time.time() - t0) * 1000), str(ex)
    return None, None, 0, "Unknown error"


def analyze_path_result(body):
    """Extract hop device set, FW fingerprint, path count from a path search body.

    Unions hop sets and FW sets across ALL returned paths so that multi-path
    results give a more complete picture of what devices are involved.
    """
    if not body:
        return {"total_paths": 0, "hop_device_set": [], "fw_fingerprint": [], "timed_out": False}

    paths     = body.get("paths") or []
    timed_out = bool(body.get("timedOut"))

    hop_device_set = []
    fw_fingerprint = []
    for path in paths:
        for hop in (path.get("hops") or []):
            name  = hop.get("deviceName") or hop.get("name") or ""
            dtype = (hop.get("deviceType") or "").upper()
            if name and name not in hop_device_set:
                hop_device_set.append(name)
            if dtype in FIREWALL_TYPES and name not in fw_fingerprint:
                fw_fingerprint.append(name)

    total_paths = 0
    info = body.get("info") or {}
    th   = info.get("totalHits") or {}
    if isinstance(th, dict):
        total_paths = th.get("value", len(paths))
    elif isinstance(th, int):
        total_paths = th
    else:
        total_paths = len(paths)

    return {
        "total_paths":    total_paths,
        "hop_device_set": hop_device_set,
        "fw_fingerprint": fw_fingerprint,
        "timed_out":      timed_out,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hop-set comparison (ported from path_search_history.py)
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein_ratio(a, b):
    a, b = a.lower(), b.lower()
    if a == b: return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0: return 0.0
    prev_row = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr_row = [i]
        for j, cb in enumerate(b, 1):
            curr_row.append(min(
                prev_row[j] + 1,
                curr_row[j - 1] + 1,
                prev_row[j - 1] + (ca != cb),
            ))
        prev_row = curr_row
    return 1.0 - prev_row[lb] / max(la, lb)


FUZZY_THRESHOLD = 0.6


def classify_change(baseline, current):
    """
    Compare current result against the baseline (fixed) snapshot result.
    Returns (classification, detail_dict)

    Classifications:
      NO_CHANGE        — identical hop set, FW set, path count
      PATH_ZERO        — path count dropped to zero
      TIMED_OUT        — timedOut appeared in result
      FW_DISAPPEARED   — firewalls present in baseline, gone now
      FW_APPEARED      — no firewalls in baseline, now there are
      FW_SET_CHANGED   — firewall set changed
      HOP_SET_CHANGED  — meaningful hop-set change
      HOP_SET_SIMILAR  — hop-set changed but looks like peer swaps
      PATH_COUNT_ONLY  — same hops, different count
    """
    if not current:
        return "ERROR", {}

    detail = {}

    # Zero paths
    if current["total_paths"] == 0:
        return "PATH_ZERO", {"baseline_count": baseline["total_paths"]}

    # TimedOut appeared
    if current["timed_out"] and not baseline.get("timed_out"):
        detail["timed_out"] = True

    # FW changes
    base_fw = set(baseline.get("fw_fingerprint") or [])
    curr_fw = set(current.get("fw_fingerprint") or [])
    if base_fw != curr_fw:
        detail["fw_added"]   = sorted(curr_fw - base_fw)
        detail["fw_removed"] = sorted(base_fw - curr_fw)
        if base_fw and not curr_fw:
            return "FW_DISAPPEARED", detail
        if not base_fw and curr_fw:
            return "FW_APPEARED", detail
        return "FW_SET_CHANGED", detail

    # Hop-set changes
    base_hops = set(baseline.get("hop_device_set") or [])
    curr_hops = set(current.get("hop_device_set") or [])
    if base_hops != curr_hops:
        added   = sorted(curr_hops - base_hops)
        removed = sorted(base_hops - curr_hops)
        # Fuzzy match
        scores = []
        for r in removed:
            for a in added:
                ratio = _levenshtein_ratio(r, a)
                if ratio >= FUZZY_THRESHOLD:
                    scores.append((ratio, r, a))
        scores.sort(reverse=True)
        matched_r, matched_a = set(), set()
        similar = []
        for ratio, r, a in scores:
            if r not in matched_r and a not in matched_a:
                similar.append((r, a, round(ratio, 2)))
                matched_r.add(r); matched_a.add(a)
        net_removed = [r for r in removed if r not in matched_r]
        net_added   = [a for a in added   if a not in matched_a]
        detail.update({"added": added, "removed": removed,
                       "similar": similar, "net_added": net_added, "net_removed": net_removed})
        if net_removed or net_added:
            return "HOP_SET_CHANGED", detail
        return "HOP_SET_SIMILAR", detail

    if current["total_paths"] != baseline["total_paths"]:
        detail["baseline_count"] = baseline["total_paths"]
        detail["current_count"]  = current["total_paths"]
        return "PATH_COUNT_ONLY", detail

    if detail.get("timed_out"):
        return "TIMED_OUT", detail

    return "NO_CHANGE", {}


# ─────────────────────────────────────────────────────────────────────────────
# Forward API helpers
# ─────────────────────────────────────────────────────────────────────────────

def api_patch(network_id, path, payload=None, params=None):
    """PATCH request helper. Returns (status, body_or_None, error_or_None)."""
    if network_id not in CREDENTIALS:
        return None, None, f"No credentials for network {network_id}"
    qs  = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{BASE_URL.rstrip('/')}{path}{qs}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else b""
    req  = urllib.request.Request(url, data=data, method="PATCH")
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            try:    body = json.loads(resp.read().decode("utf-8"))
            except: body = {}
            return resp.status, body, None
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}"
    except Exception as ex:
        return None, None, str(ex)


def favorite_snapshot(network_id, snapshot_id):
    return api_patch(network_id, f"/api/snapshots/{snapshot_id}", params={"action": "favorite"})


def set_snapshot_note(network_id, snapshot_id, note):
    return api_patch(network_id, f"/api/snapshots/{snapshot_id}", payload={"note": note})


def build_monitoring_note(case_id, jira_id):
    parts = []
    if case_id and case_id.strip():
        parts.append(f"case:{case_id.strip()}")
    if jira_id and jira_id.strip():
        parts.append(jira_id.strip())
    if parts:
        return "monitoring for " + " ".join(parts)
    return "monitoring for resolution"


# ─────────────────────────────────────────────────────────────────────────────
# Run logic
# ─────────────────────────────────────────────────────────────────────────────

def get_snapshots_after(network_id, baseline_snapshot_id):
    """Return list of PROCESSED snapshots after the baseline, oldest first."""
    if network_id not in CREDENTIALS:
        return []
    for net in NETWORKS_DATA:
        if net["id"] == network_id:
            snaps = [s for s in net.get("snapshots", [])
                     if s.get("state") == "PROCESSED"]
            # Sort oldest first by processedAt / createdAt
            def snap_ts(s):
                return s.get("createdAt") or s.get("processedAt") or ""
            snaps.sort(key=snap_ts)
            # Find baseline index and return everything after
            ids = [s["id"] for s in snaps]
            if baseline_snapshot_id in ids:
                idx = ids.index(baseline_snapshot_id)
                return snaps[idx + 1:]
            return snaps  # baseline not found, return all
    return []


def run_entry_check(entry):
    """
    Run a full regression check for one watchlist entry.
    Returns updated entry dict with run results.
    """
    network_id     = entry["networkId"]
    baseline_id    = entry["baselineSnapshotId"]
    src_ip         = entry["srcIp"]
    dst_ip         = entry["dstIp"]
    intent         = entry.get("intent")       or None
    ip_proto       = entry.get("ipProto")      or None
    dst_port       = entry.get("dstPort")      or None
    max_candidates = entry.get("maxCandidates") or None
    max_results    = int(entry.get("maxResults")  or 1)
    max_seconds    = int(entry.get("maxSeconds")  or 30)

    results = []

    # Run baseline first to get the reference result
    status, body, elapsed, err = run_path_search(
        network_id, baseline_id, src_ip, dst_ip,
        intent=intent, ip_proto=ip_proto, dst_port=dst_port,
        max_candidates=max_candidates, max_results=max_results, max_seconds=max_seconds
    )
    if err or not body:
        return {**entry,
                "lastRun": _now_iso(),
                "lastResult": "error",
                "lastError": err or "No response from baseline snapshot",
                "runResults": []}

    baseline_analysis = analyze_path_result(body)
    results.append({
        "snapshotId":    baseline_id,
        "snapshotLabel": _snap_label(network_id, baseline_id),
        "isBaseline":    True,
        "status":        status,
        "elapsed_ms":    elapsed,
        "analysis":      baseline_analysis,
        "classification": "BASELINE",
        "detail":        {},
        "body":          body,
    })

    # Run against all subsequent snapshots
    subsequent = get_snapshots_after(network_id, baseline_id)
    for snap in subsequent:
        snap_id = snap["id"]
        s, b, el, er = run_path_search(
            network_id, snap_id, src_ip, dst_ip,
            intent=intent, ip_proto=ip_proto, dst_port=dst_port,
            max_candidates=max_candidates, max_results=max_results, max_seconds=max_seconds
        )
        if er or not b:
            results.append({
                "snapshotId":    snap_id,
                "snapshotLabel": _snap_label(network_id, snap_id),
                "isBaseline":    False,
                "status":        s,
                "elapsed_ms":    el,
                "analysis":      None,
                "classification": "ERROR",
                "detail":        {"error": er or "No response"},
                "body":          None,
            })
            continue

        analysis = analyze_path_result(b)
        classification, detail = classify_change(baseline_analysis, analysis)
        results.append({
            "snapshotId":    snap_id,
            "snapshotLabel": _snap_label(network_id, snap_id),
            "isBaseline":    False,
            "status":        s,
            "elapsed_ms":    el,
            "analysis":      analysis,
            "classification": classification,
            "detail":        detail,
            "body":          b,
        })

    # Determine overall last result
    non_baseline = [r for r in results if not r["isBaseline"]]
    changed_results = [r for r in non_baseline
                       if r["classification"] not in ("NO_CHANGE", "PATH_COUNT_ONLY", "HOP_SET_SIMILAR")]
    if not non_baseline:
        overall = "no_subsequent"
    elif changed_results:
        overall = "changed"
    else:
        overall = "clean"

    # Count clean snapshots / days since baseline
    clean_count = sum(1 for r in non_baseline if r["classification"] == "NO_CHANGE")
    total_subsequent = len(non_baseline)

    return {**entry,
            "lastRun":        _now_iso(),
            "lastResult":     overall,
            "lastError":      None,
            "cleanCount":     clean_count,
            "totalSubsequent": total_subsequent,
            "runResults":     results}


def _snap_label(network_id, snapshot_id):
    for net in NETWORKS_DATA:
        if net["id"] == network_id:
            for s in net.get("snapshots", []):
                if s["id"] == snapshot_id:
                    return s.get("label") or snapshot_id[-8:]
    return snapshot_id[-8:]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Evidence export
# ─────────────────────────────────────────────────────────────────────────────

def export_evidence(entry):
    """Write a zip of all path search results and return the file path."""
    parts = []
    if entry.get("caseId"):  parts.append(re.sub(r"[^\w\-]", "_", entry["caseId"]))
    if entry.get("jiraId"):  parts.append(re.sub(r"[^\w\-]", "_", entry["jiraId"]))
    if not parts:            parts.append("untracked")
    date_str = datetime.now().strftime("%Y%m%d")
    filename = "_".join(parts) + f"_resolved_{date_str}.zip"

    dest_dir = EVIDENCE_DIR if EVIDENCE_DIR else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(dest_dir, exist_ok=True)
    zip_path = os.path.join(dest_dir, filename)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Summary JSON
        summary = {k: v for k, v in entry.items() if k != "runResults"}
        zf.writestr("summary.json", json.dumps(summary, indent=2))
        # One JSON file per snapshot result
        for r in (entry.get("runResults") or []):
            snap_label = re.sub(r"[^\w\-]", "_", r.get("snapshotLabel") or r["snapshotId"][-8:])
            name = f"{'BASELINE_' if r['isBaseline'] else ''}{snap_label}.json"
            zf.writestr(name, json.dumps(r, indent=2))

    return zip_path


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._html(HTML)

        elif path == "/api/networks":
            self._json([{"id": n["id"], "name": n["name"]} for n in NETWORKS_DATA])

        elif path == "/networks-data":
            self._json(NETWORKS_DATA)

        elif path == "/api/entries":
            self._json(read_monitor_data()["entries"])

        elif path == "/api/config":
            self._json({
                "jiraBaseUrl": JIRA_BASE_URL,
                "evidenceDir": EVIDENCE_DIR,
            })

        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}
        path   = self.path.split("?")[0]

        if path == "/api/entries":
            # Add new entry
            data = read_monitor_data()
            entry = {
                "id":                 _now_iso().replace(":", "-").replace(".", "-"),
                "caseId":             body.get("caseId") or None,
                "caseUrl":            body.get("caseUrl") or None,
                "jiraId":             body.get("jiraId") or None,
                "networkId":          body["networkId"],
                "baselineSnapshotId": body["baselineSnapshotId"],
                "srcIp":              body["srcIp"],
                "dstIp":              body["dstIp"],
                "intent":             body.get("intent") or None,
                "ipProto":            body.get("ipProto") or None,
                "dstPort":            body.get("dstPort") or None,
                "maxCandidates":      body.get("maxCandidates") or None,
                "maxResults":         int(body.get("maxResults") or 1),
                "maxSeconds":         int(body.get("maxSeconds") or 30),
                "notes":              body.get("notes") or "",
                "dateAdded":          _now_iso(),
                "status":             "active",
                "lastRun":            None,
                "lastResult":         "never",
                "lastError":          None,
                "cleanCount":         0,
                "totalSubsequent":    0,
                "runResults":         [],
            }
            # Favorite and annotate the baseline snapshot
            fav_status, _, fav_err = favorite_snapshot(entry["networkId"], entry["baselineSnapshotId"])
            note = build_monitoring_note(entry["caseId"], entry["jiraId"])
            note_status, _, note_err = set_snapshot_note(entry["networkId"], entry["baselineSnapshotId"], note)

            data["entries"].append(entry)
            write_monitor_data(data)
            self._json({
                "entry": entry,
                "favoriteStatus": fav_status,
                "favoriteError":  fav_err,
                "noteStatus":     note_status,
                "noteError":      note_err,
            })

        elif path == "/api/run-all":
            # Run checks for all active entries, streaming JSON progress
            data    = read_monitor_data()
            active  = [e for e in data["entries"] if e.get("status") == "active"]
            updated = []
            for entry in active:
                result = run_entry_check(entry)
                # Update in data
                for i, e in enumerate(data["entries"]):
                    if e["id"] == result["id"]:
                        data["entries"][i] = result
                        break
                updated.append(result)
            write_monitor_data(data)
            self._json({"updated": updated})

        elif path == "/api/run-one":
            entry_id = body.get("id")
            data     = read_monitor_data()
            entry    = next((e for e in data["entries"] if e["id"] == entry_id), None)
            if not entry:
                self._json({"error": "Entry not found"}, 404); return
            result = run_entry_check(entry)
            for i, e in enumerate(data["entries"]):
                if e["id"] == entry_id:
                    data["entries"][i] = result
                    break
            write_monitor_data(data)
            self._json(result)

        elif path == "/api/archive":
            entry_id = body.get("id")
            data     = read_monitor_data()
            zip_path = None
            for i, e in enumerate(data["entries"]):
                if e["id"] == entry_id:
                    try:
                        zip_path = export_evidence(e)
                    except Exception as ex:
                        zip_path = None
                        print(f"  ⚠  Evidence export failed: {ex}")
                    data["entries"][i]["status"]      = "archived"
                    data["entries"][i]["archivedAt"]  = _now_iso()
                    data["entries"][i]["evidencePath"] = zip_path
                    break
            write_monitor_data(data)
            self._json({"evidencePath": zip_path})

        elif path == "/api/delete":
            entry_id = body.get("id")
            data     = read_monitor_data()
            data["entries"] = [e for e in data["entries"] if e["id"] != entry_id]
            write_monitor_data(data)
            self._json({"ok": True})

        else:
            self.send_response(404); self.end_headers()


# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forward Networks · Path Search Monitor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --surface2: #1c2128;
    --border:   #30363d;
    --accent:   #00c8c8;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --success:  #3fb950;
    --error:    #f85149;
    --warn:     #d29922;
    --info:     #58a6ff;
    --radius:   6px;
    --font:     'JetBrains Mono', monospace;
  }
  body { background:var(--bg); color:var(--text); font-family:var(--font);
         font-size:0.78rem; min-height:100vh; display:flex; flex-direction:column; }

  /* ── Header ── */
  header { display:flex; align-items:baseline; gap:10px; padding:10px 18px 8px;
           border-bottom:1px solid var(--border); flex-shrink:0; }
  .logo  { color:var(--accent); font-size:1.3rem; font-weight:700; }
  .title { font-size:0.78rem; font-weight:700; letter-spacing:.1em; color:var(--accent); }
  .sub   { font-size:0.65rem; color:var(--muted); }
  .home-link { margin-left:auto; font-size:0.67rem; color:var(--muted);
               text-decoration:none; letter-spacing:.04em; }
  .home-link:hover { color:var(--accent); }
  .divider { height:2px; background:linear-gradient(90deg,var(--accent),transparent); }

  /* ── Layout ── */
  .layout { display:flex; flex:1; overflow:hidden; }
  .left-pane  { width:340px; flex-shrink:0; border-right:1px solid var(--border);
                display:flex; flex-direction:column; overflow:hidden; }
  .right-pane { flex:1; display:flex; flex-direction:column; overflow:hidden; }

  /* ── Left: action bar ── */
  .action-bar { padding:10px 12px; border-bottom:1px solid var(--border);
                display:flex; gap:8px; align-items:center; flex-shrink:0; }
  .btn { padding:5px 12px; border-radius:var(--radius); border:1px solid var(--border);
         background:var(--surface2); color:var(--text); font-family:var(--font);
         font-size:0.7rem; cursor:pointer; letter-spacing:.04em; }
  .btn:hover { border-color:var(--accent); color:var(--accent); }
  .btn-primary { background:var(--accent); color:#000; border-color:var(--accent);
                 font-weight:700; }
  .btn-primary:hover { background:#00e0e0; }
  .btn-sm { padding:3px 8px; font-size:0.65rem; }
  .btn-warn  { border-color:var(--warn);  color:var(--warn); }
  .btn-warn:hover  { background:var(--warn);  color:#000; }
  .btn-error { border-color:var(--error); color:var(--error); }
  .btn-error:hover { background:var(--error); color:#fff; }

  /* ── Entry list ── */
  .entry-list { flex:1; overflow-y:auto; }
  .entry-section-title { padding:6px 12px; font-size:0.6rem; letter-spacing:.1em;
                         color:var(--muted); border-bottom:1px solid var(--border);
                         background:var(--surface); cursor:pointer;
                         display:flex; align-items:center; gap:6px; }
  .entry-section-title:hover { color:var(--accent); }
  .entry-row { padding:10px 12px; border-bottom:1px solid var(--border);
               cursor:pointer; display:flex; flex-direction:column; gap:4px; }
  .entry-row:hover { background:var(--surface2); }
  .entry-row.active { background:var(--surface2); border-left:2px solid var(--accent); }
  .entry-row.archived { opacity:.55; }
  .entry-title { display:flex; align-items:center; gap:6px; }
  .entry-name  { font-weight:600; font-size:0.73rem; flex:1;
                 white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .entry-meta  { font-size:0.62rem; color:var(--muted); }
  .result-dot  { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
  .dot-clean   { background:var(--success); }
  .dot-changed { background:var(--error); }
  .dot-warn    { background:var(--warn); }
  .dot-never   { background:var(--muted); }
  .dot-error   { background:var(--error); animation:pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  /* ── Right: detail pane ── */
  .right-header { padding:10px 18px; border-bottom:1px solid var(--border);
                  display:flex; align-items:center; gap:10px; flex-shrink:0; }
  .right-title  { font-size:0.7rem; font-weight:700; letter-spacing:.1em; color:var(--accent); }
  .right-content { flex:1; overflow-y:auto; padding:16px 18px; }

  /* ── Add form ── */
  .form-panel { max-width:580px; }
  .form-row   { display:flex; flex-direction:column; gap:4px; margin-bottom:12px; }
  .form-row label { font-size:0.62rem; color:var(--muted); letter-spacing:.06em; }
  .form-row input, .form-row select, .form-row textarea {
    background:var(--surface2); border:1px solid var(--border);
    color:var(--text); padding:6px 8px; border-radius:var(--radius);
    font-family:var(--font); font-size:0.72rem; width:100%;
  }
  .form-row input:focus, .form-row select:focus, .form-row textarea:focus {
    outline:none; border-color:var(--accent);
  }
  .form-row textarea { resize:vertical; min-height:52px; }
  .form-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .form-actions { display:flex; gap:8px; margin-top:4px; }
  .form-msg { font-size:0.65rem; padding:6px 10px; border-radius:var(--radius);
              margin-top:8px; display:none; }
  .form-msg.ok  { background:#1a2f1a; color:var(--success); border:1px solid var(--success); display:block; }
  .form-msg.err { background:#2f1a1a; color:var(--error);   border:1px solid var(--error);   display:block; }

  /* ── Entry detail ── */
  .detail-header  { margin-bottom:14px; }
  .detail-ids     { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:6px; }
  .id-chip        { font-size:0.65rem; padding:2px 8px; border-radius:3px;
                    background:var(--surface2); border:1px solid var(--border); }
  .id-chip a      { color:var(--accent); text-decoration:none; }
  .id-chip a:hover{ text-decoration:underline; }
  .detail-params  { font-size:0.65rem; color:var(--muted); margin-bottom:10px;
                    font-family:var(--font); }
  .detail-actions { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }
  .clean-banner   { padding:10px 14px; border-radius:var(--radius); margin-bottom:14px;
                    font-size:0.72rem; border:1px solid; }
  .banner-clean   { background:#0d1f0d; border-color:var(--success); color:var(--success); }
  .banner-changed { background:#1f0d0d; border-color:var(--error);   color:var(--error); }
  .banner-never   { background:var(--surface2); border-color:var(--border); color:var(--muted); }
  .banner-running { background:var(--surface2); border-color:var(--accent); color:var(--accent); }

  /* ── Results table ── */
  .results-table { width:100%; border-collapse:collapse; font-size:0.68rem; }
  .results-table th { text-align:left; padding:5px 8px; color:var(--muted);
                      border-bottom:1px solid var(--border); font-weight:600;
                      letter-spacing:.06em; font-size:0.6rem; }
  .results-table td { padding:5px 8px; border-bottom:1px solid var(--border);
                      vertical-align:top; }
  .results-table tr:last-child td { border-bottom:none; }
  .results-table tr.baseline-row td { color:var(--muted); font-style:italic; }
  .cls-badge { display:inline-block; padding:1px 6px; border-radius:3px;
               font-size:0.6rem; font-weight:700; letter-spacing:.05em; }
  .cls-NO_CHANGE       { background:#0d1f0d; color:var(--success); }
  .cls-BASELINE        { background:var(--surface2); color:var(--muted); }
  .cls-HOP_SET_CHANGED { background:#2f1a0a; color:var(--warn); }
  .cls-HOP_SET_SIMILAR { background:#1f1a0a; color:var(--warn); }
  .cls-FW_DISAPPEARED  { background:#2f1a1a; color:var(--error); }
  .cls-FW_APPEARED     { background:#2f1a1a; color:var(--error); }
  .cls-FW_SET_CHANGED  { background:#2f1a1a; color:var(--error); }
  .cls-PATH_ZERO       { background:#2f1a1a; color:var(--error); }
  .cls-PATH_COUNT_ONLY { background:#1a1f2f; color:var(--info); }
  .cls-TIMED_OUT       { background:#1f1a0a; color:var(--warn); }
  .cls-ERROR           { background:#2f1a1a; color:var(--error); }
  .detail-row { font-size:0.62rem; color:var(--muted); margin-top:2px; }
  .spinner { display:inline-block; width:10px; height:10px; border:2px solid var(--border);
             border-top-color:var(--accent); border-radius:50%; animation:spin .6s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }

  /* ── Empty state ── */
  .empty-state { padding:40px 20px; text-align:center; color:var(--muted); }
  .empty-state .big { font-size:2rem; display:block; margin-bottom:8px; }

  /* ── Progress overlay ── */
  .run-progress { padding:8px 18px; background:var(--surface2);
                  border-bottom:1px solid var(--border); display:none;
                  align-items:center; gap:10px; font-size:0.65rem; color:var(--muted); }
  .prog-bar-wrap { flex:1; background:var(--border); border-radius:3px; height:4px; }
  .prog-bar      { height:4px; background:var(--accent); border-radius:3px;
                   transition:width .3s; width:0%; }
</style>
</head>
<body>

<div>
  <header>
    <span class="logo">⬡</span>
    <span class="title">PATH SEARCH MONITOR</span>
    <span class="sub">Regression Watchlist</span>
    <a href="http://localhost:8760" class="home-link" title="Back to launcher">⌂ Home</a>
  </header>
  <div class="divider"></div>
</div>

<div class="layout">

  <!-- ── Left: entry list ── -->
  <div class="left-pane">
    <div class="action-bar">
      <button class="btn btn-primary" onclick="showAddForm()">+ Add Entry</button>
      <button class="btn" id="run-all-btn" onclick="runAll()">▶ Run All</button>
    </div>
    <div class="entry-list" id="entry-list">
      <div class="empty-state"><span class="big">↑</span>No entries yet</div>
    </div>
  </div>

  <!-- ── Right: detail / add form ── -->
  <div class="right-pane">
    <div class="right-header">
      <span class="right-title" id="right-title">ADD ENTRY</span>
    </div>
    <div class="run-progress" id="run-progress">
      <span class="spinner"></span>
      <span id="prog-label">Running checks…</span>
      <div class="prog-bar-wrap"><div class="prog-bar" id="prog-bar"></div></div>
    </div>
    <div class="right-content" id="right-content">

      <!-- Add form (default view) -->
      <div id="add-form" class="form-panel">
        <div class="form-row">
          <label>NETWORK</label>
          <select id="f-network" onchange="onNetworkChange()" autocomplete="off"
                  data-form-type="other" data-lpignore="true">
            <option value="">— select network —</option>
          </select>
        </div>
        <div class="form-row">
          <label>BASELINE SNAPSHOT (the "fixed" snapshot)</label>
          <select id="f-snapshot" autocomplete="off" data-form-type="other" data-lpignore="true">
            <option value="">— select network first —</option>
          </select>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label>SOURCE IP</label>
            <input id="f-src" type="text" placeholder="10.0.0.1" autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>DESTINATION IP</label>
            <input id="f-dst" type="text" placeholder="10.0.0.2" autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>IP PROTO (optional)</label>
            <select id="f-proto" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="">— any —</option>
              <option value="1">1 · ICMP</option>
              <option value="6">6 · TCP</option>
              <option value="17">17 · UDP</option>
              <option value="47">47 · GRE</option>
              <option value="50">50 · ESP</option>
            </select>
          </div>
          <div class="form-row">
            <label>DST PORT (optional)</label>
            <input id="f-port" type="text" placeholder="443" autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>INTENT (optional)</label>
            <select id="f-intent" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="">— default —</option>
              <option value="PREFER_DELIVERED">PREFER_DELIVERED</option>
              <option value="PREFER_VIOLATIONS">PREFER_VIOLATIONS</option>
              <option value="VIOLATIONS_ONLY">VIOLATIONS_ONLY</option>
            </select>
          </div>
          <div class="form-row">
            <label>MAX CANDIDATES (optional, API default if blank)</label>
            <input id="f-maxcand" type="number" min="1" max="10000" placeholder="API default"
                   autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>MAX RESULTS (default 1, max = maxCandidates)</label>
            <input id="f-maxresults" type="number" min="1" value="1"
                   autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>MAX SECONDS (default 30, max 300)</label>
            <input id="f-maxsec" type="number" min="1" max="300" value="30"
                   autocomplete="off" data-lpignore="true">
          </div>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label>CASE ID (optional)</label>
            <input id="f-case-id" type="text" placeholder="CS-12345" autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>CASE URL (optional)</label>
            <input id="f-case-url" type="text" placeholder="https://..." autocomplete="off" data-lpignore="true">
          </div>
          <div class="form-row">
            <label>JIRA ID (optional)</label>
            <input id="f-jira" type="text" placeholder="FWD-1234" autocomplete="off" data-lpignore="true">
          </div>
        </div>
        <div class="form-row">
          <label>NOTES</label>
          <textarea id="f-notes" placeholder="Brief description of the issue…"></textarea>
        </div>
        <div class="form-actions">
          <button class="btn btn-primary" onclick="submitAdd()">Add to Watchlist</button>
          <button class="btn" onclick="cancelAdd()">Cancel</button>
        </div>
        <div class="form-msg" id="form-msg"></div>
      </div>

      <!-- Entry detail (shown when entry selected) -->
      <div id="entry-detail" style="display:none"></div>

    </div>
  </div>

</div>

<script>
let config             = {};
let discoveredNetworks = [];
let entries            = [];
let activeId           = null;
let archiveOpen        = false;

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  try {
    const r    = await fetch('/networks-data');
    const data = await r.json();
    discoveredNetworks = Array.isArray(data) ? data : [];
  } catch(e) { discoveredNetworks = []; }

  try {
    const r = await fetch('/api/config');
    config  = await r.json();
  } catch(e) {}

  try {
    const r = await fetch('/api/entries');
    entries = await r.json();
  } catch(e) { entries = []; }

  setTimeout(() => {
    renderNetworkDropdown();
    renderEntryList();
  }, 300);
}

function renderNetworkDropdown() {
  const sel = document.getElementById('f-network');
  sel.innerHTML = '<option value="">— select network —</option>';
  discoveredNetworks.forEach((n, i) => {
    const opt       = document.createElement('option');
    opt.value       = i;
    opt.textContent = n.name;
    sel.appendChild(opt);
  });
}

function onNetworkChange() {
  const idx = document.getElementById('f-network').value;
  const sel = document.getElementById('f-snapshot');
  sel.innerHTML = '<option value="">— select snapshot —</option>';
  if (idx === '') return;
  const net = discoveredNetworks[parseInt(idx)];
  (net.snapshots || []).forEach((s, i) => {
    const opt       = document.createElement('option');
    opt.value       = s.id;
    opt.textContent = (s.label || s.id) + (i === 0 ? ' (latest)' : '');
    sel.appendChild(opt);
  });
}

// ── Entry list ────────────────────────────────────────────────────────────────
function renderEntryList() {
  const el      = document.getElementById('entry-list');
  const active  = entries.filter(e => e.status === 'active');
  const archived = entries.filter(e => e.status === 'archived');

  if (!entries.length) {
    el.innerHTML = '<div class="empty-state"><span class="big">\u2191</span>No entries yet<br><span style="font-size:0.62rem">Click + Add Entry to get started</span></div>';
    return;
  }

  let html = '';

  active.forEach(e => {
    html += entryRow(e);
  });

  if (archived.length) {
    html += `<div class="entry-section-title" onclick="toggleArchive()">
      ${archiveOpen ? '\u25bc' : '\u25ba'} ARCHIVED (${archived.length})
    </div>`;
    if (archiveOpen) {
      archived.forEach(e => { html += entryRow(e); });
    }
  }

  el.innerHTML = html;
}

function entryRow(e) {
  const dotClass = {
    clean: 'dot-clean', changed: 'dot-changed', never: 'dot-never',
    error: 'dot-error', no_subsequent: 'dot-never'
  }[e.lastResult] || 'dot-never';

  const label = entryLabel(e);
  const meta  = e.lastRun
    ? `Last run: ${fmtDate(e.lastRun)} · ${e.cleanCount}/${e.totalSubsequent} clean`
    : 'Never run';

  return `<div class="entry-row${e.status === 'archived' ? ' archived' : ''}${e.id === activeId ? ' active' : ''}"
               id="row-${e.id}" onclick="selectEntry('${e.id}')">
    <div class="entry-title">
      <span class="result-dot ${dotClass}"></span>
      <span class="entry-name">${esc(label)}</span>
    </div>
    <div class="entry-meta">${esc(meta)}</div>
  </div>`;
}

function entryLabel(e) {
  const parts = [e.caseId, e.jiraId].filter(Boolean);
  if (parts.length) return parts.join(' / ');
  return `${e.srcIp} \u2192 ${e.dstIp}`;
}

function toggleArchive() {
  archiveOpen = !archiveOpen;
  renderEntryList();
}

// ── Add form ──────────────────────────────────────────────────────────────────
function showAddForm() {
  activeId = null;
  renderEntryList();
  document.getElementById('add-form').style.display = '';
  document.getElementById('entry-detail').style.display = 'none';
  document.getElementById('right-title').textContent = 'ADD ENTRY';
  document.getElementById('form-msg').className = 'form-msg';
}

function cancelAdd() {
  if (activeId) selectEntry(activeId);
  else showAddForm();
}

async function submitAdd() {
  const netIdx  = document.getElementById('f-network').value;
  const snapId  = document.getElementById('f-snapshot').value;
  const src     = document.getElementById('f-src').value.trim();
  const dst     = document.getElementById('f-dst').value.trim();
  const msg     = document.getElementById('form-msg');

  if (netIdx === '' || !snapId || !src || !dst) {
    msg.textContent = 'Network, snapshot, source IP, and destination IP are required.';
    msg.className   = 'form-msg err'; return;
  }

  const netId = discoveredNetworks[parseInt(netIdx)].id;

  msg.textContent = 'Adding entry and annotating snapshot…';
  msg.className   = 'form-msg ok';

  const payload = {
    networkId:          netId,
    baselineSnapshotId: snapId,
    srcIp:   src,
    dstIp:   dst,
    ipProto:       document.getElementById('f-proto').value  || null,
    dstPort:       document.getElementById('f-port').value.trim() || null,
    intent:        document.getElementById('f-intent').value || null,
    maxCandidates: document.getElementById('f-maxcand').value.trim()    || null,
    maxResults:    parseInt(document.getElementById('f-maxresults').value) || 1,
    maxSeconds:    parseInt(document.getElementById('f-maxsec').value)    || 30,
    caseId:  document.getElementById('f-case-id').value.trim()  || null,
    caseUrl: document.getElementById('f-case-url').value.trim() || null,
    jiraId:  document.getElementById('f-jira').value.trim()     || null,
    notes:   document.getElementById('f-notes').value.trim(),
  };

  try {
    const resp = await fetch('/api/entries', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    entries.push(data.entry);
    renderEntryList();

    let note = 'Entry added.';
    if (data.favoriteError) note += ` (favorite failed: ${data.favoriteError})`;
    if (data.noteError)     note += ` (note failed: ${data.noteError})`;
    msg.textContent = note;

    // Clear form
    ['f-src','f-dst','f-port','f-case-id','f-case-url','f-jira','f-notes','f-maxcand'].forEach(id => {
      document.getElementById(id).value = '';
    });
    ['f-proto','f-intent'].forEach(id => { document.getElementById(id).value = ''; });
    document.getElementById('f-maxresults').value = '1';
    document.getElementById('f-maxsec').value = '30';

    selectEntry(data.entry.id);
  } catch(e) {
    msg.textContent = 'Error: ' + e.message;
    msg.className   = 'form-msg err';
  }
}

// ── Entry detail ──────────────────────────────────────────────────────────────
function selectEntry(id) {
  activeId = id;
  renderEntryList();
  const entry = entries.find(e => e.id === id);
  if (!entry) return;
  document.getElementById('add-form').style.display = 'none';
  document.getElementById('entry-detail').style.display = '';
  document.getElementById('right-title').textContent = entryLabel(entry).toUpperCase();
  renderDetail(entry);
}

function renderDetail(entry) {
  const el = document.getElementById('entry-detail');

  // IDs / links
  let ids = '';
  if (entry.caseId) {
    const label = esc(entry.caseId);
    ids += `<span class="id-chip">${entry.caseUrl
      ? `<a href="${esc(entry.caseUrl)}" target="_blank">${label}</a>`
      : label}</span>`;
  }
  if (entry.jiraId && config.jiraBaseUrl) {
    ids += `<span class="id-chip"><a href="${esc(config.jiraBaseUrl)}/browse/${esc(entry.jiraId)}"
              target="_blank">${esc(entry.jiraId)}</a></span>`;
  } else if (entry.jiraId) {
    ids += `<span class="id-chip">${esc(entry.jiraId)}</span>`;
  }

  // Path params line
  const PROTO_MAP = {'1':'ICMP','6':'TCP','17':'UDP','47':'GRE','50':'ESP','51':'AH','58':'ICMPv6'};
  let searchStr = `f(${entry.srcIp})(ipv4_dst.${entry.dstIp})`;
  if (entry.ipProto) searchStr += `(ip_proto.${PROTO_MAP[String(entry.ipProto)] || entry.ipProto})`;
  if (entry.dstPort) searchStr += `(tp_dst.${entry.dstPort})`;
  searchStr += `m(permit_all)`;
  let paramStr = searchStr;
  const extras = [];
  if (entry.maxCandidates) extras.push(`maxCandidates=${entry.maxCandidates}`);
  if (entry.maxResults > 1) extras.push(`maxResults=${entry.maxResults}`);
  if (entry.maxSeconds && entry.maxSeconds !== 30) extras.push(`maxSeconds=${entry.maxSeconds}`);
  if (extras.length) paramStr += `  [${extras.join(', ')}]`;

  // Banner
  let banner = '';
  const lastResult = entry.lastResult;
  if (lastResult === 'clean') {
    banner = `<div class="clean-banner banner-clean">
      \u2713 ${entry.cleanCount} of ${entry.totalSubsequent} subsequent snapshot(s) clean since baseline</div>`;
  } else if (lastResult === 'changed') {
    banner = `<div class="clean-banner banner-changed">
      \u26a0 Change detected in one or more snapshots</div>`;
  } else if (lastResult === 'never') {
    banner = `<div class="clean-banner banner-never">Not yet run — click Run to check</div>`;
  } else if (lastResult === 'no_subsequent') {
    banner = `<div class="clean-banner banner-never">No snapshots after baseline yet</div>`;
  } else if (lastResult === 'error') {
    banner = `<div class="clean-banner banner-changed">\u26a0 Error: ${esc(entry.lastError || 'unknown')}</div>`;
  }

  // Actions
  const isArchived = entry.status === 'archived';
  let actions = `<button class="btn btn-sm" onclick="runOne('${entry.id}')">▶ Run Check</button>`;
  if (!isArchived) {
    actions += `<button class="btn btn-sm btn-warn" onclick="archiveEntry('${entry.id}')">Archive &amp; Export Evidence</button>`;
  } else if (entry.evidencePath) {
    actions += `<span style="font-size:0.62rem;color:var(--muted)">Evidence: ${esc(entry.evidencePath)}</span>`;
  }
  actions += `<button class="btn btn-sm btn-error" onclick="deleteEntry('${entry.id}')">Delete</button>`;

  // Results table
  let tableRows = '';
  if (entry.runResults && entry.runResults.length) {
    entry.runResults.forEach(r => {
      const cls = r.classification || 'ERROR';
      let detailStr = '';
      const d = r.detail || {};
      if (d.fw_removed && d.fw_removed.length) detailStr += `FW removed: ${d.fw_removed.join(', ')} `;
      if (d.fw_added   && d.fw_added.length)   detailStr += `FW added: ${d.fw_added.join(', ')} `;
      if (d.net_removed && d.net_removed.length) detailStr += `hops removed: ${d.net_removed.join(', ')} `;
      if (d.net_added   && d.net_added.length)   detailStr += `hops added: ${d.net_added.join(', ')} `;
      if (d.similar     && d.similar.length)     detailStr += `similar swap(s) `;
      if (d.error) detailStr += d.error;
      if (d.baseline_count != null) detailStr += `baseline: ${d.baseline_count} paths`;
      if (d.current_count  != null) detailStr += ` → now: ${d.current_count}`;

      tableRows += `<tr class="${r.isBaseline ? 'baseline-row' : ''}">
        <td>${esc(r.snapshotLabel)}</td>
        <td><span class="cls-badge cls-${cls}">${cls.replace(/_/g,' ')}</span>
          ${detailStr ? `<div class="detail-row">${esc(detailStr)}</div>` : ''}</td>
        <td style="color:var(--muted)">${r.analysis ? r.analysis.total_paths : '—'}</td>
        <td style="color:var(--muted)">${r.elapsed_ms ? r.elapsed_ms+'ms' : '—'}</td>
      </tr>`;
    });
  }

  const table = tableRows ? `
    <table class="results-table">
      <thead><tr>
        <th>SNAPSHOT</th><th>RESULT</th><th>PATHS</th><th>TIME</th>
      </tr></thead>
      <tbody>${tableRows}</tbody>
    </table>` : '';

  el.innerHTML = `
    <div class="detail-header">
      <div class="detail-ids">${ids}</div>
      <div class="detail-params">${esc(paramStr)}</div>
      ${entry.notes ? `<div style="font-size:0.65rem;color:var(--muted);margin-bottom:8px">${esc(entry.notes)}</div>` : ''}
    </div>
    ${banner}
    <div class="detail-actions">${actions}</div>
    ${table}
    ${!tableRows ? '<div style="color:var(--muted);font-size:0.65rem">No results yet — run a check to populate.</div>' : ''}
  `;
}

// ── Run ───────────────────────────────────────────────────────────────────────
async function runOne(id) {
  const prog = document.getElementById('run-progress');
  const label = document.getElementById('prog-label');
  const bar   = document.getElementById('prog-bar');
  prog.style.display = 'flex'; bar.style.width = '30%';
  const entry = entries.find(e => e.id === id);
  label.textContent = `Running: ${entryLabel(entry)}…`;

  try {
    const resp = await fetch('/api/run-one', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id}),
    });
    const updated = await resp.json();
    const idx = entries.findIndex(e => e.id === id);
    if (idx >= 0) entries[idx] = updated;
    renderEntryList();
    if (activeId === id) renderDetail(updated);
  } catch(e) { alert('Run failed: ' + e.message); }
  finally { prog.style.display = 'none'; bar.style.width = '0%'; }
}

async function runAll() {
  const active = entries.filter(e => e.status === 'active');
  if (!active.length) { alert('No active entries to run.'); return; }

  const btn   = document.getElementById('run-all-btn');
  const prog  = document.getElementById('run-progress');
  const label = document.getElementById('prog-label');
  const bar   = document.getElementById('prog-bar');
  btn.disabled = true;
  prog.style.display = 'flex';

  try {
    label.textContent = `Running ${active.length} check(s)…`;
    bar.style.width = '10%';
    const resp = await fetch('/api/run-all', {method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'});
    const data = await resp.json();
    bar.style.width = '100%';
    data.updated.forEach(u => {
      const idx = entries.findIndex(e => e.id === u.id);
      if (idx >= 0) entries[idx] = u;
    });
    renderEntryList();
    if (activeId) {
      const updated = entries.find(e => e.id === activeId);
      if (updated) renderDetail(updated);
    }
  } catch(e) { alert('Run all failed: ' + e.message); }
  finally { btn.disabled = false; prog.style.display = 'none'; bar.style.width = '0%'; }
}

// ── Archive ───────────────────────────────────────────────────────────────────
async function archiveEntry(id) {
  if (!confirm('Archive this entry and export evidence zip?')) return;
  try {
    const resp = await fetch('/api/archive', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id}),
    });
    const data = await resp.json();
    const idx = entries.findIndex(e => e.id === id);
    if (idx >= 0) {
      entries[idx].status      = 'archived';
      entries[idx].evidencePath = data.evidencePath;
    }
    renderEntryList();
    if (activeId === id) renderDetail(entries[idx]);
    if (data.evidencePath) {
      alert(`Archived. Evidence saved to:\n${data.evidencePath}`);
    } else {
      alert('Archived. Evidence export failed — check terminal for details.');
    }
  } catch(e) { alert('Archive failed: ' + e.message); }
}

// ── Delete ────────────────────────────────────────────────────────────────────
async function deleteEntry(id) {
  if (!confirm('Permanently delete this entry and all its run results?')) return;
  try {
    await fetch('/api/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id}),
    });
    entries = entries.filter(e => e.id !== id);
    activeId = null;
    renderEntryList();
    showAddForm();
  } catch(e) { alert('Delete failed: ' + e.message); }
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function fmtDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'
    });
  } catch { return iso.slice(0, 16); }
}

boot();
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print("\n  ⬡  Forward Networks — Path Search Monitor")
    print("  " + "─" * 50)
    base_url = os.environ.get("FWD_BASE_URL", "https://fwd.app")
    collect_credentials(base_url)

    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)

    if "--no-browser" not in sys.argv:
        def open_browser():
            time.sleep(0.4)
            webbrowser.open(f"http://localhost:{PORT}")
        threading.Thread(target=open_browser, daemon=True).start()

    print(f"     Running at: http://localhost:{PORT}")
    print(f"     Data file:  {MONITOR_FILE}")
    print(f"     Press Ctrl+C to quit\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down. Goodbye.\n")
        server.shutdown()


if __name__ == "__main__":
    run()