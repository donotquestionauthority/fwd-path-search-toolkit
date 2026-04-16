#!/usr/bin/env python3
"""
Forward Networks — Path Search Diff Tool
Investigates why a path search works in one snapshot but not another.

For each unique device on the working-snapshot path:
  1. Device metadata diff  (osVersion, collectionError, processingError, vendor, model, platform)
  2. Topology link diff    (interface adjacency changes between snapshots)
  3. File diff             (all device files, with configurable noise suppression)

Uses the Forward Networks API:
  GET /api/networks/{networkId}/paths?snapshotId=...
  GET /api/networks/{networkId}/devices/{deviceName}?snapshotId=...
  GET /api/networks/{networkId}/devices/{deviceName}/files?snapshotId=...
  GET /api/networks/{networkId}/devices/{deviceName}/files/{fileName}?snapshotId=...
  GET /api/snapshots/{snapshotId}/topology

Author: Robert Tavoularis — Forward Networks Customer Success Engineering
"""

import sys
import http.server
import webbrowser
import threading
import json
import os
import re
import urllib.request
import urllib.parse
import urllib.error
import base64
import time
import difflib
import importlib.util
import concurrent.futures

def _load_helpers():
    import importlib.util as _ilu
    _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_helpers.py")
    _s = _ilu.spec_from_file_location("fwd_helpers", _p)
    _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
    return _m
_helpers = _load_helpers()


PORT          = 8768
CREDENTIALS   = {}
NETWORKS_DATA = []
CONFIG_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_search_config.json")
FILTERS_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path_diff_filters.json")

# Seed filters written to path_diff_filters.json on first run (if the file is absent).
# This is the single source of truth for filter content — do not add patterns here
# as an alternative to adding them to the JSON. Edit the JSON file directly.
# On fresh installs this seed is written to disk and then loaded like any other JSON.
_SEED_FILTERS = {
    "_comment": "Noise filter patterns for path_search_diff.py. Edit freely — each group selectable in the UI.",
    "_version": 9,
    "_comment_concurrency": "Number of devices analysed in parallel. Increase to speed up analysis on well-resourced instances. Default 10. Set to 1 to disable parallelism.",
    "concurrency": 10,
    "_comment_lineTransforms": (
        "Pre-diff line transforms: strip volatile fragments before comparing lines. "
        "Each entry has 'pattern' (regex), 'replacement' (string), and 'description'. "
        "Applied to both old and new lines before difflib runs — so only the remaining "
        "content is compared. Useful when a line has both meaningful and noisy fields."
    ),
    "lineTransforms": [
        {
            "description": "HSRP: strip 'expires in X.X sec(s)' — keeps IP/priority visible if they change",
            "pattern": r",?\s*expires in [\d\.]+\s*sec\w*(\s*\(\w+\))?",
            "replacement": ""
        },
        {
            "description": "MAC table: strip trailing age timestamp — keeps VLAN/MAC/interface/port visible",
            "pattern": r"\s+(?:\d+\s+days?,\s*)?\d+:\d{2}:\d{2}\s+ago\s*$",
            "replacement": ""
        },
        {
            "description": "OSPF: strip checksum sum fragment — keeps LSA count visible if it changes",
            "pattern": r",?\s*Checksum\s+[Ss]um\s+\d+",
            "replacement": ""
        },
    ],
    "includeFiles": [],
    "default": {
        "description": "Suppress common time-varying fields with no forwarding relevance",
        "patterns": [
            r"\b\d+\s+(year|week|day|hour|minute|second|min|sec|hr)s?\b",
            r"\b\d{1,2}:\d{2}:\d{2}\b",
            r"\bage\b", r"\buptime\b", r"\blast.change\b", r"\blast.cleared\b",
            r"\blast.input\b", r"\blast.output\b", r"\binput rate\b", r"\boutput rate\b",
            r"\brate\b.*\bpps\b", r"\brate\b.*\bbps\b",
            r"\bpackets input\b", r"\bpackets output\b",
            r"\bbytes input\b", r"\bbytes output\b",
            r"\binput errors\b", r"\boutput errors\b",
            r"\bno buffer\b", r"\bcrc\b", r"\bframe\b.*\berror\b",
            r"\boverrun\b", r"\bignored\b", r"\bwatchdog\b", r"\bcollisions\b",
            r"\blate.collision\b", r"\bdeferred\b", r"\blost.carrier\b", r"\bno.carrier\b",
            r"\boutput.buffer.failure\b", r"\boutput.buffers.swapped\b", r"\bqueue.drops\b",
            r"\b5 minute\b", r"\b30 second\b", r"snapshot_time", r"^\s*$",
            r"\b\d+d\d+h\b", r"\b\d+w\d+d\b", r"\b\d+y\d+w\b",
            r"\bKeepalives\b", r"\bNotifications\b",
            r"\bup for\b",
            r"\bLast (sent|rcvd)\b",
            r"\bFirst time\b",
            r"\bRepeats\b",
            r"Next hello sent in \d+\.\d+ sec",
            r"\bHoldtime:\s*\d+ sec\b",
            r"BGP table version is \d+",
            r"BGP community entries \[\d+/\d+\]",
            r"BGP clusterlist entries \[\d+/\d+\]",
            r"BGP attribute entries \[",
            r"BGP AS path entries \[",
            r"client-specific data:\s*[0-9a-fA-F]+",
            r"Free memory:\s*\d+\s*kB",
            r"\d+ network entries and \d+ paths using \d+ bytes",
            r"\d+ received paths for inbound soft reconfiguration",
            r"\d+ identical,\s*\d+ modified,\s*\d+ filtered received paths",
            r"Checksum\s+sum\s+\d+",
            r"SPF algorithm executed \d+ times",
            r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d\s+\d+\s+\d{5,}\s+\d{5,}\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+\s*$",
            r"^\s{10,}\d{5,}\s+\d{5,}\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+\s*$",
        ]
    },
    "strict": {
        "description": "Also suppress routing metrics, BGP counters, and sequence numbers",
        "patterns": [
            r"\b\d+\s+(year|week|day|hour|minute|second|min|sec|hr)s?\b",
            r"\b\d{1,2}:\d{2}:\d{2}\b",
            r"\bage\b", r"\buptime\b", r"\blast.change\b", r"\blast.cleared\b",
            r"\blast.input\b", r"\blast.output\b", r"\binput rate\b", r"\boutput rate\b",
            r"\brate\b.*\bpps\b", r"\brate\b.*\bbps\b",
            r"\bpackets input\b", r"\bpackets output\b",
            r"\bbytes input\b", r"\bbytes output\b",
            r"\binput errors\b", r"\boutput errors\b",
            r"\bno buffer\b", r"\bcrc\b", r"\boverrun\b", r"\bignored\b",
            r"\bcollisions\b", r"\blost.carrier\b", r"\bno.carrier\b",
            r"\b5 minute\b", r"\b30 second\b", r"snapshot_time",
            r"\bmetric\b", r"\bweight\b", r"\bMsgRcvd\b", r"\bMsgSent\b",
            r"\bTblVer\b", r"\bInQ\b", r"\bOutQ\b", r"\bUp/Down\b", r"\bPrefRcvd\b",
            r"\bkeepalive\b", r"\bhold time\b", r"\bsequence\b", r"\bseq.*num\b",
            r"^\s*$",
            r"\b\d+d\d+h\b", r"\b\d+w\d+d\b", r"\b\d+y\d+w\b",
            r"\bKeepalives\b", r"\bNotifications\b",
            r"\bup for\b",
            r"\bLast (sent|rcvd)\b",
            r"\bFirst time\b",
            r"\bRepeats\b",
            r"Next hello sent in \d+\.\d+ sec",
            r"expires in \d+\.\d+ sec",
            r"\bHoldtime:\s*\d+ sec\b",
            r"BGP table version is \d+",
            r"BGP community entries \[\d+/\d+\]",
            r"BGP clusterlist entries \[\d+/\d+\]",
            r"BGP attribute entries \[",
            r"BGP AS path entries \[",
            r"client-specific data:\s*[0-9a-fA-F]+",
            r"Free memory:\s*\d+\s*kB",
            r"\d+ network entries and \d+ paths using \d+ bytes",
            r"\d+ received paths for inbound soft reconfiguration",
            r"\d+ identical,\s*\d+ modified,\s*\d+ filtered received paths",
            r"Checksum\s+sum\s+\d+",
            r"SPF algorithm executed \d+ times",
            r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d\s+\d+\s+\d{5,}\s+\d{5,}\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+\s*$",
            r"^\s{10,}\d{5,}\s+\d{5,}\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+\s*$",
        ]
    },
    "off": {
        "description": "Show all changes including counters and timers",
        "patterns": []
    }
}

# Files that are predominantly counters/timers — collapsed by default in UI.
# Kept in source because this is UI behaviour, not filter config.
NOISY_FILES = frozenset([
    "arp.txt", "mac.txt", "metadata.txt",
    "ndp.txt", "ipv4_mcast.txt", "ipv6_mcast.txt",
    "ip_igmp_snoop_explicit_tracking.txt"
])

# Files to skip entirely — will always differ between snapshots and carry no signal.
# Kept in source as a hard guard; these should never appear in the include list either.
EXCLUDE_FILES = frozenset([
    "snapshot_time.txt",
    "root_device_name.txt",
])

# File name prefixes to skip entirely — e.g. custom_cli,1.txt, custom_cli,21.txt
EXCLUDE_PREFIXES = (
    "custom_cli,",
)

# Runtime globals — populated by load_filters() from path_diff_filters.json.
# Do not set these directly; edit the JSON file.
LINE_TRANSFORMS: list = []
INCLUDE_FILES: frozenset = frozenset()

# Synthetic/carrier prefixes in topology port names — no device API calls
SYNTHETIC_PREFIXES = ("internet ", "MPLS-", "MPLS_")

# Global topology cache — populated by /run-diff-all, consumed by analysis
_topo_cache    = {}
_file_name_cache = set()  # unique file names seen across last run
ANALYSIS_POOL_SIZE = 10  # concurrent device analysis workers


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def _load_discovery():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_discovery.py")
    spec = importlib.util.spec_from_file_location("fwd_discovery", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def read_config():
    """Return the full config file, defaulting missing keys."""
    if not os.path.exists(CONFIG_FILE):
        return {"savedSearches": [], "diffSavedSearches": []}
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
        if "diffSavedSearches" not in data:
            data["diffSavedSearches"] = []
        return data
    except Exception:
        return {"savedSearches": [], "diffSavedSearches": []}


def write_config(data):
    """Merge data into the config file, preserving keys we don't own."""
    existing = read_config()
    existing.update(data)
    with open(CONFIG_FILE, "w") as f:
        json.dump(existing, f, indent=2)


def load_filters():
    """Load noise filter patterns, include file list, and concurrency from path_diff_filters.json.

    If the file is absent, write the seed defaults to disk first so there is always
    exactly one source of truth. No filtering is applied from hardcoded Python values
    at runtime — everything comes from the JSON file.
    """
    global INCLUDE_FILES, ANALYSIS_POOL_SIZE, LINE_TRANSFORMS
    _ensure_filters_file()
    try:
        with open(FILTERS_FILE) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ⚠  Could not read {FILTERS_FILE}: {e} — no filters applied this run.")
        data = {"off": {"description": "Fallback: file unreadable", "patterns": []}}
    # Apply includeFiles to the global — used by analyze_device
    raw_includes = data.get("includeFiles", [])
    INCLUDE_FILES = frozenset(raw_includes) if raw_includes else frozenset()
    # Apply concurrency setting
    if "concurrency" in data:
        try:
            ANALYSIS_POOL_SIZE = max(1, int(data["concurrency"]))
        except (ValueError, TypeError):
            pass
    # Apply lineTransforms
    LINE_TRANSFORMS.clear()
    for t in data.get("lineTransforms", []):
        try:
            pattern = re.compile(t["pattern"], re.IGNORECASE)
            LINE_TRANSFORMS.append((pattern, t.get("replacement", "")))
        except Exception:
            pass
    return {k: v for k, v in data.items()
            if not k.startswith("_") and k not in ("includeFiles", "concurrency", "lineTransforms")}


def _ensure_filters_file():
    """Write path_diff_filters.json from the seed if it does not exist.

    Does not overwrite or merge into an existing file — the file is the source of truth.
    If the user has deleted or never had the file, they get the seed defaults as a
    starting point. After that, all changes are made to the JSON directly.
    """
    if os.path.exists(FILTERS_FILE):
        return
    try:
        with open(FILTERS_FILE, "w") as f:
            json.dump(_SEED_FILTERS, f, indent=2)
        print(f"  ✓  Created {FILTERS_FILE} with default filter patterns.")
    except Exception as e:
        print(f"  ⚠  Could not write {FILTERS_FILE}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# API helpers
# ─────────────────────────────────────────────────────────────────────────────

def api_get(base_url, network_id, path, params=None, timeout=30, text=False,
            _retries=2, _backoff=2.0):
    """GET wrapper with retry on transient errors (SSL EOF, connection reset, timeout)."""
    if network_id not in CREDENTIALS:
        return None, None, f"No credentials for network {network_id}"
    qs  = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{base_url.rstrip('/')}{path}{qs}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", CREDENTIALS[network_id])
    req.add_header("Accept", "text/plain, application/json" if text else "application/json")

    last_err = None
    for attempt in range(1 + _retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if text:
                    return resp.status, raw.decode("utf-8", errors="replace"), None
                return resp.status, json.loads(raw.decode("utf-8")), None
        except urllib.error.HTTPError as e:
            # HTTP errors (4xx/5xx) are definitive — don't retry
            body = e.read().decode("utf-8", errors="replace")
            try:
                msg = json.loads(body).get("message", body)
            except Exception:
                msg = body[:300]
            return e.code, None, f"HTTP {e.code}: {msg}"
        except Exception as ex:
            last_err = str(ex)
            if attempt < _retries:
                time.sleep(_backoff * (attempt + 1))
            continue

    return None, None, last_err


def run_path_search(base_url, network_id, snapshot_id, src_ip, dst_ip,
                    intent, max_candidates, max_results, ip_proto, dst_port, max_seconds=30):
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
            body    = json.loads(resp.read().decode("utf-8"))
            elapsed = round((time.time() - t0) * 1000)
            return resp.status, body, elapsed, None
    except urllib.error.HTTPError as e:
        raw     = e.read().decode("utf-8")
        elapsed = round((time.time() - t0) * 1000)
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw}
        return e.code, body, elapsed, f"HTTP {e.code}"
    except Exception as ex:
        return None, None, round((time.time() - t0) * 1000), str(ex)


# ─────────────────────────────────────────────────────────────────────────────
# Path analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_synthetic(device_name):
    for prefix in SYNTHETIC_PREFIXES:
        if device_name.startswith(prefix):
            return True
    return False


def extract_device_from_port(port_str):
    parts = port_str.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return port_str, ""


def extract_hops_from_path(path_obj):
    hops = []
    seen = set()
    for hop in path_obj.get("hops", []):
        name = hop.get("deviceName", "")
        if name and name not in seen:
            seen.add(name)
            hops.append({
                "deviceName":       name,
                "displayName":      hop.get("displayName", name),
                "deviceType":       hop.get("deviceType", ""),
                "forwardingOutcome":hop.get("forwardingOutcome", ""),
                "securityOutcome":  hop.get("securityOutcome", ""),
            })
    return hops


def build_device_set(path_search_body, max_paths=10):
    """
    Returns (ordered_hops_from_top_path, set_of_all_unique_device_names).
    Peer paths must match top path's forwardingOutcome, securityOutcome, and hop count.
    """
    paths = path_search_body.get("info", {}).get("paths", [])
    if not paths:
        return [], set()
    top      = paths[0]
    top_hops = extract_hops_from_path(top)
    top_fo   = top.get("forwardingOutcome", "")
    top_so   = top.get("securityOutcome", "")
    top_len  = len(top.get("hops", []))

    all_names    = set(h["deviceName"] for h in top_hops)
    ordered_hops = top_hops

    for p in paths[1:max_paths]:
        if (p.get("forwardingOutcome") == top_fo and
                p.get("securityOutcome") == top_so and
                len(p.get("hops", [])) == top_len):
            for h in extract_hops_from_path(p):
                all_names.add(h["deviceName"])

    return ordered_hops, all_names


# ─────────────────────────────────────────────────────────────────────────────
# Per-device analysis
# ─────────────────────────────────────────────────────────────────────────────

def get_device_meta(base_url, network_id, device_name, snapshot_id):
    status, data, err = api_get(
        base_url, network_id,
        f"/api/networks/{network_id}/devices/{urllib.parse.quote(device_name, safe='')}",
        params={"snapshotId": snapshot_id}
    )
    return (data, None) if not err else (None, err)


def get_topology(base_url, network_id, snapshot_id):
    status, data, err = api_get(
        base_url, network_id,
        f"/api/snapshots/{snapshot_id}/topology",
        timeout=60
    )
    if err or data is None:
        return [], err
    return (data if isinstance(data, list) else []), None


def filter_topology_for_device(topology, device_name):
    links  = set()
    for link in topology:
        sp = link.get("sourcePort", "")
        tp = link.get("targetPort", "")
        sd, _ = extract_device_from_port(sp)
        td, _ = extract_device_from_port(tp)
        if sd == device_name or td == device_name:
            links.add(tuple(sorted([sp, tp])))
    return links


def get_device_files(base_url, network_id, device_name, snapshot_id):
    status, data, err = api_get(
        base_url, network_id,
        f"/api/networks/{network_id}/devices/{urllib.parse.quote(device_name, safe='')}/files",
        params={"snapshotId": snapshot_id}
    )
    if err or data is None:
        return [], err
    files = data.get("files", data) if isinstance(data, dict) else data
    return (files if isinstance(files, list) else []), None


def get_file_content(base_url, network_id, device_name, file_name, snapshot_id):
    status, data, err = api_get(
        base_url, network_id,
        f"/api/networks/{network_id}/devices/{urllib.parse.quote(device_name, safe='')}/files/{urllib.parse.quote(file_name, safe='')}",
        params={"snapshotId": snapshot_id},
        text=True
    )
    return (data, None) if not err else (None, err)


def _apply_transforms(lines):
    """Strip timer/counter fragments from lines before diffing."""
    result = []
    for line in lines:
        for pattern, replacement in LINE_TRANSFORMS:
            line = pattern.sub(replacement, line)
        result.append(line)
    return result


def compute_file_diff(text_a, text_b, filter_patterns):
    lines_a  = _apply_transforms((text_a or "").splitlines(keepends=True))
    lines_b  = _apply_transforms((text_b or "").splitlines(keepends=True))
    compiled = [re.compile(p, re.IGNORECASE) for p in filter_patterns]
    raw_diff = list(difflib.unified_diff(lines_a, lines_b, lineterm=""))

    # First pass: suppress noisy +/- lines
    filtered   = []
    suppressed = 0
    for line in raw_diff:
        if (line.startswith("+") or line.startswith("-"))                 and not line.startswith("---") and not line.startswith("+++"):
            if any(p.search(line[1:]) for p in compiled):
                suppressed += 1
                continue
        filtered.append(line)

    # Second pass: strip @@ hunk headers whose hunks contain no remaining +/- lines
    # (all changes in that hunk were suppressed by the noise filter)
    meaningful = []
    i = 0
    while i < len(filtered):
        line = filtered[i]
        if line.startswith("@@"):
            j = i + 1
            has_changes = False
            while j < len(filtered) and not filtered[j].startswith("@@"):
                if (filtered[j].startswith("+") or filtered[j].startswith("-"))                         and not filtered[j].startswith("---")                         and not filtered[j].startswith("+++"):
                    has_changes = True
                    break
                j += 1
            if has_changes:
                meaningful.append(line)
        else:
            meaningful.append(line)
        i += 1

    # A file counts as changed only if meaningful has actual +/- lines
    # (not just --- +++ headers). All-noise diffs are treated as unchanged.
    has_meaningful_changes = any(
        (l.startswith("+") or l.startswith("-"))
        and not l.startswith("---") and not l.startswith("+++")
        for l in meaningful
    )
    return {
        "meaningful":       meaningful,
        "suppressed_count": suppressed,
        "raw":              raw_diff,
        "changed":          has_meaningful_changes,
    }


def analyze_device(base_url, network_id, device_name,
                   snap_working, snap_broken,
                   topo_working, topo_broken,
                   filter_name, filters):
    result = {
        "deviceName": device_name,
        "synthetic":  is_synthetic(device_name),
        "metadata":   {"rows": [], "any_changed": False},
        "topology":   {"rows": [], "lost_count": 0, "new_count": 0, "any_changed": False},
        "files":      [],
        "errors":     [],
        "severity":   "clean",
    }

    if result["synthetic"]:
        return result

    # ── 1. Metadata ──────────────────────────────────────────────────────────
    meta_w, err_w = get_device_meta(base_url, network_id, device_name, snap_working)
    meta_b, err_b = get_device_meta(base_url, network_id, device_name, snap_broken)
    if err_w: result["errors"].append(f"metadata (working): {err_w}")
    if err_b: result["errors"].append(f"metadata (broken): {err_b}")

    META_FIELDS = ["osVersion", "collectionError", "processingError",
                   "vendor", "model", "platform", "type", "managementIps"]
    meta_rows = []
    for field in META_FIELDS:
        val_w = (meta_w or {}).get(field)
        val_b = (meta_b or {}).get(field)
        if isinstance(val_w, list): val_w = ", ".join(str(x) for x in val_w)
        if isinstance(val_b, list): val_b = ", ".join(str(x) for x in val_b)
        changed = str(val_w or "") != str(val_b or "")
        meta_rows.append({"field": field, "working": val_w, "broken": val_b, "changed": changed})

    result["metadata"] = {
        "rows":        meta_rows,
        "any_changed": any(r["changed"] for r in meta_rows),
        "raw_working": meta_w,
        "raw_broken":  meta_b,
    }

    # ── 2. Topology ───────────────────────────────────────────────────────────
    links_w = filter_topology_for_device(topo_working, device_name)
    links_b = filter_topology_for_device(topo_broken,  device_name)

    only_w  = sorted(links_w - links_b)
    only_b  = sorted(links_b - links_w)
    common  = sorted(links_w & links_b)

    def link_row(pair, status):
        sp, tp = pair
        return {"sourcePort": sp, "targetPort": tp, "status": status}

    topo_rows = (
        [link_row(p, "lost")      for p in only_w] +
        [link_row(p, "new")       for p in only_b]  +
        [link_row(p, "unchanged") for p in common]
    )
    result["topology"] = {
        "rows":        topo_rows,
        "lost_count":  len(only_w),
        "new_count":   len(only_b),
        "any_changed": bool(only_w or only_b),
    }

    # ── 3. Files ──────────────────────────────────────────────────────────────
    files_w, err_fw = get_device_files(base_url, network_id, device_name, snap_working)
    files_b, err_fb = get_device_files(base_url, network_id, device_name, snap_broken)
    if err_fw: result["errors"].append(f"file list (working): {err_fw}")
    if err_fb: result["errors"].append(f"file list (broken): {err_fb}")

    names_w   = {f["name"] for f in files_w}
    names_b   = {f["name"] for f in files_b}
    # Record all file names seen (before exclusions) for the export endpoint
    _file_name_cache.update(names_w | names_b)
    all_names = sorted(
        n for n in (names_w | names_b)
        if n not in EXCLUDE_FILES
        and not n.startswith(EXCLUDE_PREFIXES)
        and (not INCLUDE_FILES or n in INCLUDE_FILES)
    )

    filter_patterns = filters.get(filter_name, filters.get("default", {})).get("patterns", [])

    def fetch_and_diff_file(fname):
        in_w  = fname in names_w
        in_b  = fname in names_b
        noisy = fname in NOISY_FILES
        if in_w and in_b:
            content_w, cerr_w = get_file_content(base_url, network_id, device_name, fname, snap_working)
            content_b, cerr_b = get_file_content(base_url, network_id, device_name, fname, snap_broken)
            if cerr_w or cerr_b:
                return {"name": fname, "status": "error",
                        "error": cerr_w or cerr_b, "noisy": noisy}
            diff = compute_file_diff(content_w, content_b, filter_patterns)
            return {
                "name":             fname,
                "status":           "diff",
                "changed":          diff["changed"],
                "meaningful_lines": diff["meaningful"],
                "suppressed_count": diff["suppressed_count"],
                "raw_lines":        diff["raw"],
                "noisy":            noisy,
            }
        elif in_w:
            return {"name": fname, "status": "only_working", "noisy": noisy}
        else:
            return {"name": fname, "status": "only_broken",  "noisy": noisy}

    # Fetch and diff all files in parallel — each file needs 2 API calls
    # Use a modest per-device pool to avoid overwhelming the API
    file_pool_size = max(1, min(ANALYSIS_POOL_SIZE, len(all_names)))
    file_results = []
    if all_names:
        with concurrent.futures.ThreadPoolExecutor(max_workers=file_pool_size) as fpool:
            futs = {fpool.submit(fetch_and_diff_file, fname): fname for fname in all_names}
            # Preserve sorted order (all_names is already sorted)
            results_map = {}
            for fut in concurrent.futures.as_completed(futs):
                fname = futs[fut]
                try:
                    results_map[fname] = fut.result()
                except Exception as e:
                    results_map[fname] = {"name": fname, "status": "error",
                                          "error": str(e), "noisy": fname in NOISY_FILES}
            file_results = [results_map[fname] for fname in all_names]

    def file_sort(f):
        changed = 0 if (f.get("changed") or f["status"] in ("only_working","only_broken","error")) else 1
        return (changed, 1 if f["noisy"] else 0, f["name"])

    file_results.sort(key=file_sort)
    result["files"] = file_results

    # ── Severity ──────────────────────────────────────────────────────────────
    has_coll_err  = any(r["field"] in ("collectionError","processingError") and r["changed"]
                        for r in meta_rows)
    has_meta      = result["metadata"]["any_changed"]
    has_topo      = result["topology"]["any_changed"]
    has_file      = any(f.get("changed") or f["status"] in ("only_working","only_broken")
                        for f in file_results)
    has_err       = bool(result["errors"]) or any(f["status"]=="error" for f in file_results)

    if has_err or has_coll_err:
        result["severity"] = "error"
    elif has_meta or has_topo:
        result["severity"] = "warn"
    elif has_file:
        result["severity"] = "info"
    else:
        result["severity"] = "clean"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forward Networks &middot; Path Search Diff</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
    --accent:#00b4d8;--accent2:#90e0ef;--text:#e6edf3;--muted:#8b949e;
    --success:#3fb950;--error:#f85149;--warn:#d29922;--info:#58a6ff;
    --radius:6px;
  }
  html,body{height:100%}
  body{background:var(--bg);color:var(--text);
    font-family:'JetBrains Mono','Courier New',monospace;
    height:100vh;overflow:hidden;display:flex;flex-direction:column}
  .topbar{flex-shrink:0;padding:14px 24px 0}
  header{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}
  .home-link{margin-left:auto;font-size:0.67rem;color:var(--muted);text-decoration:none;letter-spacing:.04em}
  .home-link:hover{color:var(--accent)}
  .logo{color:var(--accent);font-size:1.3rem;font-weight:700}
  .title{font-size:1.15rem;font-weight:700;letter-spacing:.05em}
  .subtitle{color:var(--muted);font-size:0.8rem}
  .divider{height:1px;background:var(--accent);margin:10px 0 0}
  .main{flex:1;min-height:0;display:flex;overflow:hidden}
  .left-pane{width:300px;flex-shrink:0;min-height:0;display:flex;flex-direction:column;border-right:1px solid var(--border);overflow:hidden}
  .left-header{padding:10px 14px 8px;border-bottom:1px solid var(--border);flex-shrink:0}
  .snap-compare{font-size:0.68rem;line-height:1.8}
  .snap-working{color:var(--success)}.snap-broken{color:var(--error)}
  .snap-label{color:var(--muted);font-size:0.63rem}
  .hop-list{flex:1;overflow-y:auto;padding:4px 0}
  .hop-row{display:flex;align-items:center;gap:7px;padding:7px 14px;cursor:pointer;
    border-left:3px solid transparent;transition:background .1s}
  .hop-row:hover{background:var(--surface2)}
  .hop-row.active{background:var(--surface);border-left-color:var(--accent)}
  .hop-row.synthetic{opacity:.45;cursor:default}
  .hop-num{color:var(--muted);font-size:0.6rem;width:18px;flex-shrink:0;text-align:right}
  .hop-name{flex:1;font-size:0.71rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .hop-type{font-size:0.58rem;color:var(--muted);white-space:nowrap}
  .presence{width:7px;height:7px;border-radius:50%;flex-shrink:0}
  .presence.present{background:var(--success)}.presence.absent{background:var(--error)}
  .presence.synth{background:transparent}
  .sev{font-size:0.58rem;font-weight:700;padding:1px 5px;border-radius:3px;flex-shrink:0;min-width:20px;text-align:center}
  .sev-error{background:var(--error);color:#000}.sev-warn{background:var(--warn);color:#000}
  .sev-info{background:var(--info);color:#000}
  .sev-clean{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
  .sev-pending{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
  .right-pane{flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden}
  .right-header{padding:10px 20px 8px;border-bottom:1px solid var(--border);flex-shrink:0;display:flex;align-items:center;gap:10px}
  .right-title{font-size:0.7rem;font-weight:700;color:var(--accent);letter-spacing:.1em}
  .right-content{flex:1;min-height:0;overflow-y:auto;padding:14px 20px 24px}
  .config-panel{max-width:680px}
  .config-panel h2{font-size:0.82rem;color:var(--accent);margin-bottom:14px;letter-spacing:.1em}
  .field-group{margin-bottom:12px}
  .field-group label{display:block;font-size:0.65rem;color:var(--muted);margin-bottom:3px;letter-spacing:.05em}
  .field-group input,.field-group select{width:100%;background:var(--surface);border:1px solid var(--border);
    color:var(--text);padding:6px 9px;border-radius:var(--radius);font-family:inherit;font-size:0.73rem}
  .field-group input:focus,.field-group select:focus{outline:none;border-color:var(--accent)}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
  .row4{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px}
  .btn{background:var(--accent);color:var(--bg);border:none;padding:7px 18px;border-radius:var(--radius);
    font-family:inherit;font-size:0.75rem;font-weight:700;cursor:pointer;transition:opacity .15s}
  .btn:hover{opacity:.85}.btn:disabled{opacity:.4;cursor:not-allowed}
  .btn-sm{background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:3px 9px;
    border-radius:var(--radius);font-family:inherit;font-size:0.63rem;cursor:pointer}
  .btn-sm:hover{border-color:var(--accent);color:var(--accent)}
  .saved-row{margin-bottom:14px}
  .saved-row label{font-size:0.65rem;color:var(--muted);display:block;margin-bottom:3px}
  .saved-row select{width:100%;background:var(--surface);border:1px solid var(--border);
    color:var(--text);padding:5px 8px;border-radius:var(--radius);font-family:inherit;font-size:0.72rem}
  .filter-inline{display:flex;align-items:center;gap:8px;margin-bottom:14px}
  .filter-inline label{font-size:0.65rem;color:var(--muted);white-space:nowrap}
  .filter-inline select{background:var(--surface);border:1px solid var(--border);
    color:var(--text);padding:4px 8px;border-radius:var(--radius);font-family:inherit;font-size:0.7rem}
  .fdesc{font-size:0.6rem;color:var(--muted)}
  .section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px}
  .sec-hdr{display:flex;align-items:center;gap:8px;padding:8px 12px;cursor:pointer;border-bottom:1px solid transparent;user-select:none}
  .sec-hdr:hover{background:var(--surface2)}.sec-hdr.open{border-bottom-color:var(--border)}
  .sec-title{font-size:0.68rem;font-weight:700;letter-spacing:.07em;flex:1}
  .sec-badge{font-size:0.6rem;padding:1px 6px;border-radius:3px}
  .badge-changed{background:var(--warn);color:#000}.badge-ok{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
  .badge-error{background:var(--error);color:#fff}
  .sec-body{padding:12px;display:none}.sec-body.open{display:block}
  .chev{font-size:0.58rem;color:var(--muted);width:10px}
  .meta-tbl{width:100%;border-collapse:collapse;font-size:0.69rem}
  .meta-tbl th{text-align:left;padding:3px 8px;color:var(--muted);font-weight:400;border-bottom:1px solid var(--border)}
  .meta-tbl td{padding:3px 8px;vertical-align:top}
  .meta-tbl tr.changed td{background:rgba(210,153,34,.07)}
  .meta-tbl tr.changed td:first-child{color:var(--warn);font-weight:700}
  .val-null{color:var(--muted);font-style:italic}.val-chg{color:var(--warn)}
  .topo-tbl{width:100%;border-collapse:collapse;font-size:0.67rem}
  .topo-tbl th{text-align:left;padding:3px 8px;color:var(--muted);font-weight:400;border-bottom:1px solid var(--border)}
  .topo-tbl td{padding:3px 8px;font-family:'JetBrains Mono',monospace}
  .link-lost{color:var(--error)}.link-new{color:var(--success)}.link-unchanged{color:var(--muted)}
  .link-stat{font-size:0.58rem;font-weight:700;white-space:nowrap}
  .file-list{display:flex;flex-direction:column;gap:5px}
  .file-item{background:var(--surface2);border:1px solid var(--border);border-radius:4px;overflow:hidden}
  .file-hdr{display:flex;align-items:center;gap:7px;padding:5px 10px;cursor:pointer;user-select:none}
  .file-hdr:hover{background:rgba(255,255,255,.03)}
  .file-name{flex:1;font-size:0.69rem}
  .file-badge{font-size:0.57rem;padding:1px 5px;border-radius:3px;white-space:nowrap}
  .fb-changed{background:var(--warn);color:#000}.fb-unchanged{background:var(--surface);color:var(--muted);border:1px solid var(--border)}
  .fb-only-w{background:var(--error);color:#fff}.fb-only-b{background:var(--success);color:#000}
  .fb-error{background:var(--error);color:#fff}
  .file-body{display:none;border-top:1px solid var(--border)}.file-body.open{display:block}
  .diff-meta{padding:4px 10px;font-size:0.61rem;color:var(--muted);border-bottom:1px solid var(--border);display:flex;gap:12px}
  .diff-view{font-size:0.64rem;line-height:1.5;overflow-x:auto;overflow-y:auto;max-height:400px}
  .diff-line{padding:0 10px;white-space:pre;font-family:'JetBrains Mono',monospace}
  .diff-add{background:rgba(63,185,80,.10);color:var(--success)}.diff-del{background:rgba(248,81,73,.10);color:var(--error)}
  .diff-hdr{background:rgba(0,180,216,.08);color:var(--accent)}.diff-ctx{color:var(--muted)}
  .supp-note{font-size:0.61rem;color:var(--muted);padding:3px 10px;font-style:italic}
  .diff-toggle{padding:4px 10px}
  .placeholder{display:flex;flex-direction:column;align-items:center;
    justify-content:center;height:160px;gap:8px;color:var(--muted);font-size:0.78rem;text-align:center}
  .placeholder .big{font-size:2rem}
  .loading-msg{color:var(--muted);font-size:0.73rem;padding:20px}
  .err-msg{color:var(--error);font-size:0.73rem;padding:20px}
  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
  /* legend */
  .legend{padding:6px 14px 5px;border-bottom:1px solid var(--border);font-size:0.58rem;color:var(--muted);display:none;flex-direction:column;gap:3px}
  .legend.visible{display:flex}
  .legend-title{font-size:0.57rem;color:var(--muted);letter-spacing:.06em;margin-bottom:1px}
  .legend-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .legend-item{display:flex;align-items:center;gap:4px}
  .legend-sev{font-size:0.58rem;font-weight:700;padding:1px 4px;border-radius:3px;min-width:16px;text-align:center}
  .legend-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
  /* back button */
  .back-btn{display:none;align-items:center;gap:5px;background:var(--surface2);
    border:1px solid var(--border);color:var(--muted);padding:3px 10px;
    border-radius:var(--radius);font-family:inherit;font-size:0.65rem;cursor:pointer}
  .back-btn:hover{border-color:var(--accent);color:var(--accent)}
  /* progress */
  .prog-bar-wrap{width:100%;height:3px;background:var(--surface2);border-radius:2px;overflow:hidden;margin-top:2px}
  .prog-bar{height:100%;background:var(--accent);border-radius:2px;transition:width .3s}
  .analysis-progress{display:none;align-items:center;gap:10px;padding:6px 0 2px;font-size:0.65rem;color:var(--muted)}
</style>
</head>
<body>

<div class="topbar">
  <header>
    <span class="logo">&#x2b61;</span>
    <span class="title">FORWARD NETWORKS</span>
    <span class="subtitle">Path Search Diff</span>
    <a href="http://localhost:8760" class="home-link" title="Back to launcher">⌂ Home</a>
  </header>
  <div class="divider"></div>
</div>

<div class="main">
  <div class="left-pane">
    <div class="left-header">
      <div class="snap-compare" id="snap-labels">
        <span class="snap-label">Select snapshots and run</span>
      </div>
    </div>
    <div class="legend" id="hop-legend">
      <div class="legend-title">SEVERITY</div>
      <div class="legend-row">
        <span class="legend-item"><span class="legend-sev sev-error">!</span><span>error / collection fail</span></span>
        <span class="legend-item"><span class="legend-sev sev-warn">△</span><span>metadata or topology changed</span></span>
        <span class="legend-item"><span class="legend-sev sev-info">●</span><span>file changes only</span></span>
        <span class="legend-item"><span class="legend-sev sev-clean">✓</span><span>no changes</span></span>
      </div>
      <div class="legend-title" style="margin-top:3px">PRESENCE DOT</div>
      <div class="legend-row">
        <span class="legend-item"><span class="legend-dot" style="background:var(--success)"></span><span>in broken path</span></span>
        <span class="legend-item"><span class="legend-dot" style="background:var(--error)"></span><span>absent from broken path</span></span>
      </div>
    </div>
    <div class="hop-list" id="hop-list">
      <div class="placeholder"><span class="big">&#x2191;</span><span>Configure and run</span></div>
    </div>
  </div>

  <div class="right-pane">
    <div class="right-header" style="flex-direction:column;align-items:stretch;padding-bottom:6px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:10px">
        <button class="back-btn" id="back-btn" onclick="showCfg()">&#x25c4; Search</button>
        <span class="right-title" id="right-title">CONFIGURATION</span>
        <span id="hdr-search-str" style="display:none;margin-left:12px;font-size:0.6rem;color:var(--muted);font-family:'JetBrains Mono',monospace;word-break:break-all;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>
        <span id="hdr-filter" style="margin-left:auto;display:none;align-items:center;gap:6px">
        <span style="font-size:0.63rem;color:var(--muted)">noise filter:</span>
        <select id="hdr-filter-sel" onchange="syncFilter('hdr')" autocomplete="off" data-form-type="other" data-lpignore="true"
          style="background:var(--surface);border:1px solid var(--border);color:var(--text);
                 padding:3px 6px;border-radius:4px;font-family:inherit;font-size:0.67rem">
        </select>
      </span>
    </div>
    <div class="analysis-progress" id="analysis-progress" style="padding:4px 20px 6px;display:none;align-items:center;gap:10px;border-bottom:1px solid var(--border)">
      <span class="prog-label" style="font-size:0.65rem;color:var(--muted)"></span>
      <div class="prog-bar-wrap" style="flex:1"><div class="prog-bar" id="prog-bar" style="width:0%"></div></div>
    </div>
  </div>
  <div class="right-content" id="right-content">

      <div id="cfg-panel" class="config-panel">
        <h2>SEARCH PARAMETERS</h2>

        <div class="saved-row">
          <label>SAVED SEARCHES</label>
          <div style="display:flex;gap:6px;align-items:center">
            <select id="saved-sel" autocomplete="off" data-form-type="other" data-lpignore="true" onchange="loadSaved()" style="flex:1">
              <option value="">&#x2014; select a saved search &#x2014;</option>
            </select>
            <button class="btn-sm" onclick="deleteSaved()" title="Delete selected search" style="flex-shrink:0;padding:3px 8px;color:var(--error);border-color:var(--error)">&#x2715;</button>
          </div>
        </div>

        <div class="field-group row2">
          <div><label>NETWORK</label>
            <select id="sel-net" autocomplete="off" data-form-type="other" data-lpignore="true" onchange="onNetChange()">
              <option value="">&#x2014; select network &#x2014;</option>
            </select>
          </div>
          <div><label>INTENT</label>
            <select id="sel-intent" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="PREFER_DELIVERED">PREFER_DELIVERED</option>
              <option value="PREFER_DELIVERED_NO_VIOLATIONS">PREFER_DELIVERED_NO_VIOLATIONS</option>
              <option value="DELIVERED">DELIVERED</option>
              <option value="VIOLATIONS">VIOLATIONS</option>
              <option value="ALL">ALL</option>
            </select>
          </div>
        </div>

        <div class="field-group row2">
          <div><label>WORKING SNAPSHOT</label>
            <select id="sel-snap-w" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="">Select network first</option>
            </select>
          </div>
          <div><label>BROKEN SNAPSHOT</label>
            <select id="sel-snap-b" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="">Select network first</option>
            </select>
          </div>
        </div>

        <div class="field-group row2">
          <div><label>SOURCE IP</label>
            <input id="inp-src" type="text" placeholder="10.0.0.1" autocomplete="off" data-lpignore="true">
          </div>
          <div><label>DESTINATION IP</label>
            <input id="inp-dst" type="text" placeholder="10.0.0.2" autocomplete="off" data-lpignore="true">
          </div>
        </div>

        <div class="field-group row4">
          <div><label>IP PROTOCOL</label>
            <select id="sel-proto" autocomplete="off" data-form-type="other" data-lpignore="true">
              <option value="">Any</option>
              <option value="6">TCP (6)</option>
              <option value="17">UDP (17)</option>
              <option value="1">ICMP (1)</option>
            </select>
          </div>
          <div><label>DST PORT</label>
            <input id="inp-port" type="text" placeholder="443" autocomplete="off" data-lpignore="true">
          </div>
          <div><label>MAX CANDIDATES</label>
            <input id="inp-maxcand" type="text" value="5000" autocomplete="off" data-lpignore="true">
          </div>
          <div><label>MAX SECONDS</label>
            <input id="inp-maxsec" type="text" value="30" autocomplete="off" data-lpignore="true">
          </div>
        </div>

        <div class="field-group row2">
          <div><label>PATHS TO ANALYZE (unique device union)</label>
            <input id="inp-maxpaths" type="text" value="10" autocomplete="off" data-lpignore="true">
          </div>
          <div>
            <div class="filter-inline" style="margin-bottom:0;margin-top:18px">
              <label>NOISE FILTER</label>
              <select id="cfg-filter-sel" onchange="syncFilter('cfg')" autocomplete="off" data-form-type="other" data-lpignore="true"></select>
              <span id="filter-desc" class="fdesc"></span>
            </div>
          </div>
        </div>

        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:4px">
          <button class="btn" id="run-btn" onclick="runDiff()">&#x25b6; RUN DIFF</button>
          <button class="btn-sm" onclick="saveSearch()">&#x229e; Save Search</button>
          <button class="btn-sm" onclick="clearAll()">&#x2715; Clear</button>
          <a id="export-file-list-btn" href="/export-file-list" download="diff_file_list.txt"
             class="btn-sm" style="display:none;text-decoration:none">&#x2b07; Export File List</a>
          <span id="run-status" style="font-size:0.68rem;color:var(--muted)"></span>
        </div>
      </div>

      <div id="dev-panel" style="display:none"></div>

    </div>
  </div>
</div>

<script>
'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let networksData  = [];
let diffSavedSearches = [];
let filterDefs    = {};
let currentFilter = 'default';
let runResults    = null;   // { hops, devices_in_broken, analysis, params, ... }
let activeIdx     = null;
let cache         = {};     // deviceName -> analysis result (pre-populated eagerly)

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  try {
    const r    = await fetch('/networks-data');
    const data = await r.json();
    networksData = Array.isArray(data) ? data : (data.networks || []);
  } catch(e) { networksData = []; }

  try {
    const r = await fetch('/config');
    const c = await r.json();
    diffSavedSearches = c.diffSavedSearches || [];
  } catch(e) { diffSavedSearches = []; }

  try {
    const r = await fetch('/filters');
    filterDefs = await r.json();
  } catch(e) { filterDefs = {}; }

  setTimeout(() => {
    buildNetSel();
    buildSavedSel();
    buildFilterSels();
    updateFilterDesc();
  }, 300);
}

// ── Network / snapshot dropdowns ──────────────────────────────────────────────
function buildNetSel() {
  const sel = document.getElementById('sel-net');
  const cur = sel.value;
  sel.innerHTML = '<option value="">\u2014 select network \u2014</option>';
  networksData.forEach(n => {
    const o = document.createElement('option');
    o.value = n.id;
    o.textContent = n.name || n.id;
    sel.appendChild(o);
  });
  if (cur) sel.value = cur;
}

function buildSavedSel() {
  const sel = document.getElementById('saved-sel');
  const cur = sel.value;
  sel.innerHTML = '<option value="">\u2014 select a saved search \u2014</option>';
  diffSavedSearches.forEach((s, i) => {
    const o = document.createElement('option');
    o.value = i;
    o.textContent = s.name || ((s.srcIp || '') + ' \u2192 ' + (s.dstIp || ''));
    sel.appendChild(o);
  });
  if (cur !== '') sel.value = cur;
}

function buildFilterSels() {
  ['hdr-filter-sel', 'cfg-filter-sel'].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const cur = sel.value || currentFilter;
    sel.innerHTML = '';
    Object.keys(filterDefs).forEach(k => {
      const o = document.createElement('option');
      o.value = k; o.textContent = k;
      if (k === cur) o.selected = true;
      sel.appendChild(o);
    });
  });
}

function onNetChange() {
  const netId = document.getElementById('sel-net').value;
  const net   = networksData.find(n => n.id === netId);
  const snaps = net ? (net.snapshots || []) : [];
  ['sel-snap-w', 'sel-snap-b'].forEach(id => {
    const sel = document.getElementById(id);
    sel.innerHTML = '<option value="">Select network first</option>';
    snaps.forEach(s => {
      const o = document.createElement('option');
      o.value = s.id;
      o.textContent = s.label || s.id;
      sel.appendChild(o);
    });
  });
  if (snaps.length >= 1) document.getElementById('sel-snap-w').value = snaps[0].id;
  if (snaps.length >= 2) document.getElementById('sel-snap-b').value = snaps[1].id;
}

function syncFilter(src) {
  const val = document.getElementById(src === 'hdr' ? 'hdr-filter-sel' : 'cfg-filter-sel').value;
  currentFilter = val;
  document.getElementById('hdr-filter-sel').value = val;
  document.getElementById('cfg-filter-sel').value = val;
  updateFilterDesc();
  // Re-render active device with new filter — cache is stale, clear it
  if (activeIdx !== null && runResults) {
    cache = {};
    // Re-populate cache from run results if we have them
    if (runResults.analysis) {
      Object.assign(cache, runResults.analysis);
    }
    const hop = runResults.hops[activeIdx];
    if (hop && cache[hop.deviceName]) showDevPanel(hop, cache[hop.deviceName]);
  }
}

function updateFilterDesc() {
  const el = document.getElementById('filter-desc');
  if (!el) return;
  const f = filterDefs[currentFilter];
  el.textContent = f ? '\u2014 ' + f.description : '';
}

// ── Saved searches ────────────────────────────────────────────────────────────
function applySearch(s) {
  // All diff-saved searches store networkId as the actual ID string.
  const netSel = document.getElementById('sel-net');
  const netId  = String(s.networkId || '');
  if (netId) {
    const opt = Array.from(netSel.options).find(o => String(o.value) === netId);
    if (opt) {
      netSel.value = opt.value;
      onNetChange();  // populates snapshot dropdowns
      // Restore saved snapshot selections after onNetChange fills the options
      if (s.snapWorking) setv('sel-snap-w', s.snapWorking);
      if (s.snapBroken)  setv('sel-snap-b', s.snapBroken);
    }
  }
  setv('inp-src',     s.srcIp         || '');
  setv('inp-dst',     s.dstIp         || '');
  setv('sel-intent',  s.intent        || 'PREFER_DELIVERED');
  setv('sel-proto',   s.ipProto       || '');
  setv('inp-port',    s.dstPort       || '');
  setv('inp-maxcand', s.maxCandidates || '5000');
}

function loadSaved() {
  const idx = document.getElementById('saved-sel').value;
  if (idx === '') return;
  const s = diffSavedSearches[parseInt(idx)];
  if (!s) return;
  if (networksData.length > 0) {
    applySearch(s);
  } else {
    setTimeout(() => applySearch(s), 350);
  }
}

async function deleteSaved() {
  const idx = document.getElementById('saved-sel').value;
  if (idx === '') return;
  const s = diffSavedSearches[parseInt(idx)];
  if (!s) return;
  if (!confirm('Delete saved search "' + (s.name || 'this search') + '"?')) return;
  diffSavedSearches.splice(parseInt(idx), 1);
  await fetch('/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({diffSavedSearches})
  });
  buildSavedSel();
}

async function saveSearch() {
  const name = prompt('Save search as:');
  if (!name) return;
  diffSavedSearches.push({
    name,
    networkId:     document.getElementById('sel-net').value,
    snapWorking:   document.getElementById('sel-snap-w').value,
    snapBroken:    document.getElementById('sel-snap-b').value,
    srcIp:         document.getElementById('inp-src').value.trim(),
    dstIp:         document.getElementById('inp-dst').value.trim(),
    intent:        document.getElementById('sel-intent').value,
    ipProto:       document.getElementById('sel-proto').value,
    dstPort:       document.getElementById('inp-port').value.trim(),
    maxCandidates: document.getElementById('inp-maxcand').value.trim(),
  });
  await fetch('/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({diffSavedSearches})
  });
  buildSavedSel();
}

function clearAll() {
  ['inp-src','inp-dst','inp-port'].forEach(id => setv(id, ''));
  runResults = null; activeIdx = null; cache = {};
  document.getElementById('hop-list').innerHTML =
    '<div class="placeholder"><span class="big">&#x2191;</span><span>Configure and run</span></div>';
  document.getElementById('snap-labels').innerHTML =
    '<span class="snap-label">Select snapshots and run</span>';
  document.getElementById('back-btn').style.display = 'none';
  const _expBtn = document.getElementById('export-file-list-btn');
  if (_expBtn) _expBtn.style.display = 'none';
  const _leg = document.getElementById('hop-legend');
  if (_leg) _leg.classList.remove('visible');
  document.getElementById('hdr-filter').style.display = 'none';
  const _hdrStr = document.getElementById('hdr-search-str');
  if (_hdrStr) _hdrStr.style.display = 'none';
  showCfg();
}

function setv(id, val) { const el = document.getElementById(id); if (el) el.value = val; }

// ── Run ───────────────────────────────────────────────────────────────────────
function runDiff() {
  const netId    = document.getElementById('sel-net').value;
  const snapW    = document.getElementById('sel-snap-w').value;
  const snapB    = document.getElementById('sel-snap-b').value;
  const src      = document.getElementById('inp-src').value.trim();
  const dst      = document.getElementById('inp-dst').value.trim();
  const intent   = document.getElementById('sel-intent').value;
  const proto    = document.getElementById('sel-proto').value;
  const port     = document.getElementById('inp-port').value.trim();
  const maxCand  = parseInt(document.getElementById('inp-maxcand').value) || 5000;
  const maxPaths = parseInt(document.getElementById('inp-maxpaths').value) || 10;
  const maxSec   = parseInt(document.getElementById('inp-maxsec').value)   || 30;

  if (!netId || !snapW || !snapB || !src || !dst) { setStatus('Missing required fields', true); return; }
  if (snapW === snapB) { setStatus('Snapshots must differ', true); return; }

  // Close any existing stream
  if (window._diffStream) { window._diffStream.close(); window._diffStream = null; }

  document.getElementById('run-btn').disabled = true;
  cache = {}; runResults = null; activeIdx = null;

  // Progress elements
  const progWrap  = document.getElementById('analysis-progress');
  const progLabel = progWrap ? progWrap.querySelector('.prog-label') : null;
  const progBar   = document.getElementById('prog-bar');
  if (progWrap) progWrap.style.display = 'flex';
  if (progLabel) progLabel.textContent = 'Connecting\u2026';
  if (progBar)   progBar.style.width = '0%';

  // Build query string for GET request
  const qs = new URLSearchParams({
    networkId: netId, snapWorking: snapW, snapBroken: snapB,
    srcIp: src, dstIp: dst, intent,
    maxCandidates: maxCand, maxPaths, maxSeconds: maxSec,
    filterName: currentFilter,
  });
  if (proto) qs.set('ipProto', proto);
  if (port)  qs.set('dstPort', port);

  let totalDevices = 0;
  let doneDevices  = 0;

  const es = new EventSource('/run-diff-stream?' + qs.toString());
  window._diffStream = es;

  es.onmessage = function(e) {
    let d;
    try { d = JSON.parse(e.data); } catch(err) { return; }

    switch (d.stage) {
      case 'searching':
        setStatus(d.msg);
        if (progLabel) progLabel.textContent = d.msg;
        if (progBar)   progBar.style.width = '5%';
        break;

      case 'hops':
        // Hop list is ready — render left column immediately
        runResults = d;
        runResults.analysis = {};
        renderHopList(d);
        updateSnapLabels(d);
        document.getElementById('hdr-filter').style.display = 'flex';
        document.getElementById('back-btn').style.display   = 'inline-flex';
        showCfg();
        if (progBar) progBar.style.width = '15%';
        break;

      case 'topology':
        setStatus(d.msg);
        if (progLabel) progLabel.textContent = d.msg;
        if (progBar)   progBar.style.width = '25%';
        break;

      case 'analysing':
        totalDevices = d.total;
        if (progLabel) progLabel.textContent = `Analysing devices (0 / ${totalDevices})\u2026`;
        if (progBar)   progBar.style.width = '30%';
        break;

      case 'device':
        doneDevices = d.done;
        totalDevices = d.total;
        // Store analysis in cache and update badge immediately
        if (d.analysis && d.deviceName) {
          cache[d.deviceName] = d.analysis;
          if (runResults) runResults.analysis[d.deviceName] = d.analysis;
        }
        // Find the hop index for this device and update its badge
        if (runResults) {
          const hopIdx = runResults.hops.findIndex(h => h.deviceName === d.deviceName);
          if (hopIdx >= 0) setSevBadge(hopIdx, d.severity);
        }
        const pct = Math.round(30 + (doneDevices / Math.max(totalDevices, 1)) * 65);
        if (progBar)   progBar.style.width = pct + '%';
        if (progLabel) progLabel.textContent =
          `Analysing devices (${doneDevices} / ${totalDevices})\u2026`;
        setStatus(`Analysing devices \u2014 ${doneDevices} / ${totalDevices} done`);
        break;

      case 'done':
        es.close(); window._diffStream = null;
        document.getElementById('run-btn').disabled = false;
        if (progWrap) progWrap.style.display = 'none';
        if (progBar)  progBar.style.width = '0%';
        const nDev = runResults ? runResults.hops.filter(h => !h.synthetic).length : 0;
        setStatus(
          (runResults ? runResults.hops.length : 0) + ' hops \u00b7 ' +
          nDev + ' device(s) analysed'
        );
        // Show export button now that file cache is populated
        const expBtn = document.getElementById('export-file-list-btn');
        if (expBtn) expBtn.style.display = 'inline-block';
        break;

      case 'error':
        es.close(); window._diffStream = null;
        document.getElementById('run-btn').disabled = false;
        if (progWrap) progWrap.style.display = 'none';
        setStatus(d.msg || 'An error occurred', true);
        break;
    }
  };

  es.onerror = function() {
    es.close(); window._diffStream = null;
    document.getElementById('run-btn').disabled = false;
    if (progWrap) progWrap.style.display = 'none';
    // Only show error if we haven't already completed successfully
    if (!runResults || !runResults.hops) {
      setStatus('Connection lost or server error', true);
    }
  };
}


function setStatus(msg, err) {
  const el = document.getElementById('run-status');
  el.textContent = msg;
  el.style.color = err ? 'var(--error)' : 'var(--muted)';
}

const PROTO_MAP = {
  '1':  'ICMP',  '3':  'GGP',   '6':  'TCP',   '8':  'EGP',
  '12': 'PUP',   '17': 'UDP',   '20': 'HMP',   '27': 'RDP',
  '46': 'RSVP',  '47': 'GRE',   '50': 'ESP',   '51': 'AH',
  '58': 'ICMPv6','66': 'RVD',   '88': 'IGMP',  '89': 'OSPF'
};

function buildSearchStr(p) {
  if (!p || !p.srcIp) return '';
  let s = `f(${p.srcIp})`;
  if (p.dstIp)   s += `(ipv4_dst.${p.dstIp})`;
  if (p.ipProto) s += `(ip_proto.${PROTO_MAP[String(p.ipProto)] || p.ipProto})`;
  if (p.dstPort) s += `(tp_dst.${p.dstPort})`;
  s += `m(permit_all)`;
  return s;
}

function updateSnapLabels(data) {
  const wl = data.snap_working_label || data.params.snapWorking;
  const bl = data.snap_broken_label  || data.params.snapBroken;
  const wc = data.working_path_count != null ? data.working_path_count : '?';
  const bc = data.broken_path_count  != null ? data.broken_path_count  : '?';
  const p  = data.params || {};
  document.getElementById('snap-labels').innerHTML =
    `<div><span class="snap-working">&#x25cf; working</span> <span class="snap-label">${esc(wl)} &middot; ${wc} path(s)</span></div>` +
    `<div style="margin-top:2px"><span class="snap-broken">&#x25cf; broken</span> <span class="snap-label">${esc(bl)} &middot; ${bc} path(s)</span></div>`;
  const searchStr = buildSearchStr(p);
  const hdrStr = document.getElementById('hdr-search-str');
  if (hdrStr) {
    hdrStr.textContent = searchStr;
    hdrStr.style.display = searchStr ? 'inline' : 'none';
    hdrStr.title = searchStr;
  }
}

// ── Hop list ──────────────────────────────────────────────────────────────────
function renderHopList(data) {
  const legend = document.getElementById('hop-legend');
  if (legend) legend.classList.add('visible');
  const list = document.getElementById('hop-list');
  list.innerHTML = '';
  data.hops.forEach((hop, i) => {
    const inB   = data.devices_in_broken.includes(hop.deviceName);
    const synth = hop.synthetic;
    const row   = document.createElement('div');
    row.className = 'hop-row' + (synth ? ' synthetic' : '');
    row.dataset.idx = i;
    row.innerHTML =
      `<span class="hop-num">${i+1}</span>` +
      `<span class="presence ${synth ? 'synth' : inB ? 'present' : 'absent'}" ` +
        `title="${synth ? 'synthetic' : inB ? 'present in broken snapshot' : 'absent from broken snapshot'}"></span>` +
      `<span class="hop-name" title="${esc(hop.deviceName)}">${esc(hop.displayName || hop.deviceName)}</span>` +
      `<span class="hop-type">${esc(hop.deviceType || '')}</span>` +
      `<span class="sev sev-pending" id="sev-${i}">\u2026</span>`;
    if (!synth) row.addEventListener('click', () => selectHop(i));
    list.appendChild(row);
  });
}

function selectHop(idx) {
  document.querySelectorAll('.hop-row').forEach(r => r.classList.remove('active'));
  const row = document.querySelector(`.hop-row[data-idx="${idx}"]`);
  if (row) row.classList.add('active');
  activeIdx = idx;
  const hop = runResults.hops[idx];
  setRightTitle('DEVICE: ' + (hop.displayName || hop.deviceName));

  // Always instant — cache is pre-populated
  if (cache[hop.deviceName]) {
    showDevPanel(hop, cache[hop.deviceName]);
    return;
  }
  // Fallback: device was synthetic or analysis not available
  if (hop.synthetic) {
    document.getElementById('cfg-panel').style.display = 'none';
    const dp = document.getElementById('dev-panel');
    dp.style.display = '';
    dp.innerHTML = '<div class="loading-msg" style="color:var(--muted)">Synthetic/carrier object \u2014 no device API endpoints.</div>';
  }
}

function setSevBadge(idx, sev) {
  const el = document.getElementById('sev-' + idx);
  if (!el) return;
  const map = {error:['sev-error','!'], warn:['sev-warn','\u25b3'], info:['sev-info','\u25cf'], clean:['sev-clean','\u2713']};
  const [cls, lbl] = map[sev] || ['sev-pending', '\u2026'];
  el.className = 'sev ' + cls;
  el.textContent = lbl;
}

// ── Right panel ───────────────────────────────────────────────────────────────
function showCfg() {
  document.getElementById('cfg-panel').style.display = '';
  document.getElementById('dev-panel').style.display = 'none';
  setRightTitle('CONFIGURATION');
}
function setRightTitle(t) { document.getElementById('right-title').textContent = t; }

function showDevPanel(hop, data) {
  document.getElementById('cfg-panel').style.display = 'none';
  const dp = document.getElementById('dev-panel');
  dp.style.display = '';
  if (data.synthetic) {
    dp.innerHTML = '<div class="loading-msg" style="color:var(--muted)">Synthetic/carrier object \u2014 no device API endpoints available.</div>';
    return;
  }
  const errs = (data.errors || []).map(e => `<div style="color:var(--error);font-size:0.67rem;margin-bottom:4px">&#x26a0; ${esc(e)}</div>`).join('');
  dp.innerHTML = errs + renderMeta(data.metadata) + renderTopo(data.topology) + renderFiles(data.files);
}

// ── Metadata ──────────────────────────────────────────────────────────────────
function renderMeta(meta) {
  const chg = meta.any_changed;
  const rows = (meta.rows || []).map(r => {
    const wv = r.working != null ? esc(String(r.working)) : '<span class="val-null">\u2014</span>';
    const bv = r.broken  != null ? esc(String(r.broken))  : '<span class="val-null">\u2014</span>';
    return `<tr${r.changed ? ' class="changed"' : ''}>` +
      `<td>${esc(r.field)}</td>` +
      `<td>${r.changed ? `<span class="val-chg">${wv}</span>` : wv}</td>` +
      `<td>${r.changed ? `<span class="val-chg">${bv}</span>` : bv}</td></tr>`;
  }).join('');
  return mkSection('DEVICE METADATA', chg ? 'CHANGED' : 'no change', chg ? 'badge-changed' : 'badge-ok', chg,
    `<table class="meta-tbl"><thead><tr><th>FIELD</th><th>WORKING</th><th>BROKEN</th></tr></thead><tbody>${rows}</tbody></table>`);
}

// ── Topology ──────────────────────────────────────────────────────────────────
function renderTopo(topo) {
  const chg = topo.any_changed;
  const badge = chg ? (topo.lost_count + ' lost, ' + topo.new_count + ' new') : 'no change';
  const rows = (topo.rows || []).map(r => {
    const cls = 'link-' + r.status;
    const pfx = r.status === 'lost' ? '\u2212' : r.status === 'new' ? '+' : ' ';
    return `<tr><td class="${cls} link-stat">${pfx} ${r.status.toUpperCase()}</td>` +
      `<td class="${cls}">${esc(r.sourcePort)}</td>` +
      `<td class="${cls}">\u2194 ${esc(r.targetPort)}</td></tr>`;
  }).join('');
  const body = rows
    ? `<table class="topo-tbl"><thead><tr><th>STATUS</th><th>SOURCE PORT</th><th>TARGET PORT</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div style="color:var(--muted);font-size:0.69rem">No topology links found for this device.</div>';
  return mkSection('TOPOLOGY LINKS', badge, chg ? 'badge-changed' : 'badge-ok', chg, body);
}

// ── Files ─────────────────────────────────────────────────────────────────────
function renderFiles(files) {
  const anyChg  = files.some(f => f.changed || f.status === 'only_working' || f.status === 'only_broken');
  const cnt     = files.filter(f => f.changed || f.status === 'only_working' || f.status === 'only_broken').length;
  const badge   = anyChg ? (cnt + ' file(s) changed') : 'no change';
  const items   = files.map((f, i) => renderFileItem(f, i)).join('');
  return mkSection('FILE DIFF', badge, anyChg ? 'badge-changed' : 'badge-ok', anyChg,
    `<div class="file-list">${items || '<div style="color:var(--muted);font-size:0.69rem">No files available.</div>'}</div>`);
}

function renderFileItem(f, i) {
  const id = 'fb-' + i;
  let bcls, btxt;
  if      (f.status === 'only_working') { bcls = 'fb-only-w'; btxt = 'ONLY IN WORKING'; }
  else if (f.status === 'only_broken')  { bcls = 'fb-only-b'; btxt = 'ONLY IN BROKEN'; }
  else if (f.status === 'error')        { bcls = 'fb-error';  btxt = 'ERROR'; }
  else if (f.changed)                   { bcls = 'fb-changed'; btxt = 'CHANGED'; }
  else                                  { bcls = 'fb-unchanged'; btxt = 'unchanged'; }
  const autoOpen = f.changed && !f.noisy;
  let body = '';
  if (f.status === 'diff' && f.changed) {
    const suppNote = f.suppressed_count > 0 ? `<div class="supp-note">${f.suppressed_count} line(s) suppressed by noise filter</div>` : '';
    const lines = (f.meaningful_lines || []).map(l => {
      if (l.startsWith('+') && !l.startsWith('+++')) return `<div class="diff-line diff-add">${esc(l)}</div>`;
      if (l.startsWith('-') && !l.startsWith('---')) return `<div class="diff-line diff-del">${esc(l)}</div>`;
      if (l.startsWith('@@')) return `<div class="diff-line diff-hdr">${esc(l)}</div>`;
      return `<div class="diff-line diff-ctx">${esc(l)}</div>`;
    }).join('');
    const rawLines = (f.raw_lines || []).map(l => {
      if (l.startsWith('+') && !l.startsWith('+++')) return `<div class="diff-line diff-add">${esc(l)}</div>`;
      if (l.startsWith('-') && !l.startsWith('---')) return `<div class="diff-line diff-del">${esc(l)}</div>`;
      if (l.startsWith('@@')) return `<div class="diff-line diff-hdr">${esc(l)}</div>`;
      return `<div class="diff-line diff-ctx">${esc(l)}</div>`;
    }).join('');
    const hasRaw = f.raw_lines && f.raw_lines.length !== (f.meaningful_lines || []).length;
    const mCount = (f.meaningful_lines || []).filter(l => (l.startsWith('+') && !l.startsWith('+++')) || (l.startsWith('-') && !l.startsWith('---'))).length;
    body = `<div class="diff-meta"><span>${mCount} meaningful changes</span>${f.suppressed_count ? `<span>${f.suppressed_count} suppressed</span>` : ''}</div>` +
      suppNote + `<div class="diff-view">${lines}</div>` +
      (hasRaw ? `<div class="diff-toggle"><button class="btn-sm" onclick="toggleRaw('raw-${i}',this)">show raw diff</button><div id="raw-${i}" style="display:none"><div class="diff-view">${rawLines}</div></div></div>` : '');
  } else if (f.status === 'diff' && !f.changed) {
    body = '<div style="padding:7px 10px;font-size:0.67rem;color:var(--muted)">Files are identical.</div>';
  } else if (f.status === 'error') {
    body = `<div style="padding:7px 10px;font-size:0.67rem;color:var(--error)">${esc(f.error || 'Unknown error')}</div>`;
  }
  return `<div class="file-item">` +
    `<div class="file-hdr" onclick="toggleFileBody('${id}')">` +
    `<span class="file-name">${esc(f.name)}</span>` +
    (f.noisy ? '<span style="font-size:0.57rem;color:var(--muted)">(high-noise)</span>' : '') +
    `<span class="file-badge ${bcls}">${btxt}</span></div>` +
    `<div class="file-body${autoOpen ? ' open' : ''}" id="${id}">${body}</div></div>`;
}

// ── Section helper ────────────────────────────────────────────────────────────
function mkSection(title, badge, badgeCls, open, body) {
  return `<div class="section">` +
    `<div class="sec-hdr${open ? ' open' : ''}" onclick="toggleSec(this)">` +
    `<span class="chev">${open ? '\u25bc' : '\u25b6'}</span>` +
    `<span class="sec-title">${title}</span>` +
    `<span class="sec-badge ${badgeCls}">${badge}</span></div>` +
    `<div class="sec-body${open ? ' open' : ''}">${body}</div></div>`;
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function toggleSec(hdr) {
  const body = hdr.nextElementSibling;
  const chev = hdr.querySelector('.chev');
  const open = body.classList.toggle('open');
  hdr.classList.toggle('open', open);
  if (chev) chev.textContent = open ? '\u25bc' : '\u25b6';
}
function toggleFileBody(id) { const el = document.getElementById(id); if (el) el.classList.toggle('open'); }
function toggleRaw(id, btn) {
  const el = document.getElementById(id); if (!el) return;
  const open = el.style.display === 'none';
  el.style.display = open ? '' : 'none';
  btn.textContent  = open ? 'hide raw diff' : 'show raw diff';
}
function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

boot();
</script>
</body>
</html>"""



# ─────────────────────────────────────────────────────────────────────────────
# HTTP Handler
# ─────────────────────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # SSE stream endpoint — path includes query string
        if self.path.startswith('/run-diff-stream'):
            qs = self.path[len('/run-diff-stream'):]
            if qs.startswith('?'): qs = qs[1:]
            self._handle_run_diff_stream(qs)
        elif self.path == '/export-file-list':
            self._handle_export_file_list()
        elif self.path == '/networks-data':
            self._json(NETWORKS_DATA)
        elif self.path == '/config':
            self._json(read_config())
        elif self.path == '/filters':
            self._json(load_filters())
        else:
            self._respond(200, 'text/html; charset=utf-8', HTML.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw    = self.rfile.read(length)

        if self.path == '/config':
            try:
                data = json.loads(raw)
                write_config(data)
                self._json({"ok": True})
            except Exception:
                self._respond(400, 'application/json', b'{"ok":false}')

        elif self.path == '/run-diff':
            self._handle_run_diff(raw)


        elif self.path == '/analyze-device':
            self._handle_analyze_device(raw)

        else:
            self._respond(404, 'application/json', b'{"ok":false}')

    def _handle_run_diff(self, raw):
        try:
            req      = json.loads(raw)
            base_url = os.environ.get('FWD_BASE_URL', 'https://fwd.app')
            net_id   = req['networkId']
            snap_w   = req['snapWorking']
            snap_b   = req['snapBroken']
            src_ip   = req['srcIp']
            dst_ip   = req['dstIp']
            intent   = req.get('intent', 'PREFER_DELIVERED')
            ip_proto = req.get('ipProto')
            dst_port = req.get('dstPort')
            max_cand = int(req.get('maxCandidates', 5000))
            max_paths= int(req.get('maxPaths', 10))
            max_sec  = int(req.get('maxSeconds', 30))

            # Path search — working snapshot
            _, body_w, _, err_w = run_path_search(
                base_url, net_id, snap_w, src_ip, dst_ip,
                intent, max_cand, max_paths, ip_proto, dst_port, max_sec
            )
            if err_w and body_w is None:
                self._json({'error': f'Path search failed on working snapshot: {err_w}'})
                return

            # Path search — broken snapshot (failure here is OK — may return nothing)
            _, body_b, _, _ = run_path_search(
                base_url, net_id, snap_b, src_ip, dst_ip,
                intent, max_cand, max_paths, ip_proto, dst_port, max_sec
            )

            # Build device investigation set from working path
            ordered_hops, all_device_names = build_device_set(body_w or {}, max_paths)
            if not ordered_hops:
                self._json({'error': 'No paths returned from working snapshot. Check search parameters.'})
                return

            for hop in ordered_hops:
                hop['synthetic'] = is_synthetic(hop['deviceName'])

            # Devices present in broken snapshot paths
            broken_paths = (body_b or {}).get('info', {}).get('paths', [])
            devices_in_broken = list({
                h.get('deviceName', '')
                for p in broken_paths
                for h in p.get('hops', [])
                if h.get('deviceName')
            })

            # Snapshot labels
            net   = next((n for n in NETWORKS_DATA if n['id'] == net_id), None)
            snaps = net['snapshots'] if net else []
            def snap_label(sid):
                s = next((x for x in snaps if x['id'] == sid), None)
                return s['label'] if s else sid

            # Fetch topology for both snapshots and cache
            topo_w, _ = get_topology(base_url, net_id, snap_w)
            topo_b, _ = get_topology(base_url, net_id, snap_b)
            _topo_cache[f"{net_id}:{snap_w}"] = topo_w
            _topo_cache[f"{net_id}:{snap_b}"] = topo_b

            def hit_count(body):
                th = (body or {}).get('info', {}).get('totalHits', {})
                return th.get('value') if isinstance(th, dict) else th

            self._json({
                'hops':                ordered_hops,
                'unique_device_count': len(all_device_names),
                'devices_in_broken':   devices_in_broken,
                'snap_working_label':  snap_label(snap_w),
                'snap_broken_label':   snap_label(snap_b),
                'working_path_count':  hit_count(body_w),
                'broken_path_count':   hit_count(body_b),
                'params': {
                    'networkId':   net_id,
                    'snapWorking': snap_w,
                    'snapBroken':  snap_b,
                    'srcIp':       src_ip,
                    'dstIp':       dst_ip,
                    'intent':      intent,
                    'ipProto':     ip_proto,
                    'dstPort':     dst_port,
                },
            })
        except Exception as e:
            self._json({'error': str(e)})

    def _stream_event(self, data_dict):
        """Write one SSE event and flush. Must be called after SSE headers sent."""
        line = 'data: ' + json.dumps(data_dict) + '\n\n'
        self.wfile.write(line.encode('utf-8'))
        self.wfile.flush()

    def _handle_run_diff_stream(self, qs):
        """
        GET /run-diff-stream?<params>
        Streams Server-Sent Events while running path searches and device analysis.
        Event sequence:
          {stage:'searching',  msg:'...'}
          {stage:'hops',       hops:[...], devices_in_broken:[...], ...}
          {stage:'topology',   msg:'...'}
          {stage:'analysing',  total:N, done:0}
          {stage:'device',     done:K, total:N, deviceName:'...', severity:'...', analysis:{...}}
          {stage:'done'}
        On error: {stage:'error', msg:'...'}
        """
        # Parse query string
        params      = urllib.parse.parse_qs(qs)
        def qp(k, default=None): v = params.get(k); return v[0] if v else default

        base_url    = os.environ.get('FWD_BASE_URL', 'https://fwd.app')
        net_id      = qp('networkId', '')
        snap_w      = qp('snapWorking', '')
        snap_b      = qp('snapBroken', '')
        src_ip      = qp('srcIp', '')
        dst_ip      = qp('dstIp', '')
        intent      = qp('intent', 'PREFER_DELIVERED')
        ip_proto    = qp('ipProto')
        dst_port    = qp('dstPort')
        max_cand    = int(qp('maxCandidates', '5000'))
        max_paths   = int(qp('maxPaths', '10'))
        max_sec     = int(qp('maxSeconds', '30'))
        filter_name = qp('filterName', 'default')

        # Send SSE headers
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('X-Accel-Buffering', 'no')
        self.end_headers()

        def emit(d):
            self._stream_event(d)

        try:
            # Clear file name cache for this run
            _file_name_cache.clear()

            # ── Stage 1: path searches ───────────────────────────────────────
            emit({'stage': 'searching', 'msg': 'Running path search on working snapshot…'})

            _, body_w, _, err_w = run_path_search(
                base_url, net_id, snap_w, src_ip, dst_ip,
                intent, max_cand, max_paths, ip_proto, dst_port, max_sec
            )
            if err_w and body_w is None:
                emit({'stage': 'error', 'msg': f'Path search failed on working snapshot: {err_w}'})
                return

            emit({'stage': 'searching', 'msg': 'Running path search on broken snapshot…'})
            _, body_b, _, _ = run_path_search(
                base_url, net_id, snap_b, src_ip, dst_ip,
                intent, max_cand, max_paths, ip_proto, dst_port, max_sec
            )

            ordered_hops, all_device_names = build_device_set(body_w or {}, max_paths)
            if not ordered_hops:
                emit({'stage': 'error', 'msg': 'No paths returned from working snapshot. Check search parameters.'})
                return

            for hop in ordered_hops:
                hop['synthetic'] = is_synthetic(hop['deviceName'])

            broken_paths = (body_b or {}).get('info', {}).get('paths', [])
            devices_in_broken = list({
                h.get('deviceName', '')
                for p in broken_paths
                for h in p.get('hops', [])
                if h.get('deviceName')
            })

            net   = next((n for n in NETWORKS_DATA if n['id'] == net_id), None)
            snaps = net['snapshots'] if net else []
            def snap_label(sid):
                s = next((x for x in snaps if x['id'] == sid), None)
                return s['label'] if s else sid

            def hit_count(body):
                th = (body or {}).get('info', {}).get('totalHits', {})
                return th.get('value') if isinstance(th, dict) else th

            # ── Stage 2: emit hop list so UI can render left column ──────────
            emit({
                'stage':               'hops',
                'hops':                ordered_hops,
                'unique_device_count': len(all_device_names),
                'devices_in_broken':   devices_in_broken,
                'snap_working_label':  snap_label(snap_w),
                'snap_broken_label':   snap_label(snap_b),
                'working_path_count':  hit_count(body_w),
                'broken_path_count':   hit_count(body_b),
                'params': {
                    'networkId':   net_id,
                    'snapWorking': snap_w,
                    'snapBroken':  snap_b,
                    'srcIp':       src_ip,
                    'dstIp':       dst_ip,
                    'intent':      intent,
                    'ipProto':     ip_proto,
                    'dstPort':     dst_port,
                },
            })

            # ── Stage 3: topology ────────────────────────────────────────────
            emit({'stage': 'topology', 'msg': 'Fetching topology for both snapshots…'})
            topo_w, _ = get_topology(base_url, net_id, snap_w)
            topo_b, _ = get_topology(base_url, net_id, snap_b)
            _topo_cache[f"{net_id}:{snap_w}"] = topo_w
            _topo_cache[f"{net_id}:{snap_b}"] = topo_b

            # ── Stage 4: parallel device analysis ───────────────────────────
            filters       = load_filters()
            non_synthetic = [h for h in ordered_hops if not h['synthetic']]
            total         = len(non_synthetic)
            done_count    = 0

            emit({'stage': 'analysing', 'total': total, 'done': 0,
                  'msg': f'Analysing {total} device(s)…'})

            def analyse_one(hop):
                return hop['deviceName'], analyze_device(
                    base_url, net_id, hop['deviceName'],
                    snap_w, snap_b, topo_w, topo_b,
                    filter_name, filters
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=ANALYSIS_POOL_SIZE) as pool:
                futures = {pool.submit(analyse_one, h): h for h in non_synthetic}
                for fut in concurrent.futures.as_completed(futures):
                    done_count += 1
                    try:
                        name, result = fut.result()
                    except Exception as e:
                        hop  = futures[fut]
                        name = hop['deviceName']
                        result = {
                            'deviceName': name, 'synthetic': False,
                            'severity': 'error', 'errors': [str(e)],
                            'metadata': {}, 'topology': {}, 'files': []
                        }
                    emit({
                        'stage':      'device',
                        'done':       done_count,
                        'total':      total,
                        'deviceName': name,
                        'severity':   result.get('severity', 'clean'),
                        'analysis':   result,
                    })

            emit({'stage': 'done'})

        except Exception as e:
            try:
                emit({'stage': 'error', 'msg': str(e)})
            except Exception:
                pass


    def _handle_analyze_device(self, raw):
        try:
            req         = json.loads(raw)
            base_url    = os.environ.get('FWD_BASE_URL', 'https://fwd.app')
            net_id      = req['networkId']
            device_name = req['deviceName']
            snap_w      = req['snapWorking']
            snap_b      = req['snapBroken']
            filter_name = req.get('filterName', 'default')

            topo_w  = _topo_cache.get(f"{net_id}:{snap_w}", [])
            topo_b  = _topo_cache.get(f"{net_id}:{snap_b}", [])
            filters = load_filters()

            result = analyze_device(
                base_url, net_id, device_name,
                snap_w, snap_b,
                topo_w, topo_b,
                filter_name, filters
            )
            self._json(result)
        except Exception as e:
            self._json({'severity': 'error', 'errors': [str(e)],
                        'synthetic': False, 'metadata': {}, 'topology': {}, 'files': []})

    def _handle_export_file_list(self):
        """Return sorted unique file names seen in last run as plain text.
        Annotates each file: [included], [excluded-list], [excluded-prefix], [excluded-file]
        """
        if not _file_name_cache:
            body = b'# No file data yet - run a diff first\n'
        else:
            all_seen = sorted(_file_name_cache)
            header = (
                '# Unique file names across all devices in last diff run\n'
                '# Status: [diffed] = currently diffed | [skipped] = not diffed\n'
                '# To change what gets diffed, edit INCLUDE_FILES in path_search_diff.py\n\n'
            )
            annotated = []
            for name in all_seen:
                if name in EXCLUDE_FILES:
                    status = '[skipped:always-excluded]'
                elif name.startswith(EXCLUDE_PREFIXES):
                    status = '[skipped:prefix-excluded]'
                elif INCLUDE_FILES and name not in INCLUDE_FILES:
                    status = '[skipped:not-in-include-list]'
                else:
                    status = '[diffed]'
                annotated.append(f'{name:<55} {status}')
            body = (header + '\n'.join(annotated) + '\n').encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="diff_file_list.txt"')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        body = json.dumps(obj).encode('utf-8')
        self._respond(200, 'application/json', body)

    def _respond(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def run():
    print('\n  \u2b61  Forward Networks \u2014 Path Search Diff Tool')
    print('  ' + '\u2500' * 50)
    global NETWORKS_DATA
    args = _helpers.parse_args()
    _ensure_filters_file()
    base_url, NETWORKS_DATA = _helpers.collect_credentials(
        CREDENTIALS, args, _load_discovery().discover_all)

    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)

    if not args['no_browser']:
        def open_browser():
            time.sleep(0.4)
            webbrowser.open(f'http://localhost:{PORT}')
        threading.Thread(target=open_browser, daemon=True).start()

    print(f'     Running at: http://localhost:{PORT}')
    print(f'     Press Ctrl\u2013C to quit\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n  Shutting down. Goodbye.\n')
        server.shutdown()


if __name__ == '__main__':
    run()