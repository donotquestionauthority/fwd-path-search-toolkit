#!/usr/bin/env python3
"""
fwd_helpers.py — Shared utilities for the Forward Networks Path Search Toolkit.

Provides credential loading, argument parsing, and common helpers used by all tools.
Import with:
    import importlib.util, os
    _h = importlib.util.spec_from_file_location(
             "fwd_helpers",
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_helpers.py"))
    helpers = importlib.util.module_from_spec(_h); _h.loader.exec_module(helpers)
"""

import base64
import http.server
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


# ─────────────────────────────────────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────────────────────────────────────

# Single source of truth for all API call timeouts across the toolkit.
# Applied to every urlopen() call and every concurrent.futures.as_completed()
# wait.  Path search socket timeouts use maxSeconds + API_TIMEOUT_S so the
# socket outlives the server-side search budget.
API_TIMEOUT_S = 150


# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_args(argv=None):
    """Parse toolkit command-line arguments.

    Recognised flags:
      --no-browser              Suppress automatic browser launch (used by launcher)
      --keychain                Load credentials from macOS Keychain (requires --instance + --network)
      --instance <hostname>     Forward Networks instance hostname, e.g. fwd.app
      --network  <id>           Network ID to load (repeatable)

    Returns a dict:
      {
        "no_browser": bool,
        "use_keychain": bool,
        "instance": str or None,
        "network_ids": [str, ...],
      }
    """
    if argv is None:
        argv = sys.argv[1:]

    result = {
        "no_browser":   False,
        "use_keychain": False,
        "instance":     None,
        "network_ids":  [],
    }

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--no-browser":
            result["no_browser"] = True
        elif arg == "--keychain":
            result["use_keychain"] = True
        elif arg == "--instance" and i + 1 < len(argv):
            result["instance"] = argv[i + 1]; i += 1
        elif arg == "--network" and i + 1 < len(argv):
            result["network_ids"].append(argv[i + 1]); i += 1
        i += 1

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Credential loading
# ─────────────────────────────────────────────────────────────────────────────

def load_credentials_from_env(credentials_dict):
    """Scan FWD_CREDS_* environment variables and populate credentials_dict.
    Returns number of credentials found.
    """
    prefix = "FWD_CREDS_"
    found  = 0
    for key, val in os.environ.items():
        if key.startswith(prefix):
            net_id = key[len(prefix):]
            token  = base64.b64encode(val.encode()).decode()
            credentials_dict[net_id] = f"Basic {token}"
            found += 1
    return found


def load_credentials_from_keychain(credentials_dict, instance, network_ids):
    """Load credentials from macOS Keychain for the given instance and network IDs.
    Credentials are held in memory only — never written to disk.
    Returns number of credentials successfully loaded.
    """
    service = f"fwd-path-search-toolkit:{instance}"
    found   = 0
    for net_id in network_ids:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", service, "-a", net_id, "-w"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"  ⚠  No keychain entry found for network {net_id} in '{service}'")
                continue
            val   = result.stdout.strip()
            token = base64.b64encode(val.encode()).decode()
            credentials_dict[net_id] = f"Basic {token}"
            print(f"  ✓  Network {net_id} credential loaded from keychain.")
            found += 1
        except FileNotFoundError:
            print("  ⚠  'security' command not found — keychain is only supported on macOS.")
            sys.exit(1)
        except Exception as e:
            print(f"  ⚠  Keychain lookup failed for network {net_id}: {e}")
    return found


def prompt_for_credentials(credentials_dict):
    """Prompt operator for network ID and credentials at runtime.
    Credentials are held in memory only — never written to disk.
    """
    import getpass
    print("  No credentials found in environment.")
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
            credentials_dict[net_id] = f"Basic {token}"
            print(f"  ✓  Network {net_id} credential stored.\n")
        else:
            print("  ⚠  Both access key and secret key are required. Try again.\n")
    if not credentials_dict:
        print("  ⚠  No credentials entered. Exiting.\n")
        sys.exit(1)


def collect_credentials(credentials_dict, args, discovery_fn):
    """Top-level credential collection and network discovery.

    Selects the appropriate credential source based on parsed args:
      - --keychain: macOS Keychain
      - FWD_CREDS_* env vars: environment
      - neither: interactive prompt

    After loading credentials, calls discovery_fn(base_url, credentials_dict)
    to populate network/snapshot data.

    Returns base_url string.
    """
    if args["use_keychain"]:
        instance = args["instance"]
        network_ids = args["network_ids"]
        if not instance:
            print("  ⚠  --keychain requires --instance <hostname>  e.g. --instance fwd.app\n")
            sys.exit(1)
        if not network_ids:
            print("  ⚠  --keychain requires at least one --network <id>\n")
            sys.exit(1)
        base_url = f"https://{instance}"
        found = load_credentials_from_keychain(credentials_dict, instance, network_ids)
        if found == 0:
            print("  ⚠  No credentials loaded from keychain. Exiting.\n")
            sys.exit(1)
    else:
        if args["instance"]:
            base_url = f"https://{args['instance']}"
        else:
            base_url = os.environ.get("FWD_BASE_URL", "https://fwd.app")
        found = load_credentials_from_env(credentials_dict)
        if found == 0:
            prompt_for_credentials(credentials_dict)
        else:
            print(f"  ✓  {found} network credential(s) loaded from environment.")

    print("  Discovering networks and snapshots...\n")
    try:
        networks_data = discovery_fn(base_url, credentials_dict)
        print()
        return base_url, networks_data
    except Exception as e:
        print(f"  ⚠  Discovery failed: {e}\n")
        fallback = [{"id": nid, "name": nid, "snapshots": []} for nid in credentials_dict]
        return base_url, fallback


# ─────────────────────────────────────────────────────────────────────────────
# Domain constants
# ─────────────────────────────────────────────────────────────────────────────

# Device types the Forward Networks API treats as firewalls. Used by all tools
# that detect or count firewall hops; importing from one place keeps cloud
# firewalls (AWS_NETWORK_FIREWALL, AZURE_FIREWALL) from being silently missed.
FIREWALL_TYPES = frozenset((
    "FIREWALL",
    "AWS_NETWORK_FIREWALL",
    "AZURE_FIREWALL",
))


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_snapshot_label(networks_data, network_id, snapshot_id):
    """Return a human-readable label for a snapshot ID.
    Falls back to the last 8 characters of the ID if not found.
    """
    for net in networks_data:
        if net["id"] == network_id:
            for s in net.get("snapshots", []):
                if s["id"] == snapshot_id:
                    return s.get("label") or snapshot_id[-8:]
    return snapshot_id[-8:]


# ─────────────────────────────────────────────────────────────────────────────
# Path search
# ─────────────────────────────────────────────────────────────────────────────

def build_path_search_url(base_url, network_id, snapshot_id, src_ip, dst_ip,
                          intent="PREFER_DELIVERED",
                          max_candidates=5000, max_results=1, max_seconds=30,
                          ip_proto=None, dst_port=None):
    """Construct the full Path Search API URL (with query string) without
    issuing the request. Used by tools that need to display or copy the URL
    in addition to executing the search.

    intent may be None or empty to omit it from the URL — the API will use
    its server-side default in that case.
    max_candidates may be None to omit it (server-side default applies).
    """
    params = {
        "srcIp":      src_ip,
        "dstIp":      dst_ip,
        "maxResults": str(max_results),
        "maxSeconds": str(max_seconds),
    }
    if intent:
        params["intent"] = intent
    if max_candidates:
        params["maxCandidates"] = str(max_candidates)
    if snapshot_id:
        params["snapshotId"] = snapshot_id
    if ip_proto:
        params["ipProto"] = str(ip_proto)
    if dst_port:
        params["dstPort"] = str(dst_port)
    qs = urllib.parse.urlencode(params)
    return f"{base_url.rstrip('/')}/api/networks/{network_id}/paths?{qs}"


def run_path_search(base_url, credentials, network_id, snapshot_id,
                    src_ip, dst_ip,
                    intent="PREFER_DELIVERED",
                    max_candidates=5000, max_results=1, max_seconds=30,
                    ip_proto=None, dst_port=None,
                    retries=1, retry_delay=3):
    """Run a Forward Networks Path Search API call.

    Single point of truth for path search across the toolkit. The socket
    timeout is `max_seconds + API_TIMEOUT_S` so the socket outlives the
    server-side search budget. Transient socket failures are retried with
    a fixed delay; HTTP errors (4xx/5xx) are returned immediately.

    Args:
      base_url:       Forward Networks instance URL (e.g. "https://fwd.app")
      credentials:    dict {network_id: "Basic <base64>"}; the caller's
                      module-level CREDENTIALS dict is passed in directly so
                      this helper holds no state of its own.
      network_id:     str, must be a key in `credentials`
      snapshot_id:    str (optional — pass empty/None to use the live network)
      src_ip, dst_ip: required IPs
      intent:         "PREFER_DELIVERED" | "PREFER_VIOLATIONS" | "VIOLATIONS_ONLY"
      retries:        number of additional attempts on transient failure
                      (0 disables retry; default 1 = 2 attempts total)
      retry_delay:    seconds to sleep between attempts

    Returns:
      (status, body_dict_or_None, elapsed_ms, error_or_None)

      - On success: (status_code, parsed_json_dict, ms, None)
      - On HTTP 4xx/5xx: (status_code, parsed_body_or_{"_raw": text}, ms, "HTTP {code}")
      - On transient failure with retries exhausted: (None, None, ms, str(exception))
      - On missing credentials: (None, None, 0, "No credentials for network {id}")
    """
    if network_id not in credentials:
        return None, None, 0, f"No credentials for network {network_id}"

    url = build_path_search_url(
        base_url, network_id, snapshot_id, src_ip, dst_ip,
        intent=intent,
        max_candidates=max_candidates, max_results=max_results, max_seconds=max_seconds,
        ip_proto=ip_proto, dst_port=dst_port,
    )
    req = urllib.request.Request(url)
    req.add_header("Authorization", credentials[network_id])
    req.add_header("Accept", "application/json")

    socket_timeout = max_seconds + API_TIMEOUT_S
    t0 = time.time()
    last_err = None

    for attempt in range(1 + retries):
        try:
            with urllib.request.urlopen(req, timeout=socket_timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body, round((time.time() - t0) * 1000), None
        except urllib.error.HTTPError as e:
            # HTTP errors are definitive — don't retry.
            raw = e.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(raw)
            except Exception:
                body = {"_raw": raw}
            return e.code, body, round((time.time() - t0) * 1000), f"HTTP {e.code}"
        except Exception as ex:
            last_err = str(ex)
            if attempt < retries:
                time.sleep(retry_delay)
            continue

    return None, None, round((time.time() - t0) * 1000), last_err


# ─────────────────────────────────────────────────────────────────────────────
# HTTP server
# ─────────────────────────────────────────────────────────────────────────────

class ToolkitServer(http.server.ThreadingHTTPServer):
    """Shared base server for all toolkit tools.

    Provides:
    * Threaded request handling — long-running path searches and SSE streams
      no longer block health-check pings from the launcher.
    * Daemon worker threads — Ctrl+C exits cleanly even if requests are
      still in flight.
    * BrokenPipeError / ConnectionResetError suppression — these are routine
      when a browser closes a connection mid-response (refresh, navigate
      away, hit Stop) and produce noisy tracebacks otherwise.
    """
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(
            exc_type, (BrokenPipeError, ConnectionResetError)
        ):
            return
        super().handle_error(request, client_address)