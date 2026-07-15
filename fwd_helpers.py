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
import errno
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
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
      --port     <n>            Preferred port to bind (falls back if in use)

    Returns a dict:
      {
        "no_browser": bool,
        "use_keychain": bool,
        "instance": str or None,
        "network_ids": [str, ...],
        "port": int or None,
      }
    """
    if argv is None:
        argv = sys.argv[1:]

    result = {
        "no_browser":   False,
        "use_keychain": False,
        "instance":     None,
        "network_ids":  [],
        "port":         None,
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
        elif arg == "--port" and i + 1 < len(argv):
            try:
                result["port"] = int(argv[i + 1])
            except ValueError:
                print(f"  ⚠  --port expects an integer, got '{argv[i + 1]}' — ignoring.")
            i += 1
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
        # Catastrophic failure — discover_all raised before classifying
        # any individual network. Only happens for things outside any
        # single network's scope (bad base_url, network module crash,
        # etc.). Per-network credential failures now flow through
        # discover_all's normal return path with status fields and do
        # NOT hit this except.
        #
        # Item 3.6 fold-in: previously this fallback produced stub
        # entries with no status info, indistinguishable in the UI
        # from healthy networks with no processed snapshots. The
        # stub now carries status="cred_other_error" so each tool's
        # network dropdown badges it as broken instead of pretending
        # everything is fine.
        print(f"  ⚠  Discovery failed catastrophically: {e}\n")
        fallback = [
            {
                "id":        nid,
                "name":      nid,
                "snapshots": [],
                "status":    "cred_other_error",
                "error":     f"Discovery aborted: {e}",
            }
            for nid in credentials_dict
        ]
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
# Atomic file writes (item 10)
# ─────────────────────────────────────────────────────────────────────────────

_atomic_write_counter = [0]
_atomic_write_counter_lock = threading.Lock()


def atomic_write_json(path, data, indent=2):
    """Write `data` as JSON to `path` atomically.

    Pattern: serialise to a sibling temp file, fsync it, then os.replace
    onto the target path. os.replace is atomic on POSIX — readers see
    either the old contents or the new contents in their entirety, never
    a partial / truncated file. Without this, a kill -9 mid-write (or a
    concurrent writer racing the same file) could leave the JSON file
    truncated and unparseable on next read.

    Temp file name combines the PID with a per-process monotonic counter
    so that two threads (or two coroutines, etc.) inside the same
    process writing to the same target file never collide on the same
    temp file. PID alone is sufficient across processes but not within
    one — without the counter, thread A writing to <path>.tmp.<pid>
    and thread B doing the same race each other on truncate / replace
    and one of them sees FileNotFoundError when its os.replace tries
    to rename a file the other already replaced away.

    The caller is still responsible for any cross-call locking — this
    function only guarantees the *write itself* is atomic, not that the
    full read-modify-write pattern in caller code is. For the watchlist
    file (which has read-modify-write semantics across HTTP requests),
    see _MONITOR_LOCK in path_search_monitor.py.
    """
    with _atomic_write_counter_lock:
        _atomic_write_counter[0] += 1
        seq = _atomic_write_counter[0]
    tmp = f"{path}.tmp.{os.getpid()}.{seq}"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync can fail on some filesystems / mount options.
                # Continue — os.replace still gives us the atomic swap;
                # we just lose the durability guarantee that fsync adds.
                pass
        os.replace(tmp, path)
    except Exception:
        # Best-effort cleanup of the temp file on any failure path so
        # we don't accumulate <file>.tmp.<pid>.<seq> orphans.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


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
                          ip_proto=None, dst_port=None,
                          # Practical pass-through params added in Phase 1
                          # item 4. All default None — when None they are
                          # omitted from the query string so the server's
                          # default (per the OpenAPI spec) applies. Numeric
                          # values are validated by item 5; non-numeric
                          # values (from_device, app_id, url_param, domain)
                          # are passed through as-is and the Forward
                          # Networks API surfaces its own 400 on bad input.
                          # Deferred: TCP flag bits (fin/syn/rst/psh/ack/urg)
                          # and userGroupId. Add when a real user need
                          # appears — keeping the surface tight here.
                          from_device=None,
                          src_port=None,
                          icmp_type=None,
                          app_id=None,
                          url_param=None,
                          domain=None,
                          include_tags=None,
                          include_network_functions=None,
                          max_return_path_results=None):
    """Construct the full Path Search API URL (with query string) without
    issuing the request. Used by tools that need to display or copy the URL
    in addition to executing the search.

    intent may be None or empty to omit it from the URL — the API will use
    its server-side default in that case.
    max_candidates may be None to omit it (server-side default applies).

    The Phase 1 item 4 pass-through params (from_device, src_port, icmp_type,
    app_id, url_param, domain, include_tags, include_network_functions,
    max_return_path_results) all default None and are omitted when None.
    Naming notes:
      - `from_device` maps to the `from` query param (Python keyword).
      - `url_param`   maps to the `url`  query param (avoids shadowing the
        urllib.request.url attribute used elsewhere in the helper).
      - Boolean params (include_tags, include_network_functions) are
        serialised as lowercase 'true'/'false' to match the API's
        documented format. Callers may pass either Python bools or the
        strings 'true'/'false' — both work.

    Phase 1 item 5 validation: numeric range checks for maxCandidates,
    maxResults, maxSeconds, ipProto, icmpType, maxReturnPathResults, and
    port values are performed BEFORE the URL is assembled. Out-of-range
    values raise ValueError with a clear, actionable message ("maxSeconds
    must be 1-300, got 500") rather than letting the API return an
    opaque HTTP 400. Strings are coerced to ints where appropriate so
    values arriving from the wire (form posts, JSON requests) work
    without callers needing to pre-cast. Port values may be bare ints
    or "N-M" range strings per the API spec — both forms are validated.
    """
    # ── Phase 1 item 5 validation ─────────────────────────────────────────
    # Validate before any URL assembly so we fail loudly on the local
    # side instead of letting the API reject with HTTP 400.
    max_candidates = _coerce_int_in_range(
        max_candidates, "maxCandidates", 1, 10000)
    max_results    = _coerce_int_in_range(
        max_results,    "maxResults",    1, 10000)
    max_seconds    = _coerce_int_in_range(
        max_seconds,    "maxSeconds",    1, 300)
    ip_proto       = _coerce_int_in_range(
        ip_proto,       "ipProto",       0, 255)
    icmp_type      = _coerce_int_in_range(
        icmp_type,      "icmpType",      0, 255)
    max_return_path_results = _coerce_int_in_range(
        max_return_path_results, "maxReturnPathResults", 0, 10000)

    # Cross-field check: maxResults must not exceed maxCandidates per
    # the API spec. When max_candidates is None the URL omits it and
    # the API applies its server-side default of 5000 — so the check
    # has to use that effective value, not skip the comparison
    # entirely. Without this, a caller could pass max_results=10000
    # and max_candidates=None, pass local validation, and still get a
    # 400 from the API because it evaluates against default 5000.
    # Item 5's stated goal is to fail loudly before the API does, so
    # the effective-default substitution is required for completeness.
    SERVER_DEFAULT_MAX_CANDIDATES = 5000
    effective_max_candidates = (
        max_candidates if max_candidates is not None
        else SERVER_DEFAULT_MAX_CANDIDATES
    )
    if max_results is not None and max_results > effective_max_candidates:
        explicit = max_candidates is not None
        raise ValueError(
            f"maxResults ({max_results}) must be <= maxCandidates "
            f"({effective_max_candidates}"
            f"{'' if explicit else ', server default'})"
        )

    # Ports: int 0-65535 OR "N-M" range string with both sides in range.
    dst_port = _validate_port_value(dst_port, "dstPort")
    src_port = _validate_port_value(src_port, "srcPort")

    # Cross-field check: url and domain are mutually exclusive per the
    # API spec — both target the L7 layer but represent different match
    # modes. Surfacing this here gives a clearer error than the 400 the
    # API returns ("Invalid combination of L7 parameters").
    if url_param and domain:
        raise ValueError(
            "url and domain cannot be specified together — they are "
            "mutually exclusive L7 match modes"
        )

    params = {
        "dstIp":      dst_ip,
        "maxResults": str(max_results),
        "maxSeconds": str(max_seconds),
    }
    # srcIp is conditional, not unconditional. The API supports a
    # from=<device> + dstIp=<addr> shape that has no srcIp at all
    # (when the caller is searching from a device's perspective rather
    # than from an IP). Unconditionally inserting srcIp into the params
    # dict produced literal `srcIp=None` in the URL when src_ip was
    # None — invalid input on the wire that the API would reject with
    # an unhelpful 400. Empty string is also treated as "not supplied"
    # since form posts often send '' rather than None.
    if src_ip is not None and src_ip != "":
        params["srcIp"] = src_ip
    if intent:
        params["intent"] = intent
    if max_candidates:
        params["maxCandidates"] = str(max_candidates)
    if snapshot_id:
        params["snapshotId"] = snapshot_id
    # Use `is not None` rather than truthiness so legal-but-falsy values
    # (ipProto=0, the IPv6 Hop-by-Hop number) round-trip. Item 5
    # validation has already converted these to int-or-None, so a None
    # check is sufficient. dst_port/src_port have been coerced to a
    # string-or-None by _validate_port_value.
    if ip_proto is not None:
        params["ipProto"] = str(ip_proto)
    if dst_port is not None:
        params["dstPort"] = dst_port

    # ── Phase 1 item 4 pass-through params ────────────────────────────────
    if from_device:
        params["from"] = from_device
    if src_port is not None:
        params["srcPort"] = src_port
    if icmp_type is not None and icmp_type != "":
        # icmp_type=0 is a legal value (echo reply), so check explicitly
        # for None/empty rather than truthiness.
        params["icmpType"] = str(icmp_type)
    if app_id:
        params["appId"] = app_id
    if url_param:
        params["url"] = url_param
    if domain:
        params["domain"] = domain
    if include_tags is not None and include_tags != "":
        params["includeTags"] = _bool_param(include_tags)
    if include_network_functions is not None and include_network_functions != "":
        params["includeNetworkFunctions"] = _bool_param(include_network_functions)
    if max_return_path_results is not None and max_return_path_results != "":
        # Server allows 0 (the default). Omit only when the caller didn't
        # pass anything — passing 0 explicitly should round-trip.
        params["maxReturnPathResults"] = str(max_return_path_results)

    qs = urllib.parse.urlencode(params)
    return f"{base_url.rstrip('/')}/api/networks/{network_id}/paths?{qs}"


def _bool_param(value):
    """Normalise a boolean-ish value to the 'true'/'false' form the
    Forward Networks API expects on the wire. Accepts Python bools, the
    strings 'true'/'false' (any case), '1'/'0', and 'yes'/'no'.
    Anything else is returned unchanged so the API can surface its own
    400 if the value is genuinely unsupported."""
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value).strip().lower()
    if s in ("true", "1", "yes"):
        return "true"
    if s in ("false", "0", "no"):
        return "false"
    return str(value)


def _coerce_int_in_range(value, name, lo, hi):
    """Validate and coerce value to int in [lo, hi]. None and "" are
    treated as "not supplied" and pass through as None so existing
    None-defaulting call sites keep working. Strings are coerced via
    int() so values arriving from JSON form posts work without manual
    casting. Booleans are rejected explicitly because Python's int(True)
    silently returns 1 and would mask a caller passing the wrong type
    (e.g. include_tags=True into a numeric slot)."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(
            f"{name} must be an integer in [{lo}, {hi}], got bool {value!r}"
        )
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"{name} must be an integer in [{lo}, {hi}], got {value!r}"
        )
    if not (lo <= n <= hi):
        raise ValueError(
            f"{name} must be in [{lo}, {hi}], got {n}"
        )
    return n


def _validate_port_value(value, name):
    """Validate a port value per the API spec: either a single port
    0-65535 or an inclusive range "N-M" with both sides in range and
    N <= M. Returns the value as a string ready for the query string,
    or None if not supplied. Raises ValueError on any malformed input.
    Booleans are rejected for the same reason as in _coerce_int_in_range."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(
            f"{name} must be a port (0-65535) or range 'N-M', got bool {value!r}"
        )
    s = str(value).strip()
    # Range form
    if "-" in s:
        parts = s.split("-")
        if len(parts) != 2:
            raise ValueError(
                f"{name} range must be 'N-M', got {value!r}"
            )
        try:
            lo, hi = int(parts[0]), int(parts[1])
        except ValueError:
            raise ValueError(
                f"{name} range bounds must be integers, got {value!r}"
            )
        if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
            raise ValueError(
                f"{name} range bounds must be in [0, 65535], got {value!r}"
            )
        if lo > hi:
            raise ValueError(
                f"{name} range start ({lo}) must be <= end ({hi})"
            )
        # Return the canonical form ("80-90") rather than the original
        # surface string ("80 - 90", "0080-0090") so URL output is
        # consistent regardless of how the caller formatted the input.
        return f"{lo}-{hi}"
    # Single-port form
    try:
        n = int(s)
    except ValueError:
        raise ValueError(
            f"{name} must be a port (0-65535) or range 'N-M', got {value!r}"
        )
    if not (0 <= n <= 65535):
        raise ValueError(
            f"{name} must be in [0, 65535], got {n}"
        )
    return str(n)


def is_path_search_error(status, body, err):
    """True when a path search call did NOT succeed.

    Centralises the rule that "the helper returned an err string AND a
    parsed body" still means failure — for HTTP 4xx/5xx, run_path_search
    returns BOTH a populated body (the parsed error response) and an err
    string ("HTTP 401", "HTTP 409", etc.). Callers that only checked
    `body is None` were misclassifying these as success and then trying
    to read body["info"]["paths"], surfacing API errors as the
    misleading "No paths returned. Check search parameters."

    Use this wherever a tool needs to gate on "did the path search
    actually deliver a usable result body."
    """
    if err is not None:
        return True
    if status is None:
        return True
    if not (200 <= status < 300):
        return True
    return False


def extract_path_search_error_message(status, body, err):
    """Best-effort human-readable error string for a failed path search.

    Pulls the API's `message` field out of the parsed body when present
    (Forward Networks ErrorInfo schema), otherwise falls back to the
    err string from run_path_search, otherwise to a status code.
    Always returns something — never None.
    """
    if isinstance(body, dict):
        msg = body.get("message") or body.get("error") or body.get("_raw")
        if msg:
            # Trim noisy multi-line server error strings to one line.
            msg = str(msg).strip().splitlines()[0][:300]
            if err and err not in msg:
                return f"{err}: {msg}"
            return msg
    if err:
        return err
    if status is not None:
        return f"HTTP {status}"
    return "Unknown path search error"


def run_path_search(base_url, credentials, network_id, snapshot_id,
                    src_ip, dst_ip,
                    intent="PREFER_DELIVERED",
                    max_candidates=5000, max_results=1, max_seconds=30,
                    ip_proto=None, dst_port=None,
                    retries=1, retry_delay=3,
                    # Phase 1 item 4 pass-through params. Default None
                    # everywhere so existing callers remain unaffected;
                    # only the Builder UI's proxy path currently sends
                    # any of these (it builds the URL in JS), but tools
                    # that adopt them via this helper now produce
                    # identical URLs across the toolkit. This is what
                    # closes the cross-tool drift on includeNetworkFunctions.
                    from_device=None,
                    src_port=None,
                    icmp_type=None,
                    app_id=None,
                    url_param=None,
                    domain=None,
                    include_tags=None,
                    include_network_functions=None,
                    max_return_path_results=None):
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

      Phase 1 item 4 pass-through params (all optional, all default None):
      from_device:               source device name; maps to `from`
      src_port:                  L4 source port or range string ("8080-8088")
      icmp_type:                 implies ipProto=1
      app_id:                    L7 app id, or "unidentified"
      url_param:                 L7 URL pattern; maps to `url`
      domain:                    L7 domain pattern (cannot combine with url)
      include_tags:              bool/'true'/'false' — adds device tags per hop
      include_network_functions: bool/'true'/'false' — adds detailed forwarding info
      max_return_path_results:   int — return-path result cap (0–10000)

    Returns:
      (status, body_dict_or_None, elapsed_ms, error_or_None)

      - On success: (status_code, parsed_json_dict, ms, None)
      - On HTTP 4xx/5xx: (status_code, parsed_body_or_{"_raw": text}, ms, "HTTP {code}")
      - On transient failure with retries exhausted: (None, None, ms, str(exception))
      - On missing credentials: (None, None, 0, "No credentials for network {id}")
      - On client-side validation failure (Phase 1 item 5): (None, None, 0, "ValueError: ...")
        — caught here so callers don't need try/except for what is_path_search_error
        already covers as a generic failure.
    """
    if network_id not in credentials:
        return None, None, 0, f"No credentials for network {network_id}"

    try:
        url = build_path_search_url(
            base_url, network_id, snapshot_id, src_ip, dst_ip,
            intent=intent,
            max_candidates=max_candidates, max_results=max_results, max_seconds=max_seconds,
            ip_proto=ip_proto, dst_port=dst_port,
            from_device=from_device,
            src_port=src_port,
            icmp_type=icmp_type,
            app_id=app_id,
            url_param=url_param,
            domain=domain,
            include_tags=include_tags,
            include_network_functions=include_network_functions,
            max_return_path_results=max_return_path_results,
        )
    except ValueError as ve:
        # Validation failed before the URL was even built. Surface
        # via the existing error tuple shape so is_path_search_error
        # picks it up just like a transient failure or HTTP 4xx —
        # no caller needs to add try/except around run_path_search.
        return None, None, 0, f"ValueError: {ve}"
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
# Port selection
# ─────────────────────────────────────────────────────────────────────────────

# The default ports the toolkit tools prefer. Fallback scanning skips these so
# a tool that can't get its own default never lands on another tool's default.
RESERVED_PORTS = frozenset({8760, 8765, 8766, 8767, 8768, 8769})


def _port_is_free(port, host="127.0.0.1"):
    """Return True if a TCP socket can bind (host, port) right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_free_port(preferred, host="127.0.0.1", reserved=RESERVED_PORTS, max_scan=200):
    """Return an available port, preferring `preferred`.

    If `preferred` is busy, scans upward from just above the reserved range so
    fallback ports never collide with another toolkit tool's default. Used by
    the launcher to assign ports up front. Note: availability can change between
    this check and an actual bind, so servers should still bind defensively via
    bind_toolkit_server().
    """
    if _port_is_free(preferred, host):
        return preferred
    base = (max(reserved) + 1) if reserved else preferred + 1
    for candidate in range(base, base + max_scan):
        if candidate in reserved:
            continue
        if _port_is_free(candidate, host):
            return candidate
    raise OSError(f"No free port found near {preferred} (scanned {max_scan}).")


def bind_toolkit_server(handler, preferred_port, host="127.0.0.1",
                        reserved=RESERVED_PORTS, max_scan=200):
    """Create a ToolkitServer bound to an available port.

    Tries `preferred_port` first; if it is already in use (EADDRINUSE, e.g. the
    port is held by another app such as Okta Verify), scans upward from just
    above the reserved range for the next free port so a busy port never stops
    the tool from starting. Read the actual port via server.server_address[1].
    """
    candidates = [preferred_port]
    base = (max(reserved) + 1) if reserved else preferred_port + 1
    candidates += [p for p in range(base, base + max_scan) if p not in reserved]

    last_err = None
    for port in candidates:
        try:
            return ToolkitServer((host, port), handler)
        except OSError as e:
            if e.errno in (errno.EADDRINUSE, errno.EACCES):
                last_err = e
                continue
            raise
    raise OSError(f"Could not bind a port near {preferred_port}: {last_err}")


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