"""
Forward Networks — shared network/snapshot discovery module.
Used by all toolkit tools (builder, compare, history, diff, monitor) to
populate networks and snapshots at startup.

GET /api/networks          — get all networks visible to a credential
GET /api/networks/:id/snapshots — get snapshots for a credentialed network

Item 9: discovery iterates over each credential the user supplied (via
FWD_CREDS_<id> env vars or --keychain) and uses THAT credential to look
up THAT network's name. Previously the code used whichever credential
came first in the dict to call /api/networks once and tried to map all
networks back from that single response, which silently mislabelled
networks whose proper credential wasn't first. Per-network status is
now reported on each network record so the UI can distinguish:

  - ok                            — credential authenticated, network found
  - cred_invalid                  — 401/403 from /api/networks (bad cred)
  - cred_other_error              — 5xx, timeout, or transport failure
  - network_not_in_cred_allowlist — credential is valid but doesn't see
                                    this network ID in its /api/networks
                                    response (typo, stale config, scope
                                    change at the Forward Networks side)

Folds in original review item 3.6: instead of silently producing a
"looks normal" fallback list when discovery hits errors, the failure
modes flow up to the tool UI as per-network badges. A user with a bad
credential sees "[auth failed]" next to that network in the dropdown
instead of an inexplicable empty snapshot list.
"""

import importlib.util
import os
import urllib.request
import urllib.error
import json


def _load_helpers():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_helpers.py")
    spec = importlib.util.spec_from_file_location("fwd_helpers", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_helpers = _load_helpers()


# Per-network discovery status values. Tools use these to decide whether
# to enable/disable each network's <option> and what message to show.
STATUS_OK                            = "ok"
STATUS_CRED_INVALID                  = "cred_invalid"
STATUS_CRED_OTHER_ERROR              = "cred_other_error"
STATUS_NETWORK_NOT_IN_CRED_ALLOWLIST = "network_not_in_cred_allowlist"


def api_get(base_url, path, auth_header):
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth_header)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=_helpers.API_TIMEOUT_S) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}: {e.read().decode('utf-8')[:300]}"
    except Exception as ex:
        return None, None, str(ex)


def _classify_networks_call(status, err):
    """Map an api_get() result for /api/networks into a per-network
    status. Note that "network_not_in_cred_allowlist" can only be
    determined AFTER inspecting the response body, so this function
    only handles the auth/transport classification — the body-based
    case is decided by the caller below."""
    if status == 401 or status == 403:
        return STATUS_CRED_INVALID
    if err is not None or status is None or not (200 <= status < 300):
        return STATUS_CRED_OTHER_ERROR
    return STATUS_OK


def _fetch_snapshots(base_url, net_id, auth_header):
    """Fetch and format snapshots for one credentialed network.
    Returns (snap_list, error_or_None).

    snap_list is a list of {"id", "label", "ready"} dicts sorted by
    createdAt descending (newest first). Non-PROCESSED snapshots get
    a "[reprocessing required]" tag and ready=False so the UI can
    disable the option without filtering it out — the user still sees
    that the snapshot exists.
    """
    status, snap_data, err = api_get(
        base_url, f"/api/networks/{net_id}/snapshots", auth_header
    )
    # An empty list is a legitimate result (the network exists but has
    # no snapshots yet) — distinct from err being set, which means the
    # request itself failed. The original code treated `not snap_data`
    # as failure which conflated the two; result was a misleading
    # "failed (HTTP 200)" log line for legitimately empty networks.
    if err is not None:
        return [], err
    if snap_data is None:
        return [], f"HTTP {status} with empty body"

    snapshots = snap_data if isinstance(snap_data, list) \
                else snap_data.get("snapshots", [])

    # Sort by createdAt descending — newest data first.
    # createdAt is when the snapshot's data was captured/imported and is
    # the only date we expose. processedAt and processingTrigger are
    # implementation details of the snapshot pipeline and are not used
    # for ordering, labeling, or filtering anywhere in the toolkit.
    snapshots.sort(key=lambda s: s.get("createdAt") or "", reverse=True)

    snap_list = []
    for s in snapshots:
        snap_id = s.get("id", "")
        if not snap_id:
            continue
        ts_raw = s.get("createdAt") or ""
        label  = ts_raw[:19].replace("T", " ") if ts_raw else snap_id

        # A snapshot can be selected for path search only if it is fully
        # processed. Anything else (PROCESSING, COLLECTING, FAILED, etc.)
        # gets a clear "reprocessing required" tag and is marked not-ready
        # so the UI can disable the option rather than letting the user
        # pick something the API won't accept.
        state = (s.get("state") or "").upper()
        ready = (state == "PROCESSED")
        if not ready:
            label += " [reprocessing required]"

        if s.get("note"):
            label += f" — {s['note']}"

        # Append short snapshot ID for cross-reference
        label += f"  ({snap_id[-8:]})"

        snap_list.append({"id": snap_id, "label": label, "ready": ready})

    return snap_list, None


def discover_all(base_url, credentials):
    """Discover networks and snapshots for each credential the user
    supplied. The keys of `credentials` are the user's allowlist —
    only networks whose IDs appear there are surfaced to the UI.

    For each credential:
      1. Call GET /api/networks WITH THAT CREDENTIAL (item 9 fix:
         previously only the first credential was used).
      2. Look for the matching network ID in the response. If found,
         use the API-returned name and fetch its snapshots.
      3. Each network record carries a `status` and `error` field so
         the UI can badge bad credentials, unreachable instances, and
         allowlist mismatches distinctly from a healthy network with
         no processed snapshots (item 3.6 fold-in).

    Returns list of:
      {
        "id":        str,
        "name":      str,
        "snapshots": [{"id", "label", "ready"}],
        "status":    "ok" | "cred_invalid" | "cred_other_error" |
                     "network_not_in_cred_allowlist",
        "error":     str | None  # human message, None when status == ok
      }
    """
    if not credentials:
        return []

    # Cache /api/networks responses per credential. If two env vars
    # share the same credential value (rare but possible — same Bearer
    # used twice), we should only call /api/networks once for that
    # credential. Key on the auth header so identical Bearer strings
    # collapse, different Bearers stay separate.
    networks_response_cache = {}

    networks = []
    for net_id, auth_header in credentials.items():
        # Fetch /api/networks for this credential (cached).
        if auth_header not in networks_response_cache:
            print(f"  → Fetching network list for credential {net_id}...",
                  end=" ", flush=True)
            status, data, err = api_get(base_url, "/api/networks", auth_header)
            networks_response_cache[auth_header] = (status, data, err)
            cred_status = _classify_networks_call(status, err)
            if cred_status == STATUS_CRED_INVALID:
                print(f"auth failed (HTTP {status})")
            elif cred_status == STATUS_CRED_OTHER_ERROR:
                print(f"failed ({err or f'HTTP {status}'})")
            else:
                # Count for user feedback
                all_n = data if isinstance(data, list) \
                        else data.get("networks", data.get("items", [])) \
                        if isinstance(data, dict) else []
                print(f"{len(all_n)} network(s) visible to this credential")
        status, data, err = networks_response_cache[auth_header]

        cred_status = _classify_networks_call(status, err)

        # Credential-level failure: surface the network as broken in the
        # dropdown. Don't try to fetch snapshots — the same credential
        # would fail there too, just adding noise.
        if cred_status != STATUS_OK:
            err_msg = err or f"HTTP {status}"
            networks.append({
                "id":        net_id,
                "name":      net_id,  # no name available
                "snapshots": [],
                "status":    cred_status,
                "error":     err_msg,
            })
            continue

        # Credential is OK. Look for THIS network in its response.
        all_networks = data if isinstance(data, list) \
                       else data.get("networks", data.get("items", []))
        match = None
        for n in all_networks:
            if str(n.get("id", "")) == net_id:
                match = n
                break

        if match is None:
            # Credential is valid (we got a 200) but doesn't see this
            # network. Most common causes: typo in env var name, stale
            # config, or org-scope change at Forward Networks. Surface
            # this distinctly from "credential is bad" so the user can
            # tell which fix to apply.
            print(f"  ⚠  Credential for {net_id} authenticated but the network "
                  f"isn't in its scope; check FWD_CREDS_{net_id}.")
            networks.append({
                "id":        net_id,
                "name":      net_id,
                "snapshots": [],
                "status":    STATUS_NETWORK_NOT_IN_CRED_ALLOWLIST,
                "error":     "Credential authenticated but network is not "
                             "in its scope — check the env var name.",
            })
            continue

        # Healthy network. Fetch snapshots.
        name = match.get("name") or net_id
        print(f"  → Fetching snapshots for {name}...", end=" ", flush=True)
        snap_list, snap_err = _fetch_snapshots(base_url, net_id, auth_header)

        if snap_err:
            # Snapshots failed even though /api/networks succeeded.
            # Treat as cred_other_error since the same credential just
            # worked one call ago — likely a transport blip.
            print(f"failed ({snap_err})")
            networks.append({
                "id":        net_id,
                "name":      name,
                "snapshots": [],
                "status":    STATUS_CRED_OTHER_ERROR,
                "error":     f"Snapshot fetch failed: {snap_err}",
            })
            continue

        ready_count = sum(1 for s in snap_list if s.get("ready"))
        total       = len(snap_list)
        if total == ready_count:
            print(f"{total} snapshot(s)")
        else:
            print(f"{total} snapshot(s) ({ready_count} ready, "
                  f"{total - ready_count} not ready)")

        networks.append({
            "id":        net_id,
            "name":      name,
            "snapshots": snap_list,
            "status":    STATUS_OK,
            "error":     None,
        })

    return networks