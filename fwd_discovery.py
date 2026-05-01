"""
Forward Networks — shared network/snapshot discovery module.
Used by all toolkit tools (builder, compare, history, diff, monitor) to
populate networks and snapshots at startup.

GET /api/networks          — get all networks, find ours by ID
GET /api/networks/:id/snapshots — get snapshots for each credentialed network
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


def discover_all(base_url, credentials):
    """
    1. Call GET /api/networks to get all networks visible to this credential.
       (Use the first credential — all creds are for the same instance.)
    2. Filter to networks we have credentials for.
    3. For each, call GET /api/networks/:id/snapshots, sort by createdAt desc
       (newest data first). All snapshots are returned regardless of state;
       non-PROCESSED ones get a "reprocessing required" label and ready=False
       so consumers can show them but disable selection.

    Returns list of:
      { "id": str, "name": str,
        "snapshots": [{"id": str, "label": str, "ready": bool}] }
    """
    if not credentials:
        return []

    # Use first available credential to list all networks
    first_auth = next(iter(credentials.values()))

    print(f"  → Fetching network list...", end=" ", flush=True)
    status, data, err = api_get(base_url, "/api/networks", first_auth)
    if err or not data:
        print(f"failed ({err})")
        # Fall back: build stub entries from credential keys
        return [{"id": nid, "name": nid, "snapshots": []} for nid in credentials]

    # API may return list directly or wrapped
    all_networks = data if isinstance(data, list) else data.get("networks", data.get("items", []))
    print(f"{len(all_networks)} network(s) found")

    # Build id→name map for networks we have creds for
    cred_ids   = set(credentials.keys())
    net_map    = {}
    for n in all_networks:
        nid = str(n.get("id", ""))
        if nid in cred_ids:
            net_map[nid] = n.get("name") or nid

    # For any credentialed network not returned by the list, use the ID as name
    for nid in cred_ids:
        if nid not in net_map:
            net_map[nid] = nid

    networks = []
    for net_id, auth_header in credentials.items():
        name = net_map.get(net_id, net_id)
        print(f"  → Fetching snapshots for {name}...", end=" ", flush=True)

        status, snap_data, err = api_get(
            base_url, f"/api/networks/{net_id}/snapshots", auth_header
        )
        if err or not snap_data:
            print(f"failed ({err})")
            networks.append({"id": net_id, "name": name, "snapshots": []})
            continue

        # May be list or wrapped
        snapshots = snap_data if isinstance(snap_data, list) \
                    else snap_data.get("snapshots", [])

        # Sort by createdAt descending — newest data first.
        # createdAt is when the snapshot's data was captured/imported and is
        # the only date we expose. processedAt and processingTrigger are
        # implementation details of the snapshot pipeline and are not used
        # for ordering, labeling, or filtering anywhere in the toolkit.
        snapshots.sort(key=lambda s: s.get("createdAt") or "", reverse=True)

        snap_list = []
        ready_count = 0
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
            else:
                ready_count += 1

            if s.get("note"):
                label += f" — {s['note']}"

            # Append short snapshot ID for cross-reference
            label += f"  ({snap_id[-8:]})"

            snap_list.append({"id": snap_id, "label": label, "ready": ready})

        total = len(snap_list)
        if total == ready_count:
            print(f"{total} snapshot(s)")
        else:
            print(f"{total} snapshot(s) ({ready_count} ready, {total - ready_count} not ready)")
        networks.append({"id": net_id, "name": name, "snapshots": snap_list})

    return networks