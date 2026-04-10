"""
Forward Networks — shared network/snapshot discovery module.
Used by both path_search_builder.py and path_search_compare.py.

GET /api/networks          — get all networks, find ours by ID
GET /api/networks/:id/snapshots — get snapshots for each credentialed network
"""

import urllib.request
import urllib.error
import json


def api_get(base_url, path, auth_header):
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth_header)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
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
    3. For each, call GET /api/networks/:id/snapshots, filter to PROCESSED,
       sort by processedAt desc.

    Returns list of:
      { "id": str, "name": str, "snapshots": [{"id": str, "label": str}] }
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

        # Filter to PROCESSED
        processed = [s for s in snapshots if s.get("state") == "PROCESSED"]

        # Sort by processedAt desc
        processed.sort(key=lambda s: s.get("processedAt") or "", reverse=True)

        snap_list = []
        for s in processed:
            snap_id = s.get("id", "")
            if not snap_id:
                continue
            ts_raw = s.get("processedAt", "")
            label  = ts_raw[:19].replace("T", " ") if ts_raw else snap_id
            if s.get("note"):
                label += f" — {s['note']}"
            snap_list.append({"id": snap_id, "label": label})

        print(f"{len(snap_list)} processed snapshot(s)")
        networks.append({"id": net_id, "name": name, "snapshots": snap_list})

    return networks