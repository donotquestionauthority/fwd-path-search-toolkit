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
import os
import subprocess
import sys


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
# Snapshot helpers
# ─────────────────────────────────────────────────────────────────────────────

def snapshot_sort_key(snapshot):
    """Sort key for snapshots: use createdAt (reflects data age for COLLECTION
    snapshots); fall back to processedAt if absent."""
    return snapshot.get("createdAt") or snapshot.get("processedAt") or ""


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