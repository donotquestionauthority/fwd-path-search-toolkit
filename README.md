# Forward Networks — Path Search Toolkit

**By Robert Tavoularis** · Customer Success Engineer · Forward Networks

A collection of local browser-based tools for building, comparing, and auditing
Forward Networks Path Search API queries — no external dependencies, pure Python stdlib.

---

## Tools

| Script | Port | Purpose |
|---|---|---|
| `path_search_builder.py` | 8765 | Interactive URL builder + live API runner with firewall analysis |
| `path_search_compare.py` | 8766 | Parameter matrix tester — find which combination reliably surfaces firewalls |
| `path_search_history.py` | 8767 | Day-by-day snapshot audit — detect when firewall visibility changes across snapshots |

All three tools share the same credential and network discovery mechanism, and
read/write the same `path_search_config.json` file for saved searches.

---

## Requirements

- Python 3.7+ (standard library only — no `pip install` needed)
- Forward Networks instance with API access
- One API credential pair (access key + secret key) per network

---

## Setup

### 1. Create API Credentials

In the Forward Networks UI: **Settings → API Access → Create API Key**

Each key gives you an **Access Key** and a **Secret Key**.

### 2. Set Environment Variables

Add one variable per network to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
# Format: FWD_CREDS_<networkId>="accessKey:secretKey"
export FWD_CREDS_123456="myAccessKey:mySecretKey"
export FWD_CREDS_789012="anotherAccessKey:anotherSecretKey"

# Optional: override the default instance URL (defaults to https://fwd.app)
export FWD_BASE_URL="https://your-instance.fwd.app"
```

Reload your shell:

```bash
source ~/.zshrc
```

**Finding your Network ID:** In the Forward Networks UI, the network ID is visible
in the URL when you navigate to a network: `.../networks/123456/...`

### 3. Run a Tool

```bash
python3 path_search_builder.py
python3 path_search_compare.py
python3 path_search_history.py
```

Each script starts a local web server and opens your browser automatically.
Press `Ctrl+C` in the terminal to stop.

---

## Tool Reference

### Path Search Builder (`path_search_builder.py`)

The core tool. Build and execute Forward Networks
[Path Search API](https://docs.fwd.app/latest/api/) queries interactively.

**Features:**
- Dynamic network and snapshot discovery via the API — no manual configuration
- Build `GET /api/networks/{networkId}/paths` URLs with full parameter control
- Run queries directly against the API with live JSON response and syntax highlighting
- Navigate multi-path results one at a time
- Filter results by `forwardingOutcome`, `securityOutcome`, device type, device name, and display name
- **Firewall Summary panel** — detects asymmetric routing by comparing firewall sets across all returned paths, flags when different paths traverse different firewalls
- Generate the equivalent Forward Networks App search string and deep-link URL for in-app follow-up
- Save and reload named searches

**Key parameters:**

| Parameter | Description |
|---|---|
| `srcIp` | Source IP (required) |
| `dstIp` | Destination IP (required) |
| `intent` | `PREFER_DELIVERED` (most paths), `PREFER_VIOLATIONS` (policy violations first), `VIOLATIONS_ONLY` |
| `ipProto` | IP protocol number: `6`=TCP, `17`=UDP, `1`=ICMP |
| `dstPort` | Destination port (0–65535) |
| `maxCandidates` | How many candidate paths to evaluate (higher = more thorough, slower) |
| `maxResults` | How many paths to return |
| `maxSeconds` | Query timeout |
| `includeNetworkFunctions` | Include virtualized network functions in the path |

**Tip — surfacing firewalls:**
Path Search returns the *shortest/most efficient* path by default. Firewalls are
often discovered only when `maxCandidates` is large enough that the search
explores paths that traverse them. If you're not seeing expected firewalls,
increase `maxCandidates` (try 5000, 10000) and use the Firewall Summary panel
to compare consistency across returned paths.

---

### Path Search Comparison (`path_search_compare.py`)

Automates the "which parameters surface firewalls?" question by running the same
src/dst pairs across a configurable matrix of `maxCandidates`, `intent`, and port
combinations, then scoring each combination.

**Features:**
- Enter multiple src/dst pairs at once
- Configurable parameter matrix (candidates × intents × ports)
- Per-row analysis: path count, firewall hit rate, consensus quality, whether result #1 has a firewall
- **Combination ranking** scored on:
  - Result #1 has FW (50 pts) — the most actionable signal
  - Consensus is CLEAN or SOFT (30 pts) — path set is internally consistent
  - Result #1 matches the dominant FW fingerprint (20 pts)
- CSV export

**Consensus definitions:**

| Status | Meaning |
|---|---|
| `CLEAN` | All FW-containing paths traverse the same firewall set |
| `SOFT` | ≥ threshold % (configurable, default 80%) traverse the same set |
| `SPLIT` | FW paths are split across multiple distinct firewall sets |
| `NO_FIREWALL` | No FIREWALL hops found in any returned path |

**Workflow:**
1. Enter a representative set of src/dst pairs (the more diverse, the better)
2. Set your candidate range (e.g. `50,5000,10000`) and ports (`none,443,80`)
3. Run — the tool executes every combination sequentially
4. Read the **Combination Ranking** at the bottom for a go/no-go verdict
5. Take the winning combination back to the Builder for deeper investigation

---

### Path Search History (`path_search_history.py`)

Runs the same path search across historical snapshots going back a configurable
number of days and reports how firewall visibility changes over time.

**Features:**
- Select how many days back to audit (configurable in the UI)
- For each snapshot in range, runs the path search and records the firewall set
- Day-by-day timeline showing which snapshots have firewalls, which don't
- **Change detection** — flags days where the firewall set changes from the previous snapshot
- Distinguishes between:
  - **Firewall set change** (different devices) — flagged, likely meaningful
  - **Path count change only** — noted but not flagged as a problem
  - **No firewall at all** — flagged as a regression
- Configurable "ignore ECMP peers" mode: when enabled, device-level redundant pairs
  (e.g. `fw-a` / `fw-b` in an active/standby cluster) are normalized before comparison
  so failovers don't generate false positives

**Use case:**
A customer reports "path search worked last week but the firewall isn't showing up
anymore." Use this tool to find exactly which snapshot introduced the regression.

---

## Shared Configuration

All tools read and write `path_search_config.json` in the same directory.
This file stores saved searches (Builder) and is created automatically on first run.

```json
{
  "savedSearches": [
    {
      "name": "prod-web-to-db",
      "params": {
        "base": "https://fwd.app",
        "networkIdx": "0",
        "srcIp": "10.0.1.100",
        "dstIp": "10.0.2.50",
        "intent": "PREFER_DELIVERED",
        ...
      }
    }
  ]
}
```

---

## Architecture

Each tool is a self-contained Python script that:

1. Reads credentials from `FWD_CREDS_*` environment variables
2. Uses `fwd_discovery.py` to call the Forward Networks API and enumerate available
   networks and snapshots (no manual config files needed)
3. Starts a local `http.server` on localhost — no data leaves your machine except
   the API calls you explicitly trigger
4. Serves a single-page HTML/JS UI with all logic inline
5. Proxies API requests through the Python server so credentials are never
   exposed to the browser

---

## Files

```
.
├── README.md
├── path_search_builder.py      # Tool 1: URL builder + live runner
├── path_search_compare.py      # Tool 2: parameter matrix comparison
├── path_search_history.py      # Tool 3: snapshot history audit
├── fwd_discovery.py            # Shared: network/snapshot discovery via API
└── path_search_config.json     # Auto-created: saved searches
```

---

## Troubleshooting

**"No FWD_CREDS_* environment variables found"**
Your shell hasn't loaded the variables. Run `source ~/.zshrc` (or restart Terminal)
and try again. Confirm with `echo $FWD_CREDS_123456`.

**"No credentials for network X"**
The network ID in the environment variable name must exactly match the network ID
returned by the API. Check the ID shown next to the network name in the dropdown.

**"Discovery failed"**
The tool couldn't reach the Forward Networks API. Check that:
- `FWD_BASE_URL` is set correctly if you're not using `https://fwd.app`
- Your network has internet access or VPN connectivity to the instance
- The access key and secret key are in `accessKey:secretKey` order (colon-separated)

**Firewalls not appearing in results**
See [Tip — surfacing firewalls](#tip--surfacing-firewalls) above. The short answer:
increase `maxCandidates`. Start with `5000`, try `10000` if still not appearing.

---

## Author

**Robert Tavoularis**
Customer Success Engineer — Forward Networks
[github.com/donotquestionauthority](https://github.com/donotquestionauthority)

Forward Networks builds network digital twins and network intelligence platforms.
These tools are independent utilities for working with the Forward Networks API and
are not official Forward Networks software.

---

## License

MIT License — use freely, attribution appreciated.