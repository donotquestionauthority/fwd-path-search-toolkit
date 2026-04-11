# Forward Networks — Path Search Toolkit

**By Robert Tavoularis** · Senior Customer Success Engineer · Forward Networks

A collection of local browser-based tools for working with the Forward Networks
Path Search API — building queries interactively, testing parameter combinations,
auditing results across historical snapshots, and investigating why a path search
changes between snapshots. No external dependencies, pure Python stdlib.

---

## Tools

| Script | Port | Purpose |
|---|---|---|
| `path_search_builder.py` | 8765 | Interactive query builder and live API runner |
| `path_search_compare.py` | 8766 | Parameter matrix tester — find the combination that produces the most consistent results |
| `path_search_history.py` | 8767 | Snapshot history audit — track how path search results change over time |
| `path_search_diff.py`    | 8768 | Snapshot diff investigator — hop-by-hop analysis of why a path search changed between two snapshots |

All four tools share the same credential and network discovery mechanism, and
read/write the same `path_search_config.json` file for saved searches.

---

## Requirements

- Python 3.7+ (standard library only — no `pip install` needed)
- Forward Networks instance with API access
- One API credential pair (access key + secret key) per network

---

## Setup

### 1. Create API Credentials

In the Forward Networks UI: **Settings → Personal → Account → API Tokens → Generate API Token**

Each token gives you an **Access Key** and a **Secret Key**.

### 2. Find your Network ID

Navigate to your network in the Forward Networks UI. The network ID is visible in the
URL: `https://fwd.app/?/search?networkId=123456` — the numeric value is your network ID.

### 3. Set Environment Variables

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

### 4. Run a Tool

```bash
python3 path_search_builder.py
python3 path_search_compare.py
python3 path_search_history.py
python3 path_search_diff.py
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
- Build and execute `GET /api/networks/{networkId}/paths` queries with the most commonly used parameters
- Live JSON response with syntax highlighting
- Navigate multi-path results one at a time
- Filter results by `forwardingOutcome`, `securityOutcome`, device type, device name, and display name
- Firewall summary panel — compares firewall device sets across all returned paths to validate consistency
- Generate the equivalent Forward Networks App search string and deep-link URL for in-app follow-up
- Save and reload named searches

**Key parameters:**

| Parameter | Description |
|---|---|
| `srcIp` | Source IP (required) |
| `dstIp` | Destination IP (required) |
| `intent` | Path selection strategy: `PREFER_DELIVERED`, `PREFER_DELIVERED_NO_VIOLATIONS`, `DELIVERED`, `VIOLATIONS`, `ALL` |
| `ipProto` | IP protocol number: `6`=TCP, `17`=UDP, `1`=ICMP |
| `dstPort` | Destination port (0–65535) |
| `maxCandidates` | Search space size — how many candidate paths to evaluate (higher = more thorough, slower) |
| `maxResults` | How many paths to return |
| `maxSeconds` | Query timeout (API default 30, max 300) |

---

### Path Search Comparison (`path_search_compare.py`)

Runs the same src/dst pairs across a configurable matrix of `maxCandidates`, `intent`,
and port combinations, then scores and ranks each combination by result consistency.
Useful when you need to determine which parameter set reliably produces the expected
result and gives you confidence the model is working correctly for a given flow.

**Features:**
- Enter multiple src/dst pairs at once
- Configurable parameter matrix (candidates × intents × ports)
- Per-combination scoring based on result consistency and whether the top result matches
  the expected path
- Combination ranking with plain-English verdict
- CSV export

**Consensus definitions:**

| Status | Meaning |
|---|---|
| `CLEAN` | All paths with the expected device set traverse the same set consistently |
| `SOFT` | ≥ threshold % (configurable, default 80%) traverse the same set |
| `SPLIT` | Results are split across multiple distinct device sets |
| `NO_FIREWALL` | No firewall hops found in any returned path |

**Workflow:**
1. Enter a representative set of src/dst pairs
2. Set your candidate range (e.g. `50,5000,10000`) and ports (`none,443,80`)
3. Run — the tool executes every combination sequentially
4. Read the **Combination Ranking** at the bottom for a verdict
5. Take the winning combination back to the Builder for deeper investigation

---

### Path Search History (`path_search_history.py`)

Runs the same path search across historical snapshots going back a configurable
number of days and reports how results change over time.

**Features:**
- Configurable audit window (default 7 days)
- For each snapshot in range, runs the path search and records the result set
- Day-by-day timeline with change detection between consecutive snapshots
- Detects and classifies changes:
  - **Path hops changed** — devices appearing in the path are different from the previous snapshot, with details on which devices were added, removed, or swapped
  - **Peer swap** — hop set changed but all differences are fuzzy-matched peer devices (e.g. `sw-01` → `sw-02`), rendered as a softer callout
  - **Firewall set changed** — the set of firewall devices in the path changed
  - **Path count only** — same device set, different number of returned paths (likely ECMP variation)
- Configurable peer normalization: strips trailing `-a`/`-b` suffixes before comparing
  device names, so active/standby failovers don't generate false positives
- Per-row expand panel with app search string, app URL, API URL, and full JSON response
- Summary bar and CSV export

**Use case:**
A path search returns different results than expected. Use this tool to find which
snapshot introduced the change and get a precise description of what shifted.

---

### Path Search Diff (`path_search_diff.py`)

Investigates why a path search returns results in one snapshot but not another.
For each device on the working path, runs a three-layer analysis across both snapshots.

**Features:**
- Runs path search against both snapshots and shows the working path as a hop list
- Each hop shows a presence indicator (green = device in broken path, red = absent)
- Severity badge per device, computed on demand: `!` error · `△` metadata/topology changed · `●` file changes only · `✓` clean
- Unions device names across ECMP-equivalent paths from the working snapshot, so
  redundant parallel devices are all included in the investigation set
- **Device metadata diff** — side-by-side comparison of `osVersion`, `collectionError`,
  `processingError`, `vendor`, `model`, `platform` between snapshots
- **Topology link diff** — interface adjacency changes between snapshots (lost links in red, new in green)
- **File diff** — unified diff of every device file across both snapshots, with configurable
  noise suppression to filter counters, timers, and other high-churn fields
- Noise filter selectable in the UI (default / strict / off); patterns stored in
  `path_diff_filters.json` for easy editing
- Shared saved searches via `path_search_config.json`

**Use case:**
A path search returns 10 hops in snapshot A but only 3 in snapshot B, or returns nothing
at all. Work through each device on the known-good path to find what changed — a downed
interface, a config change, a collection error, or a lost topology adjacency.

---

## Shared Configuration

All tools read and write `path_search_config.json` in the same directory.
This file stores saved searches and is created automatically on first run.

```json
{
  "savedSearches": [
    {
      "name": "prod-web-to-db",
      "srcIp": "10.0.1.100",
      "dstIp": "10.0.2.50",
      "intent": "PREFER_DELIVERED"
    }
  ]
}
```

The file is gitignored — it may contain customer network addressing.

---

## Architecture

Each tool is a self-contained Python script that:

1. Reads credentials from `FWD_CREDS_*` environment variables
2. Uses `fwd_discovery.py` to call the Forward Networks API and enumerate available
   networks and snapshots — no manual config files needed
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
├── path_search_builder.py      # Tool 1: interactive query builder and runner
├── path_search_compare.py      # Tool 2: parameter matrix comparison
├── path_search_history.py      # Tool 3: snapshot history audit
├── path_search_diff.py         # Tool 4: snapshot diff investigator
├── fwd_discovery.py            # Shared: network/snapshot discovery via API
├── path_search_config.json     # Auto-created: saved searches (gitignored)
└── path_diff_filters.json      # Auto-created: noise filter patterns for diff tool
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

---

## Author

**Robert Tavoularis**
Senior Customer Success Engineer — Forward Networks
[github.com/donotquestionauthority](https://github.com/donotquestionauthority)

Forward Networks builds network digital twins and network intelligence platforms.
These tools are independent utilities for working with the Forward Networks API and
are not official Forward Networks software.

---

## License

MIT License — use freely, attribution appreciated.