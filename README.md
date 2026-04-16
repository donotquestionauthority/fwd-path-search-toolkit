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
| `launch.py` | 8760 | Launcher — starts all tools and serves a home page |
| `path_search_builder.py` | 8765 | Interactive query builder and live API runner |
| `path_search_compare.py` | 8766 | Parameter matrix tester — find the combination that produces the most consistent results |
| `path_search_history.py` | 8767 | Snapshot history audit — track how path search results change over time |
| `path_search_diff.py` | 8768 | Snapshot diff investigator — hop-by-hop analysis of why a path changed between two snapshots |
| `path_search_monitor.py` | 8769 | Regression monitor — watchlist of resolved issues, alerts on reappearance |

All tools share the same credential and network discovery mechanism and
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

### 3. Credentials

The toolkit reads credentials from environment variables at startup.
If none are found, you will be prompted to enter them at runtime —
credentials entered this way are held in memory only and never written to disk.

**Environment variables (optional — if not set, you will be prompted at runtime):**

| Variable | Description |
|---|---|
| `FWD_CREDS_<networkId>` | Credentials for a network, as `accessKey:secretKey`. One variable per network. |
| `FWD_BASE_URL` | Your Forward Networks instance URL. Defaults to `https://fwd.app` if not set. |
| `JIRA_BASE_URL` | Your Jira instance URL. Used by the monitor tool to hyperlink Jira IDs. Optional. |
| `EVIDENCE_DIR` | Folder path where the monitor tool writes evidence archives. Optional. |

How you set and persist environment variables is your choice and should follow
your organisation's credential management policy.

### 4. Run

**Launch all tools at once (recommended):**

```bash
python3 launch.py
```

Opens a home page at `http://localhost:8760` with links to all tools.
Press `Ctrl+C` to stop all tools.

**Run a single tool:**

```bash
python3 path_search_builder.py
```

Each script starts a local web server and opens your browser automatically.
Press `Ctrl+C` to stop.

---

## Tool Reference

### Path Search Builder (`path_search_builder.py`)

Build and execute Forward Networks [Path Search API](https://docs.fwd.app/latest/api/) queries interactively.

**Features:**
- Dynamic network and snapshot discovery — no manual configuration
- Live JSON response with syntax highlighting
- Navigate multi-path results one at a time
- Filter by `forwardingOutcome`, `securityOutcome`, device type, device name
- **Smart rank** — sorts by outcome tier then longest hops
- **Rank by hops** — sorts by longest path regardless of outcome
- Firewall summary panel — compares firewall device sets across all returned paths
- Forward Networks App search string and deep-link URL generation
- **Copy summary / Export summary** — formatted path summary for sharing
- Save and reload named searches

**Key parameters:**

| Parameter | Description |
|---|---|
| `srcIp` | Source IP (required) |
| `dstIp` | Destination IP (required) |
| `intent` | `PREFER_DELIVERED` (default), `PREFER_VIOLATIONS`, `VIOLATIONS_ONLY` |
| `ipProto` | IP protocol number: `6`=TCP, `17`=UDP, `1`=ICMP |
| `dstPort` | Destination port (0–65535) |
| `maxCandidates` | Search space size (API default if blank, max 10,000) |
| `maxResults` | Paths to return (default 1, max = maxCandidates) |
| `maxSeconds` | Query timeout (default 30, max 300) |

---

### Path Search Comparison (`path_search_compare.py`)

Runs src/dst pairs across a matrix of `maxCandidates`, `intent`, and port combinations,
then scores and ranks each combination by result consistency.

---

### Path Search History (`path_search_history.py`)

Runs the same path search across historical snapshots and reports how results change over time.
Detects and classifies: `HOP_SET_CHANGED`, `HOP_SET_SIMILAR`, `FW_SET_CHANGED`,
`FW_APPEARED`, `FW_DISAPPEARED`, `PATH_COUNT_ONLY`.

---

### Path Search Diff (`path_search_diff.py`)

Investigates why a path search returns different results between two snapshots.
Per-device analysis: metadata diff, topology link diff, file diff with configurable noise suppression.

Noise patterns are stored in `path_diff_filters.json` — edit directly, no code changes needed.

---

### Path Search Monitor (`path_search_monitor.py`)

Watchlist-based regression monitor for tracking resolved issues.

- Add entries with baseline snapshot, path parameters, case ID, Jira ID, and notes
- On add: favorites the baseline snapshot and sets a monitoring note via the API
- Runs path searches against all subsequent snapshots, classifies each result
- Archive exports a zip of all results to `EVIDENCE_DIR` as audit evidence

**Additional environment variables:**

| Variable | Description |
|---|---|
| `JIRA_BASE_URL` | Jira instance URL — Jira IDs become clickable links |
| `EVIDENCE_DIR` | Folder where evidence zips are written on archive |

---

## Security
This tool is intended for individual use with your own API credentials against a Forward Networks instance you have authorized access to. How you supply and store those credentials is your choice and should follow your organization's policies.

- Credentials are read from environment variables at startup, or prompted at runtime
- Credentials entered at runtime are held in memory only — never written to disk by the application
- No credential values are stored in any configuration file, log, or the repository
- All API calls are proxied through the local Python server — credentials are never exposed to the browser
- The local server binds to `127.0.0.1` only — not accessible from other machines on the network

---

## Files

```
.
├── README.md
├── launch.py                   # Launcher: starts all tools, home page at :8760
├── path_search_builder.py      # Tool 1: interactive query builder and runner
├── path_search_compare.py      # Tool 2: parameter matrix comparison
├── path_search_history.py      # Tool 3: snapshot history audit
├── path_search_diff.py         # Tool 4: snapshot diff investigator
├── path_search_monitor.py      # Tool 5: regression watchlist monitor
├── fwd_discovery.py            # Shared: network/snapshot discovery via API
├── path_search_config.json     # Auto-created: saved searches (gitignored)
├── path_search_monitor.json    # Auto-created: monitor watchlist (gitignored)
└── path_diff_filters.json      # Auto-created: noise filter patterns (gitignored)
```

---

## Troubleshooting

**No credentials found at startup**
You will be prompted to enter your network ID, access key, and secret key.
Credentials are used for this session only and are not persisted.

**"No credentials for network X"**
The network ID must exactly match what the API returns.
Check the ID shown in the dropdown after credentials load.

**"Discovery failed"**
Check that `FWD_BASE_URL` is correct, your machine has connectivity to the
Forward Networks instance, and the access key and secret key are correct.

---

## Author

**Robert Tavoularis**
Senior Customer Success Engineer — Forward Networks
[github.com/donotquestionauthority](https://github.com/donotquestionauthority)

These tools are independent utilities for working with the Forward Networks API
and are not official Forward Networks software.

---

## License

MIT License — use freely, attribution appreciated.