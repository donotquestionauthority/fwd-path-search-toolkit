# Forward Networks — Path Search Toolkit

**By Robert Tavoularis** · Senior Customer Success Engineer · Forward Networks

A collection of local browser-based tools for working with the Forward Networks
Path Search API. Each tool runs as a small Python web server that you open in
your browser — no cloud, no external dependencies, no install step beyond Python.

The toolkit is built for the use case of a network engineer who already has
Forward Networks deployed and wants to go deeper than the standard UI:
validating what parameters actually produce consistent results, tracking how
path behaviour changes across snapshots, investigating the root cause of a
regression, or monitoring that a resolved issue stays resolved.

---

## Tools

| Script | Port | Purpose |
|---|---|---|
| `launch.py` | 8760 | Launcher — starts all tools and serves a home page |
| `path_search_builder.py` | 8765 | Interactive query builder and live API runner |
| `path_search_compare.py` | 8766 | Parameter matrix tester |
| `path_search_history.py` | 8767 | Snapshot history audit |
| `path_search_diff.py` | 8768 | Snapshot diff investigator |
| `path_search_monitor.py` | 8769 | Regression watchlist monitor |

All tools share the same credential and network discovery mechanism and
read/write the same `path_search_config.json` file for saved searches.

---

## Requirements

- Python 3.7+ (standard library only — no `pip install` needed)
- Forward Networks instance with API access
- One API credential pair (access key + secret key) per network you want to work with

---

## Setup

### 1. Create API Credentials

In the Forward Networks UI: **Settings → Personal → Account → API Tokens → Generate API Token**

Each token gives you an **Access Key** and a **Secret Key**.

### 2. Find your Network ID

Navigate to your network in the Forward Networks UI. The network ID is visible in the
URL: `https://fwd.app/?/search?networkId=123456` — the numeric value is your network ID.

### 3. Set credentials

The toolkit reads credentials from environment variables at startup.
If none are found, you will be prompted to enter them at runtime —
credentials entered interactively are held in memory only and never written to disk.

Set one variable per network you want to work with, plus optionally a custom base URL:

```bash
export FWD_CREDS_123456="myAccessKey:mySecretKey"
export FWD_CREDS_789012="anotherKey:anotherSecret"
export FWD_BASE_URL="https://fwd.app"      # optional, this is the default
```

To make these permanent, add the `export` lines to your `~/.zshrc` or `~/.bash_profile`.

The environment variable name determines which network the credential is used for.
If you have one credential that gives access to many networks, you still need one
`FWD_CREDS_<networkId>` variable per network you want the toolkit to surface — the
variable names are your explicit allowlist.

### 4. Run

**Launch all tools at once (recommended):**

```bash
python3 launch.py
```

Opens a home page at `http://localhost:8760` with links and live status for all tools.
Press `Ctrl+C` to stop everything.

**Run a single tool:**

```bash
python3 path_search_builder.py
```

Each script starts a local web server and opens your browser automatically.
Press `Ctrl+C` to stop.

---

## Tool Reference

### Path Search Builder (`path_search_builder.py` · port 8765)

Build and run Forward Networks Path Search API queries interactively.
The left pane is the query form; the right pane shows the raw API response with
syntax highlighting, navigable one path at a time.

**What it does:**
- Discovers your networks and their snapshots automatically at startup
- Lets you set every key query parameter and see the URL it produces before running
- Navigates multi-path results one path at a time with filter pills for
  `forwardingOutcome`, `securityOutcome`, device type, and device name
- Shows a firewall summary panel that compares firewall device sets across all
  returned paths and flags asymmetry
- Generates the equivalent Forward Networks app deep-link URL alongside the API URL
- Saves and reloads named searches

**Parameters exposed in the UI:**

| Parameter | Description |
|---|---|
| `srcIp` | Source IP. Required unless using `from` (device-based search). |
| `dstIp` | Destination IP. Required. |
| `intent` | `PREFER_DELIVERED` (default), `PREFER_VIOLATIONS`, `VIOLATIONS_ONLY` |
| `ipProto` | IP protocol: `6`=TCP, `17`=UDP, `1`=ICMP |
| `dstPort` | Destination port (0–65535) or range e.g. `8080-8088` |
| `maxCandidates` | How far the search tree explores (API default if blank, max 10,000) |
| `maxResults` | Paths returned (default 1, max = maxCandidates) |
| `maxSeconds` | Query timeout in seconds (default 30, max 300) |
| `includeNetworkFunctions` | Include detailed per-hop forwarding information |

---

### Path Search Comparison (`path_search_compare.py` · port 8766)

Runs one or more src/dst pairs across a configurable matrix of `maxCandidates`,
`intent`, and port values. Scores each combination by firewall fingerprint
consistency and assigns a plain-English verdict.

Use this when you are not sure which parameter combination gives the most reliable
results for a given flow — for example, whether `PREFER_DELIVERED` or
`PREFER_VIOLATIONS` better surfaces the firewall you expect to see.

**Consensus states:**

| State | Meaning |
|---|---|
| `CLEAN` | All paths with a firewall hit the same device set |
| `SOFT` | One device set is dominant but not unanimous |
| `SPLIT` | No dominant fingerprint — results are inconsistent |
| `NO_FIREWALL` | No firewall hops found in any returned path |

The path count shown is the API's true hit count from `totalHits`, not the
number of paths analysed. When the tool's analysis used only a subset of paths
(the tool caps returned paths to keep the browser responsive), the cell shows
`(top N)` so you know the verdict is based on a sample.

Results are exportable as CSV.

---

### Path Search History (`path_search_history.py` · port 8767)

Runs the same path search across a range of historical snapshots and reports
how the results changed over time. Each snapshot gets a classification:

| Class | Meaning |
|---|---|
| `NO_CHANGE` | Identical hop and firewall sets |
| `HOP_SET_CHANGED` | Different devices in the path |
| `HOP_SET_SIMILAR` | Same devices, different count |
| `FW_SET_CHANGED` | Firewall devices changed |
| `FW_APPEARED` | Firewall present in this snapshot but not the baseline |
| `FW_DISAPPEARED` | Firewall present in baseline but not this snapshot |
| `PATH_COUNT_ONLY` | Only the number of paths changed |

Use this to answer "when did this path start behaving differently" and narrow
the time range before opening the diff tool.

---

### Path Search Diff (`path_search_diff.py` · port 8768)

Investigates *why* a path search returns different results between two snapshots.
You select a working snapshot and a broken snapshot; the tool runs the same search
against both, identifies the devices on the changed path, and for each device
shows a three-layer analysis:

1. **Device inventory** — metadata changes (platform, OS version, collection errors)
2. **Config file diff** — line-by-line diff of configuration files with noise suppression
3. **Interface state** — link and interface status changes

Noise suppression patterns are stored in `path_diff_filters.json`. Edit the file
directly — no code changes needed. When the toolkit starts for the first time it
writes a default set of patterns; after that the file is yours to customise.

---

### Path Search Monitor (`path_search_monitor.py` · port 8769)

A watchlist-based regression monitor for tracking whether resolved issues stay
resolved. Add an entry with the baseline snapshot where the path was known-good,
plus the path parameters and optional case/Jira IDs. The monitor then runs the
same search against every subsequent snapshot and classifies each result.

**Workflow:**
- When you add an entry, the tool favorites the baseline snapshot via the API
  and adds a monitoring note to it so it is protected from rotation
- Run checks manually per entry, or click **Run All** to process the full watchlist
  — each entry updates live as it completes rather than blocking until the whole
  run finishes
- Click **Stop** at any time to halt after the current entry completes
- **Archive** exports a zip of all results to `EVIDENCE_DIR` as audit evidence
  and marks the entry as resolved

**Additional environment variables:**

| Variable | Description |
|---|---|
| `JIRA_BASE_URL` | Your Jira instance URL — Jira IDs in entries become clickable links |
| `EVIDENCE_DIR` | Folder path where archived evidence zips are written |

---

## Credential and network status

At startup each tool calls the Forward Networks API to look up the name and
snapshots for every network in your credentials. If something goes wrong with a
specific credential the affected network shows a status badge in its dropdown
rather than appearing as an empty-snapshot entry:

| Badge | Cause |
|---|---|
| `[auth failed]` | The credential was rejected (401/403). Check the access key and secret key. |
| `[unreachable]` | The API returned an error or timed out. Check connectivity and `FWD_BASE_URL`. |
| `[not in cred scope]` | The credential authenticated but the network ID is not in its scope. Check that the env var name matches the actual network ID. |

Networks with a status badge stay visible in the dropdown but cannot be selected.
Other networks in the same toolkit session continue to work normally.

---

## Security

The toolkit is intended for individual use against a Forward Networks instance
you have authorized access to.

- All API calls are proxied through the local Python server — credential values
  are never sent to the browser or stored in config files
- The local server binds to `127.0.0.1` only and is not reachable from other
  machines on the network
- Credentials entered at the runtime prompt are held in memory only for that session
- No credential values appear in any log, config file, or the repository

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
├── fwd_helpers.py              # Shared: API helpers, path search, validation
├── fwd_discovery.py            # Shared: network/snapshot discovery via API
├── path_search_config.json     # Auto-created: saved searches (gitignored)
├── path_search_monitor.json    # Auto-created: monitor watchlist (gitignored)
└── path_diff_filters.json      # Auto-created: noise filter patterns (gitignored)
```

---

## Troubleshooting

**No credentials found at startup**
You will be prompted to enter your network ID, access key, and secret key interactively.
To avoid the prompt on every startup, set `FWD_CREDS_<networkId>` in your shell profile.

**Network shows `[auth failed]` in the dropdown**
The access key or secret key for that network is wrong or has been revoked.
Fix the `FWD_CREDS_<networkId>` value and restart.

**Network shows `[not in cred scope]`**
The credential authenticated successfully but the API did not return that network ID
in the list of networks visible to that credential. The most common cause is a typo
in the env var name — check that `FWD_CREDS_<networkId>` exactly matches the
network ID shown in the Forward Networks URL.

**Snapshot dropdown is empty for a network**
The network has no snapshots in `PROCESSED` state. This is a data state issue
in Forward Networks, not a credential or configuration problem.

**"No paths returned. Check search parameters"**
The path search ran but the API returned zero paths. Try relaxing the parameters —
increase `maxCandidates`, change `intent` to `PREFER_DELIVERED`, or check that
the source and destination IPs are correct for the selected network.

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
