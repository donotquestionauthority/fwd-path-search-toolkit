#!/usr/bin/env python3
"""
Forward Networks Path Search Toolkit — Launcher
Starts all four tools and serves a home page at http://localhost:8760
"""

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

HOME_PORT = 8760

TOOLS = [
    {
        "name":     "Path Search Builder",
        "subtitle": "URL Builder & API Runner",
        "script":   "path_search_builder.py",
        "port":     8765,
        "icon":     "⬡",
    },
    {
        "name":     "Path Search Compare",
        "subtitle": "Parameter Matrix Analyzer",
        "script":   "path_search_compare.py",
        "port":     8766,
        "icon":     "⬡",
    },
    {
        "name":     "Path Search History",
        "subtitle": "Snapshot Audit Over Time",
        "script":   "path_search_history.py",
        "port":     8767,
        "icon":     "⬡",
    },
    {
        "name":     "Path Search Diff",
        "subtitle": "Snapshot Diff Investigator",
        "script":   "path_search_diff.py",
        "port":     8768,
        "icon":     "⬡",
    },
    {
        "name":     "Path Search Monitor",
        "subtitle": "Regression Watchlist",
        "script":   "path_search_monitor.py",
        "port":     8769,
        "icon":     "⬡",
    },
]

_processes: dict[int, subprocess.Popen] = {}


def _load_helpers():
    import importlib.util as _ilu
    _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fwd_helpers.py")
    _s = _ilu.spec_from_file_location("fwd_helpers", _p)
    _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
    return _m


def launch_tools(extra_env=None):
    """Start all tool subprocesses.
    extra_env: dict of additional environment variables to inject (e.g. credentials).
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    for tool in TOOLS:
        script = os.path.join(script_dir, tool["script"])
        if not os.path.exists(script):
            print(f"  ⚠  {tool['script']} not found — skipping")
            continue
        proc = subprocess.Popen(
            [sys.executable, script, '--no-browser'],
            cwd=script_dir,
            env=env,
        )
        _processes[tool["port"]] = proc
        print(f"  ✓  Started {tool['name']} (port {tool['port']}, pid {proc.pid})")


def tool_alive(port: int) -> bool:
    try:
        urllib.request.urlopen(f"http://localhost:{port}", timeout=1)
        return True
    except Exception:
        return False


HOME_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forward Networks — Path Search Toolkit</title>
<style>
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #21262d;
    --accent:   #00c8c8;
    --text:     #e6edf3;
    --muted:    #6e7681;
    --success:  #3fb950;
    --warning:  #d29922;
    --radius:   8px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 48px 24px;
  }
  .logo-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 6px;
  }
  .logo { font-size: 2rem; color: var(--accent); }
  h1 {
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: .12em;
    color: var(--accent);
  }
  .subtitle {
    font-size: 0.72rem;
    color: var(--muted);
    letter-spacing: .06em;
    margin-bottom: 40px;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
    width: 100%;
    max-width: 860px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px 20px 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    transition: border-color .15s;
    text-decoration: none;
    color: inherit;
  }
  .card:hover { border-color: var(--accent); }
  .card-icon { font-size: 1.4rem; color: var(--accent); }
  .card-name {
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: .1em;
    color: var(--accent);
  }
  .card-sub {
    font-size: 0.68rem;
    color: var(--muted);
  }
  .card-status {
    margin-top: auto;
    padding-top: 12px;
    font-size: 0.63rem;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot-up   { background: var(--success); }
  .dot-down { background: var(--warning); }
  .port { color: var(--muted); margin-left: auto; font-family: monospace; }
  .footer {
    margin-top: 48px;
    font-size: 0.62rem;
    color: var(--muted);
  }
</style>
</head>
<body>
<div class="logo-row">
  <span class="logo">⬡</span>
  <h1>FORWARD NETWORKS</h1>
</div>
<div class="subtitle">PATH SEARCH TOOLKIT</div>

<div class="grid" id="grid">Loading…</div>

<div class="footer">Launcher running at localhost:HOME_PORT &nbsp;·&nbsp; Ctrl+C in terminal to stop all tools</div>

<script>
const TOOLS = TOOLS_JSON;

async function render() {
  const grid = document.getElementById('grid');
  let statuses = {};
  try {
    const r = await fetch('/status');
    statuses = await r.json();
  } catch { /* leave statuses empty — all show Starting */ }

  grid.innerHTML = TOOLS.map(t => {
    const up = !!statuses[String(t.port)];
    const href = `http://localhost:${t.port}`;
    return `<a class="card" href="${href}" ${up ? 'target="_blank"' : 'onclick="return false"'}>
      <div class="card-icon">${t.icon}</div>
      <div class="card-name">${t.name}</div>
      <div class="card-sub">${t.subtitle}</div>
      <div class="card-status">
        <span class="dot ${up ? 'dot-up' : 'dot-down'}"></span>
        <span>${up ? 'Running' : 'Starting\u2026'}</span>
        <span class="port">:${t.port}</span>
      </div>
    </a>`;
  }).join('');

  const allUp = TOOLS.every(t => !!statuses[String(t.port)]);
  setTimeout(render, allUp ? 10000 : 3000);
}

render();
</script>
</body>
</html>
"""


def build_home_html() -> str:
    tools_json = json.dumps([
        {"name": t["name"], "subtitle": t["subtitle"],
         "port": t["port"], "icon": t["icon"]}
        for t in TOOLS
    ])
    return (HOME_HTML
            .replace("TOOLS_JSON", tools_json)
            .replace("HOME_PORT", str(HOME_PORT)))


class HomeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # suppress request logs

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = build_home_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/status":
            # Check all tool ports server-side to avoid CORS issues
            statuses = {str(t["port"]): tool_alive(t["port"]) for t in TOOLS}
            body = json.dumps(statuses).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()


def run():
    print("\n  ⬡  Forward Networks — Path Search Toolkit Launcher")
    print("  " + "─" * 50)

    helpers = _load_helpers()
    args    = helpers.parse_args()

    extra_env = {}

    if args["use_keychain"]:
        if not args["instance"]:
            print("  ⚠  --keychain requires --instance <hostname>  e.g. --instance fwd.app\n")
            sys.exit(1)
        if not args["network_ids"]:
            print("  ⚠  --keychain requires at least one --network <id>\n")
            sys.exit(1)

        # Load credentials from keychain into a temporary dict
        tmp_creds = {}
        found = helpers.load_credentials_from_keychain(tmp_creds, args["instance"], args["network_ids"])
        if found == 0:
            print("  ⚠  No credentials loaded from keychain. Exiting.\n")
            sys.exit(1)

        # Inject as FWD_CREDS_* env vars — each tool reads these on startup
        # Decode the Basic token back to raw value for env var format
        import base64
        for net_id, auth_header in tmp_creds.items():
            # auth_header is "Basic <base64(accessKey:secretKey)>"
            raw = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            extra_env[f"FWD_CREDS_{net_id}"] = raw

        # Inject base URL so tools know which instance to talk to
        extra_env["FWD_BASE_URL"] = f"https://{args['instance']}"
        print(f"\n  ✓  Credentials for {found} network(s) ready for injection.")
    else:
        # Non-keychain path — tools will read FWD_CREDS_* from env themselves
        # or fall back to interactive prompt (not ideal in launcher context)
        found = 0
        for k in os.environ:
            if k.startswith("FWD_CREDS_"):
                found += 1
        if found == 0:
            print("  ⚠  No FWD_CREDS_* environment variables found.")
            print("     Use --keychain --instance <host> --network <id> for keychain auth,")
            print("     or set FWD_CREDS_<networkId> environment variables before launching.\n")
            sys.exit(1)
        print(f"  ✓  {found} FWD_CREDS_* variable(s) found in environment.")

    launch_tools(extra_env=extra_env if extra_env else None)

    server = http.server.HTTPServer(("127.0.0.1", HOME_PORT), HomeHandler)

    def open_browser():
        time.sleep(0.6)
        webbrowser.open(f"http://localhost:{HOME_PORT}")

    threading.Thread(target=open_browser, daemon=True).start()

    print(f"\n  Home page: http://localhost:{HOME_PORT}")
    print(f"  Press Ctrl+C to stop all tools\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopping all tools…")
        for port, proc in _processes.items():
            proc.terminate()
        for port, proc in _processes.items():
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("  Done. Goodbye.\n")
        server.shutdown()


if __name__ == "__main__":
    run()