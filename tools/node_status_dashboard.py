#!/usr/bin/env python3
"""Loopback-only MindChain node health and capacity dashboard."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MindChain Node Status</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--paper:#f7f2e5;--ink:#3a352b;--strong:#1c1811;--muted:#96907f;--signal:#b8340f;--line:rgba(28,24,17,.18);--soft:rgba(28,24,17,.055)}
*{box-sizing:border-box}html{background:var(--paper);color:var(--ink);font-family:"Space Grotesk","Avenir Next","Helvetica Neue",sans-serif}body{margin:0;min-height:100dvh;background:radial-gradient(circle at 84% 4%,rgba(184,52,15,.055),transparent 25%),var(--paper)}
body:after{content:"";position:fixed;inset:0;pointer-events:none;opacity:.17;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.12'/%3E%3C/svg%3E")}
.shell{width:min(1480px,calc(100% - 48px));margin:0 auto;padding:22px 0 24px}.topbar{display:grid;grid-template-columns:270px 1fr auto;align-items:center;min-height:58px;border-bottom:1px solid var(--strong)}
.brand{display:flex;gap:12px;align-items:center;color:var(--strong);font-weight:600;font-size:19px}.mark{width:27px;height:33px}.title{font-size:clamp(24px,2.4vw,38px);letter-spacing:-.045em;color:var(--strong)}.live{display:flex;align-items:center;gap:12px;font:500 13px/1 "Fira Code",monospace;letter-spacing:.08em;text-transform:uppercase}.live-ring{width:26px;height:26px;border:2px solid var(--signal);border-radius:50%;display:grid;place-items:center}.live-ring:after{content:"";width:8px;height:8px;border-radius:50%;background:var(--signal);animation:breathe 2.2s cubic-bezier(.16,1,.3,1) infinite}
.grid{display:grid;grid-template-columns:minmax(0,1.85fr) minmax(330px,1fr);border-bottom:1px solid var(--strong)}.main{padding:28px 36px 22px 0}.side{border-left:1px solid var(--strong);padding:28px 0 22px 32px}.hero{display:flex;align-items:flex-end;justify-content:space-between;border-bottom:1px solid var(--strong);padding:0 0 10px}.hero h1{margin:0;color:var(--strong);font-size:clamp(56px,7vw,106px);line-height:.85;letter-spacing:-.075em;font-weight:700}.signal{width:25px;height:25px;background:var(--signal);border-radius:50%;margin:0 8px 7px 24px;animation:breathe 2.2s cubic-bezier(.16,1,.3,1) infinite}.signal.offline{animation:none;background:var(--muted)}
.data-row{display:grid;grid-template-columns:minmax(170px,1fr) minmax(180px,1.1fr);min-height:38px;align-items:center;border-bottom:1px solid var(--line);font-size:17px}.data-row span:last-child,.mono{font-family:"Fira Code",ui-monospace,monospace;font-variant-numeric:tabular-nums}.section-title{margin:30px 0 8px;font:600 17px/1 "Fira Code",monospace;letter-spacing:.04em;text-transform:uppercase;color:var(--strong)}
.capacity-row{display:grid;grid-template-columns:160px 165px minmax(160px,1fr);gap:14px;align-items:center;min-height:42px;border-top:1px solid var(--line)}.capacity-row:last-child{border-bottom:1px solid var(--line)}.capacity-name{font-size:16px}.capacity-value{font:500 14px/1.2 "Fira Code",monospace}.bar{height:10px;border:1px solid rgba(28,24,17,.45);position:relative}.bar>i{position:absolute;inset:0 auto 0 0;background:var(--ink);transform-origin:left;transition:transform .6s cubic-bezier(.16,1,.3,1)}
.side h2{font-size:30px;letter-spacing:-.04em;margin:0 0 10px;color:var(--strong);font-weight:500}.capability{display:grid;grid-template-columns:minmax(140px,1fr) auto 14px;gap:14px;align-items:center;min-height:66px;border-top:1px solid var(--line)}.capability:last-of-type{border-bottom:1px solid var(--line)}.capability-name{font-size:15px}.capability-state{font:500 13px/1 "Fira Code",monospace}.cap-dot{width:8px;height:8px;border-radius:50%;background:var(--strong)}.cap-dot.warn{background:var(--muted)}.action{width:100%;margin-top:34px;min-height:70px;border:1px solid var(--strong);background:var(--strong);color:var(--paper);font:500 20px/1 "Space Grotesk",sans-serif;cursor:pointer;transition:transform .25s cubic-bezier(.16,1,.3,1),background .25s}.action:hover{background:var(--ink)}.action:active{transform:translateY(1px) scale(.995)}.action[disabled]{background:var(--muted);border-color:var(--muted);cursor:not-allowed}
.footer{display:grid;grid-template-columns:1.3fr .8fr .8fr;min-height:68px;align-items:center}.foot{display:flex;align-items:center;gap:12px;font:400 12px/1.4 "Fira Code",monospace}.foot+ .foot{border-left:1px solid var(--line);padding-left:24px}.check{width:24px;height:24px;border:1px solid var(--ink);border-radius:50%;display:grid;place-items:center}.check:before{content:"";width:8px;height:4px;border-left:2px solid var(--ink);border-bottom:2px solid var(--ink);transform:rotate(-45deg) translateY(-1px)}.error{color:var(--signal)}.loading .value{position:relative;color:transparent}.loading .value:after{content:"";position:absolute;left:0;top:50%;width:45%;height:9px;background:var(--soft);transform:translateY(-50%);animation:shimmer 1.4s ease-in-out infinite}
@keyframes breathe{0%,100%{transform:scale(.72);opacity:.65}50%{transform:scale(1);opacity:1}}@keyframes shimmer{0%,100%{opacity:.45}50%{opacity:1}}
@media(min-width:851px) and (max-height:950px){.shell{padding:10px 0 12px}.topbar{min-height:48px}.main{padding:18px 26px 14px 0}.side{padding:18px 0 14px 24px}.hero h1{font-size:clamp(52px,6vw,88px)}.data-row{min-height:32px;font-size:15px}.section-title{margin:20px 0 7px;font-size:15px}.capacity-row{min-height:34px}.capacity-name{font-size:14px}.capacity-value{font-size:12px}.capability{min-height:54px}.action{margin-top:24px;min-height:58px;font-size:18px}.footer{min-height:54px}}
@media(max-width:850px){.shell{width:min(100% - 28px,720px);padding-top:10px}.topbar{grid-template-columns:1fr auto}.title{display:none}.grid{grid-template-columns:1fr}.main{padding:24px 0}.side{border-left:0;border-top:1px solid var(--strong);padding:24px 0}.hero h1{font-size:clamp(48px,15vw,76px)}.capacity-row{grid-template-columns:115px 1fr}.capacity-row .bar{grid-column:1/-1;margin-bottom:10px}.footer{grid-template-columns:1fr}.foot{min-height:48px}.foot+.foot{border-left:0;border-top:1px solid var(--line);padding-left:0}.live{font-size:11px}}
</style>
</head>
<body class="loading">
<main class="shell">
  <header class="topbar">
    <div class="brand"><svg class="mark" viewBox="0 0 28 34" fill="none" aria-hidden="true"><path d="M3 2v29M25 2v29M3 3l11 10L25 3M3 15l11 10 11-10M3 31l11-10 11 10" stroke="currentColor" stroke-width="2.6"/></svg><span>MindChain</span></div>
    <div class="title">Node Status</div>
    <div class="live"><span>LOCAL MAC · <b id="live-label">CHECKING</b></span><span class="live-ring"></span></div>
  </header>
  <section class="grid">
    <div class="main">
      <div class="hero"><h1 id="headline">NODE STATUS</h1><span class="signal offline" id="signal"></span></div>
      <div id="chain-rows">
        <div class="data-row"><span>Chain head</span><span class="value" id="head">—</span></div>
        <div class="data-row"><span>Justified epoch</span><span class="value" id="justified">—</span></div>
        <div class="data-row"><span>Finalized epoch</span><span class="value" id="finalized">—</span></div>
        <div class="data-row"><span>Sync state</span><span class="value" id="sync">—</span></div>
        <div class="data-row"><span>Uptime</span><span class="value" id="uptime">—</span></div>
        <div class="data-row"><span>Witness role</span><span class="value" id="role">—</span></div>
        <div class="data-row"><span>Peer target</span><span class="value" id="peer">—</span></div>
        <div class="data-row"><span>Last refresh</span><span class="value" id="refresh">—</span></div>
      </div>
      <h2 class="section-title">Device capacity</h2>
      <div id="capacity"></div>
    </div>
    <aside class="side">
      <h2>Capabilities</h2>
      <div id="capabilities"></div>
      <button class="action" id="compute" disabled>Open Compute Helper</button>
    </aside>
  </section>
  <footer class="footer">
    <div class="foot"><span class="check"></span><span id="summary">Reading local node state</span></div>
    <div class="foot"><span class="live-ring"></span><span id="poll-state">Local monitor active</span></div>
    <div class="foot"><span class="cap-dot warn" id="error-dot"></span><span id="error-state">No active errors</span></div>
  </footer>
</main>
<script>
const $=id=>document.getElementById(id);let market="";
const fmtBytes=n=>{if(n==null)return"Unavailable";const units=["B","KB","MB","GB","TB"];let i=0,v=n;while(v>=1024&&i<units.length-1){v/=1024;i++}return `${v>=10?v.toFixed(0):v.toFixed(1)} ${units[i]}`};
const metric=(name,value,percent)=>`<div class="capacity-row"><span class="capacity-name">${name}</span><span class="capacity-value">${value}</span><span class="bar"><i style="transform:scaleX(${Math.max(0,Math.min(100,percent||0))/100})"></i></span></div>`;
const capability=(name,state,warn=false)=>`<div class="capability"><span class="capability-name">${name}</span><span class="capability-state">${state}</span><span class="cap-dot ${warn?'warn':''}"></span></div>`;
async function refresh(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw new Error(`monitor HTTP ${response.status}`);const d=await response.json();document.body.classList.remove('loading');$('headline').textContent=d.online?'NODE ONLINE':'NODE OFFLINE';$('live-label').textContent=d.online?'LIVE':'OFFLINE';$('signal').classList.toggle('offline',!d.online);$('head').textContent=d.chain.head??'Unavailable';$('justified').textContent=d.chain.justified_epoch??'Unavailable';$('finalized').textContent=d.chain.finalized_epoch??'Unavailable';$('sync').textContent=d.chain.sync_state;$('uptime').textContent=d.process.uptime||'Unavailable';$('role').textContent=`Witness ${d.node.witness_index} · ${d.node.mode}`;$('peer').textContent=d.node.peer_target;$('refresh').textContent=new Date(d.observed_unix_ms).toLocaleTimeString();
const memPct=d.system.memory_total_bytes?100*d.system.memory_used_bytes/d.system.memory_total_bytes:0;const diskPct=d.system.disk_total_bytes?100*d.system.disk_used_bytes/d.system.disk_total_bytes:0;$('capacity').innerHTML=[metric('Host CPU',`${d.system.cpu_percent.toFixed(1)}%`,d.system.cpu_percent),metric('Memory',`${fmtBytes(d.system.memory_used_bytes)} / ${fmtBytes(d.system.memory_total_bytes)}`,memPct),metric('Disk',`${fmtBytes(d.system.disk_available_bytes)} available`,diskPct),metric('CPU cores',String(d.system.cpu_cores),100),metric('Architecture',d.system.architecture,100),metric('Process RSS',fmtBytes(d.process.rss_bytes),d.system.memory_total_bytes?100*d.process.rss_bytes/d.system.memory_total_bytes:0),metric('Node process CPU',`${d.process.cpu_percent.toFixed(1)}%`,d.process.cpu_percent)].join('');
$('capabilities').innerHTML=d.capabilities.map(c=>capability(c.name,c.state,c.state==='Unavailable')).join('');market=d.node.compute_market_url||'';$('compute').disabled=!market;$('summary').textContent=d.online?'All systems nominal · reconnect monitor armed':'Node unavailable · automatic reconnect remains armed';$('summary').classList.toggle('error',!d.online);$('error-state').textContent=d.error||'No active errors';$('error-state').classList.toggle('error',!!d.error);$('error-dot').classList.toggle('warn',!d.error);$('error-dot').style.background=d.error?'var(--signal)':'';$('poll-state').textContent=`Refresh ${d.cache_seconds}s · loopback only`;}catch(error){document.body.classList.remove('loading');$('headline').textContent='MONITOR ERROR';$('live-label').textContent='ERROR';$('signal').classList.add('offline');$('summary').textContent='Status monitor could not read local state';$('summary').classList.add('error');$('error-state').textContent=error.message;$('error-state').classList.add('error');}}
$('compute').addEventListener('click',()=>{if(market)window.open(market,'_blank','noopener')});refresh();setInterval(refresh,3000);
</script>
</body>
</html>"""


def run_text(command: list[str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def parse_elapsed(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    days = ""
    if "-" in value:
        day, value = value.split("-", 1)
        days = f"{int(day)}d "
    parts = [int(item) for item in value.split(":")]
    if len(parts) == 3:
        hours, minutes, _ = parts
    elif len(parts) == 2:
        hours, minutes = 0, parts[0]
    else:
        return value
    return f"{days}{hours:02d}h {minutes:02d}m"


def mac_memory() -> tuple[int | None, int | None]:
    total_text = run_text(["/usr/sbin/sysctl", "-n", "hw.memsize"])
    total = int(total_text) if total_text.isdigit() else None
    vm = run_text(["/usr/bin/vm_stat"])
    page_match = re.search(r"page size of (\d+) bytes", vm)
    if total is None or page_match is None:
        return total, None
    page_size = int(page_match.group(1))
    pages: dict[str, int] = {}
    for line in vm.splitlines():
        match = re.match(r"([^:]+):\s+(\d+)\.", line)
        if match:
            pages[match.group(1)] = int(match.group(2))
    reclaimable = sum(pages.get(name, 0) for name in (
        "Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"
    )) * page_size
    return total, max(0, total - reclaimable)


def host_cpu_percent(cores: int) -> float:
    values = run_text(["/bin/ps", "-A", "-o", "%cpu="])
    try:
        return min(100.0, max(0.0, sum(float(item) for item in values.split()) / max(1, cores)))
    except ValueError:
        try:
            return min(100.0, max(0.0, os.getloadavg()[0] * 100.0 / max(1, cores)))
        except OSError:
            return 0.0


def node_process() -> dict[str, Any]:
    pid_text = run_text(["/usr/bin/pgrep", "-x", "noosd"])
    pid = pid_text.splitlines()[0] if pid_text else ""
    if not pid.isdigit():
        return {"pid": None, "cpu_percent": 0.0, "rss_bytes": 0, "uptime": ""}
    values = run_text(["/bin/ps", "-o", "%cpu=,rss=,etime=", "-p", pid]).split()
    if len(values) < 3:
        return {"pid": int(pid), "cpu_percent": 0.0, "rss_bytes": 0, "uptime": ""}
    return {
        "pid": int(pid),
        "cpu_percent": float(values[0]),
        "rss_bytes": int(values[1]) * 1024,
        "uptime": parse_elapsed(values[2]),
    }


def operator_status(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=2) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("operator status was not an object")
    return value


class Monitor:
    def __init__(self, config: dict[str, Any], cache_seconds: float = 2.0):
        self.config = config
        self.cache_seconds = cache_seconds
        self.lock = threading.Lock()
        self.cached_at = 0.0
        self.cached: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            now = time.monotonic()
            if self.cached is not None and now - self.cached_at < self.cache_seconds:
                return self.cached
            value = self._collect()
            self.cached, self.cached_at = value, now
            return value

    def _collect(self) -> dict[str, Any]:
        invite = json.loads(Path(self.config["invite_path"]).read_text(encoding="utf-8"))
        cores = os.cpu_count() or 1
        total_memory, used_memory = mac_memory()
        disk = shutil.disk_usage(Path.home())
        process = node_process()
        error = None
        status: dict[str, Any] = {}
        try:
            status = operator_status(self.config["rpc_status_url"], self.config["rpc_token"])
        except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as exc:
            error = f"Local node RPC unavailable: {exc}"
        online = bool(status) and process["pid"] is not None
        unsafe = status.get("unsafe_head") if isinstance(status.get("unsafe_head"), dict) else {}
        justified = status.get("justified") if isinstance(status.get("justified"), dict) else {}
        finalized = status.get("finalized") if isinstance(status.get("finalized"), dict) else {}
        market = str(invite.get("compute_market_url", ""))
        architecture = platform.machine() or "unknown"
        return {
            "schema": "noos/node-status-dashboard/v1",
            "observed_unix_ms": int(time.time() * 1000),
            "cache_seconds": self.cache_seconds,
            "online": online,
            "error": error,
            "chain": {
                "chain_id": status.get("chain_id", invite.get("chain_id")),
                "genesis_hash": status.get("genesis_hash", invite.get("genesis_hash")),
                "head": unsafe.get("height"),
                "justified_epoch": justified.get("epoch"),
                "finalized_epoch": finalized.get("epoch"),
                "sync_state": "Following chain" if online else "Disconnected",
            },
            "node": {
                "mode": "Observer witness",
                "witness_index": int(invite["witness_index"]),
                "peer_target": f"{invite['validator_host']}:{invite['validator_p2p_port']}",
                "compute_market_url": market,
            },
            "process": process,
            "system": {
                "architecture": architecture,
                "platform": platform.platform(),
                "cpu_cores": cores,
                "cpu_percent": host_cpu_percent(cores),
                "memory_total_bytes": total_memory,
                "memory_used_bytes": used_memory,
                "disk_total_bytes": disk.total,
                "disk_used_bytes": disk.used,
                "disk_available_bytes": disk.free,
            },
            "capabilities": [
                {"name": "P2P transport", "state": "Active" if online else "Unavailable"},
                {"name": "Witness voting", "state": "Active" if online else "Unavailable"},
                {"name": "Automatic reconnect", "state": "Active"},
                {"name": "Local operator RPC", "state": "Available" if status else "Unavailable"},
                {"name": "Compute helper", "state": "Available" if market else "Unavailable"},
                {"name": "Device architecture", "state": architecture},
            ],
        }


class Handler(BaseHTTPRequestHandler):
    monitor: Monitor

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self.respond(APP_HTML.encode(), "text/html; charset=utf-8")
            return
        if self.path == "/api/status":
            self.respond(json.dumps(self.monitor.snapshot(), separators=(",", ":")).encode(), "application/json")
            return
        if self.path == "/health":
            self.respond(b'{"ok":true}', "application/json")
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def respond(self, body: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="127.0.0.1:19440")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    required = {"rpc_status_url", "rpc_token", "invite_path"}
    if not isinstance(config, dict) or not required.issubset(config):
        raise SystemExit("dashboard config is incomplete")
    host, port_text = args.listen.rsplit(":", 1)
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("dashboard must listen on loopback")
    Handler.monitor = Monitor(config)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    print(f"MindChain node dashboard ready at http://{host}:{port_text}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
