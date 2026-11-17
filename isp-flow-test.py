#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["rich>=13", "scapy>=2.5"]
# ///
"""
isp-flow-test.py — guided test for "some connections are fast, others crawl" on a broadband line.

The fault it was written for: each TCP connection to some destinations is either full speed or
stuck far below it for its whole life, while other destinations are always fine. That pattern
usually means one member of a link bundle (LAG) or an equal-cost path (ECMP) inside the ISP or
its upstream is faulty: each connection is hashed onto one member, and keeps it.

The script runs the same battery from up to four vantage points, asking first which ones, then
prompting between each:

  1. own-wired  — wired into your own network (your router behind the ISP's)
  2. own-wifi   — on your own Wi-Fi
  3. isp-wifi   — on the ISP router's own Wi-Fi (none of your equipment in the path)
  4. isp-wired  — wired into the ISP router (none of your equipment, no Wi-Fi) [default]

Per vantage point it collects:
  * per-connection throughput: fresh, sequential TCP connections (default 16 rounds x 5 s),
    interleaved across targets so that changes over time affect every target equally
  * a fixed-source-port test: re-uses the same local ports several times. If outcomes stick to
    the port, the fault follows a flow hash (LAG/ECMP member); if they don't, it's random
  * packet captures (tcpdump, headers only; needs sudo once) of single downloads, analysed for
    retransmissions, holes, SACKs and stalls; slow captures and one fast one are kept as .pcap
  * long-running connections (default 4 x 30 s) with throughput sampled every second, to show
    whether a slow connection ever recovers
  * a parallel-stream test (iperf3, 16 streams, both directions) against public servers; needs
    `brew install iperf3`, otherwise it's skipped
  * traceroutes (3 probes per hop) with reverse DNS, origin AS and internet-exchange hops
    flagged, merged into a ROUTE MAP that colours every router by the share of slow connections
    through it and highlights routers found only on bad routes
  * per-flow path probes: TCP traceroutes (scapy, needs sudo) sent with the exact source ports
    that were consistently slow or fast, to show where the bad and good paths part
  * ping loss/RTT to every destination, and forward DNS for every target

It then aggregates everything into one folder and a .zip for the ISP's support team:
  report.html (self-contained, open in any browser), summary.txt, message.txt (a draft
  message with the automatic analysis appended at the bottom), README.txt and raw data.

Drives curl, traceroute/traceroute6, ping/ping6, whois, tcpdump and iperf3. Rich (progress
display) and scapy (path probes) are optional; `uv run` installs both. Written for macOS.

Usage:
  ./isp-flow-test.py                            # asks which vantage points (default: ISP router, wired)
  ./isp-flow-test.py --phases own-wired,isp-wired   # skip the question
  ./isp-flow-test.py --targets hetzner-fsn,ovh-rbx  # a subset of destinations (control always kept)
  ./isp-flow-test.py --quick                    # 4 rounds x 3 s, for a dry run
  ./isp-flow-test.py --report-only DIR          # rebuild the report and zip from an earlier run
  ./isp-flow-test.py --resume DIR               # add phases to an earlier run
"""

import argparse
import csv
import datetime as dt
import getpass
import html
import ipaddress
import json
import math
import os
import platform
import random
import re
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

VERSION = "3.1.0"

# name, IPv4 URL, IPv6 URL (None = target has no IPv6), role, note
TARGETS = [
    ("github-fastly",
     "https://github.com/espressif/crosstool-NG/releases/download/esp-14.2.0_20260121/"
     "riscv32-esp-elf-14.2.0_20260121-x86_64-linux-gnu.tar.xz",
     None, "test", "GitHub release download, served by Fastly (github.com has no IPv6)"),
    ("alpine-fastly",
     "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-extended-3.20.3-x86_64.iso",
     "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-extended-3.20.3-x86_64.iso",
     "test", "Alpine Linux CDN, Fastly"),
    ("hetzner-ash-http",
     "http://ash-speed.hetzner.com/1GB.bin", "http://ash-speed.hetzner.com/1GB.bin",
     "test", "Hetzner speed-test server, Ashburn USA, plain HTTP (~75 ms away)"),
    ("hetzner-ash-https",
     "https://ash-speed.hetzner.com/1GB.bin", "https://ash-speed.hetzner.com/1GB.bin",
     "test", "Hetzner speed-test server, Ashburn USA, HTTPS (~75 ms away)"),
    ("thinkbroadband",
     "http://ipv4.download.thinkbroadband.com/1GB.zip", "http://ipv6.download.thinkbroadband.com/1GB.zip",
     "control", "thinkbroadband test file, UK; usually reached via exchange peering (control)"),
    # Extra destinations on different networks. Their route (exchange peering or not) is worked
    # out from this run's traceroutes rather than assumed.
    ("leaseweb-lon",
     "http://speedtest.lon1.uk.leaseweb.net/1000mb.bin", "http://speedtest.lon1.uk.leaseweb.net/1000mb.bin",
     "probe", "Leaseweb speed-test server, London"),
    ("clouvider-lon",
     "http://lon.speedtest.clouvider.net/1g.bin", "http://lon.speedtest.clouvider.net/1g.bin",
     "probe", "Clouvider speed-test server, London"),
    ("vultr-lon",
     "https://lon-gb-ping.vultr.com/vultr.com.1000MB.bin", None,
     "probe", "Vultr speed-test server, London (no IPv6)"),
    ("ovh-rbx",
     "https://proof.ovh.net/files/1Gb.dat", "https://proof.ovh.net/files/1Gb.dat",
     "probe", "OVHcloud test file, Roubaix, France"),
    ("hetzner-fsn",
     "https://fsn1-speed.hetzner.com/1GB.bin", "https://fsn1-speed.hetzner.com/1GB.bin",
     "probe", "Hetzner speed-test server, Falkenstein, Germany"),
]
TARGET_NAMES = [t[0] for t in TARGETS]
PORT_TEST_TARGET = "hetzner-ash-http"   # also used by the packet-capture and long-connection tests

# Internet-exchange peering LANs: a traceroute hop inside one means the path peers there.
# Add your local exchanges' peering LAN prefixes (published by each exchange, or on PeeringDB).
IX_PREFIXES = [
    ("LINX", "195.66.224.0/22"), ("LINX", "195.66.236.0/22"), ("LINX", "2001:7f8:4::/48"),
    ("LONAP", "5.57.80.0/22"), ("LONAP", "2001:7f8:17::/48"),
]
IX_NETS = [(n, ipaddress.ip_network(p)) for n, p in IX_PREFIXES]
IX_LABEL = ", ".join(sorted({n for n, _ in IX_PREFIXES}))

# Public iperf3 servers (host, first port, last port, note). Busy ports are skipped.
IPERF_SERVERS = [
    ("lon.speedtest.clouvider.net", 5200, 5209, "Clouvider, London"),
    ("speedtest.lon1.uk.leaseweb.net", 5201, 5210, "Leaseweb, London"),
    ("nyc.speedtest.clouvider.net", 5200, 5209, "Clouvider, New York"),
    ("ping.online.net", 5200, 5209, "Scaleway, Paris"),
]

PHASES = {
    "own-wired": {
        "title": "Via your own router, wired",
        "short": "Own wired",
        "medium": "wired",
        "side": "own",
        "prompt": ("Plug this computer into your normal network (a port on your own router or switch)\n"
                   "  and turn Wi-Fi OFF. If your router has more than one internet connection, make\n"
                   "  sure traffic leaves via the one under test."),
    },
    "own-wifi": {
        "title": "Via your own router, over its Wi-Fi",
        "short": "Own Wi-Fi",
        "medium": "wifi",
        "side": "own",
        "prompt": ("Unplug Ethernet and join your normal Wi-Fi.\n"
                   "  Traffic must leave via the internet connection under test."),
    },
    "isp-wifi": {
        "title": "Directly on the ISP router, over its own Wi-Fi",
        "short": "ISP Wi-Fi",
        "medium": "wifi",
        "side": "isp",
        "prompt": "Join the ISP router's own Wi-Fi network. Unplug any Ethernet cable.",
    },
    "isp-wired": {
        "title": "Directly on the ISP router, wired",
        "short": "ISP wired",
        "medium": "wired",
        "side": "isp",
        "prompt": ("Plug into an Ethernet port on the ISP router (its fastest one, if they differ),\n"
                   "  then turn Wi-Fi OFF."),
    },
}
# Ordered to need the fewest cable/Wi-Fi changes: own cable -> own Wi-Fi -> ISP Wi-Fi -> ISP cable
PHASE_ORDER = ["own-wired", "own-wifi", "isp-wifi", "isp-wired"]
PHASE_ALIASES = {"own": ["own-wired", "own-wifi"], "isp": ["isp-wifi", "isp-wired"]}

CURL_FMT = ("%{http_code}|%{remote_ip}|%{local_port}|%{time_connect}|%{time_appconnect}|"
            "%{time_starttransfer}|%{time_total}|%{size_download}")
VPN_IFACE_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap", "wg")
FLOW_FIELDS = ["phase", "test", "round", "target", "role", "family", "requested_port", "class", "mbps",
               "bytes", "http_code", "remote_ip", "local_port", "t_connect", "t_tls", "t_ttfb", "t_total",
               "curl_rc", "error", "time"]


# ---------------------------------------------------------------- helpers

def run(cmd, timeout=30):
    # stdin=DEVNULL matters: `sudo` (use_pty, the macOS default) puts the controlling terminal into
    # raw mode while its child runs if it can see the tty. That turned off newline translation and
    # left the progress display "staircased" and smeared mid-run.
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


class BudgetExceeded(Exception):
    """Raised before a transfer would start once --max-gb has been used up."""


class Budget:
    """Bytes moved by test transfers: downloads, capture and long-connection downloads, and iperf3
    in both directions. Transfers are sequential, so no locking is needed."""

    def __init__(self):
        self.limit, self.used = None, 0

    def add(self, n):
        self.used += max(int(n or 0), 0)

    def check(self):
        if self.limit is not None and self.used >= self.limit:
            raise BudgetExceeded(f"data budget of {self.limit / 1e9:g} GB reached "
                                 f"({self.used / 1e9:.1f} GB moved)")

    def label(self):
        return f"{self.used / 1e9:.1f} GB" + (f" of {self.limit / 1e9:g}" if self.limit is not None else "")


BUDGET = Budget()


class UI:
    """Terminal output. Uses Rich (progress bars, colour, tables) when it's installed — `uv run`
    installs it automatically from the header above — and falls back to plain text otherwise."""

    def __init__(self):
        self.rich, self.console, self.progress = False, None, None
        self.overall = self.sub = None
        self.sub_total = self.sub_done_n = 0
        self.counts = {}
        self.plain_done = self.plain_total = 0
        try:
            from rich.console import Console
            self.console = Console(highlight=False)
            self.rich = True
        except ImportError:
            pass

    # ---- lines
    @staticmethod
    def _style(msg):
        m = msg.strip()
        if "<-- SLOW" in m or m.startswith("PROBLEM") or m.startswith("ABORT"):
            return "bold red" if m.startswith("PROBLEM") else "red"
        if "<-- ERROR" in m or m.startswith("WARNING") or "skipped" in m:
            return "yellow"
        if m.startswith("--"):
            return "bold cyan"
        if m.startswith("OK") or m.startswith("✓"):
            return "green"
        return None

    def print(self, msg="", style=None):
        if not self.rich:
            print(msg, flush=True)
            return
        con = self.progress.console if self.progress else self.console
        con.print(msg, style=style or self._style(msg), markup=False, highlight=False)

    def rule(self, title):
        if self.rich:
            self.console.print()
            self.console.rule(f"[bold]{title}")
        else:
            print("\n" + "=" * 78 + f"\n  {title}\n" + "=" * 78, flush=True)

    # ---- terminal state guard
    _tty_saved = None

    def tty_save(self):
        try:
            import termios
            if sys.stdin.isatty():
                UI._tty_saved = termios.tcgetattr(sys.stdin.fileno())
        except (ImportError, OSError):
            UI._tty_saved = None

    def tty_restore(self):
        """Put the terminal back the way it was, in case a child process changed its mode."""
        if UI._tty_saved is None:
            return
        try:
            import termios
            if termios.tcgetattr(sys.stdin.fileno()) != UI._tty_saved:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, UI._tty_saved)
        except (ImportError, OSError):
            pass

    # ---- progress
    def phase_start(self, title, total):
        self.tty_save()
        self.counts = {}
        self.plain_done, self.plain_total = 0, total
        if not self.rich:
            return
        from rich.progress import (BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn,
                                   TimeElapsedColumn, TimeRemainingColumn)
        self.progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30),
                                 MofNCompleteColumn(), TimeElapsedColumn(), TextColumn("· left"),
                                 TimeRemainingColumn(), console=self.console)
        self.progress.start()
        self.title = title
        self.overall = self.progress.add_task(f"[bold]{title} — overall · {BUDGET.label()}", total=max(total, 1))

    def section(self, name, total):
        self._close_section()
        self.sub_total, self.sub_done_n, self.sub_name = max(total, 1), 0, name
        self.counts = {"fast": 0, "slow": 0, "error": 0}
        if self.progress:
            self.sub = self.progress.add_task(f"  {name}", total=self.sub_total)

    def tick(self, cls=None, detail=""):
        self.tty_restore()
        self.sub_done_n += 1
        self.plain_done += 1
        if cls in self.counts:
            self.counts[cls] += 1
        if self.progress:
            c = self.counts
            tally = (f" · [red]{c['slow']} slow[/] / [green]{c['fast']} fast[/]" if c.get("slow") or c.get("fast") else "")
            tally += f" · [yellow]{c['error']} err[/]" if c.get("error") else ""
            self.progress.update(self.sub, advance=1, description=f"  {self.sub_name}{' · ' + detail if detail else ''}{tally}")
            self.progress.update(self.overall, advance=1,
                                 description=f"[bold]{self.title} — overall · {BUDGET.label()}")
        elif self.plain_total and self.plain_done % 10 == 0:
            print(f"     [{self.plain_done}/{self.plain_total} steps done in this phase · {BUDGET.label()}]",
                  flush=True)

    def _close_section(self):
        if self.sub is not None and self.progress:
            rest = self.sub_total - self.sub_done_n
            if rest > 0:
                self.progress.update(self.overall, advance=rest)
            self.progress.update(self.sub, completed=self.sub_total)
        elif not self.rich and self.sub_total:
            self.plain_done += max(self.sub_total - self.sub_done_n, 0)
        self.sub, self.sub_total, self.sub_done_n = None, 0, 0

    def phase_end(self):
        self.tty_restore()
        self._close_section()
        if self.progress:
            self.progress.update(self.overall, completed=self.progress.tasks[0].total)
            self.progress.stop()
        self.progress = self.overall = None

    # ---- results
    def results(self, an, files):
        if not self.rich:
            print(summary_table(an))
            print("\nAnalysis")
            for line in an["lines"]:
                print(f"  - {line}")
            for k, v in files:
                print(f"{k + ':':<10}{v}")
            return
        from rich.panel import Panel
        from rich.table import Table
        t = Table(title="Results by vantage point and destination", show_lines=False, header_style="bold")
        for col, j in (("Vantage point", "left"), ("Target", "left"), ("Fam", "left"), ("Slow", "right"),
                       ("Median fast MB/s", "right"), ("Median slow MB/s", "right")):
            t.add_column(col, justify=j)
        for ph in an["phases"]:
            for (tname, fam), st in ph["per"].items():
                slow_txt = fmt_pct(st)
                t.add_row(ph["P"]["meta"]["short"], tname, f"v{fam}",
                          f"[red]{slow_txt}[/]" if st["slow"] else f"[green]{slow_txt}[/]",
                          num(st["med_fast"], ".1f"), num(st["med_slow"], ".2f"))
        self.console.print(t)
        self.console.print(Panel("\n".join(f"• {l}" for l in an["lines"]), title="Analysis", border_style="cyan"))
        body = "\n".join(f"[bold]{k:<8}[/] {v}" for k, v in files)
        self.console.print(Panel(body, title="Support package", border_style="green"))


ui = UI()


def say(msg=""):
    ui.print(msg)


def hr(title):
    ui.rule(title)


def num(v, fmt):
    return "-" if v is None else format(v, fmt)


def phase_seconds(args, nfam):
    """Rough duration of one phase, for the progress messages."""
    combos = sum(1 for t in TARGETS if t[1]) + (sum(1 for t in TARGETS if t[2]) if nfam > 1 else 0)
    s = combos * args.rounds * (args.seconds + 1.2) + 30
    if not args.no_port_test:
        s += nfam * args.port_count * args.port_reps * (args.seconds + 1.2)
    if not args.no_trace:
        s += 60 * nfam
    if not args.no_pcap:
        s += nfam * min(args.pcap_flows, 6) * (args.pcap_seconds + 3)
    if not args.no_flowtrace and not args.no_port_test:
        s += nfam * 4 * args.flowtrace_ports * 5
    if not args.no_long:
        s += nfam * args.long_count * (args.long_seconds + 2)
    if not args.no_iperf:
        s += nfam * args.iperf_max * 2 * (args.iperf_seconds + 5)
    return s


def default_route(family):
    cmd = ["route", "-n", "get"] + (["-inet6"] if family == 6 else []) + ["default"]
    rc, out, _ = run(cmd, timeout=5)
    if rc != 0:
        return None, None
    gw = iface = None
    for line in out.splitlines():
        k, _, v = line.strip().partition(":")
        if k == "gateway":
            gw = v.strip()
        elif k == "interface":
            iface = v.strip()
    return gw, iface


def hardware_ports():
    """device -> hardware port name, e.g. {'en0': 'Wi-Fi', 'en7': 'USB 10/100/1G/2.5G/5G/10G LAN'}."""
    rc, out, _ = run(["networksetup", "-listallhardwareports"], timeout=10)
    ports, name = {}, None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and name:
            ports[line.split(":", 1)[1].strip()] = name
    return ports


def iface_media(iface):
    if not iface:
        return ""
    rc, out, _ = run(["ifconfig", iface], timeout=5)
    m = re.search(r"media:\s*(.+)", out)
    return m.group(1).strip() if m else ""


def wifi_info():
    rc, out, _ = run(["system_profiler", "SPAirPortDataType", "-json"], timeout=30)
    try:
        for ent in json.loads(out).get("SPAirPortDataType", []):
            for iface in ent.get("spairport_airport_interfaces", []):
                cur = iface.get("spairport_current_network_information")
                if cur:
                    return {"interface": iface.get("_name"), "phy_mode": cur.get("spairport_network_phymode"),
                            "channel": cur.get("spairport_network_channel"),
                            "tx_rate_mbps": cur.get("spairport_network_rate"),
                            "signal_noise": cur.get("spairport_signal_noise")}
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return {}


def public_ip(family):
    probe = "https://api6.ipify.org?format=json" if family == 6 else "https://api.ipify.org?format=json"
    rc, out, _ = run(["curl", "-s", f"-{family}", "-m", "6", probe], timeout=10)
    try:
        ip = json.loads(out).get("ip") if rc == 0 and out else None
    except json.JSONDecodeError:
        ip = None
    if not ip:
        return None
    info = {"ip": ip, "org": ""}
    rc, out, _ = run(["curl", "-s", "-m", "6", f"https://ipinfo.io/{ip}/json"], timeout=10)
    try:
        j = json.loads(out) if rc == 0 and out else {}
        info.update(org=j.get("org", ""), hostname=j.get("hostname", ""), city=j.get("city", ""))
    except json.JSONDecodeError:
        pass
    return info


def is_public(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


_RDNS, _ASN = {}, {}


def rdns(ip):
    if ip in _RDNS:
        return _RDNS[ip]
    ex = ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(socket.gethostbyaddr, ip)
    try:
        name = fut.result(timeout=3)[0]
    except Exception:
        name = ""
    ex.shutdown(wait=False)
    _RDNS[ip] = name
    return name


def asn_lookup(ip):
    """Origin AS via Team Cymru's whois service. Public addresses only."""
    if ip in _ASN:
        return _ASN[ip]
    res = {}
    if is_public(ip) and shutil.which("whois"):
        rc, out, _ = run(["whois", "-h", "whois.cymru.com", f" -v {ip}"], timeout=12)
        lines = [l for l in out.splitlines() if "|" in l and not l.lower().startswith("as ")]
        if lines:
            f = [x.strip() for x in lines[-1].split("|")]
            if len(f) >= 7:
                res = {"asn": f[0], "prefix": f[2], "cc": f[3], "as_name": f[6]}
    _ASN[ip] = res
    return res


def forward_dns(host):
    out = {"A": [], "AAAA": []}
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            key = "AAAA" if fam == socket.AF_INET6 else "A"
            if sa[0] not in out[key]:
                out[key].append(sa[0])
    except socket.gaierror as e:
        out["error"] = str(e)
    return out


def host_of(url):
    return url.split("/")[2]


def url_for(target, family):
    return target[1] if family == 4 else target[2]


def trace_key(tname, fam):
    """Traceroute key for a target (the HTTPS Hetzner target shares the HTTP one's host)."""
    return f"{'hetzner-ash-http' if tname == 'hetzner-ash-https' else tname}/v{fam}"


def route_class(traces, tname, fam):
    tr = traces.get(trace_key(tname, fam)) or {}
    if not tr.get("hops"):
        return None
    return "ix" if tr.get("via_ix") else "no-ix"


# ---------------------------------------------------------------- environment checks

def detect_env(args):
    gw4, if4 = default_route(4)
    gw6, if6 = default_route(6)
    ports = hardware_ports()
    env = {"time": now_iso(), "host": platform.node(), "os": platform.platform(),
           "gateway_v4": gw4, "iface_v4": if4, "gateway_v6": gw6, "iface_v6": if6,
           "iface_port_name": ports.get(if4 or "", ""), "iface_media": iface_media(if4),
           "public_v4": public_ip(4), "public_v6": public_ip(6)}
    pn = env["iface_port_name"].lower()
    env["is_wifi"] = "wi-fi" in pn or "airport" in pn
    env["wifi"] = wifi_info() if env["is_wifi"] else {}
    note_isp_asn(env)
    return env


def check_env(phase_id, env, args, seen):
    """Returns (fatal_problems, warnings). `seen` holds what earlier phases of this run saw, so a
    phase that didn't actually change network, or left via a different connection, is caught."""
    ph = PHASES[phase_id]
    fatal, warn = [], []
    side = ph["side"]
    expect_gw = getattr(args, f"{side}_gateway")
    gw = env["gateway_v4"]
    if not gw:
        fatal.append("no IPv4 default route — not connected?")
    if env["iface_v4"] and env["iface_v4"].startswith(VPN_IFACE_PREFIXES):
        fatal.append(f"default route is via {env['iface_v4']} — a VPN. Disconnect it.")
    if gw and expect_gw and gw != expect_gw:
        fatal.append(f"default gateway is {gw}, expected {expect_gw} for this phase "
                     f"(set with --{side}-gateway)")
    other = "isp" if side == "own" else "own"
    if gw and not expect_gw and seen["gateway"].get(other) == gw:
        used_by = "ISP-router" if other == "isp" else "own-network"
        fatal.append(f"default gateway {gw} is the one the {used_by} phases used — are you connected "
                     "to the right router? (set --own-gateway / --isp-gateway to be explicit)")
    org = ((env.get("public_v4") or {}).get("org") or "")
    if args.expect_isp and args.expect_isp.upper() not in org.upper():
        fatal.append(f"public IPv4 belongs to '{org or 'unknown'}', not '{args.expect_isp}' — this would "
                     "not test that ISP")
    elif not args.expect_isp and seen["org"] and org and org != seen["org"]:
        fatal.append(f"public IPv4 belongs to '{org}', but an earlier phase left via '{seen['org']}' — "
                     "traffic is using a different internet connection (dual-WAN or failover?)")
    if ph["medium"] == "wifi" and not env["is_wifi"]:
        fatal.append(f"traffic is going out via {env['iface_v4']} ({env['iface_port_name'] or '?'}), not Wi-Fi")
    if ph["medium"] == "wired":
        if env["is_wifi"]:
            fatal.append("traffic is going out via Wi-Fi — turn Wi-Fi off so the Ethernet port is used")
        elif args.expect_link and args.expect_link not in env["iface_media"]:
            warn.append(f"Ethernet link is '{env['iface_media'] or 'unknown'}', not {args.expect_link}")
    if not env.get("public_v6"):
        warn.append("no working IPv6 — IPv6 tests will be skipped in this phase")
    return fatal, warn


def wait_for_network(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        gw, _ = default_route(4)
        if gw or platform.system() != "Darwin":
            rc, out, _ = run(["curl", "-s", "-4", "-m", "4", "https://api.ipify.org"], timeout=8)
            if rc == 0 and out:
                return True
        time.sleep(3)
    return False


def ask(prompt, choices, default, interactive):
    if not interactive:
        return default
    opts = "/".join(c.upper() if c == default else c for c in choices)
    while True:
        try:
            a = input(f"{prompt} [{opts}] ").strip().lower() or default
        except EOFError:
            return default
        if a in choices:
            return a


# ---------------------------------------------------------------- measurements

def one_flow(url, family, seconds, local_port=None):
    BUDGET.check()
    cmd = ["curl", "-sL", f"-{family}", "--max-time", str(seconds), "-o", os.devnull, "-w", CURL_FMT]
    if local_port:
        cmd += ["--local-port", str(local_port)]
    cmd.append(url)
    for attempt in range(3):
        rc, out, err = run(cmd, timeout=seconds + 20)
        if not (local_port and rc == 45):        # 45 = couldn't bind: port still in TIME_WAIT; wait it out
            break
        time.sleep(15)
    rec = {"curl_rc": rc, "error": "", "requested_port": local_port or ""}
    parts = out.split("|")
    if len(parts) != 8:
        rec.update(http_code="000", remote_ip="", local_port="", t_connect=0.0, t_tls=0.0, t_ttfb=0.0,
                   t_total=0.0, bytes=0, mbps=0.0, error=err or f"curl rc={rc}")
        return rec
    code, rip, lport, tc, ta, tf, tt, size = parts
    tc, ta, tf, tt, size = float(tc), float(ta), float(tf), float(tt), int(float(size))
    BUDGET.add(size)
    xfer = max(tt - tf, 0.001)          # body time only: excludes DNS/TCP/TLS/redirects
    rec.update(http_code=code, remote_ip=rip, local_port=lport, t_connect=round(tc, 4), t_tls=round(ta, 4),
               t_ttfb=round(tf, 4), t_total=round(tt, 3), bytes=size, mbps=round(size / xfer / 1e6, 3))
    if rc not in (0, 28) or code not in ("200", "206") or size == 0:   # rc 28 = hit --max-time (normal)
        rec["error"] = err or f"curl rc={rc} http={code}"
    return rec


def classify(rec, slow_mbps):
    if rec.get("error"):
        return "error"
    return "slow" if float(rec["mbps"]) < slow_mbps else "fast"


def _is_ip(tok):
    try:
        ipaddress.ip_address(tok.strip("()").split("%")[0])
        return True
    except ValueError:
        return False


def parse_traceroute(text):
    """Hops with every distinct responding address (several probes per hop can reveal parallel
    paths: ECMP routers answering from different addresses)."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        n, rest = int(m.group(1)), m.group(2).strip()
        ips = []
        for tok in rest.split():
            t = tok.strip("()")
            if _is_ip(t) and t not in ips:
                ips.append(t)
        mm = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({"hop": n, "ip": ips[0] if ips else None, "ips": ips,
                     "rtt_ms": float(mm.group(1)) if mm else None})
    return hops


def traceroute(host, family):
    tool = "traceroute6" if family == 6 else "traceroute"
    if not shutil.which(tool):
        return {"error": f"{tool} not available", "hops": []}
    rc, out, err = run([tool, "-n", "-q", "3", "-w", "1", "-m", "18", host], timeout=150)
    hops = parse_traceroute(out)
    via_ix = None
    for h in hops:
        h["alts"] = []
        for k, ip in enumerate(h.get("ips") or []):
            info = {"ip": ip, "rdns": rdns(ip), "ix": ix_name(ip)}
            info.update(asn_lookup(ip))
            via_ix = via_ix or info["ix"]
            if k == 0:
                h.update({k2: v for k2, v in info.items() if k2 != "ip"})
            else:
                h["alts"].append(info)
    return {"raw": out or err, "hops": hops, "via_ix": via_ix}


def ix_name(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    return next((n for n, net in IX_NETS if a.version == net.version and a in net), None)


_ISP_ASN = {"asn": ""}     # AS number of the public IPv4 address, set by detect_env / load_phase


def note_isp_asn(env):
    m = re.match(r"AS(\d+)", ((env or {}).get("public_v4") or {}).get("org") or "")
    if m:
        _ISP_ASN["asn"] = m.group(1)


def home_asns(traces):
    """The ISP's own AS numbers. Starts from the public address's AS, then adds any AS that every
    route passes through straight after it: an ISP may run an access AS plus a group backbone AS.
    Hops without a public AS (common inside an ISP on IPv4) are simply absent from the lists."""
    home = {_ISP_ASN["asn"]} - {""}
    seqs = [[h["asn"] for h in tr["hops"] if h.get("asn") and h.get("asn") != "NA"]
            for tr in (traces or {}).values() if tr.get("hops")]
    while home:
        nxt = []
        for seq in seqs:
            if seq and seq[0] in home:
                rest = [a for a in seq if a not in home]
                if rest:
                    nxt.append(rest[0])
        if len(nxt) < 2 or len(set(nxt)) != 1:
            break
        home.add(nxt[0])
    return home


def path_label(tr, traces=None):
    """One-line route summary: the exchange it peers at, or the first network outside the ISP."""
    if not tr or not tr.get("hops"):
        return "unknown"
    if tr.get("via_ix"):
        return f"public peering at {tr['via_ix']}"
    asns = [(h["asn"], h.get("as_name", "")) for h in tr["hops"] if h.get("asn") and h.get("asn") != "NA"]
    home = home_asns(traces)
    ext = [name.split(",")[0] for asn, name in asns if asn not in home]
    return "no known exchange hop seen" + (f"; first external network {ext[0]}" if ext else "")


def ping(host, family, count=20):
    tools = [["ping6"], ["ping", "-6"]] if family == 6 else [["ping"]]
    for base in tools:
        if not shutil.which(base[0]):
            continue
        for extra in (["-i", "0.2"], []):
            rc, out, err = run(base + ["-c", str(count), "-q"] + extra + [host], timeout=count * 2 + 15)
            if "packets transmitted" in out:
                res = {"raw": out.splitlines()[-2:]}
                m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
                if m:
                    tx, rx = int(m.group(1)), int(m.group(2))
                    res.update(sent=tx, received=rx, loss_pct=round(100 * (tx - rx) / tx, 1) if tx else None)
                m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", out)
                if m:
                    res.update(rtt_min=float(m.group(1)), rtt_avg=float(m.group(2)), rtt_max=float(m.group(3)))
                return res
    return {"error": "ping unavailable or failed"}


# ---------------------------------------------------------------- 1. packet capture

class Capture:
    """Decides how tcpdump can be run (directly if /dev/bpf* is readable, else sudo) and keeps a
    sudo timestamp alive in the background so captures don't stall waiting for a password."""

    def __init__(self, interactive, enabled):
        self.prefix, self.reason, self._stop = None, "", threading.Event()
        if not enabled:
            self.reason = "disabled (--no-pcap and --no-flowtrace)"
            return
        if not shutil.which("tcpdump"):
            self.reason = "tcpdump not found"
            return
        if (os.path.exists("/dev/bpf0") and os.access("/dev/bpf0", os.R_OK | os.W_OK)) or os.geteuid() == 0:
            self.prefix = []
            return
        if run(["sudo", "-n", "true"], timeout=5)[0] == 0:
            self.prefix = ["sudo", "-n"]
        elif interactive:
            say("\n  Packet captures (tcpdump) and per-flow path probes need your password (sudo) once.")
            if subprocess.run(["sudo", "-v"]).returncode == 0:
                self.prefix = ["sudo", "-n"]
        if self.prefix is None:
            self.reason = "no capture permission (sudo unavailable)"
            return
        if self.prefix:
            threading.Thread(target=self._keepalive, daemon=True).start()

    def _keepalive(self):
        while not self._stop.wait(60):
            run(["sudo", "-n", "-v"], timeout=10)

    @property
    def ok(self):
        return self.prefix is not None

    def stop(self):
        self._stop.set()


def capture_flow(cap, iface, url, family, seconds, path):
    """Run one curl download with a known source port while tcpdump records its headers."""
    BUDGET.check()                      # before tcpdump starts, so a stop never leaves it running
    port = random.randint(30000, 41000)
    cmd = cap.prefix + ["tcpdump", "-i", iface, "-s", "128", "-B", "16384", "-U", "-w", path]
    if cap.prefix:
        cmd += ["-Z", getpass.getuser()]
    cmd += [f"tcp port {port}"]
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    t0, started, err_lines = time.time(), False, []
    while time.time() - t0 < 5 and not started:
        r, _, _ = select.select([p.stderr], [], [], 0.5)
        if r:
            line = p.stderr.readline()
            err_lines.append(line)
            started = "listening on" in line
        if p.poll() is not None:
            break
    if not started:
        p.kill()
        return None, {"error": "tcpdump did not start: " + "".join(err_lines).strip()[:200]}
    rec = one_flow(url, family, seconds, local_port=port)
    time.sleep(0.5)
    p.send_signal(signal.SIGINT)
    try:
        _, err = p.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()
        err = ""
    m = re.search(r"(\d+) packets? dropped by kernel", err or "")
    return rec, {"kernel_drops": int(m.group(1)) if m else None, "port": port}


def read_pcap(path):
    """Yield (timestamp, ip_version, src, dst, sport, dport, seq, ack, flags, window, payload_len,
    tcp_options) for TCP packets in a classic pcap file. Stdlib only."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        en = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        en = ">"
    else:
        raise ValueError("not a classic pcap file (pcapng is not supported)")
    nsec = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(en + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _ = struct.unpack(en + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ts = ts_s + ts_f / (1e9 if nsec else 1e6)
        if link == 1:                               # Ethernet
            etype, l3 = struct.unpack("!H", pkt[12:14])[0], 14
            while etype in (0x8100, 0x88A8) and len(pkt) >= l3 + 4:
                etype, l3 = struct.unpack("!H", pkt[l3 + 2:l3 + 4])[0], l3 + 4
        elif link == 0:                             # BSD loopback / null
            l3, etype = 4, None
        elif link == 113:                           # Linux cooked (SLL)
            l3, etype = 16, None
        elif link == 276:                           # Linux cooked v2 (SLL2)
            l3, etype = 20, None
        elif link in (12, 101):                     # raw IP
            l3, etype = 0, None
        else:
            continue
        ip = pkt[l3:]
        if not ip:
            continue
        ver = ip[0] >> 4
        if ver == 4 and len(ip) >= 20:
            ihl = (ip[0] & 15) * 4
            if ip[9] != 6:
                continue
            tot = struct.unpack("!H", ip[2:4])[0]
            src, dst = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
            tcp, ip_payload = ip[ihl:], tot - ihl
        elif ver == 6 and len(ip) >= 40:
            if ip[6] != 6:
                continue
            ip_payload = struct.unpack("!H", ip[4:6])[0]
            src, dst = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
            tcp = ip[40:]
        else:
            continue
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, offf, flags, win = struct.unpack("!HHIIBBH", tcp[:16])
        thl = (offf >> 4) * 4
        yield (ts, ver, src, dst, sport, dport, seq, ack, flags, win, max(ip_payload - thl, 0), tcp[20:thl])


def tcp_options(raw):
    opts, i = {}, 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        ln = raw[i + 1]
        if ln < 2:
            break
        if kind == 3 and ln == 3 and i + 2 < len(raw):
            opts["wscale"] = raw[i + 2]
        elif kind == 5:
            opts["sack_blocks"] = (ln - 2) // 8
        i += ln
    return opts


def analyse_pcap(path, local_port):
    """Loss/stall signature of one download as seen by the client."""
    s = {"server_segments": 0, "server_bytes": 0, "retransmits": 0, "holes": 0, "client_acks": 0,
         "dup_acks": 0, "sack_acks": 0, "zero_window": 0, "stalls_200ms": 0, "longest_gap_ms": 0.0,
         "duration_s": 0.0, "packets": 0}
    isn = max_end = last_ack = None
    last_data_ts = first_ts = last_ts = None
    wscale = 0
    try:
        for (ts, _, _, _, sport, dport, seq, ack, flags, win, plen, opt) in read_pcap(path):
            s["packets"] += 1
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts
            o = tcp_options(opt) if opt else {}
            if dport == local_port:                         # server -> client
                if flags & 0x02:                            # SYN-ACK
                    isn = (seq + 1) & 0xFFFFFFFF
                    continue
                if plen == 0:
                    continue
                if isn is None:
                    isn = seq
                rel = (seq - isn) & 0xFFFFFFFF
                end = rel + plen
                s["server_segments"] += 1
                s["server_bytes"] += plen
                if max_end is not None:
                    if end <= max_end or rel < max_end:
                        s["retransmits"] += 1
                    elif rel > max_end:
                        s["holes"] += 1
                max_end = end if max_end is None else max(max_end, end)
                if last_data_ts is not None:
                    gap = (ts - last_data_ts) * 1000
                    s["longest_gap_ms"] = max(s["longest_gap_ms"], round(gap, 1))
                    if gap > 200:
                        s["stalls_200ms"] += 1
                last_data_ts = ts
            elif sport == local_port:                       # client -> server
                if flags & 0x02 and "wscale" in o:
                    wscale = o["wscale"]
                if plen == 0 and flags & 0x10 and not flags & 0x05:
                    s["client_acks"] += 1
                    if ack == last_ack:
                        s["dup_acks"] += 1
                    if o.get("sack_blocks"):
                        s["sack_acks"] += 1
                    if win == 0:
                        s["zero_window"] += 1
                    last_ack = ack
    except (ValueError, OSError, struct.error) as e:
        s["error"] = str(e)
    if first_ts is not None:
        s["duration_s"] = round(last_ts - first_ts, 3)
    s["retransmit_pct"] = round(100 * s["retransmits"] / s["server_segments"], 2) if s["server_segments"] else None
    s["client_wscale"] = wscale
    return s


def pcap_test(cap, phase_id, pdir, env, families, args):
    out = []
    if not cap.ok:
        say(f"\n  -- packet capture skipped: {cap.reason}")
        return {"skipped": cap.reason}
    iface = env.get("iface_v4") or "any"
    tgt = next(t for t in TARGETS if t[0] == PORT_TEST_TARGET)
    ui.section("Packet captures", args.pcap_flows * len(families))
    os.makedirs(os.path.join(pdir, "pcap"), exist_ok=True)
    for fam in families:
        say(f"\n  -- packet capture, IPv{fam}, {tgt[0]} (header-only; keeps slow flows + one fast)")
        kept_fast, n_slow = False, 0
        for i in range(1, args.pcap_flows + 1):
            tmp = os.path.join(pdir, "pcap", f"tmp-{fam}-{i}.pcap")
            rec, info = capture_flow(cap, iface, url_for(tgt, fam), fam, args.pcap_seconds, tmp)
            if rec is None:
                say(f"     capture failed: {info.get('error')}")
                return {"error": info.get("error"), "flows": out}
            cls = classify(rec, args.slow_mbps)
            keep = cls == "slow" or (cls == "fast" and not kept_fast)
            entry = {"family": fam, "index": i, "class": cls, "mbps": rec["mbps"], "remote_ip": rec["remote_ip"],
                     "local_port": info["port"], "kernel_drops": info.get("kernel_drops"), "time": now_iso()}
            if keep and os.path.exists(tmp):
                final = os.path.join(pdir, "pcap", f"v{fam}-port{info['port']}-{cls}.pcap")
                os.replace(tmp, final)
                entry["file"] = os.path.relpath(final, pdir)
                entry.update(analyse_pcap(final, info["port"]))
                kept_fast |= cls == "fast"
                n_slow += cls == "slow"
            elif os.path.exists(tmp):
                os.remove(tmp)
            out.append(entry)
            extra = (f"retrans {entry.get('retransmit_pct')}%, holes {entry.get('holes')}, "
                     f"stalls>200ms {entry.get('stalls_200ms')}") if "retransmit_pct" in entry else "(not kept)"
            say(f"     {i:>2} port {info['port']}  {rec['mbps']:8.2f} MB/s  {cls:<5} {extra}")
            ui.tick(cls, f"IPv{fam} capture {i}")
            if n_slow >= args.pcap_keep_slow and kept_fast:
                for _ in range(args.pcap_flows - i):                # skip the captures we no longer need
                    ui.tick(detail=f"IPv{fam} enough captured")
                break
    return {"flows": out}


# ---------------------------------------------------------------- 5. long-running connections

_SUFFIX = {"": 1, "k": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}


def _bytes(tok):
    m = re.match(r"^([\d.]+)([kMGT]?)$", tok)
    return float(m.group(1)) * _SUFFIX[m.group(2)] if m else None


def _secs(tok):
    p = tok.split(":")
    return int(p[0]) * 3600 + int(p[1]) * 60 + int(p[2]) if len(p) == 3 and all(x.isdigit() for x in p) else None


def long_flow(url, family, seconds):
    """One download for `seconds`, with throughput sampled every second from curl's progress meter."""
    BUDGET.check()
    cmd = ["curl", "-L", f"-{family}", "--max-time", str(seconds), "-o", os.devnull,
           "-w", "%{remote_ip}|%{size_download}|%{time_starttransfer}|%{time_total}|%{http_code}", url]
    rc, out, err = run(cmd, timeout=seconds + 30)
    samples = {}
    for line in err.replace("\r", "\n").splitlines():
        f = line.split()
        if len(f) >= 12 and f[0].isdigit():
            b, t = _bytes(f[3]), _secs(f[9])
            if b is not None and t is not None:
                samples[t] = b
    series, prev_t, prev_b = [], 0, 0.0
    for t in sorted(samples):
        if t <= prev_t:
            continue
        series.append(round((samples[t] - prev_b) / (t - prev_t) / 1e6, 3))
        prev_t, prev_b = t, samples[t]
    if len(series) > 2 and rc == 28:
        series = series[:-1]          # last sample is a partial second cut off by --max-time: not real
    parts = out.split("|")
    rec = {"curl_rc": rc, "series_mbps": series}
    if len(parts) == 5:
        rip, size, tf, tt, code = parts
        size, tf, tt = int(float(size)), float(tf), float(tt)
        BUDGET.add(size)
        rec.update(remote_ip=rip, bytes=size, http_code=code, mbps=round(size / max(tt - tf, 0.001) / 1e6, 3))
    else:
        rec.update(remote_ip="", bytes=0, http_code="000", mbps=0.0, error=err[-200:])
    return rec


def long_test(families, args):
    tgt = next(t for t in TARGETS if t[0] == PORT_TEST_TARGET)
    res = []
    ui.section(f"Long connections ({args.long_seconds} s each)", args.long_count * len(families))
    for fam in families:
        say(f"\n  -- long-running connections, IPv{fam}, {tgt[0]}: {args.long_count} × {args.long_seconds} s")
        for i in range(1, args.long_count + 1):
            rec = long_flow(url_for(tgt, fam), fam, args.long_seconds)
            rec.update(family=fam, index=i, target=tgt[0], time=now_iso())
            rec["class"] = "error" if rec.get("error") else ("slow" if rec["mbps"] < args.slow_mbps else "fast")
            s = rec["series_mbps"]
            rec["seconds_above_threshold"] = sum(1 for v in s if v >= args.slow_mbps)
            res.append(rec)
            say(f"     {i}  {rec['mbps']:8.2f} MB/s overall  {rec['class']:<5}  per-second min/max "
                f"{num(min(s) if s else None, '.2f')}/{num(max(s) if s else None, '.2f')}"
                + ("  <-- SLOW" if rec["class"] == "slow" else ""))
            ui.tick(rec["class"], f"IPv{fam} {i}/{args.long_count}")
    return res


# ---------------------------------------------------------------- 3. parallel streams (iperf3)

def iperf_servers(args):
    if args.iperf_servers:
        out = []
        for spec in args.iperf_servers.split(","):
            host, _, ports = spec.strip().partition(":")
            lo, _, hi = (ports or "5201").partition("-")
            out.append((host, int(lo), int(hi or lo), host))
        return out
    return IPERF_SERVERS


def iperf_one(host, port, family, reverse, args):
    BUDGET.check()
    cmd = ["iperf3", "-c", host, "-p", str(port), f"-{family}", "-P", str(args.iperf_streams),
           "-t", str(args.iperf_seconds), "-J", "--connect-timeout", "4000"]
    if reverse:
        cmd.append("-R")
    rc, out, err = run(cmd, timeout=args.iperf_seconds + 30)
    try:
        j = json.loads(out)
    except json.JSONDecodeError:
        return {"error": (err or out or f"rc={rc}")[:200]}
    if j.get("error"):
        return {"error": j["error"][:200]}
    streams = []
    for s in j.get("end", {}).get("streams", []):
        rcv, snd = s.get("receiver", {}), s.get("sender", {})
        rt = snd.get("retransmits")
        streams.append({"mbps": round(rcv.get("bits_per_second", 0) / 8e6, 3),
                        "retransmits": rt if isinstance(rt, int) and rt >= 0 else None})
    start = j.get("start", {})
    conn = (start.get("connected") or [{}])[0]
    end = j.get("end", {})
    tot = end.get("sum_received", {}).get("bits_per_second", 0) / 8e6
    BUDGET.add(max(end.get("sum_sent", {}).get("bytes", 0), end.get("sum_received", {}).get("bytes", 0)))
    return {"streams": streams, "total_mbps": round(tot, 2), "remote_ip": conn.get("remote_host", ""),
            "version": start.get("version", "")}


def iperf_test(families, args, traces):
    if not shutil.which("iperf3"):
        say("\n  -- parallel-stream test skipped: iperf3 not installed (brew install iperf3)")
        return {"skipped": "iperf3 not installed (brew install iperf3)"}
    res = []
    ui.section(f"Parallel streams (iperf3 × {args.iperf_streams})", args.iperf_max * 2 * len(families))
    for fam in families:
        done = 0
        for host, lo, hi, note in iperf_servers(args):
            if done >= args.iperf_max:
                break
            dns = forward_dns(host)
            if not dns.get("AAAA" if fam == 6 else "A"):
                continue
            key = f"iperf:{host}/v{fam}"
            if key not in traces and not args.no_trace:
                traces[key] = traceroute(host, fam)
            ok_any, unreachable = False, False
            for reverse in (True, False):
                if unreachable:
                    break
                direction = "download" if reverse else "upload"
                say(f"\n  -- iperf3 {args.iperf_streams} streams, {direction}, IPv{fam}, {host} ({note})")
                r = None
                ports = list(range(lo, hi + 1))
                random.shuffle(ports)
                for port in ports[:6]:
                    r = iperf_one(host, port, fam, reverse, args)
                    if not r.get("error"):
                        r["port"] = port
                        break
                    say(f"     port {port}: {r['error'][:80]}")
                    if "busy" not in r["error"].lower():      # not just busy: give up on this server
                        unreachable = True
                        break
                if not r or r.get("error"):
                    res.append({"host": host, "note": note, "family": fam, "direction": direction,
                                "error": (r or {}).get("error", "no ports tried")})
                    continue
                ui.tick(detail=f"{host} {direction} IPv{fam}")
                for s in r["streams"]:
                    s["class"] = "slow" if s["mbps"] < args.slow_mbps else "fast"
                n_slow = sum(1 for s in r["streams"] if s["class"] == "slow")
                say(f"     total {r['total_mbps']:.1f} MB/s; {n_slow}/{len(r['streams'])} streams slow; per stream "
                    + " ".join(f"{s['mbps']:.1f}" for s in sorted(r["streams"], key=lambda s: s["mbps"])))
                r.update(host=host, note=note, family=fam, direction=direction, time=now_iso(),
                         path=path_label(traces.get(key), traces))
                res.append(r)
                ok_any = True
            done += ok_any
    return res


# ---------------------------------------------------------------- per-flow path probes

FT_BASE_SEQ = 1_000_000


def flowtrace_worker(spec):
    """Runs in a child process with raw-packet rights (sudo). Paris-traceroute style: a TCP SYN
    per TTL with the 5-tuple held fixed, so every router hashes every probe exactly as it hashes
    the real connection from that source port. The TTL is encoded in the TCP sequence number,
    which ICMP errors quote back and the destination echoes (ack = seq + 1)."""
    import logging
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.all import IP, IPv6, TCP, conf, sr
    from scapy.layers.inet import TCPerror
    conf.verb = 0
    out, max_ttl = [], spec["max_ttl"]
    for pr in spec["probes"]:
        fam = pr["family"]
        pkts = []
        for ttl in range(1, max_ttl + 1):
            l3 = IP(dst=pr["dst"], ttl=ttl, id=40000 + ttl) if fam == 4 else IPv6(dst=pr["dst"], hlim=ttl)
            pkts.append(l3 / TCP(sport=pr["sport"], dport=pr["dport"], flags="S", seq=FT_BASE_SEQ + ttl,
                                 window=65535))
        try:
            ans, _ = sr(pkts, timeout=spec["timeout"], inter=0.02, multi=True, verbose=0)
        except Exception as e:                        # noqa: BLE001 — report, don't crash the run
            out.append(dict(pr, error=str(e)[:200], hops=[]))
            continue
        sent = {}
        for snd, _ in ans:
            t = snd.ttl if fam == 4 else snd.hlim
            sent.setdefault(t, getattr(snd, "sent_time", None))
        hops = {}
        for _, rcv in ans:
            if rcv.haslayer(TCPerror):
                ttl, reached = rcv[TCPerror].seq - FT_BASE_SEQ, False
            elif rcv.haslayer(TCP) and rcv[TCP].sport == pr["dport"]:
                ttl, reached = rcv[TCP].ack - 1 - FT_BASE_SEQ, True
            else:
                continue
            if not 1 <= ttl <= max_ttl or ttl in hops:
                continue
            st = sent.get(ttl)
            hops[ttl] = {"ip": rcv.src, "reached": reached,
                         "rtt_ms": round((rcv.time - st) * 1000, 1) if st else None}
        path = []
        for ttl in range(1, max_ttl + 1):
            h = hops.get(ttl)
            path.append(h)
            if h and h["reached"]:
                break
        while path and path[-1] is None:
            path.pop()
        out.append(dict(pr, hops=path))
    return out


def scapy_available():
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def flowtrace_test(cap, port_rows, families, args):
    """Trace the exact 5-tuples of source ports that were consistently slow and consistently fast."""
    if not scapy_available():
        say("\n  -- per-flow path probes skipped: scapy not installed (run the script with `uv run`)")
        return {"skipped": "scapy not installed (run with `uv run`)"}
    if not cap.ok:
        say(f"\n  -- per-flow path probes skipped: {cap.reason}")
        return {"skipped": cap.reason}
    tgt = next(t for t in TARGETS if t[0] == PORT_TEST_TARGET)
    dport = 443 if tgt[1].startswith("https") else 80
    probes, chosen = [], {}
    for fam in families:
        by_port, dst = {}, None
        for r in port_rows:
            if r["family"] == fam and r["class"] in ("fast", "slow"):
                by_port.setdefault(int(r["requested_port"]), []).append(r["class"])
                dst = dst or r["remote_ip"]
        steady = {p: c[0] for p, c in by_port.items() if len(c) >= 2 and len(set(c)) == 1}
        slow = [p for p, c in steady.items() if c == "slow"][:args.flowtrace_ports]
        fast = [p for p, c in steady.items() if c == "fast"][:args.flowtrace_ports]
        if not (slow and fast) or not dst:
            say(f"\n  -- per-flow path probes, IPv{fam}: skipped — need source ports that were consistently "
                "slow AND consistently fast in the fixed-port test")
            chosen[fam] = {"skipped": "no ports that were consistently slow and consistently fast"}
            continue
        chosen[fam] = {"slow": slow, "fast": fast, "dst": dst}
        for rep_n in (1, 2):                                        # twice, to see if the path is stable
            for p in slow + fast:
                probes.append({"family": fam, "dst": dst, "dport": dport, "sport": p,
                               "class": "slow" if p in slow else "fast", "rep": rep_n})
    if not probes:
        return {"chosen": chosen, "probes": []}
    say(f"\n  -- per-flow path probes: {len(probes)} TCP traceroutes using the exact source ports of slow "
        "and fast connections")
    ui.section("Per-flow path probes", len(probes))
    spec = {"max_ttl": 20, "timeout": 3}
    results = []
    for pr in probes:                                               # one child per probe = live progress
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(dict(spec, probes=[pr]), fh)
            specfile = fh.name
        cmd = cap.prefix + [sys.executable, os.path.abspath(__file__), "--_flowtrace", specfile]
        rc, out, err = run(cmd, timeout=60)
        os.unlink(specfile)
        try:
            res = json.loads(out.splitlines()[-1])[0]
        except (json.JSONDecodeError, IndexError):
            res = dict(pr, error=(err or out or f"rc={rc}")[-200:], hops=[])
        results.append(res)
        path = " > ".join((h or {}).get("ip") or "*" for h in res.get("hops", []))
        say(f"     IPv{pr['family']} port {pr['sport']:<6} {pr['class']:<5} " + (res.get("error") or path)
            + ("  <-- SLOW" if pr["class"] == "slow" else ""))
        ui.tick(pr["class"], f"IPv{pr['family']} port {pr['sport']}")
    return {"chosen": chosen, "probes": results}


def flowtrace_analysis(ft):
    """Compare the hop-by-hop paths of slow-port and fast-port probes per family."""
    out = {}
    for fam in sorted({p["family"] for p in ft.get("probes", [])}):
        ps = [p for p in ft["probes"] if p["family"] == fam and p.get("hops")]
        if not ps:
            continue
        L = max(len(p["hops"]) for p in ps)

        def ips(cls, i):
            return {(p["hops"][i] or {}).get("ip") for p in ps if p["class"] == cls and i < len(p["hops"])} - {None}
        diverge = None
        for i in range(L):
            S, F = ips("slow", i), ips("fast", i)
            if S and F and S.isdisjoint(F):
                diverge = {"hop": i + 1, "slow": sorted(S), "fast": sorted(F)}
                break
        stable = {}
        for p in ps:
            stable.setdefault(p["sport"], []).append(tuple((h or {}).get("ip") for h in p["hops"]))
        unstable = [port for port, v in stable.items() if len(set(v)) > 1]
        out[fam] = {"diverge": diverge, "hops": L, "unstable_ports": unstable,
                    "reached": sum(1 for p in ps if p["hops"] and (p["hops"][-1] or {}).get("reached")),
                    "n": len(ps)}
    return out


# ---------------------------------------------------------------- one phase

def run_phase(phase_id, outdir, args, interactive, cap):
    BUDGET.check()                      # don't ask the user to move cables if the budget is spent
    ph = PHASES[phase_id]
    hr(f"Phase: {ph['title']}")
    say(f"  {ph['prompt']}\n  Disconnect any VPN.")
    env = None
    while True:
        if interactive:
            a = ask("  Ready? (y = go, s = skip this phase, q = quit)", ["y", "s", "q"], "y", interactive)
            if a == "s":
                say("  skipped")
                return False
            if a == "q":
                raise KeyboardInterrupt
        say("  waiting for the network ...")
        if not wait_for_network():
            say("  no internet connectivity after 90 s.")
            if not interactive:
                return False
            continue
        env = detect_env(args)
        fatal, warn = check_env(phase_id, env, args, args._seen)
        say(f"  gateway {env['gateway_v4']} via {env['iface_v4']} ({env['iface_port_name'] or '?'}) "
            f"{env['iface_media']}")
        if env["wifi"]:
            w = env["wifi"]
            say(f"  Wi-Fi: {w.get('phy_mode')} ch {w.get('channel')} tx {w.get('tx_rate_mbps')} Mb/s, "
                f"{w.get('signal_noise')}")
        for fam in (4, 6):
            p = env.get(f"public_v{fam}")
            say(f"  public IPv{fam}: " + (f"{p['ip']}  {p.get('org', '')}" if p else "none"))
        for w in warn:
            say(f"  WARNING: {w}")
        for f in fatal:
            say(f"  PROBLEM: {f}")
        if not fatal or args.force:
            break
        if not interactive:
            say("  not running this phase (use --force to override)")
            return False
        a = ask("  Fix it and retry (r), run anyway (a), or skip this phase (s)?", ["r", "a", "s"], "r", interactive)
        if a == "s":
            return False
        if a == "a":
            break

    args._seen["gateway"].setdefault(ph["side"], env["gateway_v4"])
    args._seen["org"] = args._seen["org"] or ((env.get("public_v4") or {}).get("org") or "")
    pdir = os.path.join(outdir, phase_id)
    os.makedirs(pdir, exist_ok=True)
    have6 = bool(env.get("public_v6"))
    families = {"4": [4], "6": [6] if have6 else [], "both": [4] + ([6] if have6 else [])}[args.family]
    meta = {"phase": phase_id, "title": ph["title"], "short": ph["short"], "started": now_iso(),
            "env": env, "families": families, "rounds": args.rounds, "seconds": args.seconds,
            "slow_mbps": args.slow_mbps, "script_version": VERSION}

    jobs = [(t, fam) for t in TARGETS for fam in families if url_for(t, fam)]
    n_flows = len(jobs) * args.rounds
    est = phase_seconds(args, len(families))
    say(f"\n  {n_flows} throughput connections plus the extra tests; about {int(est // 60)} min. "
        "Leave this computer alone while it runs.")
    trace_jobs = [] if args.no_trace else [(t, fam) for t in TARGETS for fam in families
                                           if url_for(t, fam) and t[0] != "hetzner-ash-https"]
    n_port = 0 if args.no_port_test else args.port_count * args.port_reps * len(families)
    n_pcap = 0 if (args.no_pcap or not cap.ok) else args.pcap_flows * len(families)
    n_ft = (0 if (args.no_flowtrace or args.no_port_test or not cap.ok or not scapy_available())
            else 2 * 2 * args.flowtrace_ports * len(families))
    n_long = 0 if args.no_long else args.long_count * len(families)
    n_iperf = 0 if (args.no_iperf or not shutil.which("iperf3")) else args.iperf_max * 2 * len(families)
    ui.phase_start(ph["short"], 2 * len(trace_jobs) + n_flows + n_port + n_ft + n_pcap + n_long + n_iperf)
    b0 = BUDGET.used
    try:
        _run_phase_tests(phase_id, pdir, outdir, env, families, jobs, trace_jobs, meta, args, cap)
    except BudgetExceeded as e:
        meta["stopped"] = str(e)
        meta.setdefault("finished", now_iso())
        raise
    finally:
        meta["bytes_moved"] = BUDGET.used - b0
        with open(os.path.join(pdir, "meta.json"), "w") as fh:
            json.dump(meta, fh, indent=1, default=str)
        ui.phase_end()
    say(f"\nOK phase '{phase_id}' done.")
    return True


def _run_phase_tests(phase_id, pdir, outdir, env, families, jobs, trace_jobs, meta, args, cap):

    # forward DNS for every target host
    meta["dns"] = {}
    for t in TARGETS:
        for u in (t[1], t[2]):
            if u:
                meta["dns"].setdefault(host_of(u), forward_dns(host_of(u)))

    # traceroutes + pings
    traces, pings = {}, {}
    if trace_jobs:
        say("\n  -- traceroutes (with reverse DNS + AS) and pings")
        ui.section("Traceroutes + pings", 2 * len(trace_jobs))
        from concurrent.futures import as_completed
        with ThreadPoolExecutor(max_workers=6) as ex:          # in parallel: they're mostly waiting
            futs = {}
            for t, fam in trace_jobs:
                host, key = host_of(url_for(t, fam)), f"{t[0]}/v{fam}"
                futs[ex.submit(traceroute, host, fam)] = ("trace", key)
                futs[ex.submit(ping, host, fam)] = ("ping", key)
            for f in as_completed(futs):
                kind, key = futs[f]
                (traces if kind == "trace" else pings)[key] = f.result()
                ui.tick(detail=f"{key} {kind}")
        for t, fam in trace_jobs:
            key = f"{t[0]}/v{fam}"
            pg = pings.get(key, {})
            loss = f"ping loss {pg.get('loss_pct')}%, avg {pg.get('rtt_avg')} ms" if pg.get("sent") else "ping n/a"
            say(f"     {key:<26} {path_label(traces.get(key), traces)} · {loss}")
    with open(os.path.join(pdir, "traceroutes.json"), "w") as fh:
        json.dump(traces, fh, indent=1)
    with open(os.path.join(pdir, "pings.json"), "w") as fh:
        json.dump(pings, fh, indent=1)
    with open(os.path.join(pdir, "meta.json"), "w") as fh:      # rewritten at the end; lets an
        json.dump(meta, fh, indent=1, default=str)              # interrupted phase still be reported

    # throughput, interleaved by round
    say("\n  -- per-connection throughput")
    ui.section("Throughput", len(jobs) * args.rounds)
    with open(os.path.join(pdir, "flows.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FLOW_FIELDS)
        w.writeheader()

        port_rows = []

        def record(rec, **kw):
            rec.update(phase=phase_id, time=now_iso(), **kw)
            rec["class"] = classify(rec, args.slow_mbps)
            w.writerow({k: rec.get(k, "") for k in FLOW_FIELDS})
            fh.flush()
            if kw.get("test") == "fixed-port":
                port_rows.append(rec)
            return {"slow": "  <-- SLOW", "error": "  <-- ERROR " + rec["error"][:50]}.get(rec["class"], "")

        for r in range(1, args.rounds + 1):
            for t, fam in jobs:
                rec = one_flow(url_for(t, fam), fam, args.seconds)
                flag = record(rec, test="throughput", round=r, target=t[0], role=t[3], family=fam)
                say(f"     r{r:<2} {t[0]:<20} v{fam}  {rec['mbps']:8.2f} MB/s  {rec['remote_ip']:<20}{flag}")
                ui.tick(rec["class"], f"round {r}/{args.rounds}")

        # fixed-source-port test
        if not args.no_port_test:
            tgt = next(t for t in TARGETS if t[0] == PORT_TEST_TARGET)
            rng = random.Random(f"{os.path.abspath(outdir)}/{phase_id}")
            ui.section("Fixed-source-port test", args.port_count * args.port_reps * len(families))
            for fam in families:
                ports = rng.sample(range(42000, 60000), args.port_count)
                meta.setdefault("port_test_ports", {})[str(fam)] = ports
                say(f"\n  -- fixed-source-port test, IPv{fam}, {tgt[0]}, ports {ports}")
                for rep in range(1, args.port_reps + 1):
                    for p in ports:
                        rec = one_flow(url_for(tgt, fam), fam, args.seconds, local_port=p)
                        flag = record(rec, test="fixed-port", round=rep, target=tgt[0], role="test", family=fam)
                        say(f"     rep{rep} port {p:<6} v{fam}  {rec['mbps']:8.2f} MB/s{flag}")
                        ui.tick(rec["class"], f"IPv{fam} pass {rep}/{args.port_reps}")

    def dump(name, obj):
        with open(os.path.join(pdir, name), "w") as fh:
            json.dump(obj, fh, indent=1, default=str)

    if not args.no_flowtrace and not args.no_port_test:
        dump("flowtrace.json", flowtrace_test(cap, port_rows, families, args))
    if not args.no_pcap:
        dump("pcap.json", pcap_test(cap, phase_id, pdir, env, families, args))
    if not args.no_long:
        dump("long.json", long_test(families, args))
    if not args.no_iperf:
        dump("iperf.json", iperf_test(families, args, traces))
        dump("traceroutes.json", traces)            # now includes the iperf servers' paths

    meta["finished"] = now_iso()
    with open(os.path.join(pdir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=1, default=str)


# ---------------------------------------------------------------- analysis + report

def load_phase(pdir):
    with open(os.path.join(pdir, "meta.json")) as fh:
        meta = json.load(fh)
    note_isp_asn(meta.get("env"))
    with open(os.path.join(pdir, "flows.csv")) as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["mbps"] = float(r["mbps"] or 0)
        r["family"] = int(r["family"])
    out = {"meta": meta, "rows": rows, "traces": {}, "pings": {}, "pcap": {}, "long": [], "iperf": [],
           "flowtrace": {}}
    for k, f in (("traces", "traceroutes.json"), ("pings", "pings.json"), ("pcap", "pcap.json"),
                 ("long", "long.json"), ("iperf", "iperf.json"), ("flowtrace", "flowtrace.json")):
        p = os.path.join(pdir, f)
        if os.path.exists(p):
            with open(p) as fh:
                out[k] = json.load(fh)
    return out


def stats_for(rows):
    fast = [r["mbps"] for r in rows if r["class"] == "fast"]
    slow = [r["mbps"] for r in rows if r["class"] == "slow"]
    err = sum(1 for r in rows if r["class"] == "error")
    valid = len(fast) + len(slow)
    return {"n": len(rows), "fast": len(fast), "slow": len(slow), "err": err, "valid": valid,
            "slow_pct": (100.0 * len(slow) / valid) if valid else None,
            "med_fast": statistics.median(fast) if fast else None, "max_fast": max(fast) if fast else None,
            "med_slow": statistics.median(slow) if slow else None,
            "slow_range": (min(slow), max(slow)) if slow else None}


def poisson_binomial_tail(probs, k):
    """P(at least k successes) for independent Bernoullis with the given probabilities."""
    dp = [1.0] + [0.0] * len(probs)
    for p in probs:
        for j in range(len(dp) - 1, 0, -1):
            dp[j] = dp[j] * (1 - p) + dp[j - 1] * p
        dp[0] *= (1 - p)
    return sum(dp[k:])


def port_test_analysis(rows):
    out = {}
    for fam in sorted({r["family"] for r in rows}):
        fr = [r for r in rows if r["family"] == fam and r["class"] in ("fast", "slow")]
        if not fr:
            continue
        by_port = {}
        for r in [x for x in rows if x["family"] == fam]:
            by_port.setdefault(str(r["requested_port"]), []).append(r["class"])
        p = sum(1 for r in fr if r["class"] == "slow") / len(fr)
        usable = {k: [c for c in v if c != "error"] for k, v in by_port.items()}
        usable = {k: v for k, v in usable.items() if len(v) >= 2}
        consistent = sum(1 for v in usable.values() if len(set(v)) == 1)
        probs = [p ** len(v) + (1 - p) ** len(v) for v in usable.values()]
        expected = sum(probs)
        tail = poisson_binomial_tail(probs, consistent) if usable else None
        if not usable:
            verdict = "inconclusive — too few usable ports (binding a fixed source port may have failed)"
        elif p in (0.0, 1.0):
            verdict = "inconclusive — every connection had the same outcome"
        elif tail is not None and tail < 0.05 and consistent > expected:
            verdict = "outcome STICKS to the source port — consistent with a flow-hash (LAG/ECMP member) fault"
        else:
            verdict = "outcome does NOT clearly stick to the source port — no evidence of a port-based hash"
        out[fam] = {"ports": by_port, "slow_rate": p, "usable": len(usable), "consistent": consistent,
                    "expected_if_random": expected, "p_value": tail, "verdict": verdict}
    return out


def analyse(phases):
    """phases: ordered list of (phase_id, loaded)."""
    res = {"phases": [], "lines": []}
    for pid, P in phases:
        thr = [r for r in P["rows"] if r["test"] == "throughput"]
        prt = [r for r in P["rows"] if r["test"] == "fixed-port"]
        per, agg = {}, {}
        for t in TARGETS:
            for fam in (4, 6):
                sub = [r for r in thr if r["target"] == t[0] and r["family"] == fam]
                if sub:
                    per[(t[0], fam)] = stats_for(sub)
        for role in ("test", "control"):
            for fam in (4, 6):
                sub = [r for r in thr if r["role"] == role and r["family"] == fam]
                if sub:
                    agg[(role, fam)] = stats_for(sub)
        res["phases"].append({"id": pid, "P": P, "per": per, "agg": agg, "port": port_test_analysis(prt)})

    L = res["lines"]
    L.append("Method: many separate TCP downloads, each a fresh connection, run one at a time and rotated "
             "across targets; a connection counts as slow if its transfer rate is below "
             f"{phases[0][1]['meta']['slow_mbps']} MB/s.")
    any_test_slow, ctl_slow, ctl_valid = False, 0, 0
    for ph in res["phases"]:
        parts = []
        for fam in (4, 6):
            t, c = ph["agg"].get(("test", fam)), ph["agg"].get(("control", fam))
            if t and t["valid"]:
                parts.append(f"IPv{fam} transit targets {t['slow']}/{t['valid']} slow ({t['slow_pct']:.0f}%)")
                any_test_slow |= t["slow"] > 0
            if c and c["valid"]:
                parts.append(f"IPv{fam} control {c['slow']}/{c['valid']} slow")
                ctl_slow += c["slow"]
                ctl_valid += c["valid"]
        L.append(f"{ph['P']['meta']['title']}: " + "; ".join(parts) + ".")
        if ph["P"]["meta"].get("stopped"):
            L.append(f"{ph['P']['meta']['short']} was cut short: {ph['P']['meta']['stopped']}. Tests after that point "
                     "did not run, so some sections of the report are missing for it.")

    modes, gaps = [], []
    for ph in res["phases"]:
        thr = [r for r in ph["P"]["rows"] if r["test"] == "throughput"]
        fast = [r["mbps"] for r in thr if r["class"] == "fast"]
        slow = [r["mbps"] for r in thr if r["class"] == "slow"]
        if fast and slow:
            modes.append(f"{ph['P']['meta']['short']}: fastest connection {max(fast):.0f} MB/s "
                         f"(~{max(fast) * 8 / 1000:.1f} Gb/s), median fast {statistics.median(fast):.0f} MB/s, "
                         f"slow connections {min(slow):.2f}–{max(slow):.2f} MB/s")
            gaps.append(statistics.median(fast) / max(max(slow), 0.001))
    if modes:
        if gaps and min(gaps) >= 20:
            L.append("Connections fall into two clearly separate modes, more than an order of magnitude apart: "
                     + "; ".join(modes) + ".")
        else:
            L.append("Throughput ranges: " + "; ".join(modes) + ".")

    direct = [ph for ph in res["phases"] if ph["id"].startswith("isp-")]
    if any((ph["agg"].get(("test", f)) or {}).get("slow", 0) for ph in direct for f in (4, 6)):
        L.append("It reproduces with the test machine connected directly to the ISP router ("
                 + ", ".join(ph["P"]["meta"]["short"] for ph in direct)
                 + ") with no customer equipment in the path, so customer equipment can be ruled out.")
    for router in ("own", "isp"):
        pair = {ph["id"].split("-")[1]: ph for ph in res["phases"] if ph["id"].startswith(router + "-")}
        if len(pair) == 2 and all((ph["agg"].get(("test", 4)) or {}).get("valid") for ph in pair.values()):
            a, b = pair["wifi"]["agg"][("test", 4)]["slow_pct"], pair["wired"]["agg"][("test", 4)]["slow_pct"]
            where = "on the ISP router" if router == "isp" else "through the customer's own network"
            if abs(a - b) <= 20 and (a or b):
                L.append(f"Wi-Fi vs wired {where} makes little difference (IPv4 transit slow share {a:.0f}% vs "
                         f"{b:.0f}%), so the local link is not the cause.")
            elif a or b:
                L.append(f"Wi-Fi vs wired {where}: IPv4 transit slow share {a:.0f}% vs {b:.0f}%.")
    own = [ph for ph in res["phases"] if ph["id"].startswith("own-")]
    if own and direct:
        u = [ph["agg"].get(("test", 4)) for ph in own if (ph["agg"].get(("test", 4)) or {}).get("valid")]
        d = [ph["agg"].get(("test", 4)) for ph in direct if (ph["agg"].get(("test", 4)) or {}).get("valid")]
        if u and d:
            us = sum(x["slow"] for x in u) / sum(x["valid"] for x in u) * 100
            ds = sum(x["slow"] for x in d) / sum(x["valid"] for x in d) * 100
            L.append(f"Through the customer's own network the IPv4 transit slow share was {us:.0f}%, against "
                     f"{ds:.0f}% directly on the ISP router. "
                     + ("Similar, so the customer's router adds nothing to the problem." if abs(us - ds) <= 20 else
                        "The difference is worth noting."))
    v6 = [ph["agg"][("test", 6)] for ph in res["phases"] if (ph["agg"].get(("test", 6)) or {}).get("valid")]
    if v6 and any(s["slow"] for s in v6):
        L.append("IPv6 is affected as well as IPv4, so address translation (NAT/CGNAT) is not the cause.")
    test_slow = sum((ph["agg"].get(("test", f)) or {}).get("slow", 0) for ph in res["phases"] for f in (4, 6))
    test_valid = sum((ph["agg"].get(("test", f)) or {}).get("valid", 0) for ph in res["phases"] for f in (4, 6))
    ctl_rate = ctl_slow / ctl_valid if ctl_valid else None
    test_rate = test_slow / test_valid if test_valid else 0
    control_clean = ctl_rate is not None and ctl_rate <= 0.05 and test_rate >= 0.15
    if ctl_valid and any_test_slow:
        if control_clean:
            L.append(f"The control destination was slow in {ctl_slow} of {ctl_valid} connections across all "
                     f"vantage points, against {test_slow} of {test_valid} for transit-reached destinations. "
                     "The fault looks specific to the transit path.")
        else:
            L.append(f"The control destination was also slow in {ctl_slow} of {ctl_valid} connections "
                     f"(transit targets {test_slow} of {test_valid}), so this run doesn't isolate the transit "
                     "path. Something broader may be involved.")
    for ph in res["phases"]:
        for fam, pa in ph["port"].items():
            pv = f"p≈{pa['p_value']:.3f}" if pa["p_value"] is not None else "p n/a"
            caveat = "" if (fam == 6 or not ph["id"].startswith("own")) else " IPv4 here may cross two NATs that can rewrite ports, so treat it with caution."
            L.append(f"Fixed-source-port test ({ph['P']['meta']['short']}, IPv{fam}): {pa['consistent']} of "
                     f"{pa['usable']} ports gave the same outcome every time vs ~{pa['expected_if_random']:.1f} "
                     f"expected by chance ({pv}): {pa['verdict']}.{caveat}")
    # group every destination by the route this run actually saw: via a known exchange or not
    grp = {"ix": [], "no-ix": []}
    names = {"ix": set(), "no-ix": set()}
    for ph in res["phases"]:
        thr = [r for r in ph["P"]["rows"] if r["test"] == "throughput"]
        for (tname, fam) in ph["per"]:
            rc = route_class(ph["P"]["traces"], tname, fam)
            if rc:
                grp[rc] += [r for r in thr if r["target"] == tname and r["family"] == fam]
                names[rc].add(f"{tname} v{fam}")
    gs = {k: stats_for(v) for k, v in grp.items() if v}
    if gs:
        bits = []
        if "ix" in gs:
            bits.append(f"routes crossing an internet exchange ({', '.join(sorted(names['ix']))}): "
                        f"{gs['ix']['slow']}/{gs['ix']['valid']} slow")
        if "no-ix" in gs:
            bits.append(f"routes with no exchange hop ({', '.join(sorted(names['no-ix']))}): "
                        f"{gs['no-ix']['slow']}/{gs['no-ix']['valid']} slow")
        L.append("Grouped by the route each destination took in this run (from traceroutes): " + "; ".join(bits) + ".")

    # route map: which routers do bad routes have in common that good routes don't
    for ph in res["phases"]:
        ph["routes"] = {}
        for fam in (4, 6):
            rm = route_map(ph, fam)
            if not rm:
                continue
            ph["routes"][fam] = rm
            where = f"{ph['P']['meta']['short']}, IPv{fam}"
            if not rm["n_bad"]:
                continue
            desc = lambda n: (f"{n['ip']}" + (f" ({n['info'].get('rdns')})" if n["info"].get("rdns") else "")
                              + (f" AS{n['info'].get('asn')} {n['info'].get('as_name', '').split(',')[0]}"
                                 if n["info"].get("asn") else ""))
            if rm["on_every_bad"]:
                L.append(f"Route map ({where}): {rm['n_bad']} bad and {rm['n_good']} good destinations. Routers on "
                         "EVERY bad route and on no good route: " + "; ".join(desc(n) for n in rm["on_every_bad"][:4])
                         + ". These are the strongest candidates for where the fault sits.")
            elif rm["suspects"]:
                L.append(f"Route map ({where}): {rm['n_bad']} bad and {rm['n_good']} good destinations. Routers seen "
                         "only on bad routes (none is on all of them): "
                         + "; ".join(desc(n) for n in rm["suspects"][:5]) + ".")
            else:
                L.append(f"Route map ({where}): every router on a bad route is also used by a good route, so the "
                         "map can't single one out.")
    if any(ph.get("routes") for ph in res["phases"]):
        L.append("Caveat for the route map: traceroute probes are hashed onto paths separately from real "
                 "connections, so it shows the typical path per destination, not each connection's exact path. "
                 "The per-flow probes below address that.")

    # per-flow path probes (exact 5-tuples of slow and fast connections)
    for ph in res["phases"]:
        ph["flowtrace"] = flowtrace_analysis(ph["P"]["flowtrace"] or {})
        for fam, fa in ph["flowtrace"].items():
            where = f"{ph['P']['meta']['short']}, IPv{fam}"
            nat = (" IPv4 passes the ISP router's NAT, which may change the source port, so the IPv6 "
                   "result is the stronger one.") if fam == 4 else ""
            if fa["diverge"]:
                d = fa["diverge"]
                L.append(f"Per-flow path probes ({where}): connections from consistently SLOW source ports leave via "
                         f"{', '.join(d['slow'])} at hop {d['hop']}, while consistently FAST ones leave via "
                         f"{', '.join(d['fast'])}. The bad path is behind {', '.join(d['slow'])}." + nat)
            else:
                L.append(f"Per-flow path probes ({where}): slow and fast source ports passed the same routers at "
                         f"every hop that answered ({fa['n']} probes). The fault is then inside a link bundle "
                         "(LAG) or a router whose parallel members traceroute can't tell apart, so only the ISP can "
                         "see which member it is." + nat)
            if fa["unstable_ports"]:
                L.append(f"  (Paths changed between repeats for port(s) {', '.join(map(str, fa['unstable_ports']))}: "
                         "routing may be shifting.)")

    # path classification from traceroutes
    for ph in res["phases"]:
        tr = ph["P"]["traces"]
        labels = [f"{k.split('/')[0]} {k.split('/')[1]}: {path_label(v, tr)}" for k, v in tr.items()
                  if not k.startswith("iperf:") and v.get("hops")]
        if labels:
            L.append(f"Paths seen from {ph['P']['meta']['short']} (traceroute): " + "; ".join(labels) + ".")
            break

    # 1. packet captures
    caps = [f for ph in res["phases"] for f in (ph["P"]["pcap"] or {}).get("flows", []) if "retransmit_pct" in f]
    if caps:
        def med(cls, key):
            v = [f[key] for f in caps if f["class"] == cls and f.get(key) is not None]
            return statistics.median(v) if v else None
        sl, fa = [f for f in caps if f["class"] == "slow"], [f for f in caps if f["class"] == "fast"]
        parts = []
        for name, grp, cls in (("slow", sl, "slow"), ("fast", fa, "fast")):
            if grp:
                parts.append(f"{len(grp)} {name} connection(s): median {num(med(cls, 'retransmit_pct'), '.1f')}% of "
                             f"server segments retransmitted, {num(med(cls, 'holes'), '.0f')} holes, "
                             f"{num(med(cls, 'sack_acks'), '.0f')} SACK ACKs, {num(med(cls, 'stalls_200ms'), '.0f')} "
                             f"stalls over 200 ms (longest {num(med(cls, 'longest_gap_ms'), '.0f')} ms)")
        L.append("Packet captures (headers only, taken on the test machine): " + "; ".join(parts) + ".")
        rs, rf = med("slow", "retransmit_pct"), med("fast", "retransmit_pct")
        if rs is not None and rs >= 1 and (rf is None or rs >= 3 * max(rf, 0.1)):
            L.append("The slow connections are losing packets heavily and recovering slowly, which is what "
                     "throttles them. That fits a lossy link on their path.")
        elif rs is not None and rs < 1 and med("slow", "stalls_200ms"):
            L.append("The slow connections show little retransmission but long gaps between segments. That "
                     "looks more like queueing or rate-limiting than packet loss.")
        drops = [f for f in caps if f.get("kernel_drops")]
        if drops:
            L.append(f"Note: {len(drops)} capture(s) reported packets dropped by the kernel, so their counts are "
                     "approximate.")

    # 5. long-running connections
    longs = [f for ph in res["phases"] for f in ph["P"]["long"] if f.get("series_mbps")]
    if longs:
        sl = [f for f in longs if f["class"] == "slow"]
        fa = [f for f in longs if f["class"] == "fast"]
        secs = max(len(f["series_mbps"]) for f in longs)
        txt = f"Long connections (~{secs} s, sampled every second): {len(sl)} of {len(longs)} were slow."
        if sl:
            peak = max(max(f["series_mbps"]) for f in sl)
            above = sum(f.get("seconds_above_threshold", 0) for f in sl)
            txt += (f" The slow ones never exceeded {peak:.2f} MB/s in any second"
                    + (" and never recovered" if above == 0 else f" and spent {above} second(s) above the threshold in total")
                    + ".")
        if fa:
            # ignore the first second (slow start) and the last (cut short by the time limit;
            # older runs didn't trim it)
            low = min(min(f["series_mbps"][1:-1] or f["series_mbps"]) for f in fa)
            txt += f" The fast ones stayed above {low:.1f} MB/s throughout."
        L.append(txt)

    # 3. parallel streams
    ips = [r for ph in res["phases"] for r in (ph["P"]["iperf"] if isinstance(ph["P"]["iperf"], list) else [])
           if r.get("streams")]
    if ips:
        bits = []
        mixed = False
        for r in ips:
            n_slow = sum(1 for s in r["streams"] if s["class"] == "slow")
            mixed |= 0 < n_slow < len(r["streams"])
            bits.append(f"{r['host']} {r['direction']} IPv{r['family']} ({r.get('path', '?')}): {n_slow}/"
                        f"{len(r['streams'])} streams slow")
        L.append(f"Parallel-stream tests (iperf3, {len(ips[0]['streams'])} streams at once): " + "; ".join(bits) + ".")
        if mixed:
            L.append("Within single parallel tests, some streams crawled while others to the same server ran at "
                     "full speed at the same moment. So the split is per connection, not per server or per time.")
        rt_s = [s["retransmits"] for r in ips for s in r["streams"] if s["class"] == "slow" and s.get("retransmits") is not None]
        rt_f = [s["retransmits"] for r in ips for s in r["streams"] if s["class"] == "fast" and s.get("retransmits") is not None]
        if rt_s and rt_f:
            L.append(f"Sender-side retransmissions per stream (iperf3): median {statistics.median(rt_s):.0f} on slow "
                     f"streams vs {statistics.median(rt_f):.0f} on fast streams.")

    pinged = [pg for ph in res["phases"] for pg in ph["P"]["pings"].values() if pg.get("sent")]
    loss = [f"{ph['P']['meta']['short']} {k} {pg['loss_pct']}%" for ph in res["phases"]
            for k, pg in ph["P"]["pings"].items() if pg.get("loss_pct")]
    if pinged:
        L.append("ICMP ping loss to the targets: " + (", ".join(loss) if loss else "none observed")
                 + ". Per-flow faults often don't show up in ping, which is hashed as a separate flow.")
    if any_test_slow and control_clean:
        L.append("Interpretation (inferred from outside, not proven): each connection is either fine or slow for "
                 "its whole life, one server address gives both outcomes, and only transit-reached destinations "
                 "are affected. That pattern usually means one degraded member of a LAG/ECMP bundle on the path "
                 "towards transit, with each connection hashed onto a member.")
    elif not any_test_slow:
        L.append("No slow connections were seen in this run. The fault may have been fixed, or be intermittent.")
    return res


def fmt_pct(s):
    return "-" if not s or s["slow_pct"] is None else f"{s['slow']}/{s['valid']} ({s['slow_pct']:.0f}%)"


def summary_table(an):
    lines = [f"{'vantage point':<16}{'target':<22}{'fam':<5}{'slow':>14}{'med fast MB/s':>15}{'med slow':>10}"]
    for ph in an["phases"]:
        for (tname, fam), s in ph["per"].items():
            lines.append(f"{ph['P']['meta']['short']:<16}{tname:<22}v{fam:<4}{fmt_pct(s):>14}"
                         f"{num(s['med_fast'], '.1f'):>15}{num(s['med_slow'], '.2f'):>10}")
    return "\n".join(lines)


def svg_dotplot(an, slow_mbps):
    rows = []
    for ph in an["phases"]:
        thr = [r for r in ph["P"]["rows"] if r["test"] == "throughput"]
        for t in TARGETS:
            for fam in (4, 6):
                v = [r for r in thr if r["target"] == t[0] and r["family"] == fam and r["class"] != "error"]
                if v:
                    rc = route_class(ph["P"]["traces"], t[0], fam)
                    role = "control" if (rc == "ix" or (rc is None and t[3] == "control")) else t[3]
                    rows.append((f"{ph['P']['meta']['short']} · {t[0]} v{fam}", role, v))
    if not rows:
        return "<p class='muted'>No data.</p>"
    W, left, right, rh, top = 980, 300, 24, 20, 30
    H = top + rh * len(rows) + 30
    lo, hi = math.log10(0.01), math.log10(2000)

    def x(m):
        return left + (min(max(math.log10(max(m, 0.01)), lo), hi) - lo) / (hi - lo) * (W - left - right)
    s = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Per-connection throughput, log scale">']
    for tick in (0.01, 0.1, 1, 10, 100, 1000):
        s.append(f'<line x1="{x(tick):.1f}" y1="{top - 8}" x2="{x(tick):.1f}" y2="{H - 25}" class="grid"/>'
                 f'<text x="{x(tick):.1f}" y="{H - 10}" class="tick">{tick:g} MB/s</text>')
    s.append(f'<line x1="{x(slow_mbps):.1f}" y1="{top - 8}" x2="{x(slow_mbps):.1f}" y2="{H - 25}" class="thr"/>'
             f'<text x="{x(slow_mbps) + 4:.1f}" y="{top - 12}" class="tick" style="text-anchor:start">slow threshold</text>')
    for i, (label, role, v) in enumerate(rows):
        y = top + i * rh + rh / 2
        if i % 2 == 0:
            s.append(f'<rect x="0" y="{y - rh / 2:.1f}" width="{W}" height="{rh}" class="band"/>')
        s.append(f'<text x="{left - 8}" y="{y + 4:.1f}" class="lab{" ctl" if role == "control" else ""}" '
                 f'text-anchor="end">{html.escape(label)}</text>')
        for r in v:
            cls = "slow" if r["class"] == "slow" else "fast"
            s.append(f'<circle cx="{x(r["mbps"]):.1f}" cy="{y:.1f}" r="4" class="{cls}"><title>'
                     f'{r["mbps"]:.2f} MB/s · {html.escape(r["remote_ip"])} · round {r["round"]} · {r["time"]}'
                     f'</title></circle>')
    s.append("</svg>")
    return "\n".join(s)


# ---------------------------------------------------------------- route map

def short_name(info):
    """Compact label for a router: the most specific part of its reverse DNS, else the address."""
    name = (info.get("rdns") or "").rstrip(".")
    if name:
        parts = name.split(".")
        return ".".join(parts[:3]) if len(parts) > 3 else name
    return info.get("ip") or "?"


def route_map(ph, fam):
    """Merge one phase's traceroutes for a family into a graph and score every router by the
    connections that went through it. 'bad' destination: >=15 % of connections slow; 'good': <=5 %."""
    thr = [r for r in ph["P"]["rows"] if r["test"] == "throughput" and r["family"] == fam]
    dests = []
    for key, tr in ph["P"]["traces"].items():
        if key.startswith("iperf:") or not key.endswith(f"/v{fam}") or not tr.get("hops"):
            continue
        tname = key.split("/")[0]
        names = [tname] + (["hetzner-ash-https"] if tname == "hetzner-ash-http" else [])
        st = stats_for([r for r in thr if r["target"] in names])
        if not st["valid"]:
            continue
        status = "bad" if st["slow_pct"] >= 15 else ("good" if st["slow_pct"] <= 5 else "mixed")
        dests.append({"key": key, "name": "hetzner-ash (http+https)" if len(names) > 1 else tname,
                      "st": st, "status": status, "hops": tr["hops"], "via_ix": tr.get("via_ix")})
    if not dests:
        return None
    order = {"good": 0, "mixed": 1, "bad": 2}
    dests.sort(key=lambda d: (order[d["status"]], d["name"]))
    nodes, edges = {}, {}
    for d in dests:
        prev, gap = [("src", 0)], False
        for h in d["hops"]:
            infos = ([{k: h.get(k) for k in ("ip", "rdns", "asn", "as_name", "ix")}] if h.get("ip") else []) \
                + list(h.get("alts") or [])
            if not infos:
                gap = True
                continue
            cur = []
            for inf in infos:
                ip = inf["ip"]
                nd = nodes.setdefault(ip, {"ip": ip, "row": h["hop"], "info": inf, "dests": set(),
                                           "slow": 0, "valid": 0, "good": 0, "bad": 0})
                nd["row"] = min(nd["row"], h["hop"])
                if d["key"] not in nd["dests"]:
                    nd["dests"].add(d["key"])
                    nd["slow"] += d["st"]["slow"]
                    nd["valid"] += d["st"]["valid"]
                    nd["good"] += d["status"] == "good"
                    nd["bad"] += d["status"] == "bad"
                cur.append((ip, h["hop"]))
            for a, _ in prev:
                for b, _ in cur:
                    e = edges.setdefault((a, b), {"dests": set(), "good": 0, "bad": 0, "gap": gap})
                    if d["key"] not in e["dests"]:
                        e["dests"].add(d["key"])
                        e["good"] += d["status"] == "good"
                        e["bad"] += d["status"] == "bad"
            prev, gap = cur, False
        d["last"] = [ip for ip, _ in prev]
    bad = [d for d in dests if d["status"] == "bad"]
    good = [d for d in dests if d["status"] == "good"]
    endpoints = {ip for d in dests for ip in d["last"]}          # the destination servers themselves
    for ip in endpoints:
        nodes[ip]["endpoint"] = True
    suspects = sorted((n for n in nodes.values() if n["bad"] and not n["good"] and not n.get("endpoint")),
                      key=lambda n: (-n["bad"], n["row"]))
    on_every_bad = []
    if bad:
        common = set.intersection(*[{ip for ip, n in nodes.items() if d["key"] in n["dests"]} for d in bad])
        on_every_bad = sorted((nodes[ip] for ip in common if not nodes[ip]["good"] and not nodes[ip].get("endpoint")),
                              key=lambda n: n["row"])
    return {"fam": fam, "dests": dests, "nodes": nodes, "edges": edges, "suspects": suspects,
            "on_every_bad": on_every_bad, "n_good": len(good), "n_bad": len(bad)}


def _badness_colour(frac):
    """Green (no slow connections) -> amber -> red (all slow)."""
    stops = [(0.0, (26, 127, 55)), (0.25, (217, 119, 6)), (0.5, (220, 38, 38)), (1.0, (153, 27, 27))]
    for (a, ca), (b, cb) in zip(stops, stops[1:]):
        if frac <= b:
            t = (frac - a) / (b - a) if b > a else 0
            return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(ca, cb))
    return "#991b1b"


def svg_route_map(rm):
    """Top-to-bottom map: this machine, then each hop, then the destinations. Routers are coloured by
    the share of slow connections that went through them; links are red when only bad
    destinations used them, green when only good ones did, grey when shared."""
    esc = html.escape
    rows = sorted({n["row"] for n in rm["nodes"].values()})
    row_y = {r: 70 + i * 54 for i, r in enumerate(rows)}
    W, margin = 1000, 70
    dest_y = 70 + len(rows) * 54 + 30
    H = dest_y + 70
    nd_dest = len(rm["dests"])
    dx = {d["key"]: margin + (i + 0.5) * (W - 2 * margin) / nd_dest for i, d in enumerate(rm["dests"])}
    # place each router near the mean x of the destinations it serves, then spread out overlaps
    pos = {}
    for r in rows:
        ns = [n for n in rm["nodes"].values() if n["row"] == r]
        for n in ns:
            n["_x"] = sum(dx[k] for k in n["dests"]) / len(n["dests"])
        ns.sort(key=lambda n: n["_x"])
        gap = min(110, (W - 2 * margin) / max(len(ns), 1))
        xs = [n["_x"] for n in ns]
        for i in range(1, len(xs)):
            xs[i] = max(xs[i], xs[i - 1] + gap)
        over = xs[-1] - (W - margin) if xs else 0
        if over > 0:
            xs = [x - over for x in xs]
            for i in range(len(xs) - 2, -1, -1):
                xs[i] = min(xs[i], xs[i + 1] - gap)
        for n, x in zip(ns, xs):
            pos[n["ip"]] = (max(margin / 2, x), row_y[r])
    pos["src"] = (W / 2, 28)
    o = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Route map, IPv{rm["fam"]}">']
    for r in rows:
        o.append(f'<text x="8" y="{row_y[r] + 4}" class="tick" style="text-anchor:start">hop {r}</text>')
    # links
    for (a, b), e in rm["edges"].items():
        if a not in pos or b not in pos:
            continue
        cls = "eb" if e["bad"] and not e["good"] else ("eg" if e["good"] and not e["bad"] else "es")
        (x1, y1), (x2, y2) = pos[a], pos[b]
        dash = ' stroke-dasharray="4 4"' if e["gap"] else ""
        o.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" class="{cls}" '
                 f'stroke-width="{1 + 0.7 * len(e["dests"]):.1f}"{dash}>'
                 f'<title>{len(e["dests"])} destination(s): {e["good"]} good, {e["bad"]} bad'
                 f'{" (unanswered hops in between)" if e["gap"] else ""}</title></line>')
    for d in rm["dests"]:
        for ip in d["last"]:
            if ip in pos:
                (x1, y1) = pos[ip]
                cls = {"bad": "eb", "good": "eg"}.get(d["status"], "es")
                o.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{dx[d["key"]]:.1f}" y2="{dest_y - 10}" '
                         f'class="{cls}" stroke-width="1.5" stroke-dasharray="2 3"/>')
    # routers
    o.append(f'<circle cx="{pos["src"][0]}" cy="{pos["src"][1]}" r="9" class="srcn"/>'
             f'<text x="{pos["src"][0] + 14}" y="{pos["src"][1] + 4}" class="nlab">this machine</text>')
    for ip, n in rm["nodes"].items():
        x, y = pos[ip]
        frac = n["slow"] / n["valid"] if n["valid"] else 0
        inf = n["info"]
        ring = ' stroke="#111" stroke-width="2.5"' if n in rm["on_every_bad"] else ""
        o.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{_badness_colour(frac)}"{ring}><title>'
                 f'{esc(ip)}  {esc(inf.get("rdns") or "")}\nAS{esc(str(inf.get("asn") or "?"))} '
                 f'{esc(inf.get("as_name") or "")}{"  [" + esc(inf["ix"]) + "]" if inf.get("ix") else ""}\n'
                 f'{n["good"]} good / {n["bad"]} bad destination(s) through here; '
                 f'{n["slow"]}/{n["valid"]} connections slow</title></circle>')
        o.append(f'<text x="{x:.1f}" y="{y + 20:.1f}" class="nlab" style="text-anchor:middle">'
                 f'{esc(short_name(dict(inf, ip=ip))[:26])}</text>')
        if inf.get("asn") or inf.get("ix"):
            o.append(f'<text x="{x:.1f}" y="{y + 30:.1f}" class="nsub" style="text-anchor:middle">'
                     f'{esc(inf["ix"] if inf.get("ix") else "AS" + str(inf["asn"]))}</text>')
    # destinations
    for d in rm["dests"]:
        x = dx[d["key"]]
        col = {"bad": "#b42318", "good": "#1a7f37"}.get(d["status"], "#b45309")
        o.append(f'<rect x="{x - 8:.1f}" y="{dest_y - 10}" width="16" height="16" rx="3" fill="{col}">'
                 f'<title>{esc(d["name"])}: {d["st"]["slow"]}/{d["st"]["valid"]} slow</title></rect>'
                 f'<text x="{x:.1f}" y="{dest_y + 22}" class="nlab" style="text-anchor:middle">{esc(d["name"][:22])}</text>'
                 f'<text x="{x:.1f}" y="{dest_y + 34}" class="nsub" style="text-anchor:middle;fill:{col}">'
                 f'{d["st"]["slow_pct"]:.0f}% slow</text>')
    o.append("</svg>")
    return "\n".join(o)


def svg_spark(series, slow_mbps, w=520, h=56):
    if not series:
        return "<span class='muted'>no samples</span>"
    lo, hi = math.log10(0.01), math.log10(2000)

    def y(v):
        return h - 4 - (min(max(math.log10(max(v, 0.01)), lo), hi) - lo) / (hi - lo) * (h - 8)
    step = (w - 10) / max(len(series) - 1, 1)
    pts = " ".join(f"{5 + i * step:.1f},{y(v):.1f}" for i, v in enumerate(series))
    cls = "slow" if statistics.median(series) < slow_mbps else "fast"
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px;display:block" role="img" aria-label="throughput per second">'
            f'<line x1="0" x2="{w}" y1="{y(slow_mbps):.1f}" y2="{y(slow_mbps):.1f}" class="thr"/>'
            f'<polyline points="{pts}" fill="none" class="line {cls}"/>'
            + "".join(f'<circle cx="{5 + i * step:.1f}" cy="{y(v):.1f}" r="2" class="{cls}">'
                      f'<title>{i + 1}s: {v:.2f} MB/s</title></circle>' for i, v in enumerate(series))
            + f'<text x="{w - 4}" y="12" class="tick" style="text-anchor:end">max {max(series):.1f} · '
              f'min {min(series):.2f} MB/s</text></svg>')


CSS = """
body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;color:#1d2433;background:#f6f7f9}
main{max-width:1060px;margin:0 auto;padding:28px 22px 60px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;border-bottom:1px solid #dde1e8;padding-bottom:6px}
h3{font-size:15px;margin:22px 0 6px}.sub{color:#5b6475;margin:0 0 18px}
.card{background:#fff;border:1px solid #dde1e8;border-radius:10px;padding:14px 18px;margin:12px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.kpi{background:#fff;border:1px solid #dde1e8;border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:22px}.kpi span{color:#5b6475;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13.5px;background:#fff;margin:6px 0}
th,td{border-bottom:1px solid #e7eaf0;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f0f2f6;font-weight:600}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.bad{color:#b42318;font-weight:600}.ok{color:#1a7f37}.muted{color:#5b6475}
code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#fff;border:1px solid #dde1e8;border-radius:8px;padding:10px;overflow:auto}
ul.an li{margin:6px 0}
svg .grid{stroke:#e3e6ec}svg .thr{stroke:#b42318;stroke-dasharray:4 3}
svg .tick{font-size:11px;fill:#5b6475;text-anchor:middle}svg .lab{font-size:11.5px;fill:#1d2433}
svg .lab.ctl{fill:#1a7f37;font-weight:600}svg .band{fill:#f7f8fa}
svg .fast{fill:#2563eb;fill-opacity:.8}svg .slow{fill:#dc2626;stroke:#7f1d1d;stroke-width:.6}
svg .line.fast{stroke:#2563eb;fill:none;stroke-width:1.5}svg .line.slow{stroke:#dc2626;fill:none;stroke-width:1.5}
details summary{cursor:pointer;font-weight:600;margin:6px 0}
svg .eb{stroke:#dc2626;stroke-opacity:.75}svg .eg{stroke:#1a7f37;stroke-opacity:.75}svg .es{stroke:#9aa3b2;stroke-opacity:.7}
svg .nlab{font-size:10px;fill:#1d2433}svg .nsub{font-size:9px;fill:#5b6475}svg .srcn{fill:#1d2433}
.legend span{display:inline-block;margin-right:14px}.sw{display:inline-block;width:12px;height:12px;border-radius:50%;vertical-align:-1px;margin-right:4px}
td.hopcell{font:11px ui-monospace,Menlo,monospace;white-space:nowrap}td.div{background:#fde8e8}
@media print{details{display:block}details>*{display:block}}
"""


def html_report(an, args):
    esc = html.escape
    first = an["phases"][0]["P"]["meta"]
    pub = first["env"].get("public_v4") or {}
    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>Per-connection throughput report — {esc(pub.get('ip', ''))}</title><style>{CSS}</style></head>"
         "<body><main>", "<h1>Per-connection throughput report</h1>",
         f"<p class='sub'>Customer line with public IP <b>{esc(pub.get('ip', '?'))}</b> ({esc(pub.get('org', ''))})."
         + (f" Support reference <b>{esc(args.ref)}</b>." if args.ref else "")
         + f" Generated {esc(now_iso())} by isp-flow-test.py v{VERSION}.</p>"]

    o.append("<div class='kpis'>")
    for ph in an["phases"]:
        for fam in (4, 6):
            t, c = ph["agg"].get(("test", fam)), ph["agg"].get(("control", fam))
            if t and t["valid"]:
                ctl = f"{c['slow']}/{c['valid']}" if c else "-"
                o.append(f"<div class='kpi'><span>{esc(ph['P']['meta']['short'])} · IPv{fam}</span>"
                         f"<b class='{'bad' if t['slow'] else 'ok'}'>{t['slow_pct']:.0f}% slow</b>"
                         f"<span>transit targets {t['slow']}/{t['valid']} · control {ctl} slow</span></div>")
    o.append("</div>")

    o.append("<h2>Analysis</h2><div class='card'><ul class='an'>")
    o += [f"<li>{esc(line)}</li>" for line in an["lines"]]
    o.append("</ul></div>")

    o.append("<h2>Every connection</h2><p class='muted'>One dot per connection, log scale. Red is below the slow "
             f"threshold. Green row labels are destinations whose route crossed a known internet exchange ({IX_LABEL}). Hover a dot for details.</p>")
    o.append(f"<div class='card'>{svg_dotplot(an, args.slow_mbps)}</div>")

    o.append("<h2>Results by vantage point and target</h2><table><tr><th>Vantage point</th><th>Target</th>"
             "<th>Family</th><th>Route</th><th class='n'>Slow</th><th class='n'>Median fast MB/s</th>"
             "<th class='n'>Fastest MB/s</th><th class='n'>Median slow MB/s</th><th class='n'>Errors</th></tr>")
    for ph in an["phases"]:
        for (tname, fam), s in ph["per"].items():
            ctl = " <span class='ok'>(control)</span>" if next(t[3] for t in TARGETS if t[0] == tname) == "control" else ""
            route = path_label(ph["P"]["traces"].get(trace_key(tname, fam)), ph["P"]["traces"]) if ph["P"]["traces"] else "-"
            o.append(f"<tr><td>{esc(ph['P']['meta']['short'])}</td><td>{esc(tname)}{ctl}</td><td>IPv{fam}</td>"
                     f"<td class='muted'>{esc(route)}</td><td class='n {'bad' if s['slow'] else ''}'>{fmt_pct(s)}</td>"
                     f"<td class='n'>{num(s['med_fast'], '.1f')}</td><td class='n'>{num(s['max_fast'], '.1f')}</td>"
                     f"<td class='n'>{num(s['med_slow'], '.2f')}</td><td class='n'>{s['err']}</td></tr>")
    o.append("</table>")

    o.append("<h2>Fixed-source-port test</h2><p class='muted'>The same local source ports were re-used several "
             "times against one target. If a degraded bundle member is chosen by a hash of each connection's "
             "addresses and ports, a given port should give the same result every time. IPv6 is the cleanest "
             "test because nothing rewrites the ports.</p>")
    if not any(ph["port"] for ph in an["phases"]):
        o.append("<p class='muted'>Not run.</p>")
    for ph in an["phases"]:
        for fam, pa in ph["port"].items():
            o.append(f"<h3>{esc(ph['P']['meta']['short'])} · IPv{fam}: {esc(pa['verdict'])}</h3>"
                     "<table><tr><th>Source port</th><th>Outcomes, in order</th></tr>")
            for port, outs in sorted(pa["ports"].items(), key=lambda kv: int(kv[0] or 0)):
                o.append(f"<tr><td><code>{esc(port)}</code></td><td>" + " · ".join(
                    f"<span class='{'bad' if c == 'slow' else ('ok' if c == 'fast' else 'muted')}'>{c}</span>"
                    for c in outs) + "</td></tr>")
            o.append(f"</table><p class='muted'>{pa['consistent']} of {pa['usable']} ports consistent; "
                     f"~{pa['expected_if_random']:.1f} expected by chance at a {pa['slow_rate']:.0%} slow rate; "
                     f"p = {num(pa['p_value'], '.3f')}.</p>")

    # 1. packet captures
    o.append("<h2>Packet captures</h2><p class='muted'>Header-only captures (tcpdump, 128-byte snap) of single "
             "downloads, taken on the test machine; all slow connections were kept plus one fast one for "
             "comparison. A <i>retransmit</i> is a server segment covering data already seen; a <i>hole</i> is a "
             "segment arriving beyond a gap, meaning an earlier one went missing. The .pcap files are in the "
             "pack for Wireshark.</p>")
    cap_rows = [(ph, f) for ph in an["phases"] for f in (ph["P"]["pcap"] or {}).get("flows", []) if "retransmit_pct" in f]
    if not cap_rows:
        reasons = {(ph["P"]["pcap"] or {}).get("skipped") or (ph["P"]["pcap"] or {}).get("error") for ph in an["phases"]}
        o.append(f"<p class='muted'>Not run{': ' + esc('; '.join(r for r in reasons if r)) if any(reasons) else ''}.</p>")
    else:
        o.append("<table><tr><th>Vantage point</th><th>Family</th><th>Local port</th><th>Class</th><th class='n'>MB/s</th>"
                 "<th class='n'>Server segments</th><th class='n'>Retransmitted</th><th class='n'>Holes</th>"
                 "<th class='n'>Dup ACKs</th><th class='n'>SACK ACKs</th><th class='n'>Stalls &gt;200 ms</th>"
                 "<th class='n'>Longest gap ms</th><th>File</th></tr>")
        for ph, f in cap_rows:
            o.append(f"<tr><td>{esc(ph['P']['meta']['short'])}</td><td>IPv{f['family']}</td><td><code>{f['local_port']}</code></td>"
                     f"<td class='{'bad' if f['class'] == 'slow' else 'ok'}'>{f['class']}</td><td class='n'>{f['mbps']:.2f}</td>"
                     f"<td class='n'>{f['server_segments']}</td><td class='n'>{f['retransmits']} ({num(f['retransmit_pct'], '.1f')}%)</td>"
                     f"<td class='n'>{f['holes']}</td><td class='n'>{f['dup_acks']}</td><td class='n'>{f['sack_acks']}</td>"
                     f"<td class='n'>{f['stalls_200ms']}</td><td class='n'>{f['longest_gap_ms']:.0f}</td>"
                     f"<td><code>{esc(ph['id'] + '/' + f.get('file', ''))}</code></td></tr>")
        o.append("</table>")

    # 5. long-running connections
    o.append("<h2>Long-running connections</h2><p class='muted'>Single downloads held open for longer, with "
             "throughput sampled every second (log scale; dashed line = slow threshold). Shows whether a slow "
             "connection ever recovers.</p>")
    longs = [(ph, f) for ph in an["phases"] for f in ph["P"]["long"] if f.get("series_mbps") is not None]
    if not longs:
        o.append("<p class='muted'>Not run.</p>")
    else:
        o.append("<table><tr><th>Vantage point</th><th>Family</th><th>Class</th><th class='n'>Overall MB/s</th>"
                 "<th>Per second</th></tr>")
        for ph, f in longs:
            o.append(f"<tr><td>{esc(ph['P']['meta']['short'])}</td><td>IPv{f['family']}</td>"
                     f"<td class='{'bad' if f['class'] == 'slow' else 'ok'}'>{f['class']}</td>"
                     f"<td class='n'>{f['mbps']:.2f}</td><td>{svg_spark(f['series_mbps'], args.slow_mbps)}</td></tr>")
        o.append("</table>")

    # 3. parallel streams
    o.append("<h2>Parallel streams (iperf3)</h2><p class='muted'>Many TCP streams to one public iperf3 server at "
             "the same moment. Each stream is its own connection with its own source port. If some crawl while "
             "others run at full speed, the split is per connection.</p>")
    ips = [(ph, r) for ph in an["phases"] for r in (ph["P"]["iperf"] if isinstance(ph["P"]["iperf"], list) else [])]
    skipped = [ph["P"]["iperf"].get("skipped") for ph in an["phases"] if isinstance(ph["P"]["iperf"], dict)]
    if not ips:
        o.append(f"<p class='muted'>Not run{': ' + esc(skipped[0]) if skipped and skipped[0] else ''}.</p>")
    else:
        o.append("<table><tr><th>Vantage point</th><th>Server</th><th>Path</th><th>Direction</th><th>Family</th>"
                 "<th class='n'>Total MB/s</th><th class='n'>Slow streams</th><th>Per-stream MB/s (sender retransmits)</th></tr>")
        for ph, r in ips:
            if r.get("error"):
                o.append(f"<tr><td>{esc(ph['P']['meta']['short'])}</td><td>{esc(r['host'])}</td><td></td>"
                         f"<td>{esc(r['direction'])}</td><td>IPv{r['family']}</td>"
                         f"<td colspan='3' class='muted'>{esc(r['error'])}</td></tr>")
                continue
            n_slow = sum(1 for s in r["streams"] if s["class"] == "slow")
            chips = " ".join(
                f"<span class='{'bad' if s['class'] == 'slow' else 'ok'}'>{s['mbps']:.1f}"
                + (f" ({s['retransmits']})" if s.get("retransmits") is not None else "") + "</span>"
                for s in sorted(r["streams"], key=lambda s: s["mbps"]))
            o.append(f"<tr><td>{esc(ph['P']['meta']['short'])}</td><td>{esc(r['host'])}<br>"
                     f"<span class='muted'>{esc(r.get('note', ''))} · {esc(r.get('remote_ip', ''))}</span></td>"
                     f"<td>{esc(r.get('path', ''))}</td><td>{esc(r['direction'])}</td><td>IPv{r['family']}</td>"
                     f"<td class='n'>{r['total_mbps']:.1f}</td><td class='n {'bad' if n_slow else ''}'>"
                     f"{n_slow}/{len(r['streams'])}</td><td>{chips}</td></tr>")
        o.append("</table>")

    # route map
    o.append("<h2>Route map</h2><p class='muted'>Every destination's traceroute merged into one map, from this "
             "machine (top) to the destinations (bottom). Each router is coloured by the share of slow connections "
             "among the destinations whose route passes through it. Links are <span class='bad'>red</span> when only "
             "bad destinations (≥15&nbsp;% slow) use them, <span class='ok'>green</span> when only good ones "
             "(≤5&nbsp;%) do, and grey when shared. A thick black ring marks a router on every bad route and no "
             "good one. Dashed links skip hops that didn't answer. Hover anything for details.</p>"
             "<p class='legend muted'>" + "".join(
                 f"<span><i class='sw' style='background:{_badness_colour(f)}'></i>{lab}</span>"
                 for f, lab in ((0, "no slow connections"), (0.25, "25 % slow"), (0.5, "50 % slow"),
                                (1, "all slow"))) + "</p>")
    maps = [(ph, fam, rm) for ph in an["phases"] for fam, rm in (ph.get("routes") or {}).items()]
    if not maps:
        o.append("<p class='muted'>No traceroutes in this run.</p>")
    for i, (ph, fam, rm) in enumerate(maps):
        title = (f"{esc(ph['P']['meta']['short'])} · IPv{fam} — {rm['n_bad']} bad, {rm['n_good']} good, "
                 f"{len(rm['dests']) - rm['n_bad'] - rm['n_good']} mixed destination(s)")
        o.append(f"<details{' open' if i == 0 else ''}><summary>{title}</summary>"
                 f"<div class='card'>{svg_route_map(rm)}</div></details>")

    # per-flow path probes
    o.append("<h2>Per-flow path probes</h2><p class='muted'>TCP traceroutes sent with exactly the same addresses "
             "and ports as connections that were consistently slow or consistently fast in the fixed-port test "
             "(Paris-traceroute style), so routers hash the probes onto the same path as those connections. "
             "Each port is probed twice. The highlighted column is where slow and fast paths first part.</p>")
    fts = [(ph, ph["P"]["flowtrace"] or {}) for ph in an["phases"]]
    if not any(ft.get("probes") for _, ft in fts):
        why = {ft.get("skipped") for _, ft in fts if ft.get("skipped")}
        why |= {c.get("skipped") for _, ft in fts for c in (ft.get("chosen") or {}).values() if isinstance(c, dict) and c.get("skipped")}
        o.append(f"<p class='muted'>Not run{': ' + esc('; '.join(sorted(w for w in why if w))) if why else ''}.</p>")
    for ph, ft in fts:
        for fam, fa in (ph.get("flowtrace") or {}).items():
            ps = [p for p in ft["probes"] if p["family"] == fam]
            div = (fa.get("diverge") or {}).get("hop")
            o.append(f"<h3>{esc(ph['P']['meta']['short'])} · IPv{fam} · to {esc(ps[0]['dst'])} port {ps[0]['dport']}"
                     f" — {'paths part at hop ' + str(div) if div else 'no visible difference'}</h3>"
                     "<div style='overflow-x:auto'><table><tr><th>Source port</th><th>Class</th><th>Run</th>"
                     + "".join(f"<th{' class=div' if div == t else ''}>{t}</th>" for t in range(1, fa["hops"] + 1))
                     + "</tr>")
            for p in sorted(ps, key=lambda p: (p["class"], p["sport"], p["rep"])):
                cells = []
                for t in range(1, fa["hops"] + 1):
                    h = p["hops"][t - 1] if t - 1 < len(p["hops"]) else None
                    ip = (h or {}).get("ip") or "*"
                    tip = f"{ip} {rdns(ip) if ip != '*' else ''} {(h or {}).get('rtt_ms') or ''} ms"
                    cells.append(f"<td class='hopcell{' div' if div == t else ''}' title='{esc(tip)}'>{esc(ip)}"
                                 f"{' ✓' if (h or {}).get('reached') else ''}</td>")
                o.append(f"<tr><td><code>{p['sport']}</code></td><td class='{'bad' if p['class'] == 'slow' else 'ok'}'>"
                         f"{p['class']}</td><td>{p['rep']}</td>" + ("".join(cells) if not p.get("error") else
                         f"<td colspan='{fa['hops']}' class='muted'>{esc(p['error'])}</td>") + "</tr>")
            o.append("</table></div><p class='muted'>✓ = the destination answered.</p>")

    o.append("<h2>Paths</h2><p class='muted'>Traceroutes (three probes per hop; extra addresses at a hop are parallel paths) with reverse DNS and origin AS "
             "(Team Cymru) for public hops, plus ping to each destination. Hops inside a known internet-exchange "
             f"peering LAN ({IX_LABEL}) are flagged. The HTTPS Hetzner target shares the HTTP one's host and "
             "path.</p>")
    for ph in an["phases"]:
        o.append(f"<h3>{esc(ph['P']['meta']['title'])}</h3>")
        if not ph["P"]["traces"]:
            o.append("<p class='muted'>Not run.</p>")
        for key, tr in ph["P"]["traces"].items():
            pg = ph["P"]["pings"].get(key, {})
            ptxt = (f"ping {pg.get('received')}/{pg.get('sent')} received, loss {pg.get('loss_pct')}%, "
                    f"avg {pg.get('rtt_avg')} ms") if pg.get("sent") else "ping n/a"
            o.append(f"<details><summary>{esc(key)} <span class='muted'>— {esc(path_label(tr, ph['P']['traces']))} · {esc(ptxt)}</span>"
                     "</summary><table><tr><th>#</th><th>Address</th><th>Reverse DNS</th><th>AS</th><th>AS name</th>"
                     "<th class='n'>RTT ms</th></tr>")
            for h in tr.get("hops", []):
                ixt = f" <b class='ok'>[{esc(h['ix'])}]</b>" if h.get("ix") else ""
                alts = "".join(f"<br><code>{esc(a['ip'])}</code> <span class='muted'>{esc(a.get('rdns') or '')}</span>"
                               for a in h.get("alts") or [])
                o.append(f"<tr><td>{h['hop']}</td><td><code>{esc(h.get('ip') or '*')}</code>{ixt}{alts}</td>"
                         f"<td>{esc(h.get('rdns') or '')}</td><td>{esc(h.get('asn') or '')}</td>"
                         f"<td>{esc(h.get('as_name') or '')}</td><td class='n'>{num(h.get('rtt_ms'), '.1f')}</td></tr>")
            if tr.get("error"):
                o.append(f"<tr><td colspan='6' class='muted'>{esc(tr['error'])}</td></tr>")
            o.append("</table></details>")

    o.append("<h2>Test environment</h2>")
    for ph in an["phases"]:
        m, e = ph["P"]["meta"], ph["P"]["meta"]["env"]
        p4, p6 = e.get("public_v4") or {}, e.get("public_v6") or {}
        rows = [("Run", f"{m['started']} → {m.get('finished', '')}"),
                ("Default gateway", f"{e.get('gateway_v4')} via {e.get('iface_v4')} ({e.get('iface_port_name') or '?'})"),
                ("Link", e.get("iface_media") or "-"),
                ("Wi-Fi", ", ".join(f"{k}: {v}" for k, v in (e.get("wifi") or {}).items()) or "-"),
                ("Public IPv4", f"{p4.get('ip', 'none')} {p4.get('org', '')}"),
                ("Public IPv6", p6.get("ip", "none")),
                ("Samples", f"{m['rounds']} rounds × {m['seconds']} s per target and family; slow < {m['slow_mbps']} MB/s"),
                ("Data moved", (f"{m['bytes_moved'] / 1e9:.1f} GB" if m.get("bytes_moved") is not None else "-")
                 + (f" — stopped early: {m['stopped']}" if m.get("stopped") else "")),
                ("Machine", f"{e.get('host')} · {e.get('os')}")]
        o.append(f"<h3>{esc(m['title'])}</h3><table>"
                 + "".join(f"<tr><th>{esc(k)}</th><td>{esc(str(v))}</td></tr>" for k, v in rows) + "</table>")
        o.append("<details><summary>Target DNS</summary><pre>" + esc(json.dumps(m.get("dns", {}), indent=1))
                 + "</pre></details>")

    o.append("<h2>Method</h2><div class='card'><ul>"
             "<li>Each sample is a new TCP connection made with <code>curl</code>, one at a time, rotating through "
             "the targets each round so changes over time affect every target equally.</li>"
             "<li>Throughput counts only the transfer after the first byte, so DNS, TCP and TLS set-up don't "
             "dilute it.</li><li>Targets: " + "; ".join(f"<b>{esc(t[0])}</b> — {esc(t[4])}" for t in TARGETS)
             + ".</li><li>Raw per-connection data is in each vantage point's <code>flows.csv</code>.</li></ul></div>")
    o.append("</main></body></html>")
    return "\n".join(o)


def message_text(an, args, zipname):
    first = an["phases"][0]["P"]["meta"]
    pub = first["env"].get("public_v4") or {}
    vps = "\n".join(f"  - {ph['P']['meta']['title']} ({ph['P']['meta']['started'][:16].replace('T', ' ')})"
                    for ph in an["phases"])
    t = [f"Subject: {'Re: ref ' + args.ref + ' — ' if args.ref else ''}per-connection throughput test results", "",
         "Hello,", "",
         ("Further to my request (ref " + args.ref + "), I've" if args.ref else "I've")
         + " run a repeatable test of the per-connection throughput issue from the following places:",
         vps, "",
         "Each test makes many separate download connections, one at a time, to a mix of destinations, and "
         f"records the speed of each. A short summary is below. The attached {zipname} contains the full report "
         "(report.html opens in any browser), traceroutes with DNS and AS details, and the raw data.", "",
         summary_table(an), "",
         "I'm sharing this to help narrow the issue down. I'm happy to re-run the tests at any time, "
         "including while your engineers watch counters on their side.", "",
         "Kind regards,", args.name]
    if pub.get("ip"):
        t.append(f"(public IPv4 during testing: {pub['ip']})")
    t += ["", "-" * 72, "ANALYSIS (generated automatically by the test script)", "-" * 72]
    t += [f"- {line}" for line in an["lines"]]
    return "\n".join(t) + "\n"


README = """Per-connection throughput test pack
====================================

report.html     Open in a browser: analysis, a dot plot of every connection, results per
                vantage point and target, the fixed-source-port test, packet-capture
                loss analysis, long-running connections (per-second throughput),
                parallel-stream (iperf3) results, traceroutes with reverse DNS, AS
                numbers and internet-exchange hops, pings, and the test environment.
summary.txt     Plain-text summary table and analysis.
message.txt     The covering message, with the automatic analysis at the bottom.
<phase>/        One folder per vantage point:
  flows.csv         every connection: time, target, IP family, remote IP, local port,
                    timings (connect / TLS / first byte / total), bytes, MB/s, class
  traceroutes.json  hops with reverse DNS and origin AS
  pings.json        ICMP loss and RTT per target
  pcap/*.pcap       header-only packet captures (open in Wireshark): every slow
                    capture plus one fast one, named v<family>-port<local port>-<class>
  pcap.json         per-capture loss analysis (retransmits, holes, SACKs, stalls)
  long.json         long-running connections, throughput per second
  iperf.json        parallel-stream tests: per-stream throughput and retransmits
  flowtrace.json    per-flow TCP traceroutes from the slow and fast source ports
  meta.json         environment: gateway, interface, link speed, Wi-Fi details,
                    public IPs, target DNS, test parameters

Destinations: the route each one took is shown in the report (from traceroute). Routes
crossing a known internet exchange are grouped separately from the rest.

Vantage points: own-wired / own-wifi = through the customer's own router, wired or
over its Wi-Fi; isp-wifi = on the ISP router's Wi-Fi; isp-wired = wired into the ISP
router. "Slow" means a transfer rate below the threshold in meta.json. IPv6 connections are not address-translated, so each one's
source address and port can be matched directly against flow data.
"""


def build_report(outdir, args):
    phases, seen = [], set()
    for pid in PHASE_ORDER:
        pdir = os.path.join(outdir, pid)
        if pid in seen or not (os.path.exists(os.path.join(pdir, "meta.json"))
                               and os.path.exists(os.path.join(pdir, "flows.csv"))):
            continue
        seen.add(pid)
        phases.append((pid, load_phase(pdir)))
    phases.sort(key=lambda x: PHASE_ORDER.index(x[0]))
    if not phases:
        say("No completed phases to report on.")
        return None
    an = analyse(phases)
    base = os.path.basename(os.path.abspath(outdir))
    zipname = f"{base}.zip"
    files = {"report.html": html_report(an, args),
             "summary.txt": summary_table(an) + "\n\nAnalysis\n--------\n" + "\n".join(f"- {l}" for l in an["lines"]) + "\n",
             "message.txt": message_text(an, args, zipname),
             "README.txt": README}
    for name, content in files.items():
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write(content)
    zpath = os.path.join(os.path.dirname(os.path.abspath(outdir)), zipname)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, fnames in os.walk(outdir):
            for f in sorted(fnames):
                full = os.path.join(root, f)
                z.write(full, os.path.join(base, os.path.relpath(full, outdir)))
    with zipfile.ZipFile(zpath) as z:                         # prove the package is complete and readable
        bad = z.testzip()
        n_files = len(z.namelist())
    size = os.path.getsize(zpath)
    hr("Results")
    zip_line = (f"{zpath}  ({size / 1e6:.1f} MB, {n_files} files, verified)" if bad is None
                else f"{zpath}  — CORRUPT member {bad}")
    ui.results(an, [("Zip", zip_line),
                    ("Report", os.path.abspath(os.path.join(outdir, "report.html"))),
                    ("Message", os.path.abspath(os.path.join(outdir, "message.txt"))),
                    ("Folder", os.path.abspath(outdir))])
    return zpath


# ---------------------------------------------------------------- main

def choose_phases(args, interactive):
    m2, m1 = phase_seconds(args, 2) / 60, phase_seconds(args, 1) / 60
    if not interactive:
        return "isp-wired"
    say(f"\nWhich vantage points do you want to test? (about {m2:.0f} min each with IPv6, {m1:.0f} without;\n"
        "your own router may not pass IPv6)\n"
        "  1) ISP router, wired only (recommended: the cleanest test, nothing of yours in the path)\n"
        "  2) ISP router: Wi-Fi, then wired\n"
        "  3) Your own network wired, then ISP router wired (shows whether your router changes anything)\n"
        "  4) All four: own wired, own Wi-Fi, ISP Wi-Fi, ISP wired\n"
        "  5) Choose")
    a = ask("Choice", ["1", "2", "3", "4", "5"], "1", interactive)
    preset = {"1": "isp-wired", "2": "isp-wifi,isp-wired", "3": "own-wired,isp-wired",
              "4": ",".join(PHASE_ORDER)}
    if a in preset:
        return preset[a]
    picked = [p for p in PHASE_ORDER
              if ask(f"  Include {PHASES[p]['short']} ({PHASES[p]['title']})?", ["y", "n"],
                     "y" if p == "isp-wired" else "n", interactive) == "y"]
    return ",".join(picked) or "isp-wired"


def default_name():
    rc, out, _ = run(["id", "-F"], timeout=5)
    return out if rc == 0 and out else os.environ.get("USER", "")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--_flowtrace":      # child process for flowtrace_test
        with open(sys.argv[2]) as fh:
            print(json.dumps(flowtrace_worker(json.load(fh))))
        return
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phases", default=None,
                    help="comma list from: own-wired, own-wifi, isp-wifi, isp-wired, or own / isp for both "
                         "of a side (default: ask; non-interactive runs use isp-wired)")
    ap.add_argument("--targets", default=None, help="comma list of target names to use (default: all)")
    ap.add_argument("--rounds", type=int, default=16, help="connections per target per family (default 16)")
    ap.add_argument("--seconds", type=int, default=5, help="length of each connection sample (default 5)")
    ap.add_argument("--slow-mbps", type=float, default=3.0, help="slow threshold in MB/s (default 3)")
    ap.add_argument("--family", choices=["4", "6", "both"], default="both")
    ap.add_argument("--port-count", type=int, default=8, help="ports in the fixed-port test (default 8)")
    ap.add_argument("--port-reps", type=int, default=3, help="repeats per port (default 3)")
    ap.add_argument("--no-port-test", action="store_true")
    ap.add_argument("--no-flowtrace", action="store_true",
                    help="skip per-flow path probes (TCP traceroutes from the slow/fast source ports)")
    ap.add_argument("--flowtrace-ports", type=int, default=4, help="slow and fast ports to trace each (default 4)")
    ap.add_argument("--no-trace", action="store_true", help="skip traceroutes and pings")
    ap.add_argument("--no-pcap", action="store_true", help="skip the packet-capture test (needs sudo)")
    ap.add_argument("--pcap-flows", type=int, default=10, help="max captured downloads per family (default 10)")
    ap.add_argument("--pcap-keep-slow", type=int, default=3, help="stop once this many slow ones are captured")
    ap.add_argument("--pcap-seconds", type=int, default=4, help="length of each captured download (default 4)")
    ap.add_argument("--no-long", action="store_true", help="skip the long-running connection test")
    ap.add_argument("--long-count", type=int, default=4, help="long connections per family (default 4)")
    ap.add_argument("--long-seconds", type=int, default=30, help="length of each long connection (default 30)")
    ap.add_argument("--no-iperf", action="store_true", help="skip the iperf3 parallel-stream test")
    ap.add_argument("--iperf-streams", type=int, default=16, help="parallel streams (default 16)")
    ap.add_argument("--iperf-seconds", type=int, default=10, help="iperf3 test length (default 10)")
    ap.add_argument("--iperf-max", type=int, default=2, help="servers to test per family (default 2)")
    ap.add_argument("--iperf-servers", default="", help="override list: host:5201-5210,host2:5201")
    ap.add_argument("--own-gateway", default=None,
                    help="your own router's LAN address; if set, own-* phases check the default route uses it")
    ap.add_argument("--isp-gateway", default=None,
                    help="the ISP router's LAN address; if set, isp-* phases check the default route uses it")
    ap.add_argument("--expect-isp", default=None, metavar="TEXT",
                    help="refuse to test unless the public IPv4's organisation contains TEXT (e.g. an AS "
                         "number like AS64500); without it, phases must all leave via the same organisation")
    ap.add_argument("--expect-link", default=None, metavar="TEXT",
                    help="warn if a wired phase's link media doesn't contain TEXT (e.g. 10G, 2500Base)")
    ap.add_argument("--ref", default="", help="support ticket reference, used in the report and message")
    ap.add_argument("--name", default=None, help="your name for the message (default: macOS full name)")
    ap.add_argument("--max-gb", type=float, default=None, metavar="GB",
                    help="stop testing once this many GB have been transferred in total (downloads, uploads "
                         "and iperf3, all phases) and build the report from what finished. May overshoot by "
                         "up to one transfer")
    ap.add_argument("--quick", action="store_true", help="4 rounds x 3 s, 4 ports x 2 reps — a dry run")
    ap.add_argument("--force", action="store_true", help="run a phase even if the environment checks fail")
    ap.add_argument("--yes", action="store_true", help="don't prompt; run phases that pass their checks")
    ap.add_argument("--out-dir", default=".", help="where to write the results folder and the .zip (default: here)")
    ap.add_argument("--resume", metavar="DIR", help="add phases to an existing results folder")
    ap.add_argument("--report-only", metavar="DIR", help="rebuild report, message and zip for DIR")
    args = ap.parse_args()
    if args.quick:
        args.rounds, args.seconds, args.port_count, args.port_reps = 4, 3, 4, 2
        args.pcap_flows, args.long_count, args.long_seconds, args.iperf_seconds, args.iperf_max = 4, 1, 10, 5, 1
    args.name = args.name or default_name()
    if args.max_gb is not None:
        if args.max_gb <= 0:
            sys.exit("--max-gb must be more than 0")
        BUDGET.limit = int(args.max_gb * 1e9)
    args._seen = {"gateway": {}, "org": ""}

    if args.report_only:
        build_report(args.report_only, args)
        return
    if not shutil.which("curl"):
        sys.exit("curl not found")
    if platform.system() != "Darwin":
        say("note: written for macOS; the environment checks won't work here (use --force).")

    interactive = sys.stdin.isatty() and not args.yes
    if args.targets:
        keep = {x.strip() for x in args.targets.split(",")}
        unknown = keep - set(TARGET_NAMES)
        if unknown:
            sys.exit(f"unknown target(s): {', '.join(sorted(unknown))}. Choose from: {', '.join(TARGET_NAMES)}")
        keep |= {t[0] for t in TARGETS if t[3] == "control"} | {PORT_TEST_TARGET}   # controls + extra-test target
        TARGETS[:] = [t for t in TARGETS if t[0] in keep]
    if args.phases is None:
        args.phases = choose_phases(args, interactive)
    wanted = []
    for p in (x.strip() for x in args.phases.split(",") if x.strip()):
        wanted += PHASE_ALIASES.get(p, [p])
    bad = [p for p in wanted if p not in PHASES]
    if bad:
        sys.exit(f"unknown phase(s): {', '.join(bad)}. Choose from: {', '.join(PHASE_ORDER)}")
    phases = [p for p in PHASE_ORDER if p in wanted]
    outdir = args.resume or os.path.join(os.path.expanduser(args.out_dir),
                                         f"flow-report-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(outdir, exist_ok=True)

    hr(f"Per-connection ISP test v{VERSION}")
    say(f"  Phases: {', '.join(phases)} · {args.rounds} rounds × {args.seconds} s · up to "
        f"~{phase_seconds(args, 2) / 60:.0f} min per phase with IPv6, ~{phase_seconds(args, 1) / 60:.0f} without")
    say(f"  Results: {os.path.abspath(outdir)}")
    say(f"  Zip:     {os.path.abspath(outdir)}.zip (written at the end, even if interrupted)")
    if BUDGET.limit is not None:
        say(f"  Data:    stops cleanly after {args.max_gb:g} GB in total (may overshoot by one transfer)")
    else:
        say("  Data:    no limit set. A full phase on a fast line can move 100 GB or more; --max-gb caps it.")
    if not ui.rich:
        say("  (tip: run with `uv run` for progress bars — it installs Rich automatically)")
    if not args.no_iperf and not shutil.which("iperf3"):
        say("  iperf3 not found: the parallel-stream test will be skipped (brew install iperf3 to include it).")
    needs_raw = not args.no_pcap or not (args.no_flowtrace or args.no_port_test)
    cap = Capture(interactive, needs_raw)        # one sudo prompt covers captures and path probes
    if not cap.ok and needs_raw:
        say(f"  raw-packet access unavailable: {cap.reason}; packet captures and path probes will be skipped.")
    try:
        for pid in phases:
            run_phase(pid, outdir, args, interactive, cap)
    except KeyboardInterrupt:
        say("\n  interrupted — building the report from whatever has finished.")
    except BudgetExceeded as e:
        say(f"\n  {e} — stopping and building the report from whatever has finished.")
    finally:
        cap.stop()
    build_report(outdir, args)
    if BUDGET.used:
        say(f"  Data moved in this run: {BUDGET.used / 1e9:.1f} GB")


if __name__ == "__main__":
    main()
