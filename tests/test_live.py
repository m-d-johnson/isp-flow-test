"""Real sockets against a local HTTP server, synthetic captures, and the report pipeline end to end.
No privileges and no internet."""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import SCRIPT

CHUNK = b"\0" * (1 << 16)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/big")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/small":
            body = b"x" * 5000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/big":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(1 << 40))
        self.end_headers()
        try:
            while True:
                self.wfile.write(CHUNK)
        except OSError:
            pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_http_flow_streams_until_time_limit(ift, server):
    r = ift.http_flow(server + "/big", 4, 1.5, sample=True)
    assert r["curl_rc"] == 28 and r["error"] == "" and r["http_code"] == "200"
    assert r["bytes"] > 1_000_000 and r["mbps"] > 1
    assert r["remote_ip"] == "127.0.0.1" and r["t_ttfb"] >= r["t_connect"] > 0
    assert len(r["series_mbps"]) == 1                     # whole seconds only
    assert ift.BUDGET.used >= r["bytes"]
    if sys.platform == "darwin" or sys.platform.startswith("linux"):
        assert r["tcp_rtt_ms"] is not None and r["tcp_rx_packets"] > 0 and r["tcp_mss"] > 0


def test_http_flow_complete_small_body(ift, server):
    r = ift.http_flow(server + "/small", 4, 5)
    assert r["curl_rc"] == 0 and r["bytes"] == 5000 and r["error"] == ""


def test_http_flow_follows_redirect(ift, server):
    r = ift.one_flow(server + "/redirect", 4, 1)
    assert r["http_code"] == "200" and r["bytes"] > 0 and r["error"] == ""


def test_http_flow_404_is_an_error(ift, server):
    r = ift.one_flow(server + "/missing", 4, 1)
    assert r["http_code"] == "404" and r["error"]
    assert ift.classify(r, 3.0) == "error"


def test_http_flow_binds_requested_port(ift, server):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = ift.http_flow(server + "/small", 4, 5, local_port=port)
    assert r["local_port"] == port and r["requested_port"] == port


def test_http_flow_connection_refused(ift):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = ift.http_flow(f"http://127.0.0.1:{port}/big", 4, 2)
    assert r["curl_rc"] == 7 and r["error"]


def test_budget_stops_transfers(ift, server):
    ift.BUDGET.limit = 1
    ift.BUDGET.add(2)
    with pytest.raises(ift.BudgetExceeded):
        ift.http_flow(server + "/big", 4, 1)


# ---------------------------------------------------------------- captures

def synthetic_capture(path):
    """A download with a lost segment (a hole), its late arrival, and a retransmission."""
    scapy = pytest.importorskip("scapy.all")
    IP, TCP, Ether = scapy.IP, scapy.TCP, scapy.Ether
    c, s, cp, sp, L = "192.0.2.2", "198.51.100.2", 41000, 80, 1000
    pk, t = [], [1.0]

    def add(p, dt=0.001):
        t[0] += dt
        frame = Ether() / p
        frame.time = t[0]            # set on the composed frame: Ether()/p takes its own creation time
        pk.append(frame)

    add(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="S", seq=100))
    add(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="SA", seq=1000, ack=101))
    add(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=101, ack=1001))
    seg = [1001 + i * L for i in range(8)]
    for i in (0, 1, 3, 4):
        add(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seg[i], ack=101) / (b"x" * L))
        add(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=101, ack=seg[i] + L if i < 2 else seg[2]))
    add(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seg[2], ack=101) / (b"x" * L))
    add(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=101, ack=seg[5]))
    add(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seg[5], ack=101) / (b"x" * L))
    add(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seg[5], ack=101) / (b"x" * L), dt=0.3)
    scapy.wrpcap(path, pk)
    return cp


def test_analyse_pcap_counts_holes_and_retransmits(ift, tmp_path):
    p = str(tmp_path / "t.pcap")
    port = synthetic_capture(p)
    a = ift.analyse_pcap(p, port)
    assert a["holes"] >= 1 and a["retransmits"] >= 1 and a["server_segments"] >= 6
    assert a["longest_gap_ms"] >= 250


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
def test_tshark_cross_check(ift, tmp_path):
    p = str(tmp_path / "t.pcap")
    port = synthetic_capture(p)
    r = ift.tshark_analyse(p, port)
    assert "error" not in r, r
    assert r["data_segments"] >= 6 and r["retransmission"] >= 1 and r["lost_segment"] >= 1


# ---------------------------------------------------------------- report pipeline

def write_phase(d, ift):
    pdir = d / "isp-wired"
    pdir.mkdir(parents=True)
    targets = [("srv", "http://192.0.2.10/f", None, "test", "behind the split"),
               ("ctl", "http://192.0.2.20/f", None, "control", "control")]
    meta = {"phase": "isp-wired", "title": "Directly on the ISP router, wired", "short": "ISP wired",
            "started": "2026-01-01T00:00:00+00:00", "finished": "2026-01-01T00:10:00+00:00",
            "env": {"public_v4": {"ip": "192.0.2.99", "org": "AS64500 Example ISP"}}, "families": [4],
            "rounds": 8, "seconds": 2, "slow_mbps": 3.0, "script_version": ift.VERSION,
            "targets": [list(t) for t in targets], "port_test_target": "srv", "ix_source": "built-in list",
            "bytes_moved": 123}
    (pdir / "meta.json").write_text(json.dumps(meta))
    rows = []
    for r in range(1, 9):
        slow = r % 2 == 0
        rows.append(dict(test="throughput", round=r, target="srv", role="test", family=4, class_="slow" if slow else "fast",
                         mbps=0.9 if slow else 900, tcp_rtt_ms=14 if slow else 1))
        rows.append(dict(test="throughput", round=r, target="ctl", role="control", family=4, class_="fast",
                         mbps=950, tcp_rtt_ms=1))
    for rep in (1, 2, 3):
        for port, slow in ((50001, True), (50002, False), (50003, True), (50004, False), (50005, True),
                           (50006, False)):
            rows.append(dict(test="fixed-port", round=rep, target="srv", role="test", family=4,
                             requested_port=port, class_="slow" if slow else "fast", mbps=0.9 if slow else 900))
    with open(pdir / "flows.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ift.FLOW_FIELDS)
        w.writeheader()
        for r in rows:
            r["class"] = r.pop("class_")
            r.update(phase="isp-wired", bytes=1, http_code="200", curl_rc=28, error="", time="t")
            w.writerow({k: r.get(k, "") for k in ift.FLOW_FIELDS})
    (pdir / "traceroutes.json").write_text(json.dumps({
        "srv/v4": {"hops": [{"hop": 1, "ip": "192.0.2.1"}, {"hop": 2, "ip": "203.0.113.5"},
                            {"hop": 3, "ip": "192.0.2.10"}]},
        "ctl/v4": {"hops": [{"hop": 1, "ip": "192.0.2.1"}, {"hop": 2, "ip": "203.0.113.6"},
                            {"hop": 3, "ip": "192.0.2.20"}]}}))
    return pdir


def test_build_report_end_to_end(ift, tmp_path):
    out = tmp_path / "flow-report-test"
    write_phase(out, ift)
    zpath = ift.build_report(str(out), argparse.Namespace(ref="T-1", name="Tester"))
    assert zpath and os.path.exists(zpath)
    with zipfile.ZipFile(zpath) as z:
        assert z.testzip() is None
        names = z.namelist()
    assert "flow-report-test/report.html" in names and "flow-report-test/isp-wired/flows.csv" in names
    summary = (out / "summary.txt").read_text()
    assert "STICKS" in summary
    assert "control destination was slow in 0 of 8" in summary
    assert "14 vs 1.0 ms" in summary                          # kernel TCP statistics line
    assert "Routers on EVERY bad route" in summary and "203.0.113.5" in summary
    html = (out / "report.html").read_text()
    assert "<h2>Kernel TCP statistics</h2>" in html and "Load-balanced paths (MDA)" in html
    assert "Re: ref T-1" in (out / "message.txt").read_text()


def test_cli_help_and_report_only(tmp_path):
    r = subprocess.run([sys.executable, SCRIPT, "--help"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "--max-gb" in r.stdout and "--targets-file" in r.stdout
    r = subprocess.run([sys.executable, SCRIPT, "--report-only", str(tmp_path)], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0 and "No completed phases" in r.stdout


def test_report_surfaces_mda_failures_and_fallbacks(ift, tmp_path):
    out = tmp_path / "flow-report-mda"
    pdir = write_phase(out, ift)
    (pdir / "mda.json").write_text(json.dumps({"method": "tcp-sport", "results": [
        {"target": "srv", "family": 4, "ip": "192.0.2.10", "dport": 80,
         "error": "dlhdr_ethcb: did not get mac address for 192.0.2.1; udp-dport fallback: no route"},
        {"target": "ctl", "family": 4, "ip": "192.0.2.20", "dport": 80, "method": "udp-dport",
         "fallback_from": {"method": "tcp-sport", "error": "dlhdr_ethcb: did not get mac address"},
         "hops": [{"ttl": 1, "addrs": [{"addr": "192.0.2.1", "flows": 6}]}], "lb_hops": [], "width": 1}]}))
    ift.build_report(str(out), argparse.Namespace(ref="", name="Tester"))
    summary = (out / "summary.txt").read_text()
    assert "1 of 2 trace(s) failed" in summary and "did not get mac address" in summary
    assert "used udp-dport probes" in summary
    assert "(via udp-dport: tcp-sport failed)" in (out / "report.html").read_text()


def test_report_only_repairs_silent_mda_failures_from_3_2_0(ift, tmp_path):
    out = tmp_path / "flow-report-old"
    pdir = write_phase(out, ift)
    (pdir / "mda").mkdir()
    (pdir / "mda" / "srv-v4.json").write_text(json.dumps(
        {"type": "tracelb", "method": "tcp-sport", "probec": 0, "errmsg": "dlhdr_ethcb: did not get mac address"}))
    (pdir / "mda.json").write_text(json.dumps({"method": "tcp-sport", "results": [
        {"target": "srv", "family": 4, "ip": "192.0.2.10", "dport": 80, "dst": "192.0.2.10", "hops": [],
         "lb_hops": [], "width": 1, "file": "mda/srv-v4.json"}]}))
    ift.build_report(str(out), argparse.Namespace(ref="", name="Tester"))
    assert "1 of 1 trace(s) failed" in (out / "summary.txt").read_text()
