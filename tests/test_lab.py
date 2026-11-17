"""End to end in a network-namespace lab with a real ECMP split and one rate-limited member
(tests/lab/ecmp-lab.sh). Proves the tool finds the fault it was built for. Linux, root, opt-in:

    sudo ISP_FLOW_LAB=1 python -m pytest -m lab
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, SCRIPT

LAB = os.path.join(ROOT, "tests", "lab", "ecmp-lab.sh")
OUT = os.environ.get("ISP_FLOW_LAB_OUT", "/tmp/isp-flow-lab")

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(os.environ.get("ISP_FLOW_LAB") != "1", reason="set ISP_FLOW_LAB=1 to run the lab"),
    pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0, reason="needs Linux and root"),
]


@pytest.fixture(scope="module")
def lab_run():
    subprocess.run(["bash", LAB, "up"], check=True, timeout=120)
    try:
        shutil.rmtree(OUT, ignore_errors=True)
        cmd = ["bash", LAB, "exec", sys.executable, SCRIPT, "--phases", "isp-wired", "--yes", "--force",
               "--targets-file", os.path.join(ROOT, "tests", "lab", "targets.json"),
               "--rounds", "10", "--seconds", "2", "--port-count", "6", "--port-reps", "3",
               "--no-iperf", "--long-count", "2", "--long-seconds", "4", "--pcap-flows", "4",
               "--pcap-seconds", "2", "--no-peeringdb", "--mda-max", "2", "--out-dir", OUT]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "lab-run.log"), "w") as fh:      # uploaded by CI for inspection
            fh.write(r.stdout + r.stderr)
        assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
        report = next(os.path.join(OUT, d) for d in sorted(os.listdir(OUT)) if d.startswith("flow-report-")
                      and os.path.isdir(os.path.join(OUT, d)))
        yield report
    finally:
        subprocess.run(["bash", LAB, "down"], timeout=120)


def read(report, name):
    with open(os.path.join(report, name)) as fh:
        return fh.read()


def test_two_modes_and_clean_control(lab_run):
    s = read(lab_run, "summary.txt")
    assert "two clearly separate modes" in s
    assert "control destination was slow in 0 of" in s


def test_fixed_port_sticks(lab_run):
    assert "outcome STICKS to the source port" in read(lab_run, "summary.txt")


def test_kernel_tcp_stats_show_the_slow_member_queueing(lab_run):
    import csv
    rows = list(csv.DictReader(open(os.path.join(lab_run, "isp-wired", "flows.csv"))))
    thr = [r for r in rows if r["test"] == "throughput" and r["target"] == "lab-ecmp" and r["tcp_rtt_ms"]]
    slow = sorted(float(r["tcp_rtt_ms"]) for r in thr if r["class"] == "slow")
    fast = sorted(float(r["tcp_rtt_ms"]) for r in thr if r["class"] == "fast")
    assert slow and fast and slow[len(slow) // 2] > 3 * fast[len(fast) // 2]


@pytest.mark.skipif(not shutil.which("scamper"), reason="scamper not installed")
def test_mda_finds_the_split(lab_run):
    mda = json.loads(read(lab_run, os.path.join("isp-wired", "mda.json")))
    ecmp = next(m for m in mda["results"] if m["target"] == "lab-ecmp")
    hop2 = next(h for h in ecmp["hops"] if h["ttl"] == 2)
    assert {a["addr"] for a in hop2["addrs"]} == {"10.0.2.2", "10.0.3.2"}
    ctl = next(m for m in mda["results"] if m["target"] == "lab-control")
    assert ctl["lb_hops"] == []


def test_pack_is_complete(lab_run):
    import zipfile
    z = lab_run.rstrip("/") + ".zip"
    with zipfile.ZipFile(z) as f:
        assert f.testzip() is None
    for name in ("report.html", "summary.txt", "message.txt", "README.txt"):
        assert os.path.getsize(os.path.join(lab_run, name)) > 0
