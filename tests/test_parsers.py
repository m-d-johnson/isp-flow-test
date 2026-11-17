"""Pure functions: parsers, structs, statistics. No network, no privileges."""
import json
import os
import struct

import pytest

from conftest import FIXTURES

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:      # hypothesis is a test-only extra
    given = None


# ---------------------------------------------------------------- traceroute output

MACOS_TRACE = """traceroute to 198.51.100.7 (198.51.100.7), 18 hops max, 40 byte packets
 1  192.0.2.1  0.512 ms  0.401 ms  0.390 ms
 2  * * *
 3  203.0.113.9  5.1 ms 203.0.113.10  5.3 ms  5.2 ms
 4  198.51.100.7  9.9 ms  9.8 ms  9.7 ms
"""


def test_parse_traceroute_keeps_parallel_addresses(ift):
    hops = ift.parse_traceroute(MACOS_TRACE)
    assert [h["hop"] for h in hops] == [1, 2, 3, 4]
    assert hops[1]["ip"] is None and hops[1]["ips"] == []
    assert hops[2]["ips"] == ["203.0.113.9", "203.0.113.10"]
    assert hops[0]["rtt_ms"] == pytest.approx(0.512)


def test_parse_traceroute_ipv6(ift):
    hops = ift.parse_traceroute(" 1  2001:db8::1  1.0 ms  1.1 ms  1.2 ms\n")
    assert hops[0]["ip"] == "2001:db8::1"


# ---------------------------------------------------------------- kernel TCP structs

def test_macos_tcp_connection_info(ift):
    raw = ift._TCPCI.pack(4, 6, 6, 0, 0b11, 0b10, 210, 1440, 0, 0, 0, 0, 131072, 30, 28, 9, 0,
                          10, 1000, 0, 2000, 2_880_000, 28_800, 0)
    assert len(raw) == 112
    d = ift.parse_tcp_connection_info(raw)
    assert d["tcp_rtt_ms"] == 28 and d["tcp_rttvar_ms"] == 9 and d["tcp_mss"] == 1440
    assert d["tcp_rx_packets"] == 2000 and d["tcp_ooo_pct"] == pytest.approx(1.0)
    assert d["tcp_sack"] is True and d["tcp_reordering_detected"] is True
    assert ift.parse_tcp_connection_info(raw[:100]) == {}


def linux_tcp_info(ift, **fields):
    names = [n for n, _ in ift._TCPI_SPEC]
    return ift._TCPI.pack(*[fields.get(n, 0) for n in names])


def test_linux_tcp_info_full(ift):
    raw = linux_tcp_info(ift, rtt=50, rcv_rtt=14_000, rttvar=20, rcv_mss=1448, bytes_received=10**6,
                         min_rtt=900, data_segs_in=1000, rcv_ooopack=25, reord_seen=3)
    assert len(raw) == 232
    d = ift.parse_tcp_info_linux(raw)
    assert d["tcp_rtt_ms"] == 14.0          # the receiver's estimate wins over tcpi_rtt on a download
    assert d["tcp_srtt_ms"] == 0.05
    assert d["tcp_min_rtt_ms"] == 0.9 and d["tcp_rx_packets"] == 1000
    assert d["tcp_ooo_pct"] == pytest.approx(2.5)


def test_linux_tcp_info_older_kernel_is_truncated(ift):
    raw = linux_tcp_info(ift, rtt=50_000, bytes_received=10**6, rcv_ooopack=99)[:136]   # ~4.x kernel
    d = ift.parse_tcp_info_linux(raw)
    assert d["tcp_rtt_ms"] == 50.0 and d["tcp_rx_bytes"] == 10**6
    assert "tcp_ooo_pct" not in d and "tcp_min_rtt_ms" not in d
    assert ift.parse_tcp_info_linux(raw[:50]) == {}


# ---------------------------------------------------------------- tshark field output

def test_parse_tshark_fields(ift):
    # dstport,len,retransmission,fast_retransmission,spurious,out_of_order,lost_segment,duplicate_ack
    out = "\n".join([
        "41000,1000,,,,,,",
        "41000,1000,,,,,1,",
        "80,0,,,,,,1",
        "41000,1000,1,1,,,,",
        "41000,1000,,,,1,,",
        "41000,0,,,,,,",          # pure ACK from the server: not a data segment
        "bad line",
    ])
    r = ift.parse_tshark_fields(out, 41000)
    assert r["data_segments"] == 4
    assert r["retransmission"] == 1 and r["fast_retransmission"] == 1
    assert r["out_of_order"] == 1 and r["lost_segment"] == 1 and r["dup_acks"] == 1
    assert r["retrans_pct"] == 25.0


# ---------------------------------------------------------------- scamper tracelb

@pytest.mark.parametrize("name, lb", [("tracelb-tcp-sport.json", [2, 3]), ("tracelb-icmp-echo.json", [])])
def test_parse_tracelb(ift, name, lb):
    with open(os.path.join(FIXTURES, name)) as fh:
        r = ift.parse_tracelb(json.load(fh))
    assert r["dst"] == "10.0.9.2"
    assert r["lb_hops"] == lb
    if lb:
        hop2 = next(h for h in r["hops"] if h["ttl"] == 2)
        assert {a["addr"] for a in hop2["addrs"]} == {"10.0.2.2", "10.0.3.2"}
        assert r["width"] == 2
    assert r["hops"][0]["addrs"][0]["addr"] == "10.0.1.1"      # the first hop, never itself a probe reply


# ---------------------------------------------------------------- statistics

def brute_tail(probs, k):
    from itertools import product
    total = 0.0
    for outcome in product((0, 1), repeat=len(probs)):
        if sum(outcome) >= k:
            p = 1.0
            for o, q in zip(outcome, probs):
                p *= q if o else 1 - q
            total += p
    return total


def test_poisson_binomial_tail_matches_brute_force(ift):
    probs = [0.25, 0.5, 0.125, 0.9, 0.3]
    for k in range(len(probs) + 1):
        assert ift.poisson_binomial_tail(probs, k) == pytest.approx(brute_tail(probs, k))


if given is not None:
    @settings(max_examples=60, deadline=None)
    @given(st.lists(st.floats(0, 1), min_size=0, max_size=8), st.integers(0, 9))
    def test_poisson_binomial_tail_property(probs, k):
        from conftest import load_script
        ift = load_script()
        assert ift.poisson_binomial_tail(probs, k) == pytest.approx(brute_tail(probs, k), abs=1e-9)


def port_rows(pattern):
    """pattern: {port: "SSF"...} -> fixed-port rows for IPv4."""
    rows = []
    for port, outcomes in pattern.items():
        for c in outcomes:
            rows.append({"family": 4, "requested_port": port, "class": {"S": "slow", "F": "fast", "E": "error"}[c]})
    return rows


def test_port_test_detects_sticky_ports(ift):
    a = ift.port_test_analysis(port_rows({1: "SSS", 2: "FFF", 3: "SSS", 4: "FFF", 5: "SSS", 6: "FFF",
                                          7: "SSS", 8: "FFF"}))[4]
    assert a["consistent"] == 8 and a["p_value"] < 0.01 and "STICKS" in a["verdict"]


def test_port_test_random_outcomes_are_not_sticky(ift):
    a = ift.port_test_analysis(port_rows({1: "SFS", 2: "FSF", 3: "SFF", 4: "FFS", 5: "SSF", 6: "FSS"}))[4]
    assert a["consistent"] == 0 and "does NOT" in a["verdict"]


def test_port_test_inconclusive_when_all_fast(ift):
    a = ift.port_test_analysis(port_rows({1: "FFF", 2: "FFF"}))[4]
    assert "inconclusive" in a["verdict"]


# ---------------------------------------------------------------- routes and the ISP's own networks

def trace(*asns):
    return {"hops": [{"hop": i + 1, "ip": f"192.0.2.{i + 1}", "asn": a, "as_name": f"NET{a}, XX"}
                     for i, a in enumerate(asns)]}


def test_home_asns_adds_backbone_seen_on_every_route(ift):
    ift._ISP_ASN["asn"] = "64500"
    traces = {"a/v6": trace("64500", "64501", "65001"), "b/v6": trace("64500", "64501", "65002"),
              "c/v6": trace("64500", "64501", "65003"), "d/v4": trace("65001")}
    assert ift.home_asns(traces) == {"64500", "64501"}
    assert ift.path_label(traces["a/v6"], traces).endswith("first external network NET65001")
    assert ift.path_label(traces["d/v4"], traces).endswith("first external network NET65001")


def test_home_asns_stops_where_routes_diverge(ift):
    ift._ISP_ASN["asn"] = "64500"
    traces = {"a": trace("64500", "65001"), "b": trace("64500", "65002")}
    assert ift.home_asns(traces) == {"64500"}


def test_path_label_names_exchange_and_member(ift):
    tr = {"hops": [{"hop": 1, "ip": "192.0.2.1"}], "via_ix": "LINX LON1", "via_ix_member": "AS64511 Example"}
    assert ift.path_label(tr) == "public peering at LINX LON1, handed to AS64511 Example"


def test_ix_name_uses_table(ift):
    import ipaddress
    ift.IX_TABLE["nets"] = [("Example IX", ipaddress.ip_network("198.51.100.0/24"))]
    assert ift.ix_name("198.51.100.20") == "Example IX"
    assert ift.ix_name("192.0.2.1") is None and ift.ix_name("not-an-ip") is None


# ---------------------------------------------------------------- targets

def test_trace_owner_shares_a_host(ift):
    ift.TARGETS[:] = [("a-http", "http://h.example/x", None, "test", ""),
                      ("a-https", "https://h.example/x", None, "test", ""),
                      ("b", "http://other.example/x", None, "probe", "")]
    assert ift.trace_owner("a-https", 4) == "a-http"
    assert ift.trace_key("b", 4) == "b/v4"


def test_load_targets_file(ift, tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"targets": [{"name": "x", "url4": "http://192.0.2.1/f", "role": "test"},
                                         {"name": "c", "url6": "http://[2001:db8::1]/f", "role": "control"}]}))
    targets, port = ift.load_targets_file(str(p))
    assert port == "x" and targets[1] == ("c", None, "http://[2001:db8::1]/f", "control", "")


@pytest.mark.parametrize("body", [
    {"targets": [{"name": "c", "url4": "http://192.0.2.1/f", "role": "control"}]},       # no test target
    {"targets": [{"name": "x", "url4": "http://192.0.2.1/f", "role": "bogus"}]},
    {"targets": [{"name": "x", "role": "test"}]},                                       # no URL
    {"targets": [{"name": "x", "url4": "http://192.0.2.1/f"}], "port_test_target": "y"},
])
def test_load_targets_file_rejects(ift, tmp_path, body):
    p = tmp_path / "t.json"
    p.write_text(json.dumps(body))
    with pytest.raises(ValueError):
        ift.load_targets_file(str(p))


# ---------------------------------------------------------------- data budget

def test_budget(ift):
    ift.BUDGET.limit = 1000
    ift.BUDGET.add(600)
    ift.BUDGET.check()
    ift.BUDGET.add(500)
    with pytest.raises(ift.BudgetExceeded):
        ift.BUDGET.check()
    assert ift.BUDGET.label() == "0.0 GB of 1e-06"


def test_struct_sizes(ift):
    assert ift._TCPCI.size == 112 and ift._TCPI.size == 232
    assert struct.calcsize("<4B13I7Q") == 112
