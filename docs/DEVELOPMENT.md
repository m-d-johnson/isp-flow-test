# Developer guide

How `isp-flow-test.py` is put together, what it writes, and how to change, test and release it.

## Design constraints

- **One file.** Users download one script and run it. Keep it that way: no package, no build
  step. `pyproject.toml` holds tool configuration only.
- **PEP 723 inline metadata.** The header declares `requires-python` and the dependencies, so
  `uv run isp-flow-test.py` gets a working environment with no setup. Rich (display), scapy (path
  probes) and truststore/certifi (TLS trust) are all optional at runtime: a missing one degrades
  the run and never stops it.
- **Python 3.9+.** No `match`, no runtime `X | Y` unions, and none of the relaxed f-string
  grammar of 3.12: no backslashes and no reused quote characters inside an f-string's `{…}`. CI
  runs the tests on 3.9 to catch these.
- **The output folder is the interface.** Every measurement goes to disk as it's taken. The
  report is a pure function of the folder (`--report-only`), so an interrupted run still produces
  a report, and analysis changes can be tested against saved runs without the network.
- **Unprivileged by default.** The main process never runs as root. `tcpdump`, the scapy probe
  child and `scamper` are started through `sudo -n` after one up-front `sudo -v`, or directly
  when already root (as in the lab).
- **Optional tools are discovered, never assumed.** tshark, scamper and iperf3 are looked up
  with `shutil.which`; the run says which it found.

## Code map

The file is in sections, top to bottom:

| Section | Key names | Purpose |
|---|---|---|
| Configuration | `TARGETS`, `PORT_TEST_TARGET`, `IX_PREFIXES`, `IX_TABLE`, `IPERF_SERVERS`, `PHASES`, `FLOW_FIELDS` | Defaults a user might tune |
| Helpers | `run`, `Budget` / `BUDGET`, `UI`, `say`, `hr`, `phase_seconds` | Subprocesses, the `--max-gb` budget, terminal output, time estimate |
| Environment | `default_route`, `hardware_ports`, `iface_media`, `wifi_info`, `public_ip`, `detect_env`, `check_env`, `wait_for_network` | Where the machine is connected, and whether it's the phase it claims to be |
| Path lookups | `rdns`, `asn_lookup`, `traceroute`, `parse_traceroute`, `load_ix_table`, `ix_name`, `ix_member`, `home_asns`, `path_label`, `ping` | Hop names, origin AS, exchanges, the ISP's own AS numbers |
| HTTP client | `tls_context`, `http_get_json`, `http_flow`, `one_flow`, `classify` | One download on a socket we own |
| Kernel TCP stats | `tcp_stats`, `parse_tcp_connection_info`, `parse_tcp_info_linux` | The OS's own per-connection counters |
| Packet capture | `Capture`, `capture_flow`, `read_pcap`, `analyse_pcap`, `tshark_analyse`, `pcap_test` | Privileged capture, a stdlib pcap reader, tshark cross-check |
| Long connections | `long_flow`, `long_test` | Per-second throughput |
| Parallel streams | `iperf_servers`, `iperf_one`, `iperf_test` | iperf3 JSON, per-stream classification |
| Per-flow probes | `flowtrace_worker`, `flowtrace_test`, `flowtrace_analysis` | Paris-traceroute probes from chosen source ports |
| MDA | `parse_tracelb`, `run_tracelb`, `mda_test` | scamper's load-balancer enumeration |
| One phase | `run_phase`, `_run_phase_tests` | Prompt, check and measure for one vantage point |
| Analysis | `load_phase`, `stats_for`, `poisson_binomial_tail`, `port_test_analysis`, `analyse`, `route_map` | A results folder in, findings out |
| Report | `summary_table`, `svg_*`, `html_report`, `message_text`, `README`, `build_report` | Render and zip |
| Entry point | `load_targets_file`, `choose_phases`, `main` | Arguments, phase selection, the hidden `--_flowtrace` child mode |

## Run flow

```
main
 ├─ parse args, --quick, --max-gb, --targets-file, --targets
 ├─ load_ix_table                 PeeringDB exchange prefixes (daily cache, fallbacks)
 ├─ choose_phases                 interactive menu, or --phases
 ├─ Capture(...)                  raw-packet access: root, sudo -n, or one sudo prompt
 ├─ for each phase in PHASE_ORDER:
 │    run_phase
 │     ├─ prompt the user to move the machine; wait_for_network (TCP to a target)
 │     ├─ detect_env → check_env  fatal problems block (retry / run anyway / skip)
 │     └─ _run_phase_tests
 │          ├─ forward DNS for every target
 │          ├─ traceroutes + pings              (6 threads in parallel)
 │          ├─ throughput: rounds × targets     (strictly sequential)
 │          ├─ fixed-source-port test           (same file: flows.csv)
 │          ├─ per-flow probes                  (needs the port test's results)
 │          ├─ MDA traceroute                   (most-affected destinations + controls, 3 at a time)
 │          ├─ packet captures (+ tshark)
 │          ├─ long connections
 │          └─ iperf3                           (also traceroutes each server)
 └─ build_report                  always runs, including after Ctrl-C or the budget running out
      ├─ load_phase × n → analyse → html / summary / message / README
      └─ zip, then reopen it and testzip() to prove it's readable
```

Throughput connections run **one at a time** on purpose. Parallel connections would compete for
the line and blur the fast/slow split the tool depends on. Traceroutes, pings and MDA run in
parallel because they carry almost no traffic.

## The HTTP client

`http_flow` makes each download itself instead of running curl, for one reason: it needs the
socket afterwards to read the kernel's TCP statistics. It:

- resolves for the requested family only, and binds a fixed source port when asked
  (`SO_REUSEADDR`; a 4-tuple still in TIME_WAIT gives code 45 and `one_flow` retries after
  15 s);
- follows up to five redirects, each on a fresh connection, measuring only the last;
- sends a minimal HTTP/1.1 `GET` with `Connection: close` and no `Accept-Encoding`, so the body
  arrives as-is;
- reads into a reused 1 MiB buffer with `recv_into` until the body ends or `seconds` (total, as
  curl's `--max-time`) runs out;
- counts throughput as body bytes over the time since the first response byte, as before;
- returns curl-compatible exit codes (0, 28, 6, 7, 35, 45, 47, 56), so saved results and the
  analysis didn't need to change.

TLS uses `tls_context`: truststore (the OS trust store, Python 3.10+), then certifi, then the
default context. A uv-managed Python on macOS fails verification with the default context alone.

## Kernel TCP statistics

`tcp_stats` reads the socket just before it closes:

- **macOS:** `getsockopt(IPPROTO_TCP, TCP_CONNECTION_INFO = 0x106)`, `struct tcp_connection_info`
  from `<netinet/tcp.h>`, 112 bytes, unpacked as `<4B13I7Q`. Python doesn't export the constant
  or the layout. The struct has a bit-field word, which is why the layout is hand-written; check
  it against the SDK header if Apple changes it.
- **Linux:** `TCP_INFO`, `struct tcp_info` from `<linux/tcp.h>` up to `tcpi_snd_wnd` (232
  bytes), described field by field in `_TCPI_SPEC`. Older kernels return a shorter struct;
  `_TCPI_END` records where each field ends, so fields beyond the returned length are left out
  rather than read as zero.

What's recorded in `flows.csv`:

| Column | macOS | Linux |
|---|---|---|
| `tcp_rtt_ms` | `tcpi_srtt` | `tcpi_rcv_rtt`, falling back to `tcpi_rtt` |
| `tcp_rttvar_ms` | `tcpi_rttvar` | `tcpi_rttvar` |
| `tcp_min_rtt_ms` | — | `tcpi_min_rtt` |
| `tcp_ooo_pct` | `rxoutoforderbytes / rxbytes` | `rcv_ooopack / data_segs_in` (5.4+) |
| `tcp_rx_packets`, `tcp_mss` | `rxpackets`, `maxseg` | `data_segs_in`, `rcv_mss` |

On a download we're the receiver, and Linux's `tcpi_rtt` measures only our own ACK-only sends,
so it barely moves. `tcpi_rcv_rtt` is the receiver's estimate and is the one that shows queueing
on the data path. In the lab, slow connections read 10–15 ms and fast ones about 0.9 ms with
`rcv_rtt`, while `rtt` read about 0.02 ms for both.

## PeeringDB

`load_ix_table` fetches three tables anonymously (`ix`, `ixlan`, `ixpfx`, about 2.3 MB in all)
and joins them into `(exchange name, prefix)` pairs. The result is cached for a day in
`~/.cache/isp-flow-test/peeringdb-ix.json` (`$XDG_CACHE_HOME` respected). If a fetch fails it
falls back to a stale cache, then to the built-in `IX_PREFIXES`. The source is recorded in each
phase's `meta.json` and shown in the report.

For each traceroute hop on a peering LAN, `ix_member` asks `netixlan` which network owns that
address, then `net` for its name, so a route reads "public peering at LINX LON1: Main, handed to
AS… Name". Lookups are cached per run. `PEERINGDB_API_KEY`, if set, is sent as
`Authorization: Api-Key …`.

## The fixed-source-port test

`port_test_analysis` asks: do outcomes stick to source ports more than chance allows?

1. `p` = the share of slow connections in the test.
2. For a port tried `n` times, the chance all `n` outcomes match by luck is `pⁿ + (1−p)ⁿ`.
3. Ports differ in `n`, because errors are dropped, so the count of consistent ports follows a
   Poisson-binomial distribution; `poisson_binomial_tail` computes its exact upper tail.
4. A p-value below 0.05, with more consistent ports than expected, means "sticks to the port".

Ports come from an RNG seeded with the results path and phase, so `--resume` reproduces them.

## Per-flow path probes

`flowtrace_test` picks up to `--flowtrace-ports` consistently slow and consistently fast ports
from the fixed-port results. It writes a spec file and re-runs the script as a child,
`sudo -n <python> isp-flow-test.py --_flowtrace <spec>`, which is `flowtrace_worker`: it needs
raw sockets, so it runs as root, does nothing else, and prints JSON. `sys.executable` keeps the
same environment (scapy included) under `uv run`.

Each probe is a TCP SYN from the chosen source port to the real destination and port, one per
TTL, so routers hash the probes exactly as they hashed the real connection. The TTL is encoded
in the sequence number (`FT_BASE_SEQ + ttl`). ICMP time-exceeded messages quote it back, and the
destination's SYN-ACK acknowledges `seq + 1`, so replies match without per-probe state. Each port
is probed twice. `flowtrace_analysis` reports the first hop where the slow-port and fast-port
address sets don't overlap.

## MDA traceroute

`mda_test` runs `scamper -O json -c "tracelb -P <method> -d <port> -q 1 -w 1" -i <ip>` per
destination, three at a time, as root:

- **Destinations:** every control, then the most-affected targets first (by slow share in this
  phase), up to `--mda-max` per family.
- **Method:** the default `tcp-sport` varies the TCP source port, like real connections.

`parse_tracelb` does not rely on scamper's node and link grouping, which differs between versions
and probe methods. Ubuntu's 2021 build, for example, groups UDP and TCP probes differently from
ICMP. Instead it walks the whole result and collects every answered probe's TTL and flow id under
the address that answered it. That gives "TTL → addresses, and how many probe flows reached each",
which is all the analysis needs.

The raw scamper JSON is kept in `<phase>/mda/` for engineers who want the full detail.
`analyse` cross-references load-balanced hops with the route-map suspects and the per-flow
probes' slow path.

## tshark

`tshark_analyse` runs `tshark -T fields` over each kept capture, for the server's data segments
and our duplicate ACKs, reading these flags (each prints as `1` when set):
`tcp.analysis.retransmission`, `fast_retransmission`, `spurious_retransmission`,
`out_of_order` and `lost_segment`.

`retransmission` is also set on fast and spurious retransmissions. `lost_segment` marks
segments the capture itself missed: it's common on fast flows, where tcpdump can't keep up, and
isn't loss on the network.

The point is the one thing `analyse_pcap` can't do: tell resent data from reordered data. On a
real 10 Gb/s line, captures that `analyse_pcap` scored as 4% "retransmitted or out of order"
split into 1.2% retransmissions and 2.8% reordering.

## Route map

`route_map` runs per phase and family:

1. Classify each traced destination from its throughput: **bad** if ≥15 % of connections were
   slow, **good** if ≤5 %, **mixed** otherwise.
2. Build a graph from every responding address at every hop, including the extra addresses that
   3 probes per hop can reveal on ECMP routers.
3. Score each router by the destinations through it.
4. **Suspects** are routers seen only on bad routes. **On every bad** are routers common to all
   bad routes and no good one.
5. Destination servers are excluded: they're endpoints, not suspects.

Targets on the same host share one traceroute (`trace_owner`).

## The ISP's own networks

`home_asns` starts from the AS of the public IPv4 address (ipinfo's `org`, stored via
`note_isp_asn`). It then adds any AS that every route starting inside the ISP passes into next,
which covers an access AS plus a group backbone AS. Hops without a public AS are skipped.
`path_label` names the first AS outside that set.

## Data budget

`BUDGET` counts every byte the tests move: `http_flow` (throughput, fixed-port, capture and
long-connection downloads) and `iperf_one` (the larger of bytes sent and received).

- **Checks:** each transfer calls `BUDGET.check()` before starting. `capture_flow` checks before
  starting tcpdump, and `run_phase` checks before prompting for the next vantage point.
- **When the limit is reached:** `check()` raises `BudgetExceeded`. `run_phase` records
  `meta["stopped"]`, and `main` catches it like Ctrl-C and builds the report.
- **Overshoot:** a transfer already running isn't interrupted, so a run can go over by one
  transfer.

## Results folder format

```
flow-report-<YYYYMMDD-HHMMSS>/
  <phase-id>/
    meta.json          phase, title, short, started, finished, env{…}, families, rounds, seconds,
                       slow_mbps, script_version, dns{host: {A, AAAA}}, port_test_ports{…},
                       targets[[name, url4, url6, role, note]], port_test_target, ix_source,
                       bytes_moved, stopped (only when --max-gb cut the phase short)
    flows.csv          one row per connection; columns = FLOW_FIELDS
    traceroutes.json   {"<target>/v<fam>" | "iperf:<host>/v<fam>": {raw, hops[], via_ix, via_ix_member}}
    pings.json         {"<target>/v<fam>": {sent, received, loss_pct, rtt_min/avg/max, raw}}
    pcap.json          {flows: [{class, mbps, packets, retransmits, retransmit_pct, holes, dup_acks,
                                 sack_acks, zero_window, longest_gap_ms, tshark{…}, …}]}
    pcap/*.pcap        v<fam>-port<local port>-<class>.pcap
    long.json          [{target, family, mbps, series_mbps[], curl_rc, error, tcp_*, …}]
    iperf.json         [{host, family, direction, total_mbps, retransmits, streams[…], …}]
    flowtrace.json     {probes: [{family, sport, dport, dst, class, rep, hops[{ip, reached, rtt_ms}]}]}
    mda.json           {method, results: [{target, family, ip, dport, hops[{ttl, addrs[{addr, flows}]}],
                                           lb_hops[], width, file}]}
    mda/*.json         raw scamper tracelb output
```

`flows.csv` columns: `phase, test, round, target, role, family, requested_port, class, mbps,
bytes, http_code, remote_ip, local_port, t_connect, t_tls, t_ttfb, t_total, curl_rc, error,
time, tcp_rtt_ms, tcp_rttvar_ms, tcp_min_rtt_ms, tcp_ooo_pct, tcp_rx_packets, tcp_mss`.

`--report-only` uses the targets recorded in `meta.json`, so a run made with `--targets-file`
rebuilds correctly without it. New fields have only ever been added; keep it that way, or bump
the major version.

## Extending

### Targets

Pass `--targets-file` (format in the README), or edit `TARGETS`:

```python
("name", "https://ipv4-url" or None, "https://ipv6-url" or None, "test" | "control" | "probe", "note")
```

- **Size:** use a large file (≥1 GB), so a fast connection doesn't finish inside `--seconds`.
- **Stability:** use a stable URL. Release assets and speed-test files are good; anything
  versioned will eventually 404.
- **Controls** reach your line over a path you believe is healthy. They're always kept by
  `--targets` and always traced by MDA.

### Exchanges

PeeringDB covers them all. `IX_PREFIXES` is only the offline fallback.

### iperf3 servers

Add `(host, first_port, last_port, note)` to `IPERF_SERVERS`, or pass `--iperf-servers`.

### A new test

1. **Write it.** `<name>_test(families, args, …)` calls `ui.section(label, total)` once,
   `ui.tick(cls, detail)` per step, and returns a JSON-serialisable object. If it moves real
   data, call `BUDGET.check()` before each transfer and `BUDGET.add(bytes)` after.
2. **Run it** from `_run_phase_tests`, behind a `--no-<name>` switch, via `dump("<name>.json", …)`.
3. **Count it.** Add its steps to `run_phase` and its time to `phase_seconds`.
4. **Load it** in `load_phase`.
5. **Analyse it** in `analyse`. Lines must be conditional on evidence; never print a conclusion
   the data doesn't support.
6. **Report it.** Render it in `html_report`, describe its file in the pack's `README` string,
   and add a test.

## Terminal handling

Two lessons learned the hard way:

- **Always run children with `stdin=DEVNULL`.** macOS `sudo` uses `use_pty`. If it can see the
  terminal, it switches it to raw mode while its child runs, and Rich's live display then
  "staircases".
- **Save and restore the terminal.** `UI.tty_save` and `UI.tty_restore` snapshot termios settings
  and reapply them after each tick and at the end of a phase.

## Testing

Three layers, all under `tests/`:

| File | What | Needs |
|---|---|---|
| `test_parsers.py` | Traceroute, both TCP structs (including truncated Linux structs), tshark fields, scamper fixtures, the Poisson-binomial tail (against brute force, plus a hypothesis property test), the port test, AS and path labelling, targets files, the budget | nothing |
| `test_live.py` | `http_flow` against a local server: streaming, completion, redirects, 404, refused, fixed ports, the budget, **kernel TCP statistics on the OS running the test**. Plus synthetic captures through `analyse_pcap` and tshark, the report pipeline end to end, and the CLI | scapy; tshark optional |
| `test_lab.py` | The whole tool end to end in the ECMP lab | Linux, root, `ISP_FLOW_LAB=1` |

```sh
# everything except the lab
uv run --no-project --with pytest --with hypothesis --with scapy --with rich --with certifi \
    python -m pytest -m "not lab"

# the lab (Linux; also needs iproute2, traceroute, tcpdump, and scamper/tshark for those tests)
sudo ISP_FLOW_LAB=1 python -m pytest -m lab
```

### The ECMP lab

`tests/lab/ecmp-lab.sh up|down|exec` builds network namespaces:

```
                      ┌── ra ──┐
  cl ── r1 (ECMP, L4) ┤        ├── r2 ── srv  10.0.9.2  (test target, behind the split)
         │            └── rb ──┘
         └── ctl 10.0.8.2 (control, no split)
```

r1 and r2 hash each flow's 5-tuple onto `ra` or `rb`, and `rb`'s link back towards r1 is
rate-limited (tbf, 8 Mbit/s), like a faulty member. The test then requires the tool to find,
without being told:
- two speed modes and a clean control;
- outcomes that stick to the source port;
- higher kernel RTT on the slow connections;
- MDA's 2-way split at hop 2.

The lab hashes with `fib_multipath_hash_policy=3` and fields `0x0037`
(src/dst address, protocol, src/dst port). Policy 1 reuses a packet's existing socket hash when
it has one, and veth carries the sending host's random per-connection hash across, so a fixed
source port would land on a random member each time. Real routers hash headers, which policy 3
does.

## CI/CD

`.github/workflows/ci.yml` runs on pushes to `main`, pull requests, by hand, and as the first
stage of a release:

| Job | Runs |
|---|---|
| `lint` | `ruff check` (configuration in `pyproject.toml`) and `bash -n` on the lab script |
| `test` | `test_parsers` + `test_live` on Ubuntu and macOS × Python 3.9 and 3.13. The macOS jobs prove the `TCP_CONNECTION_INFO` layout on real macOS; Ubuntu installs tshark |
| `lab` | the ECMP lab as root on Ubuntu with scamper, tshark, traceroute and tcpdump; uploads the lab's report pack as an artifact |

`.github/workflows/release.yml` runs on a `v*` tag:

1. It runs the whole CI workflow.
2. It checks the tag matches `VERSION` in the script.
3. It publishes a GitHub release with `isp-flow-test.py` and its `.sha256` attached, with notes
   generated from the commits.

It uses the `gh` CLI and the workflow's own token, so no third-party release action is involved.

All actions are pinned to full commit SHAs, with the version in a comment. Dependabot
(`.github/dependabot.yml`) proposes updates weekly, grouped into one PR.

### Releasing

```sh
# bump VERSION in isp-flow-test.py, commit, push, wait for CI to go green, then:
git tag -a v3.2.0 -m v3.2.0
git push origin v3.2.0
```

`VERSION` is recorded in every `meta.json` and in the report footer, so you can tell which
version produced a given pack.
