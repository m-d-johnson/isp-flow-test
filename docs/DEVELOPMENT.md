# Developer guide

How `isp-flow-test.py` is put together, what it writes, and how to change it safely.

## Design constraints

- **One file.** Users download one script and run it. Keep it that way: no package, no
  config files, no build step.
- **PEP 723 inline metadata.** The header declares `requires-python` and the two optional
  dependencies, so `uv run isp-flow-test.py` gets a working environment with no setup.
- **Runs without uv too.** Everything except the progress display (Rich) and the per-flow
  probes (scapy) uses the standard library plus the system's own network tools. Missing
  optional pieces degrade the run; they never stop it.
- **Python 3.9+.** That rules out `match`, `X | Y` type unions at runtime, and the relaxed
  f-string grammar of 3.12. In particular, no backslashes and no reused quote characters inside
  an f-string's `{…}` before 3.12; precompute the value instead.
- **The output folder is the interface.** Every measurement goes to disk as it's taken. The
  report is a pure function of the folder (`--report-only`), so an interrupted run still
  produces a report, and analysis changes can be checked against saved runs without touching
  the network.
- **Unprivileged by default.** The main process never runs as root. Only `tcpdump` and the
  scapy probe child are started through `sudo -n`, after one up-front `sudo -v`.

## Code map

The file is in sections, top to bottom:

| Section | Key names | Purpose |
|---|---|---|
| Configuration | `TARGETS`, `PORT_TEST_TARGET`, `IX_PREFIXES`, `IPERF_SERVERS`, `PHASES`, `PHASE_ORDER`, `FLOW_FIELDS` | Everything a user might tune |
| Helpers | `run`, `Budget` / `BUDGET`, `UI`, `say`, `hr`, `phase_seconds` | Subprocesses, the `--max-gb` data budget, terminal output, time estimate |
| Environment | `default_route`, `hardware_ports`, `iface_media`, `wifi_info`, `public_ip`, `detect_env`, `check_env` | Where is this machine connected, and is it the phase it claims to be |
| Path lookups | `rdns`, `asn_lookup`, `traceroute`, `parse_traceroute`, `ix_name`, `home_asns`, `path_label`, `ping` | Hop names, origin AS, exchange detection, the ISP's own AS numbers |
| Measurements | `one_flow`, `classify` | One curl download, one classification |
| Packet capture | `Capture`, `capture_flow`, `read_pcap`, `analyse_pcap`, `pcap_test` | Privileged capture plus a pure-Python pcap reader |
| Long connections | `long_flow`, `long_test` | Per-second throughput parsed from curl's progress meter |
| Parallel streams | `iperf_servers`, `iperf_one`, `iperf_test` | iperf3 JSON, per-stream classification |
| Per-flow probes | `flowtrace_worker`, `flowtrace_test`, `flowtrace_analysis` | Paris-traceroute style probes from chosen source ports |
| One phase | `run_phase`, `_run_phase_tests` | The prompt-check-measure loop for one vantage point |
| Analysis | `load_phase`, `stats_for`, `poisson_binomial_tail`, `port_test_analysis`, `analyse`, `route_map` | Turn a results folder into findings |
| Report | `summary_table`, `svg_dotplot`, `svg_route_map`, `svg_spark`, `html_report`, `message_text`, `README`, `build_report` | Render and zip |
| Entry point | `choose_phases`, `main` | Arguments, phase selection, the hidden `--_flowtrace` child mode |

## Run flow

```
main
 ├─ parse args, apply --quick, trim TARGETS for --targets
 ├─ choose_phases                 interactive menu, or --phases
 ├─ Capture(...)                  decide tcpdump access: direct, sudo -n, or prompt once
 ├─ for each phase in PHASE_ORDER:
 │    run_phase
 │     ├─ prompt the user to move the machine; wait_for_network
 │     ├─ detect_env → check_env  fatal problems block (retry / run anyway / skip)
 │     └─ _run_phase_tests
 │          ├─ forward DNS for every target
 │          ├─ traceroutes + pings              (6 threads in parallel)
 │          ├─ throughput: rounds × targets     (strictly sequential)
 │          ├─ fixed-source-port test           (same file: flows.csv)
 │          ├─ per-flow probes                  (needs the port test's results)
 │          ├─ packet captures
 │          ├─ long connections
 │          └─ iperf3                           (also traceroutes each server)
 └─ build_report                  always runs, including after Ctrl-C
      ├─ load_phase × n → analyse → html / summary / message / README
      └─ zip, then reopen it and testzip() to prove it's readable
```

Throughput connections run **one at a time** on purpose. Parallel connections would compete
for the line and blur the fast/slow split the whole tool depends on. Traceroutes and pings
run in parallel because they're latency-bound and carry almost no traffic.

The **order of tests** matters in one place: the per-flow probes need the fixed-port results
to know which source ports were consistently slow or fast.

## Data budget

`BUDGET` counts every byte the tests move: `one_flow` (throughput, fixed-port and capture
downloads), `long_flow`, and `iperf_one` (the larger of bytes sent and received). Each of
those calls `BUDGET.check()` before starting and `BUDGET.add(n)` after. `capture_flow` checks
before it starts tcpdump, so a stop never leaves a capture running. `run_phase` checks before
prompting for the next vantage point.

When the limit is reached, `check()` raises `BudgetExceeded`. `run_phase` records
`meta["stopped"]`, `main` catches it like Ctrl-C, and `build_report` runs as normal. A
transfer already under way isn't interrupted, so a run can overshoot by one transfer. Every
phase records `meta["bytes_moved"]`, whether or not a budget is set, and the report shows it.

## Classification

A connection's rate is `size_download / (time_total − time_starttransfer)`, which counts only
the body. DNS, TCP and TLS set-up and redirects are excluded, so latency to distant targets
doesn't make them look slow. Below `--slow-mbps` (default 3 MB/s) a connection is `slow`;
curl failures and non-2xx responses are `error` and are left out of every rate.

`--max-time` ending a transfer (curl exit 28) is normal and not an error. In the long test,
the last per-second sample is dropped when curl exits 28, because it's a partial second.

## The fixed-source-port test

`port_test_analysis` asks: do outcomes stick to source ports more than chance allows?

1. `p` = the share of slow connections in the test.
2. For a port tried `n` times, the chance all `n` outcomes match by luck is `pⁿ + (1−p)ⁿ`.
3. Ports differ in `n`, because errors are dropped, so the count of consistent ports follows a
   Poisson-binomial distribution. `poisson_binomial_tail` computes its exact upper tail.
4. A p-value below 0.05, with more consistent ports than expected, means "sticks to the port".

Ports come from a seeded RNG (seeded from the results path and phase), so `--resume`
reproduces them. If a port is still in TIME_WAIT, curl exits 45; `one_flow` retries after
15 s, up to three attempts.

## Per-flow path probes

`flowtrace_test` picks up to `--flowtrace-ports` consistently slow and consistently fast
ports from the fixed-port results. It writes a spec file and re-runs the script as a child,
`sudo -n <python> isp-flow-test.py --_flowtrace <spec>`. The child is `flowtrace_worker`: it
needs raw sockets, so it runs as root, does nothing else, and prints JSON.
`sys.executable` is used so that, under `uv run`, the child gets the same environment,
scapy included.

Each probe is a TCP SYN from the chosen source port to the real destination and port, one
per TTL. Every router therefore hashes the probes exactly as it hashed the real connection.
The TTL is encoded in the sequence number (`FT_BASE_SEQ + ttl`). ICMP time-exceeded messages
quote it back, and the destination's SYN-ACK acknowledges `seq + 1`, so replies can be matched
without per-probe state. Each port is probed twice. `flowtrace_analysis` reports the first hop
where the sets of slow-port and fast-port addresses don't overlap, and flags ports whose path
changed between repeats.

## Route map

`route_map` runs per phase and family:

1. Classify each traced destination from its throughput: **bad** if ≥15 % of connections were
   slow, **good** if ≤5 %, **mixed** otherwise.
2. Build a graph from every responding address at every hop, including the extra addresses
   that 3 probes per hop can reveal on ECMP routers.
3. Score each router by the destinations through it.
4. **Suspects** are routers seen only on bad routes. **On every bad** are routers common to
   all bad routes and no good one.
5. Destination servers are excluded: they're endpoints, not suspects.

`svg_route_map` draws it top to bottom, coloured green → amber → red by slow share.

## The ISP's own networks

`path_label` names the first network outside the ISP. `home_asns` works out which AS numbers
are the ISP's:

1. Start with the AS of the public IPv4 address (from ipinfo's `org`, e.g. `AS64500 Example`).
   `note_isp_asn` stores it in `_ISP_ASN` from `detect_env` during a run, or from `meta.json`
   in `load_phase`.
2. Repeat: among routes that start inside the ISP, if every one goes on to the same next AS,
   that AS is the ISP's too. This handles an access AS plus a group backbone AS.

Hops in private or unannounced space have no AS and are skipped. If you change this, rebuild a
saved run with `--report-only` and compare the "Paths seen" line before and after.

## Results folder format

```
flow-report-<YYYYMMDD-HHMMSS>/
  <phase-id>/
    meta.json          phase, title, short, started, finished, env{…}, families, rounds,
                       seconds, slow_mbps, script_version, dns{host: {A, AAAA}},
                       port_test_ports{"4": [...], "6": [...]}, bytes_moved,
                       stopped (only when --max-gb cut the phase short)
    flows.csv          one row per connection; columns = FLOW_FIELDS
    traceroutes.json   {"<target>/v<fam>" | "iperf:<host>/v<fam>": {raw, hops[], via_ix}}
    pings.json         {"<target>/v<fam>": {sent, received, loss_pct, rtt_min/avg/max, raw}}
    pcap.json          {flows: [{class, mbps, packets, retransmits, retransmit_pct, holes, dup_acks,
                                 sack_acks, zero_window, longest_gap_ms, …}]}
    pcap/*.pcap        v<fam>-port<local port>-<class>.pcap
    long.json          [{target, family, mbps, series_mbps[], curl_rc, error, …}]
    iperf.json         [{host, family, direction, total_mbps, retransmits, streams[…], …}]
    flowtrace.json     {probes: [{family, sport, dport, dst, class, rep, hops[{ip, reached, rtt_ms}]}]}
```

`flows.csv` columns: `phase, test, round, target, role, family, requested_port, class, mbps,
bytes, http_code, remote_ip, local_port, t_connect, t_tls, t_ttfb, t_total, curl_rc, error,
time`. `test` is `throughput` or `fixed-port`. `meta.json` is written once before the
throughput test and again at the end, so an interrupted phase can still be reported. A phase
counts as complete for the report when it has both `meta.json` and `flows.csv`.

Changing these formats breaks `--report-only` and `--resume` on older folders. If you must,
bump the major version and say so in the changelog.

## Extending

### Add a target

Add a tuple to `TARGETS`:

```python
("name", "https://ipv4-url", "https://ipv6-url" or None, "test" | "control" | "probe", "note")
```

- Use a large file (≥1 GB), so a fast connection doesn't finish inside `--seconds`.
- Use a stable URL. Release assets and speed-test files are good; anything versioned will
  eventually 404.
- `control` targets should reach your line over a path you believe is healthy, typically an
  exchange-peered network. They're always kept by `--targets`. Use one or two.
- `probe` targets add route diversity for the route map.

### Add an internet exchange

Add `(name, prefix)` pairs to `IX_PREFIXES`, one per peering LAN, IPv4 and IPv6. Exchanges
publish these, and PeeringDB lists them under each exchange's "IX prefixes". A traceroute hop
inside one marks the route as exchange-peered.

### Add an iperf3 server

Add `(host, first_port, last_port, note)` to `IPERF_SERVERS`, or pass
`--iperf-servers host:5201-5210,host2:5201` at run time. Busy ports are skipped; a server that
refuses every port is skipped.

### Add a test

1. Write `<name>_test(families, args, …)`. Call `ui.section(label, total)` once and
   `ui.tick(cls, detail)` per step, and return a JSON-serialisable object. If it moves
   meaningful data, call `BUDGET.check()` before each transfer and `BUDGET.add(bytes)` after.
2. Call it from `_run_phase_tests` with a `--no-<name>` guard, via `dump("<name>.json", …)`.
3. Add its step count to `run_phase`, so the overall progress bar stays accurate, and its
   time to `phase_seconds`.
4. Load it in `load_phase`.
5. Add findings in `analyse`. Lines must be conditional on evidence; never print a conclusion
   the data doesn't support.
6. Render it in `html_report`, and describe the file in the pack's `README` string.

## Terminal handling

Two lessons learned the hard way:

- **Always run children with `stdin=DEVNULL`.** macOS `sudo` uses `use_pty`; if it can see the
  terminal it switches it to raw mode while its child runs. With output post-processing off,
  newlines stop returning the carriage, and Rich's live display smears and "staircases".
  `run()` and the tcpdump `Popen` both pass `DEVNULL`.
- **Save and restore the terminal.** `UI.tty_save` and `UI.tty_restore` snapshot termios
  settings and reapply them after each tick and at the end of a phase, in case anything else
  changes them.

## Testing changes

There's no network-free unit test suite yet. In order of cost:

```sh
# 1. Compiles on the oldest supported Python
uv run --python 3.9 python -m py_compile isp-flow-test.py

# 2. Analysis or report change: rebuild a saved run, diff the findings
cp -R saved-run /tmp/r && rm /tmp/r/{report.html,summary.txt,message.txt,README.txt}
uv run isp-flow-test.py --report-only /tmp/r
diff <(sed -n '/^Analysis/,$p' saved-run/summary.txt) <(sed -n '/^Analysis/,$p' /tmp/r/summary.txt)

# 3. Measurement change: a minimal live run (a minute or two, little data)
uv run isp-flow-test.py --phases own-wired --yes --quick --targets hetzner-ash-http \
    --no-port-test --no-pcap --no-flowtrace --no-long --no-iperf --out-dir /tmp

# 4. Full: one complete phase with every test, including the sudo paths
uv run isp-flow-test.py --phases isp-wired --quick --out-dir /tmp
```

Open `report.html` after any report change: the SVGs are hand-built, and layout bugs don't
show in text diffs.

Worth adding: unit tests for `parse_traceroute`, `port_test_analysis`, `home_asns`,
`route_map` and `read_pcap`, with fixtures cut from real runs and IP addresses replaced by
documentation ranges (192.0.2.0/24, 2001:db8::/32).

## Releasing

Bump `VERSION`. It's recorded in every `meta.json` and in the report footer, so you can tell
which version produced a given pack.
