# isp-flow-test

[![CI](https://github.com/m-d-johnson/isp-flow-test/actions/workflows/ci.yml/badge.svg)](https://github.com/m-d-johnson/isp-flow-test/actions/workflows/ci.yml)

A guided, single-file test for one specific broadband fault: **some connections run at full
speed while others crawl, and each connection stays in whichever state it started in.**
It collects the evidence an ISP's network team needs and packs it into one zip for a support
ticket.

Speed tests miss this fault. They open many parallel streams and report the total, so a few
slow streams vanish into the average. Day to day it looks like downloads that sometimes fly
and sometimes crawl, and retrying "fixes" them.

## When to use it

Suspect a per-flow fault when:

- one download of a large file crawls at 1 MB/s, you cancel it, and the retry runs at
  hundreds of MB/s;
- multi-stream speed tests look fine but single-stream downloads don't;
- some destinations are always fine and others are a lottery.

The usual cause is a faulty member of a link bundle (LAG) or an equal-cost multipath (ECMP)
group, inside the ISP or one of its upstream networks. Routers pick a member for each
connection by hashing its addresses and ports, and the connection keeps that member for its
whole life. Connections that land on the bad member are slow from start to finish.

This tool is built to show that pattern, rule out your own equipment, and narrow down where
the bad path is. It can't fix it: only the operator of the faulty link can.

CI runs it end to end in a network-namespace lab with a real ECMP split and one rate-limited
member, and checks that it finds that member (see [Testing](docs/DEVELOPMENT.md#testing)).

## ⚠ Data volume

**A default run on a fast line can download well over 100 GB per vantage point.** One run on a
10 Gb/s line moved 158 GB in 35 minutes. The tests download from public speed-test servers
run by hosting companies and CDNs, so be considerate:

- set **`--max-gb`** to cap a run: once the total reaches the limit it stops cleanly and still
  builds the report and zip from what finished (it can overshoot by one transfer, a few GB at
  most on multi-gigabit lines);
- use `--quick` for a dry run: it moves roughly a sixth as much;
- trim with `--rounds`, `--seconds`, `--targets` and the `--no-*` switches;
- don't run it on a metered or capped connection without working out the cost first.

Volume scales with how fast each connection runs, so slower lines move less.

## Requirements

- **macOS.** The environment checks use `networksetup`, `ifconfig` and `system_profiler`. It
  also runs on Linux (CI tests it there), but the Wi-Fi and link checks don't, so use `--force`.
- `curl`, `traceroute`, `traceroute6`, `ping`, `ping6`, `whois` and `tcpdump`. All are built
  into macOS.
- [uv](https://docs.astral.sh/uv/) (recommended). `uv run` reads the script's inline
  metadata (PEP 723) and installs its Python packages:
  - [Rich](https://github.com/Textualize/rich): the progress display (plain text without it);
  - [scapy](https://scapy.net): the per-flow path probes (skipped without it);
  - [truststore](https://github.com/sethmlarson/truststore) or
    [certifi](https://github.com/certifi/python-certifi): certificate checks for HTTPS targets.
    A uv-managed Python often can't find the system's certificates on its own.
- Python 3.9 or newer.
- Optional tools, each adding a test or a cross-check (the run says which it found):
  - `iperf3` (`brew install iperf3`): the parallel-stream test;
  - **scamper** (`brew install scamper`): the MDA traceroute;
  - **tshark** (`brew install wireshark`): Wireshark's own analysis of each capture.
- Optional: `sudo` once per run, for the packet captures, per-flow path probes and MDA
  traceroute. Without it those tests are skipped and the rest still run.

## Quick start

```sh
uv run isp-flow-test.py --quick                 # short dry run
uv run isp-flow-test.py --ref 123456 --max-gb 50 \
    --out-dir ~/Documents/isp-support           # full run, tagged with your ticket number, capped at 50 GB
```

The script asks which vantage points to test, then tells you what to plug in or join before
each one. It checks you really did:

- the default route goes over the right interface (Wi-Fi or wired);
- no VPN is active;
- the public IP belongs to the expected ISP;
- each phase's gateway differs from the other side's phases.

If a check fails, it tells you why and offers to retry, run anyway or skip.

When it finishes, or if you press Ctrl-C, it writes a results folder and a verified
`flow-report-<timestamp>.zip` next to it. Send the zip to your ISP.

## Vantage points

| Phase | Where the test machine is | Why |
|---|---|---|
| `own-wired` | Wired into your own network, behind your own router | Your normal setup |
| `own-wifi` | On your own Wi-Fi | Rules your Wi-Fi in or out |
| `isp-wifi` | On the ISP router's own Wi-Fi | None of your equipment in the path |
| `isp-wired` | Wired into the ISP router | **The cleanest test (default)**: no equipment of yours, no Wi-Fi |

If the fault reproduces on `isp-wired`, the ISP can't attribute it to your equipment. Testing
`own-wired` as well shows whether your router changes anything.

A phase took 35 minutes at default settings with IPv6 on the line this was developed on. The
script prints its own estimate before starting.
`--phases own,isp` selects both phases on a side.

## What it measures

Each vantage point gets the full set of tests below.

| Test | What it shows | Needs |
|---|---|---|
| **Per-connection throughput** | 16 rounds of fresh, sequential 5-second downloads, rotated across all targets so changes over time affect each one equally. Each connection is classed fast or slow (default threshold 3 MB/s). | — |
| **Kernel TCP statistics** | For every connection, the operating system's own round-trip estimate and out-of-order share, read just before it closes. A slow member that queues shows up as a longer round trip on the slow connections only. | — |
| **Fixed-source-port test** | Reuses the same 8 local ports 3 times each. If outcomes stick to the port far more often than chance (exact Poisson-binomial p-value), the fault follows a flow hash. | — |
| **Per-flow path probes** | TCP traceroutes sent from the consistently slow and fast source ports, holding all four address-and-port fields constant (Paris-traceroute style), so each router hashes each probe like the real connection. Shows the hop where slow and fast paths part. | sudo, scapy |
| **MDA traceroute** | scamper's Multipath Detection Algorithm keeps varying the probe flow until it has found every path a load balancer can choose, with 95% confidence. Shows which hops are load-balanced and whether the suspects sit inside such a group. | sudo, scamper |
| **Packet captures** | Header-only `tcpdump` of single downloads, analysed for retransmissions, sequence holes, duplicate and SACK acks, zero windows and stalls, and cross-checked by tshark, which tells resent data from reordered data. Slow captures and one fast one are kept as `.pcap`. | sudo (tshark optional) |
| **Long connections** | 30-second downloads sampled every second, to see whether a slow connection ever recovers. | — |
| **Parallel streams** | `iperf3` with 16 streams in each direction against public servers: how many streams of one test land slow. | iperf3 |
| **Traceroutes and pings** | 3 probes per hop, reverse DNS, origin AS (Team Cymru), ping loss and RTT. Hops on any exchange's peering LAN worldwide are flagged (from [PeeringDB](https://www.peeringdb.com)), with the network that owns that router. | — |
| **Route map** | Merges the traceroutes into a graph and colours each router by the share of slow connections through it. Routers on every bad route and no good route are the prime suspects. | — |

### Targets

| Name | Role | What |
|---|---|---|
| `github-fastly` | test | GitHub release download (IPv4 only) |
| `alpine-fastly` | test | Alpine Linux CDN |
| `hetzner-ash-http`, `-https` | test | Hetzner, Ashburn US; also used by the port, capture and long tests |
| `thinkbroadband` | **control** | UK test file, usually reached via exchange peering |
| `leaseweb-lon`, `clouvider-lon`, `vultr-lon` | probe | London speed-test servers |
| `ovh-rbx`, `hetzner-fsn` | probe | Roubaix (FR) and Falkenstein (DE) |

How each target is reached isn't assumed: each run's traceroutes decide it. Results are grouped
by whether a route crossed an internet exchange.

The built-in targets suit a UK line. Elsewhere, put your own in a JSON file and pass
`--targets-file`. Include at least one `control` that your ISP reaches over a healthy path,
such as a local exchange-peered network:

```json
{
  "targets": [
    {"name": "cdn", "url4": "https://example.com/1GB.bin", "url6": "https://example.com/1GB.bin", "role": "test"},
    {"name": "local", "url4": "http://speedtest.example.net/1GB.bin", "url6": null, "role": "control"}
  ],
  "port_test_target": "cdn"
}
```

## The support pack

```
flow-report-20261117-160927/
  report.html     self-contained report: analysis, a dot plot of every connection,
                  route map, per-target tables, captures, long connections, iperf3,
                  traceroutes, environment
  summary.txt     plain-text summary table and analysis
  message.txt     a draft covering message, with the automatic analysis at the bottom
  README.txt      explains every file, for the ISP's engineers
  <phase>/        raw data per vantage point: flows.csv (with kernel TCP statistics),
                  traceroutes.json, pings.json, pcap/*.pcap, pcap.json, long.json,
                  iperf.json, flowtrace.json, mda.json and mda/*.json (raw scamper
                  output), meta.json
flow-report-20261117-160927.zip
```

Read `message.txt` before sending it, and edit it to taste.

## Reading the results

- **Two separate speed modes, more than ten times apart**, with nothing in between: the
  signature of a per-flow fault. Congestion produces a smear of speeds instead.
- **Clean control, slow test targets**: the fault is on the path to the test targets, not
  your line as a whole.
- **"Outcome STICKS to the source port"**: a flow hash is choosing the bad path. IPv6 is the
  stronger evidence, because IPv4 may cross NAT that rewrites ports.
- **Slow connections with a longer kernel round trip** than fast ones to the same server: they
  take a different path that adds delay, usually queueing behind a congested or rate-limited
  member.
- **Per-flow probes that part at hop N**: the bad path is behind the addresses listed at
  that hop. If they never part, the bad member is inside one bundle that traceroute can't see
  into, and only the operator can find it from interface counters.
- **MDA shows the suspect inside a load-balanced group**: one member of that group is the
  likely fault. MDA finding no load balancing points to a LAG inside a single router.
- **IPv6 slow too**: rules out NAT and CGNAT.
- **No slow connections**: fixed, or intermittent. Run it again at a different time of day
  before closing a ticket.

## Options

| Option | Default | Effect |
|---|---|---|
| `--phases LIST` | ask | `own-wired,own-wifi,isp-wifi,isp-wired`, or `own` / `isp` |
| `--ref TEXT` | — | ticket reference for the report and message |
| `--name TEXT` | your macOS full name | signature in `message.txt` |
| `--out-dir DIR` | `.` | where the results folder and zip go |
| `--max-gb GB` | no limit | stop once this much data has moved in total (all phases, both directions) and report on what finished |
| `--quick` | — | 4 rounds × 3 s and fewer extras: a dry run |
| `--rounds N`, `--seconds N` | 16, 5 | throughput sample count and length |
| `--slow-mbps X` | 3.0 | slow threshold, MB/s |
| `--family 4\|6\|both` | both | IP families |
| `--targets LIST` | all | subset of targets (controls and the port-test target are always kept) |
| `--targets-file FILE` | built-in | replace the targets with your own (format above) |
| `--own-gateway IP`, `--isp-gateway IP` | — | assert each side's gateway address |
| `--expect-isp TEXT` | — | require the public IPv4's organisation to contain TEXT, e.g. `AS64500` |
| `--expect-link TEXT` | — | warn if a wired phase's link media lacks TEXT, e.g. `10G` |
| `--no-port-test`, `--no-flowtrace`, `--no-pcap`, `--no-long`, `--no-iperf`, `--no-trace`, `--no-mda` | — | skip a test |
| `--no-tshark` | — | don't cross-check captures with tshark |
| `--mda-max N`, `--mda-method M`, `--mda-timeout S` | 4, `tcp-sport`, 240 | MDA destinations per family (controls are always added), probe method, time limit per trace |
| `--no-peeringdb` | — | don't fetch exchange data; use the cached copy or the built-in list |
| `--port-count`, `--port-reps`, `--flowtrace-ports` | 8, 3, 4 | fixed-port and probe sizes |
| `--pcap-flows`, `--pcap-keep-slow`, `--pcap-seconds` | 10, 3, 4 | capture sizes |
| `--long-count`, `--long-seconds` | 4, 30 | long-connection test |
| `--iperf-streams`, `--iperf-seconds`, `--iperf-max`, `--iperf-servers` | 16, 10, 2, built-in | parallel-stream test |
| `--yes` | — | no prompts; runs phases whose checks pass |
| `--force` | — | run a phase even if its checks fail |
| `--resume DIR` | — | add phases to an earlier run |
| `--report-only DIR` | — | rebuild the report and zip from an earlier run |

## Privacy

The pack is meant for your ISP. It contains:

- your public IPv4 and IPv6 addresses and their organisation;
- the test machine's hostname and OS version;
- gateway and interface names, and link speed;
- Wi-Fi radio statistics (PHY mode, channel, rate, signal), but not the network name;
- traceroutes from your line;
- your name, in `message.txt`.

During a run, the script sends:

- your public IP to [ipify](https://www.ipify.org) and [ipinfo.io](https://ipinfo.io);
- each traceroute hop's address to Team Cymru's whois service;
- the address of any hop on an exchange's peering LAN to PeeringDB;
- its download and iperf3 traffic to the target servers.

It also downloads PeeringDB's exchange list (about 2 MB) once a day into `~/.cache/isp-flow-test`.
Set `PEERINGDB_API_KEY` to use your own PeeringDB key, or `--no-peeringdb` to skip it.

Review the pack before posting it anywhere public.

## Limitations

- Built for macOS. It runs on Linux too, but only partly checks the test machine's environment there.
- Traceroutes show the typical path to each destination, not each connection's exact path.
  The per-flow probes close most of that gap, but routers that rate-limit ICMP or hide
  bundle members limit what any outside test can see.
- Your ISP's own networks are inferred from the public address's AS, plus any AS that
  every route passes straight through. That works when the ISP's hops answer from public
  address space, which is common on IPv6 and less so on IPv4. Where it can't tell, the
  "first external network" label may name the ISP's own backbone.
- The default control assumes a UK line. Elsewhere, pick a local control with `--targets-file`.
- MDA and the per-flow probes see the path *to* each server. Downloads travel back along the
  return path, which the networks on the way hash separately and can't be probed from your
  end. The kernel statistics and captures describe the return path.

## Releases

Each [release](https://github.com/m-d-johnson/isp-flow-test/releases) attaches the script and
its SHA-256 checksum:

```sh
curl -LO https://github.com/m-d-johnson/isp-flow-test/releases/latest/download/isp-flow-test.py
curl -LO https://github.com/m-d-johnson/isp-flow-test/releases/latest/download/isp-flow-test.py.sha256
shasum -a 256 -c isp-flow-test.py.sha256
```

## Licence

[MIT](LICENSE).

## Contributing

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the architecture, data formats, tests and
release process.

Not affiliated with any ISP or equipment vendor. Test-server operators are named only to
identify the servers.
