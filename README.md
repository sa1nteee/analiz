# NetSentry

A network traffic analysis toolkit for security work, written in Rust.

NetSentry captures and inspects network traffic, groups it into conversations
between hosts, and explains *why* a piece of traffic looks suspicious. The
analysis engine is a plain Rust library with no UI dependencies; a desktop front
end is planned for a later version.

> **Status: v0.4 — under construction.**
> NetSentry can list capture interfaces, capture live packets, save them to a
> pcap file, analyse saved captures, and group packets into the conversations
> they belong to. Detecting suspicious behaviour is v0.7's job.

## Requirements

NetSentry talks to the operating system's packet capture driver. That driver is
not part of this project and has to be installed separately.

### Windows

1. **Npcap** — <https://npcap.com>
   During setup, tick **"Install Npcap in WinPcap API-compatible Mode"**. Without
   it the `wpcap.dll` NetSentry links against will not be found.
   Ticking *"Support loopback traffic"* is recommended for local testing.
2. **Npcap SDK** — downloaded separately from the same site. Extract it
   somewhere stable, e.g. `C:\npcap-sdk`.
3. **Visual Studio Build Tools** with the *Desktop development with C++*
   workload, for the MSVC linker.

Point the build at the SDK before compiling. The architecture must match your
Rust toolchain — a 64-bit toolchain needs the `Lib\x64` directory:

```powershell
$env:LIBPCAP_LIBDIR = "C:\npcap-sdk\Lib\x64"
cargo build --release
```

Npcap is third-party software with its own licence, which restricts commercial
redistribution. NetSentry does not bundle or redistribute it — you install it
yourself, exactly as Wireshark asks you to.

### Linux

```bash
sudo apt install libpcap-dev   # Debian/Ubuntu
cargo build --release
```

### macOS

libpcap ships with the system; no extra package is needed.

## Usage

```bash
netsentry list                            # show the interfaces the capture driver can see
netsentry capture -i 1                    # capture until Ctrl+C
netsentry capture -i 1 --count 20         # capture 20 packets, then stop
netsentry capture -i eth0                 # interfaces can be named instead of numbered
netsentry capture -i 1 -w session.pcap    # also save the packets to a file
netsentry read session.pcap               # analyse a saved capture
netsentry read session.pcap --count 100   # analyse only its first 100 packets
netsentry read session.pcap --flows       # report conversations, not packets
netsentry capture -i 1 --count 100 --flows
netsentry --help
netsentry capture --help
netsentry read --help
```

### `netsentry list`

```text
NetSentry 0.1.0 — network interfaces

[1] eth0
    description  (none)
    status       running  [connected]
    addresses    192.0.2.2/24

[2] lo
    description  (none)
    status       running  [loopback]
    addresses    127.0.0.1/8

2 interfaces found.
```

The **system name** on the `[n]` line is what identifies an interface to the
capture driver. `capture` accepts either form — `-i 1` or `-i eth0` — but only
the system name is stable: the `[n]` index can change between runs, so do not
put it in a script.

### `netsentry capture`

```text
$ netsentry capture -i 1 --count 12
NetSentry 0.1.0 — live capture

[*] interface   : eth0
[*] link type   : EN10MB (Ethernet)
[*] snaplen     : 65535 bytes
[*] promiscuous : on
[*] stop after  : 12 packets
[*] clock       : UTC
[*] payload     : not captured for display — metadata only

     9  13:46:10.940107  192.0.2.2:40348 → 160.79.104.10:443 TCP SYN
    10  13:46:10.940405  160.79.104.10:443 → 192.0.2.2:40348 TCP SYN,ACK
    11  13:46:10.940435  192.0.2.2:40348 → 160.79.104.10:443 TCP ACK
    12  13:46:10.940616  192.0.2.2:40348 → 160.79.104.10:443 TCP PSH,ACK
    13  13:46:29.649884  192.0.2.2:50787 → 8.8.8.8:53 UDP len=37
    14  13:46:29.664049  8.8.8.8:53 → 192.0.2.2:50787 UDP len=93
    15  13:46:59.350804  192.0.2.2 → 192.0.2.1 ICMP Echo Request
    16  13:46:59.351026  192.0.2.1 → 192.0.2.2 ICMP Echo Reply
    17  13:46:59.351275  ARP Who has 192.0.2.77? Tell 192.0.2.2

[*] Capture finished (packet count reached).

    packets captured     : 12
    ...
```

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `-i`, `--interface <INTERFACE>` | *required* | Listing index or system name |
| `-c`, `--count <N>` | run until Ctrl+C | Stop after N packets |
| `-s`, `--snaplen <BYTES>` | `65535` | Bytes to keep per packet (1–262144) |
| `-p`, `--promiscuous <BOOL>` | `true` | Accept frames not addressed to this host |

`caplen` is how much of the packet was captured; `wirelen` is how big it was on
the wire. When they differ, the snapshot length truncated the packet and part of
it is missing from the capture. NetSentry always shows both rather than hiding
the difference.

Timestamps are **UTC**, to microsecond resolution. A capture is evidence, and
UTC means a timestamp still means the same thing on someone else's machine.

Press **Ctrl+C** to stop a capture that has no `--count` limit. The capture
stops at the next packet boundary and still prints its summary.

### `netsentry read`

Analyses a saved capture through exactly the same decoder and renderer a live
capture uses. The file is opened read-only and is never modified.

```text
$ netsentry read session.pcap
NetSentry 0.1.0 — offline analysis

[*] file        : session.pcap
[*] format      : pcap/pcapng (read-only)
[*] link type   : EN10MB (Ethernet)
[*] read        : whole file
[*] clock       : UTC

     1  14:04:49.568771  192.0.2.2:57782 → 160.79.104.10:443 TCP ACK
     2  14:04:49.568960  160.79.104.10:443 → 192.0.2.2:57782 TCP ACK
     ...
     6  14:04:50.048811  192.0.2.2:57758 → 160.79.104.10:443 TCP ACK

[*] Analysis finished (capture source ended).

    packets analysed     : 6
    captured bytes       : 396
    wire bytes           : 396

    first packet         : 2026-09-21 14:04:49.568771 UTC
    last packet          : 2026-09-21 14:04:50.048811 UTC
    capture span         : 0.480s
    read in              : 0.000s (wall clock)
```

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `<FILE>` | *required* | The capture to analyse |
| `-c`, `--count <N>` | whole file | Analyse only the first N packets |

`analyze` is accepted as an alias for `read`.

Two different clocks appear in that summary and they are labelled apart on
purpose. **`capture span`** is when the traffic happened, taken from the
packets' own timestamps. **`read in`** is how long NetSentry spent reading the
file. Reading a three-hour capture takes milliseconds; reporting the second
number as though it were the first would be a lie about the evidence.

`--count` stops reading early. It is not a filter: it does not skip anything,
and the rest of the file is left unread, so the summary describes what was
analysed rather than what the file contains.

**Reading a capture file needs no privileges.** Capturing does; opening a file
does not. Verified: an unprivileged user that cannot capture on any interface
reads a capture file successfully.

### Saving a capture

```bash
netsentry capture -i 1 --write session.pcap
netsentry capture -i 1 --write session.pcap --overwrite
```

Without `--write`, NetSentry writes nothing at all — that has not changed.
With it, **full packets including payload** are written to the file:

```text
[!] Writing full packets, payload included, to session.pcap
    This file will contain whatever the traffic contained: credentials and
    session tokens from plaintext protocols, hostnames, and your network's
    internal layout. Store and share it accordingly.
```

* An existing file is **refused**, not replaced, unless `--overwrite` is given.
  A capture cannot be re-recorded, so truncating one is not a recoverable
  mistake.
* The file is created with **owner-only permissions** (mode `0600`) on Unix,
  before libpcap opens it. libpcap's own `fopen` would create it
  world-readable subject to your umask, and this file is about to contain
  other people's credentials.
* The output path is checked **before** the interface is opened, so a mistyped
  path costs nothing.

### Supported capture formats

| Format | Read | Write |
| ------ | ---- | ----- |
| `.pcap` (classic libpcap) | yes | yes |
| `.pcapng` (single interface) | yes | no |
| `.pcapng` (several interfaces of different link types) | first interface only | no |
| Compressed captures (`.gz`, `.zst`) | no — decompress first | no |

pcapng support comes from libpcap itself rather than from any extra
dependency, and it inherits libpcap's limitation: a pcapng file may contain
several interfaces, but libpcap exposes only one link type per handle. A file
whose second interface has a *different* link type is read up to that point
and then reports `an interface has a type 113 different from the type of the
first interface`. Files written by `tcpdump -w` and by Wireshark's single-
interface captures are unaffected.

### Reading a damaged capture

A capture whose writer was killed mid-packet still contains everything before
the damage, and NetSentry reports it rather than discarding it:

```text
    packets analysed     : 5
    ...
    the rest of the file could not be read:
      capture file is truncated or corrupt: cut.pcap
      cause: libpcap error: truncated dump file; tried to read 66 captured bytes, only got 26
```

The exit code is still non-zero, so a script notices.

Note the distinction NetSentry draws:

* A damaged **file structure** — a bad global header, a packet record cut in
  half, a declared packet length larger than the file — is a *file* error.
* A **well-stored packet that is itself short**, as happens with a small
  `--snaplen`, is not a file error at all. It goes through the decoder's
  ordinary graceful degradation and prints as `[truncated IPv4]`.


### What this version does not do

Packet **payload is never printed or logged**, and is only ever written to disk
when `--write` explicitly asks for a capture file. Headers are decoded and
described; the bytes after them are not read at all. Nothing above the
transport layer is parsed.

## What NetSentry decodes

| Layer | Supported | Reported |
| ----- | --------- | -------- |
| Link | Ethernet II (`DLT_EN10MB`) | source and destination MAC, EtherType |
| | 802.1Q and 802.1ad VLAN tags | priority, drop-eligible bit, VLAN id |
| | Linux cooked capture (`DLT_LINUX_SLL`, `SLL2`) | packet type, ARPHRD type, source address |
| Network | IPv4 | addresses, protocol, TTL, header/total length, DSCP/ECN, identification, fragment flags and offset |
| | IPv6 | addresses, next header, hop limit, payload length, traffic class, flow label, extension header chain |
| | ARP | operation, and for Ethernet/IPv4 the sender and target MAC and IP |
| Transport | TCP | ports, sequence, acknowledgment, header length, all nine flags, window, checksum, urgent pointer |
| | UDP | ports, declared length, checksum, bytes actually captured |
| | ICMP / ICMPv6 | type, code, checksum, and a name for the common messages |

Anything outside that list is reported rather than dropped: an unknown EtherType
prints as `EtherType 0x88cc`, an unknown IP protocol as `IP protocol 47`, and an
unnamed ICMP message as `ICMP type 99 code 7`.

Decoding stops — with a reason — rather than guessing, whenever a header cannot
be located with certainty:

```text
     1  13:47:10.208863  192.0.2.2 → 160.79.104.10 TCP [truncated TCP]
     1  13:47:11.232789  02:fc:00:00:00:01 → 02:fc:00:00:00:05 IPv4 [truncated IPv4]
     1  13:47:12.256800  [truncated Ethernet]
```

### Parser safety

Every byte reaching the decoder came off a network and is treated as hostile.

* The crate sets `unsafe_code = "forbid"`, so a length mistake in the parser
  cannot become a memory-safety bug. This is enforced by the compiler, not
  promised in a comment.
* There is no indexing anywhere in the decoder. Every read goes through a
  bounds-checked cursor that returns `Option`, so handling a short packet is
  not something a caller can forget to do.
* Attacker-controlled loops are bounded: at most 2 stacked VLAN tags and 8 IPv6
  extension headers.
* A malformed packet produces a *result*, never a panic, and the capture
  continues with the next packet.

The test suite feeds the decoder every prefix and every single-byte corruption
of its fixtures — 7808 malformed inputs — and asserts only that it returns.


## Flow tracking

A capture of a few minutes is tens of thousands of packets and perhaps a few
dozen conversations. `--flows` reports the conversations.

```text
$ netsentry read session.pcap --flows
NetSentry 0.1.0 — offline analysis

[*] file        : session.pcap
[*] link type   : EN10MB (Ethernet)
[*] output      : conversations, not individual packets

[*] Analysis finished (capture source ended).

    packets analysed     : 80
    ...

[*] Flows: 11
    A is the endpoint on the left of ↔, B the one on the right.
    The order is fixed by address and port, not by who spoke first.

  TCP 160.79.104.10:443 ↔ 192.0.2.2:50366
      packets 18      bytes 10.0 KB    duration 0.22s
      A→B 8 / 4948 B       B→A 10 / 5078 B
      TCP A→B [SYN,PSH,ACK] syn 1 fin 0 rst 0   B→A [SYN,PSH,ACK] syn 1 fin 0 rst 0

  UDP 8.8.8.8:53 ↔ 192.0.2.2:39383
      packets 2       bytes 198 B      duration 0.01s
      A→B 1 / 127 B        B→A 1 / 71 B

    3 packets formed no flow: 2 ARP, 1 ICMP.
```

### What a flow is

A flow is one conversation, identified by the classic **5-tuple**: the two IP
addresses, the two ports and the transport protocol.

The catch is that a conversation arrives as packets going *both ways*, and

```text
192.168.1.10:50000 → 1.1.1.1:443
1.1.1.1:443        → 192.168.1.10:50000
```

are the same conversation. Filing them as two flows would be the opposite of
what a flow is for. So NetSentry sorts the two endpoints into a fixed order and
calls the lower one **A** and the higher one **B**.

That means **A is not "the client" and B is not "the server"** — A is simply the
endpoint that sorts first by address and then by port. The benefit is that the
identity of a flow does not depend on which packet happened to be seen first:
the same capture read twice, or read backwards, produces the same flows with the
same A and the same B.

Which way a given packet was actually travelling is not lost. It is what the
`A→B` and `B→A` counters are keyed on, and the asymmetry between them is often
the interesting part — a client sending 4 KB and receiving 52 KB looks very
different from one sending 52 KB and receiving 4 KB.

### What forms a flow

| Traffic | Flow? | Why |
| ------- | ----- | --- |
| TCP | yes | has ports |
| UDP | yes | has ports |
| ICMP / ICMPv6 | no | no ports; see below |
| ARP | no | not IP at all |
| Non-initial IP fragment | no | its ports are in a different packet |
| Truncated or undecoded packet | no | nothing to key on |

ICMP has no ports, so an ICMP flow could only be keyed on the host pair — which
would pour an echo request, a "host unreachable" about some third connection and
a traceroute probe into one bucket, none of them a conversation with the others.
Most interesting ICMP messages also *quote* a different packet, so the
conversation they concern is not the one their own headers describe. Correlating
that quoted header with an existing flow is real work, and it belongs with the
detection rules of v0.7 rather than here.

Nothing is dropped: everything still decodes and prints in packet mode, and the
flow summary says how many packets it left out and why.

### Byte accounting

`bytes` is **wire bytes** — what the packets were on the network. When a small
`--snaplen` truncated them, the captured total differs and the flow says so:

```text
      captured 64 B of 1514 B on the wire (snapshot length truncated these packets)
```

Sizes below 10 000 bytes are printed exactly; above that they are rounded to one
decimal in decimal units (1 KB = 1000 bytes).

### Duration

`duration` is the **latest minus the earliest** timestamp on the flow's packets,
not last-arrival minus first-arrival. Capture files are not required to be in
timestamp order and real ones sometimes are not, so taking the ends of the range
keeps a duration from coming out negative. A flow whose timestamps are not
points in time at all reports its duration as `unknown` rather than inventing
one.

### Flow limit

The table holds at most **100 000** conversations by default, about 50 MB. The
bound exists because the input is not trusted: a crafted capture can name a
million distinct endpoints as cheaply as one.

Reaching it is a degradation, not an error. Conversations already being tracked
keep being counted, the analysis finishes normally, and the summary says what
was missed:

```text
    66 packets formed no flow: 66 over the flow limit.
    The flow limit of 3 was reached. Raise it with --max-flows.
```

`--max-flows N` raises or lowers it.

### Why `--flows` replaces the packet list

Printing 80 000 packet lines *and* a flow table would bury the summary under the
thing it summarises, and nobody scrolls back that far. `--flows` is therefore a
mode, not an addition: it reports conversations instead of packets. Run without
it to see packets. This keeps one flag where two would otherwise be needed, and
leaves no combination whose meaning has to be guessed at.


## Privileges

Listing interfaces generally works as a normal user. **Capturing packets does
not.**

* **Windows** — run the terminal as Administrator, if Npcap was installed with
  *"Restrict Npcap driver's access to Administrators only"* (the default).
* **Linux** — run as root, or grant the binary the two capabilities it needs,
  which avoids running the whole tool as root:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/netsentry
  ```

* **macOS** — root, or read access to the `/dev/bpf*` devices.

If the driver refuses, NetSentry says so explicitly rather than reporting an
empty capture:

```text
error: not allowed to capture on "eth0"
cause: libpcap error: socket: Operation not permitted
hint:  capturing packets needs more privileges than listing interfaces
       Windows: run this terminal as Administrator
       Linux:   run as root, or grant the binary CAP_NET_RAW and CAP_NET_ADMIN:
                sudo setcap cap_net_raw,cap_net_admin=eip ./netsentry
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The project is a single crate split into a library and a thin binary:

| Path                       | Responsibility                                        |
| -------------------------- | ----------------------------------------------------- |
| `src/main.rs`              | Argument parsing, dispatch, exit code. No logic.      |
| `src/lib.rs`               | Library root and module layout.                       |
| `src/cli.rs`               | Command line *description* (clap types only).         |
| `src/error.rs`             | `NetSentryError` — typed failures with hints.         |
| `src/capture/device.rs`    | Interface discovery and selection by index or name.   |
| `src/capture/settings.rs`  | Capture options and their validation rules.           |
| `src/capture/live.rs`      | The capture engine: opens a handle, pumps packets.    |
| `src/capture/stats.rs`     | Packet/byte accounting and the run's outcome.         |
| `src/capture/offline.rs`   | Reading a capture file.                               |
| `src/capture/pump.rs`      | The read loop live and offline capture share.         |
| `src/capture/writer.rs`    | Saving captured packets to a pcap file.               |
| `src/capture/timestamp.rs` | Packet timestamps and their conversion to text.       |
| `src/decode/bytes.rs`      | The bounds-checked cursor all parsing goes through.   |
| `src/decode/link.rs`       | Ethernet, VLAN and Linux cooked-capture decoding.     |
| `src/decode/net.rs`        | IPv4, IPv6 and ARP decoding.                          |
| `src/decode/transport.rs`  | TCP, UDP and ICMP decoding.                           |
| `src/decode/model.rs`      | The decoded-packet domain model.                      |
| `src/flow/key.rs`          | Flow identity and its canonical endpoint order.       |
| `src/flow/stats.rs`        | What a flow accumulates.                              |
| `src/flow/mod.rs`          | The flow table, its limit and what it left out.       |
| `src/render/`              | Pure terminal formatting. No I/O.                     |

Layer dependencies point one way only — `render` above `decode` above
`capture` — and `unsafe` code is `forbid`-den crate-wide: the only unsafe code
in the build lives inside the `pcap` crate's FFI bindings.

A live interface and a capture file share one pipeline:

```text
interface ─┐
           ├─→ pump ─→ decode ─→ domain model ─┬─→ render
pcap file ─┘                                   └─→ flow tracking ─→ render
```

The flow tracker takes decoded packets, never bytes: it computes no offsets and
parses no headers, so the decoder stays the single source of truth about what a
packet contains.

There is no `PacketSource` trait, deliberately. The `pcap` crate already has
one: `Capture<Active>` and `Capture<Offline>` both implement `pcap::Activated`,
and everything the read loop needs is defined once for any
`Capture<T: Activated>`. Adding our own abstraction on top would be a layer
that renames someone else's.

The decoder is a single pure function, `decode(link, &[u8]) -> DecodedPacket`.
It knows nothing about libpcap, interfaces or terminals, holds no state, and
cannot fail — which is why it can be tested entirely against hand-built byte
arrays, and why it is ready to be pointed at `cargo-fuzz` unchanged.

## Known limitations

### Decoding

* **Nothing above the transport layer is parsed.** DNS, HTTP and TLS are v0.5
  and later.
* **Checksums are not verified.** They are recorded as they appeared. A packet
  with a bad checksum is decoded and reported like any other.
* **TCP options are not parsed**, only measured. Their length is what decides
  where the payload starts, and that is all this version needs from them.
* **ICMP message bodies are not parsed**, only the type and code.
* **Fragments are not reassembled.** A non-initial fragment is reported as one;
  its transport header lives in a different packet, and joining them up is
  v0.4's work.
* **IPv6 extension headers are followed, but not all of them.** Hop-by-Hop,
  Routing, Destination Options, Fragment, Authentication and Mobility headers
  are stepped over. ESP is encrypted and ends the walk, as does any unknown
  header — decoding stops rather than reading a transport header at a guessed
  offset.
* **VLAN nesting is capped at 2 tags** and **IPv6 extension headers at 8.**
  Both limits exist because both chains are attacker-controlled.
* **Only three link types are decoded:** Ethernet, Linux SLL and Linux SLL2.
  802.11, raw IP and the rest report `no decoder for link type <n>`.
* **MACsec and 802.3 LLC/SNAP frames are not decoded.** An EtherType below
  0x0600 is an 802.3 length field, which NetSentry reports as such rather than
  misreading as a protocol.

### Flow tracking

* **Retransmissions are counted twice.** A TCP segment that appears in the
  capture twice is two packets, because telling a retransmission from a
  duplicate needs sequence-number tracking, which this version does not do.
* **Fragments are not correlated.** The first fragment of a packet carries its
  transport header and joins its flow normally; later fragments do not, and are
  counted as untrackable rather than guessed into a flow. Reassembly is not
  attempted.
* **There is no connection state.** TCP flags are counted and OR-ed together;
  no state machine decides whether a connection was established, half-open or
  reset. `syn 1` means one segment carried SYN, nothing more.
* **Flows never expire.** A conversation stays in the table for the whole run.
  There is no idle timeout and no LRU eviction — only the flow limit, and
  reaching it stops *new* flows rather than evicting old ones.
* **ICMP and ARP form no flows**, by the reasoning above.
* **`--flows` and the packet list are exclusive.** By design; see above.

### Capture and capture files

* **A pcapng file with several link types is read only as far as its first
  interface**, because libpcap exposes one link type per handle. See
  *Supported capture formats* above.
* **Compressed captures are not supported.** Decompress them first.
* **Captures cannot be merged, filtered or rewritten.** `read` analyses, it
  does not transform. Display filters are v0.6.
* **`--count` is a limit, not a filter.** It stops reading, it does not skip.
* **There is a small window between checking a path and opening it.** NetSentry
  diagnoses filesystem problems with `std::fs` and then hands the path to
  libpcap, so a file replaced in between would produce a less precise error.
  For a read-only analysis that is the whole consequence.
* **Interface status comes straight from the driver's `UP`/`RUNNING` flags.**
  NetSentry does not consult platform-specific APIs to refine it. libpcap has
  reported these flags since 1.6.1 and Npcap reports them, but a driver that
  leaves them empty will make every interface read `down`. Reporting a guess
  would be worse than reporting the driver's silence.
* **Interface-level drop counts cannot be trusted to mean "none".** libpcap sets
  `ps_ifdrop` to zero on platforms that do not support it and gives no way to
  tell that apart from a genuine zero, so NetSentry prints the number with that
  caveat attached rather than presenting it as a fact. Driver statistics do not
  exist at all for a capture file, and are not shown there.
* **Permission errors on an interface are recognised by their text.** libpcap
  reports why an open failed as free-form English. Capture *file* errors do not
  rely on this: they are diagnosed with `std::fs` before libpcap is involved.
* **A missing Npcap installation cannot be reported as a friendly error on
  Windows.** `wpcap.dll` is resolved by the Windows loader before `main()` runs,
  so the process fails to start and Windows — not NetSentry — shows the error.
  This affects `read` as well as `capture`: the DLL must be present even for
  offline analysis, although the *driver* and Administrator rights are not.
* **IPv6 scope IDs are not shown** in the interface listing, because libpcap
  does not report them.
* **High packet rates are not tuned for.** Packets are read, decoded and printed
  one at a time. If the driver reports drops, the capture buffer was filling
  faster than NetSentry emptied it.

## Legal and ethical use

NetSentry is a traffic inspection tool. Captured traffic routinely contains
credentials, session cookies, DNS lookups and other personal data.

Only capture traffic on networks you own or have explicit written authorisation
to monitor. Intercepting communications without authorisation is a criminal
offence in most jurisdictions. You are responsible for how you use this tool.

### Capture files are sensitive

A `.pcap` file is a recording of a network. It routinely contains:

* every domain and IP address that was contacted,
* credentials and session tokens carried by plaintext protocols,
* authentication material and API keys,
* the internal layout of a private network — hosts, services, naming.

Treat a capture file as you would treat the traffic it came from. NetSentry
analyses it **entirely locally**. This version sends no capture data, and no
derivative of it, to any network service, AI service or telemetry endpoint —
it makes no outbound connections at all.

What NetSentry itself reads and writes:

* **`read`** opens the file read-only and never modifies it.
* **`capture`** prints headers only and writes nothing, unless `--write` names
  a file — in which case full packets including payload are saved, with a
  warning, at mode `0600`.

## Licence

MIT.
