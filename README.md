# NetSentry

A network traffic analysis toolkit for security work, written in Rust.

NetSentry captures and inspects network traffic, groups it into conversations
between hosts, and explains *why* a piece of traffic looks suspicious. The
analysis engine is a plain Rust library with no UI dependencies; a desktop front
end is planned for a later version.

> **Status: v0.2 — under construction.**
> NetSentry can list capture interfaces, capture live packets and decode them
> down to the transport layer. Grouping packets into conversations is v0.4's
> job; detecting suspicious behaviour is v0.7's.

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
netsentry list                       # show the interfaces the capture driver can see
netsentry capture -i 1               # capture until Ctrl+C
netsentry capture -i 1 --count 20    # capture 20 packets, then stop
netsentry capture -i eth0            # interfaces can be named instead of numbered
netsentry --help
netsentry capture --help
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

### What this version does not do

Packet **payload is never printed, written to disk, or logged.** Headers are
decoded and described; the bytes after them are not read at all. Captured
traffic routinely contains credentials, session cookies and other personal
data, so until there is a reason to handle payload bytes, NetSentry does not
handle them.

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
| `src/capture/timestamp.rs` | Packet timestamps and their conversion to text.       |
| `src/decode/bytes.rs`      | The bounds-checked cursor all parsing goes through.   |
| `src/decode/link.rs`       | Ethernet, VLAN and Linux cooked-capture decoding.     |
| `src/decode/net.rs`        | IPv4, IPv6 and ARP decoding.                          |
| `src/decode/transport.rs`  | TCP, UDP and ICMP decoding.                           |
| `src/decode/model.rs`      | The decoded-packet domain model.                      |
| `src/render/`              | Pure terminal formatting. No I/O.                     |

Layer dependencies point one way only — `render` above `decode` above
`capture` — and `unsafe` code is `forbid`-den crate-wide: the only unsafe code
in the build lives inside the `pcap` crate's FFI bindings.

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

### Capture

* **Captures cannot be saved or loaded.** `.pcap` support is v0.3.
* **Interface status comes straight from the driver's `UP`/`RUNNING` flags.**
  NetSentry does not consult platform-specific APIs to refine it. libpcap has
  reported these flags since 1.6.1 and Npcap reports them, but a driver that
  leaves them empty will make every interface read `down`. Reporting a guess
  would be worse than reporting the driver's silence.
* **Interface-level drop counts cannot be trusted to mean "none".** libpcap sets
  `ps_ifdrop` to zero on platforms that do not support it and gives no way to
  tell that apart from a genuine zero, so NetSentry prints the number with that
  caveat attached rather than presenting it as a fact.
* **Permission errors are recognised by their text.** libpcap reports why an
  open failed as free-form English, so the "not allowed to capture" message is a
  best-effort reading of it. The generic open error mentions privileges too.
* **A missing Npcap installation cannot be reported as a friendly error on
  Windows.** `wpcap.dll` is resolved by the Windows loader before `main()` runs,
  so the process fails to start and Windows — not NetSentry — shows the error.
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

This version reads packet **headers** only. Payload is never printed, stored or
logged, and is not even kept in memory past the moment a packet is decoded. That
reduces the exposure but does not remove it: headers alone reveal who talks to
whom, when, how often and how much — which is frequently more than enough to
identify people and what they were doing.

## Licence

MIT.
