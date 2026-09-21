# NetSentry

A network traffic analysis toolkit for security work, written in Rust.

NetSentry captures and inspects network traffic, groups it into conversations
between hosts, and explains *why* a piece of traffic looks suspicious. The
analysis engine is a plain Rust library with no UI dependencies; a desktop front
end is planned for a later version.

> **Status: v0.1 — under construction.**
> NetSentry can list capture interfaces and capture live packets, reporting one
> line of metadata per packet. Decoding those packets is v0.2's job.

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
$ netsentry capture -i 1 --count 5
NetSentry 0.1.0 — live capture

[*] interface   : eth0
[*] link type   : EN10MB (Ethernet)
[*] snaplen     : 65535 bytes
[*] promiscuous : on
[*] stop after  : 5 packets
[*] clock       : UTC
[*] payload     : not captured for display — metadata only

     1  13:23:13.769676  caplen=695  wirelen=695
     2  13:23:13.769720  caplen=66  wirelen=66
     3  13:23:13.792817  caplen=66  wirelen=66
     4  13:23:13.793052  caplen=66  wirelen=66
     5  13:23:14.016828  caplen=66  wirelen=66

[*] Capture finished (packet count reached).

    packets captured     : 5
    captured bytes       : 959
    wire bytes           : 959
    elapsed              : 0.347s
    started at           : 2026-09-21 13:23:13.669101 UTC

    driver statistics
      received           : 5
      dropped (buffer)   : 0
      dropped (interface): 0
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

Packet **contents are never read for display, written to disk, or logged** —
only metadata (timestamp, captured length, wire length) leaves the capture
layer. Captured traffic routinely contains credentials, session cookies and
other personal data, so until there is a reason to handle payload bytes, this
version does not handle them at all. Protocol decoding arrives in v0.2.

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
| `src/render/`              | Pure terminal formatting. No I/O.                     |

Layer dependencies point one way only, and `unsafe` code is `forbid`-den
crate-wide: the only unsafe code in the build lives inside the `pcap` crate's
FFI bindings.

## Known limitations (v0.1)

* **Packets are not decoded.** Only metadata is reported; there is no Ethernet,
  IP, TCP, UDP or DNS parsing yet. That is v0.2.
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
  Detecting this in-process would need delay-loaded imports; that platform
  specific machinery is deferred until it is worth its complexity.
* **IPv6 scope IDs are not shown**, because libpcap does not report them.
* **High packet rates are not tuned for.** Packets are read and printed one at
  a time. If the driver reports drops, the capture buffer was filling faster
  than NetSentry emptied it; batching reads is a later optimisation.

## Legal and ethical use

NetSentry is a traffic inspection tool. Captured traffic routinely contains
credentials, session cookies, DNS lookups and other personal data.

Only capture traffic on networks you own or have explicit written authorisation
to monitor. Intercepting communications without authorisation is a criminal
offence in most jurisdictions. You are responsible for how you use this tool.

This version reads packet metadata only, and never prints, stores or logs packet
contents. That reduces the exposure but does not remove it: even metadata
reveals who talks to whom, when, and how much.

## Licence

MIT.
