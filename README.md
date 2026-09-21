# NetSentry

A network traffic analysis toolkit for security work, written in Rust.

NetSentry captures and inspects network traffic, groups it into conversations
between hosts, and explains *why* a piece of traffic looks suspicious. The
analysis engine is a plain Rust library with no UI dependencies; a desktop front
end is planned for a later version.

> **Status: v0.1 — under construction.**
> Today NetSentry can discover the network interfaces available for capture.
> Live packet capture is the next step.

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
netsentry list          # show the interfaces the capture driver can see
netsentry --help
netsentry list --help
```

Example output:

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
capture driver, and is what future commands will accept. The `[n]` index is a
convenience for humans and may change between runs — do not put it in a script.

## Privileges

Listing interfaces generally works as a normal user. *Capturing* packets does
not, and will require:

* **Windows** — an Administrator terminal, if Npcap was installed with
  *"Restrict Npcap driver's access to Administrators only"*.
* **Linux** — root, or `CAP_NET_RAW` and `CAP_NET_ADMIN` granted to the binary.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The project is a single crate split into a library and a thin binary:

| Path                    | Responsibility                                           |
| ----------------------- | -------------------------------------------------------- |
| `src/main.rs`           | Argument parsing, dispatch, exit code. No logic.          |
| `src/lib.rs`            | Library root and module layout.                           |
| `src/cli.rs`            | Command line *description* (clap types only).             |
| `src/error.rs`          | `NetSentryError` — typed failures with actionable hints.  |
| `src/capture/device.rs` | Interface discovery; converts driver data into our types. |
| `src/render.rs`         | Pure terminal formatting. No I/O.                         |

Layer dependencies point one way only, and `unsafe` code is `forbid`-den
crate-wide: the only unsafe code in the build lives inside the `pcap` crate's
FFI bindings.

## Known limitations (v0.1)

* **No packet capture yet.** `netsentry list` is the only command.
* **Interface status comes straight from the driver's `UP`/`RUNNING` flags.**
  NetSentry does not consult platform-specific APIs to refine it. libpcap has
  reported these flags since 1.6.1 and Npcap reports them, but a driver that
  leaves them empty will make every interface read `down`. Reporting a guess
  would be worse than reporting the driver's silence.
* **A missing Npcap installation cannot be reported as a friendly error on
  Windows.** `wpcap.dll` is resolved by the Windows loader before `main()` runs,
  so the process fails to start and Windows — not NetSentry — shows the error.
  Detecting this in-process would need delay-loaded imports; that platform
  specific machinery is deferred until it is worth its complexity.
* **IPv6 scope IDs are not shown**, because libpcap does not report them.

## Legal and ethical use

NetSentry is a traffic inspection tool. Captured traffic routinely contains
credentials, session cookies, DNS lookups and other personal data.

Only capture traffic on networks you own or have explicit written authorisation
to monitor. Intercepting communications without authorisation is a criminal
offence in most jurisdictions. You are responsible for how you use this tool.

## Licence

MIT.
