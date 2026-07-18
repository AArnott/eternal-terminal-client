# Eternal Terminal client (Rust)

[![CI](https://github.com/AArnott/eternal-terminal-client/actions/workflows/ci.yml/badge.svg)](https://github.com/AArnott/eternal-terminal-client/actions/workflows/ci.yml)

A **Windows-first** [Eternal Terminal](https://eternalterminal.dev/) client written in Rust. It also builds and runs on **Linux** and **macOS**.

Eternal Terminal (ET) is a remote shell that automatically reconnects without interrupting the session. This client speaks the same wire protocol as the official [`MisterTea/EternalTerminal`](https://github.com/MisterTea/EternalTerminal) client (protocol version **6**).

## Install

### Prebuilt binaries

Download the latest release from [GitHub Releases](https://github.com/AArnott/eternal-terminal-client/releases):

| Platform | Asset |
|----------|--------|
| Windows x64 | `et-x86_64-pc-windows-msvc.exe` |
| Windows ARM64 | `et-aarch64-pc-windows-msvc.exe` |
| Linux x64 | `et-x86_64-unknown-linux-gnu` |
| macOS Apple Silicon | `et-aarch64-apple-darwin` |
| macOS Intel | `et-x86_64-apple-darwin` |

Rename to `et` / `et.exe` and put it on your `PATH`.

### Versioning

**Single source of truth:** `[package].version` in `Cargo.toml`.

That value is embedded in:

- `et --version` (`CARGO_PKG_VERSION`)
- Windows PE **File Properties → Details** (File version, Product version, description, copyright, language) via `build.rs` + `winresource`

**Release checklist:**

1. Bump `version` in `Cargo.toml` (and commit).
2. Tag the same value with a `v` prefix: `git tag v0.2.0 && git push origin v0.2.0`
3. The **Release** workflow **fails** if the tag does not match `Cargo.toml` (prevents shipping a binary whose File Properties say `0.1.0` under a `v0.2.0` tag).

Do **not** retag over an old version; cut a new version instead so winget hashes and PE metadata stay immutable.

### Build from source

```powershell
# Windows (PowerShell)
cargo build --release
# binary: target\release\et.exe
```

```bash
# Linux / macOS
cargo build --release
# binary: target/release/et
```

## Requirements

### Client (this binary)

- OpenSSH client on `PATH` (`ssh`) — used only for the initial bootstrap (same as official ET)
- On Windows: OpenSSH is included with modern Windows, or install via Optional Features / Git for Windows
- To build from source: Rust 1.75+ (edition 2021)

### Server (remote host)

- Official **etserver** listening (default TCP **2022**)
- **etterminal** on the remote `PATH` (or pass `--terminal-path`)
- Working `ssh` login from this machine to the remote host

## Usage

```text
et [OPTIONS] [user@]host[:port]
```

| Flag | Description |
|------|-------------|
| `-u, --username` | Remote user |
| `-p, --port` | etserver port (default `2022`) |
| `-c, --command` | Run a command after connect |
| `-e, --noexit` | With `-c`, keep the session open |
| `-x, --kill-other-sessions` | Kill other `etterminal` sessions for the user |
| `-k, --keepalive` | Keepalive interval seconds (1–5, default 5) |
| `-N, --no-terminal` | Do not attach a local terminal |
| `-v, --verbose` | Log verbosity 0–4 |
| `--terminal-path` | Path to `etterminal` on the server |
| `--macserver` | Shortcut: terminal path `/usr/local/bin/etterminal` |
| `--jumphost` | SSH jumphost / ProxyJump host |
| `--jport` | etserver port on the jumphost |
| `--ssh-option` | Extra `ssh -o` options (repeatable) |

Examples:

```powershell
et user@myserver
et -p 2022 user@myserver
et -c "htop" user@myserver
et --ssh-option "Port=2222" user@myserver
et --jumphost jump.example.com user@internal
```

## How it works

1. **Ping** TCP `host:2022` (etserver).
2. **SSH** to the host and run  
   `echo 'XXX…/passkey_TERM' | etterminal`  
   then parse `IDPASSKEY:id/passkey` from the output.
3. Open a TCP connection to etserver and send an unencrypted **ConnectRequest** (client id + protocol version).
4. Exchange **InitialPayload** / **InitialResponse** over the encrypted EternalTCP stream (libsodium `crypto_secretbox` / XSalsa20-Poly1305, passkey as the 32-byte key).
5. Shuttle local terminal I/O as **TerminalBuffer** packets; send **TerminalInfo** on resize; **KEEP_ALIVE** for liveness.
6. On disconnect, reconnect with the same client id, exchange **SequenceHeader** + **CatchupBuffer**, and continue the session.

## Platform notes

### Windows

- Built and tested as a first-class target (`x86_64-pc-windows-msvc`).
- Console uses Win32 VT raw input/output (Windows Terminal, conhost, etc.).
- Uses system OpenSSH (`ssh.exe`).

### Linux / macOS

- Same networking, crypto, and protocol code paths.
- Terminal: raw mode + byte-stream stdin (`poll`/`read`).

## Status / limitations

Implemented:

- Connect, encrypt, interactive shell, window resize, keepalive, automatic reconnect
- SSH bootstrap with optional jumphost (`-J`), kill-other-sessions, custom etterminal path
- CLI parity for common flags

Not yet implemented (server may still accept the session):

- Forward / reverse port tunnels (`-t` / `-r`)
- SSH agent forwarding
- Full `ssh_config` parsing (HostName, ProxyJump, LocalForward, …) — pass options with `--ssh-option` for now

## License

MIT. Protocol and design follow Eternal Terminal by Jason Gauci / MisterTea.
