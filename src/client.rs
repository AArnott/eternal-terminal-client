//! High-level terminal client run loop (INITIAL_PAYLOAD + I/O + keepalive).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::connection::ClientConnection;
use crate::packet::Packet;
use crate::proto::{
    et_packet, terminal_packet, InitialPayload, InitialResponse, ProtoMessage, TerminalBuffer,
    TerminalInfo,
};
use crate::terminal::LocalConsole;

const DEFAULT_KEEPALIVE_SECS: u64 = 5;

pub struct ClientOptions {
    pub command: Option<String>,
    pub no_exit: bool,
    pub keepalive_secs: u64,
    pub jumphost: bool,
    pub no_terminal: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            command: None,
            no_exit: false,
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
            jumphost: false,
            no_terminal: false,
        }
    }
}

pub fn run_session(
    conn: &ClientConnection,
    opts: ClientOptions,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // INITIAL_PAYLOAD
    let payload = InitialPayload {
        jumphost: Some(opts.jumphost).filter(|&j| j),
        reverse_tunnels: Vec::new(),
        environment_variables: Default::default(),
    };
    if !conn.write_packet(Packet::new(et_packet::INITIAL_PAYLOAD, payload.encode())) {
        anyhow::bail!("failed to send initial payload");
    }

    // Wait for INITIAL_RESPONSE (up to ~3s)
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut got_response = false;
    while Instant::now() < deadline {
        if let Some(pkt) = conn.read_packet()? {
            if pkt.header() != et_packet::INITIAL_RESPONSE {
                anyhow::bail!("expected INITIAL_RESPONSE, got header {}", pkt.header());
            }
            let resp = InitialResponse::decode(pkt.payload())?;
            if let Some(err) = resp.error {
                if !err.is_empty() {
                    anyhow::bail!("error initializing connection: {err}");
                }
            }
            got_response = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !got_response {
        anyhow::bail!("connect timeout waiting for INITIAL_RESPONSE");
    }

    log::info!("session established (id={})", conn.id());

    let mut console = if opts.no_terminal {
        None
    } else {
        Some(LocalConsole::new()?)
    };

    if let Some(ref cmd) = opts.command {
        let body = if opts.no_exit {
            format!("{cmd}\n")
        } else {
            format!("{cmd}; exit\n")
        };
        let tb = TerminalBuffer {
            buffer: Some(body.into_bytes()),
        };
        conn.write_packet(Packet::new(terminal_packet::TERMINAL_BUFFER, tb.encode()));
    }

    if console.is_none() {
        eprintln!("ET running, feel free to background...");
    }

    let keepalive_duration = Duration::from_secs(opts.keepalive_secs.clamp(1, 5));
    let mut keepalive_deadline = Instant::now() + keepalive_duration;
    let mut waiting_on_keepalive = false;
    let mut last_ti = TerminalInfo::default();

    while !conn.is_shutting_down() && !shutdown.load(Ordering::SeqCst) {
        // Network first: drain remote output before waiting on local input so a
        // stalled console read cannot leave the shell prompt sitting unread.
        if conn.has_socket() {
            let mut coalesced = Vec::new();
            while let Some(pkt) = conn.read_packet()? {
                match pkt.header() {
                    terminal_packet::TERMINAL_BUFFER => {
                        if console.is_some() {
                            let tb = TerminalBuffer::decode(pkt.payload())?;
                            if let Some(buf) = tb.buffer {
                                coalesced.extend_from_slice(&buf);
                            }
                            keepalive_deadline = Instant::now() + keepalive_duration;
                        }
                    }
                    terminal_packet::KEEP_ALIVE => {
                        waiting_on_keepalive = false;
                        log::debug!("got keepalive");
                    }
                    h if h == et_packet::HEARTBEAT => {
                        // legacy
                    }
                    h => {
                        log::warn!("unknown packet type: {h}");
                    }
                }
            }
            if let Some(ref console) = console {
                if !coalesced.is_empty() {
                    console.write(&coalesced)?;
                }
            }

            // Keepalive
            if Instant::now() >= keepalive_deadline {
                keepalive_deadline = Instant::now() + keepalive_duration;
                if waiting_on_keepalive {
                    log::info!("missed keepalive, forcing reconnect");
                    conn.close_and_maybe_reconnect();
                    waiting_on_keepalive = false;
                } else {
                    log::debug!("writing keepalive");
                    conn.write_packet(Packet::new(terminal_packet::KEEP_ALIVE, Vec::new()));
                    waiting_on_keepalive = true;
                }
            }
        } else {
            waiting_on_keepalive = false;
        }

        // Local input (timeout also paces the loop when idle).
        if let Some(ref console) = console {
            match console.poll_input(Duration::from_millis(5)) {
                Ok(Some(bytes)) => {
                    let tb = TerminalBuffer {
                        buffer: Some(bytes),
                    };
                    conn.write_packet(Packet::new(terminal_packet::TERMINAL_BUFFER, tb.encode()));
                    keepalive_deadline = Instant::now() + keepalive_duration;
                }
                Ok(None) => {}
                Err(e) => {
                    log::info!("console input error: {e}");
                    break;
                }
            }

            let ti = console.terminal_info();
            if ti != last_ti {
                last_ti = ti.clone();
                conn.write_packet(Packet::new(terminal_packet::TERMINAL_INFO, ti.encode()));
            }
        } else if !conn.has_socket() {
            std::thread::sleep(Duration::from_millis(50));
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    if let Some(ref mut c) = console {
        c.teardown();
    }
    eprintln!("\r\nSession terminated");
    Ok(())
}
