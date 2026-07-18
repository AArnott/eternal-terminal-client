//! Eternal Terminal client (`et`) — Windows-first, also Linux and macOS.
//!
//! Wire-compatible with [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal)
//! protocol version 6: SSH bootstrap → TCP:2022 → libsodium secretbox → EternalTCP.

mod backed;
mod client;
mod connection;
mod crypto;
mod host;
mod packet;
mod proto;
mod ssh_setup;
mod terminal;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;

use client::{run_session, ClientOptions};
use connection::{ping_server, ClientConnection};
use host::parse_destination;
use ssh_setup::{setup_ssh, SshSetupOptions};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "et",
    version = VERSION,
    about = "Eternal Terminal client — remote shell that reconnects without interrupting the session",
    long_about = "Connect to a host running etserver (default port 2022).\n\
                  Uses ssh to start etterminal, then an encrypted EternalTCP session.\n\n\
                  Windows is a first-class target; Linux and macOS are also supported."
)]
struct Cli {
    /// Remote destination: [user@]host[:port]
    #[arg(value_name = "DESTINATION")]
    host: String,

    /// Remote username (overrides user@ in DESTINATION)
    #[arg(short = 'u', long = "username")]
    username: Option<String>,

    /// Remote etserver port
    #[arg(short = 'p', long = "port", default_value_t = 2022)]
    port: u16,

    /// Run command on connect (then exit unless --noexit)
    #[arg(short = 'c', long = "command")]
    command: Option<String>,

    /// With -c, do not exit after the command
    #[arg(short = 'e', long = "noexit")]
    noexit: bool,

    /// Path to etterminal on the server
    #[arg(long = "terminal-path")]
    terminal_path: Option<String>,

    /// Set --terminal-path=/usr/local/bin/etterminal (macOS server convenience)
    #[arg(long = "macserver")]
    macserver: bool,

    /// Kill other etterminal sessions for this user on the server
    #[arg(short = 'x', long = "kill-other-sessions")]
    kill_other_sessions: bool,

    /// Jumphost: [user@]host[:ssh_port] (SSH ProxyJump style)
    #[arg(long = "jumphost")]
    jumphost: Option<String>,

    /// etserver port on the jumphost
    #[arg(long = "jport", default_value_t = 2022)]
    jport: u16,

    /// Client keepalive interval in seconds (1–5)
    #[arg(short = 'k', long = "keepalive", default_value_t = 5)]
    keepalive: u64,

    /// Do not attach a local terminal (useful for port-forward-only style use)
    #[arg(short = 'N', long = "no-terminal")]
    no_terminal: bool,

    /// Verbose logging (0–4)
    #[arg(short = 'v', long = "verbose", default_value_t = 0)]
    verbose: u8,

    /// Extra ssh -o options (repeatable)
    #[arg(long = "ssh-option", value_name = "OPT")]
    ssh_option: Vec<String>,

    /// Server fifo path passed to etterminal
    #[arg(long = "serverfifo")]
    server_fifo: Option<String>,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("et: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose);

    let dest = parse_destination(&cli.host, cli.username.as_deref(), cli.port)?;
    // CLI -p overrides destination port only when host had no :port and user set -p.
    // parse_destination already applied default; re-apply explicit -p when host had no port.
    let mut dest = dest;
    if !cli.host.contains(':') || cli.host.matches(':').count() >= 2 && cli.host.contains("::") {
        // keep parse result for IPv6; for simple hosts allow -p override
        if !cli_host_has_explicit_port(&cli.host) {
            dest.et_port = cli.port;
        }
    } else if !cli_host_has_explicit_port(&cli.host) {
        dest.et_port = cli.port;
    }

    let (connect_host, connect_port, jumphost_mode) = if let Some(ref jump) = cli.jumphost {
        // Traffic goes to jumphost etserver; destination is reached via jump.
        let jump_host = jump_hostname(jump);
        (jump_host, cli.jport, true)
    } else {
        (dest.host.clone(), dest.et_port, false)
    };

    eprintln!(
        "Connecting to etserver at {connect_host}:{connect_port} (user {}, ssh host {})...",
        dest.user, dest.host_alias
    );

    if !ping_server(&connect_host, connect_port) {
        anyhow::bail!(
            "could not reach the ET server: {connect_host}:{connect_port}\n\
             Ensure etserver is running and the port is reachable (default 2022)."
        );
    }

    let mut etterminal_path = cli.terminal_path.clone();
    if cli.macserver && etterminal_path.is_none() {
        etterminal_path = Some("/usr/local/bin/etterminal".into());
    }

    let keys = setup_ssh(&SshSetupOptions {
        user: dest.user.clone(),
        host_alias: dest.host_alias.clone(),
        kill_other_sessions: cli.kill_other_sessions,
        verbose: cli.verbose,
        etterminal_path,
        server_fifo: cli.server_fifo.clone(),
        ssh_options: cli.ssh_option.clone(),
        jumphost: cli.jumphost.clone(),
    })?;

    log::info!(
        "got session id={} (passkey len={})",
        keys.id,
        keys.passkey.len()
    );

    let conn = ClientConnection::new(connect_host, connect_port, keys.id, keys.passkey);

    let mut attempts = 0;
    loop {
        match conn.connect() {
            Ok(()) => break,
            Err(e) => {
                attempts += 1;
                if attempts >= 3 {
                    anyhow::bail!("could not make initial connection: {e}");
                }
                log::warn!("connect attempt {attempts} failed: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
        })
        .ok();
    }

    let result = run_session(
        &conn,
        ClientOptions {
            command: cli.command,
            no_exit: cli.noexit,
            keepalive_secs: cli.keepalive,
            jumphost: jumphost_mode,
            no_terminal: cli.no_terminal,
        },
        Arc::clone(&shutdown),
    );

    conn.shutdown();
    result
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    // Prefer RUST_LOG if set.
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    builder.format_timestamp_secs();
    let _ = builder.try_init();
}

fn cli_host_has_explicit_port(host: &str) -> bool {
    let colons = host.matches(':').count();
    if colons == 1 {
        return true;
    }
    if colons == 8 {
        return true;
    }
    false
}

fn jump_hostname(jump: &str) -> String {
    // Strip user@ and :port for TCP connect to jumphost etserver.
    let mut s = jump;
    if let Some(i) = s.find('@') {
        s = &s[i + 1..];
    }
    // If single colon port suffix on hostname, strip it (SSH port, not et port).
    if s.matches(':').count() == 1 {
        if let Some(pos) = s.rfind(':') {
            // Only strip if the suffix looks like a port number.
            if s[pos + 1..].parse::<u16>().is_ok() {
                return s[..pos].to_string();
            }
        }
    }
    s.to_string()
}
