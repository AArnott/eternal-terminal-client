//! Host / user / port parsing for `user@host[:port]` arguments.

use std::env;

#[derive(Debug, Clone)]
pub struct Destination {
    pub user: String,
    pub host: String,
    /// Host string used for SSH (may be an ssh_config alias).
    pub host_alias: String,
    pub et_port: u16,
}

/// Parse `[user@]host[:port]` with basic IPv6 awareness.
///
/// - `user@host` / `user@host:2022`
/// - IPv6 with `::` abbreviation cannot include a trailing port (use `-p`).
/// - Fully expanded IPv6 with 8 colons treats the last segment as the port.
pub fn parse_destination(
    host_arg: &str,
    default_user: Option<&str>,
    default_port: u16,
) -> anyhow::Result<Destination> {
    let mut user = default_user.unwrap_or("").to_string();
    let mut host_arg = host_arg.to_string();

    if let Some(i) = host_arg.find('@') {
        user = host_arg[..i].to_string();
        host_arg = host_arg[i + 1..].to_string();
    }

    let mut et_port = default_port;
    let colon_count = host_arg.matches(':').count();

    if colon_count == 1 {
        // hostname or ipv4 with port
        if let Some(pos) = host_arg.rfind(':') {
            et_port = host_arg[pos + 1..]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port in host argument"))?;
            host_arg = host_arg[..pos].to_string();
        }
    } else if colon_count >= 2 {
        if host_arg.contains("::") {
            // abbreviated IPv6 without port
        } else if colon_count == 7 {
            // fully expanded IPv6 without port
        } else if colon_count == 8 {
            if let Some(pos) = host_arg.rfind(':') {
                et_port = host_arg[pos + 1..]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid port in host argument"))?;
                host_arg = host_arg[..pos].to_string();
            }
        } else {
            anyhow::bail!("invalid host positional arg: {host_arg}");
        }
    }

    if user.is_empty() {
        user = local_username();
    }

    let host_alias = host_arg.clone();
    Ok(Destination {
        user,
        host: host_arg,
        host_alias,
        et_port,
    })
}

pub fn local_username() -> String {
    env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "user".into())
}

pub fn client_term() -> String {
    env::var("TERM").unwrap_or_else(|_| "xterm-256color".into())
}
