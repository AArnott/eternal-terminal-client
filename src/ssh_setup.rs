//! SSH bootstrap: launch `etterminal` on the remote host and recover id/passkey.

use std::io::Write;
use std::process::{Command, Stdio};

use rand::RngExt;

use crate::host::client_term;

const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn gen_random_alphanum(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let i = rng.random_range(0..ALPHANUM.len());
            ALPHANUM[i] as char
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub id: String,
    pub passkey: String,
}

#[derive(Debug, Clone)]
pub struct SshSetupOptions {
    pub user: String,
    pub host_alias: String,
    pub kill_other_sessions: bool,
    pub verbose: u8,
    pub etterminal_path: Option<String>,
    pub server_fifo: Option<String>,
    pub ssh_options: Vec<String>,
    pub jumphost: Option<String>,
}

/// Run interactive SSH to start etterminal and parse `IDPASSKEY:id/passkey`.
pub fn setup_ssh(opts: &SshSetupOptions) -> anyhow::Result<SessionKeys> {
    // "XXX" prefix tells modern servers to regenerate id/passkey.
    let mut id_bytes = gen_random_alphanum(16).into_bytes();
    id_bytes[0] = b'X';
    id_bytes[1] = b'X';
    id_bytes[2] = b'X';
    let mut id = String::from_utf8(id_bytes).expect("alphanumeric id");
    let mut passkey = gen_random_alphanum(32);

    let term = client_term();
    let etterminal = opts.etterminal_path.as_deref().unwrap_or("etterminal");

    let mut cmdoptions = format!("--verbose={}", opts.verbose);
    if let Some(ref fifo) = opts.server_fifo {
        cmdoptions.push_str(" --serverfifo=");
        cmdoptions.push_str(fifo);
    }

    let mut remote_cmd = String::new();
    if opts.kill_other_sessions {
        remote_cmd.push_str(&format!("pkill etterminal -u {}; sleep 0.5; ", opts.user));
    }
    remote_cmd.push_str(&format!(
        "echo '{id}/{passkey}_{term}' | {etterminal} {cmdoptions}"
    ));

    let mut ssh_args: Vec<String> = Vec::new();
    if let Some(ref jump) = opts.jumphost {
        ssh_args.push("-J".into());
        ssh_args.push(jump.clone());
    }

    let dest = if opts.user.is_empty() {
        opts.host_alias.clone()
    } else {
        format!("{}@{}", opts.user, opts.host_alias)
    };
    ssh_args.push(dest);

    for opt in &opts.ssh_options {
        ssh_args.push(format!("-o{opt}"));
    }
    ssh_args.push(remote_cmd);

    log::debug!("ssh {}", ssh_args.join(" "));

    let output = run_ssh_interactive(&ssh_args)?;
    if output.trim().is_empty() {
        anyhow::bail!(
            "error starting ET through ssh — ensure `ssh` works and etterminal is installed on the server"
        );
    }

    let (new_id, new_pass) = parse_idpasskey(&output)?;
    id = new_id;
    passkey = new_pass;

    if id.is_empty() || passkey.is_empty() {
        anyhow::bail!("missing id or passkey from server");
    }
    if id.len() != 16 || passkey.len() != 32 {
        log::warn!(
            "unexpected id/passkey lengths: {} / {} (continuing)",
            id.len(),
            passkey.len()
        );
    }

    Ok(SessionKeys { id, passkey })
}

fn parse_idpasskey(ssh_buffer: &str) -> anyhow::Result<(String, String)> {
    let marker = "IDPASSKEY:";
    let Some(idx) = ssh_buffer.find(marker) else {
        anyhow::bail!(
            "error authenticating with etserver (no IDPASSKEY in output). \
             Avoid printing from .bashrc/.zshrc. Server output:\n{ssh_buffer}"
        );
    };
    let start = idx + marker.len();
    // id (16) + '/' + passkey (32)
    let slice = ssh_buffer
        .get(start..start + 16 + 1 + 32)
        .ok_or_else(|| anyhow::anyhow!("truncated IDPASSKEY payload"))?;
    let mut parts = slice.splitn(2, '/');
    let id = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing id"))?
        .to_string();
    let passkey = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing passkey"))?
        .trim()
        .to_string();
    // passkey may include trailing junk if lengths differ; take first 32 alphanum
    let passkey = passkey
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(32)
        .collect();
    Ok((id, passkey))
}

fn run_ssh_interactive(args: &[String]) -> anyhow::Result<String> {
    // Inherit stdin so password / agent prompts work. Capture stdout+stderr
    // combined because etterminal may write IDPASSKEY to either.
    let mut child = Command::new("ssh")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!("failed to spawn ssh: {e}. Is OpenSSH installed and on PATH?")
        })?;

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        out.read_to_string(&mut stdout)?;
    }

    let status = child.wait()?;
    if !status.success() && stdout.is_empty() {
        anyhow::bail!("ssh exited with {status}");
    }

    // Also scan stderr-merged content isn't available; IDPASSKEY is on stdout.
    let _ = std::io::stderr().flush();
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_idpasskey_basic() {
        let id = "XXXabcdefghijkl";
        let pass = "0123456789abcdef0123456789abcdef";
        let buf = format!("noise\nIDPASSKEY:{id}/{pass}\nmore");
        let (i, p) = parse_idpasskey(&buf).unwrap();
        assert_eq!(i, id);
        assert_eq!(p, pass);
    }
}
