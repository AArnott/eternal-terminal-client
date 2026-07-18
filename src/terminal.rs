//! Local console: raw mode, size queries, UTF-8 I/O (Windows / Linux / macOS).

use std::io::{self, Write};
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use crate::proto::TerminalInfo;

pub struct LocalConsole {
    enabled: bool,
}

impl LocalConsole {
    pub fn new() -> anyhow::Result<Self> {
        terminal::enable_raw_mode()?;
        // Ensure we can read without blocking the whole process forever.
        Ok(Self { enabled: true })
    }

    pub fn setup(&self) -> anyhow::Result<()> {
        // Raw mode already enabled; clear is optional and can surprise users,
        // so we leave the screen as-is (matches typical ssh/et behaviour).
        let _ = cursor::Show;
        Ok(())
    }

    pub fn teardown(&mut self) {
        if self.enabled {
            let _ = terminal::disable_raw_mode();
            self.enabled = false;
        }
    }

    pub fn terminal_info(&self) -> TerminalInfo {
        let (cols, rows) = terminal::size().unwrap_or((80, 24));
        // Match official ET Windows client: only row/column (no pixel size).
        // Never send 0×0 — that can confuse remote TIOCSWINSZ.
        let cols = cols.max(1);
        let rows = rows.max(1);
        TerminalInfo {
            id: None,
            row: Some(rows as i32),
            column: Some(cols as i32),
            width: None,
            height: None,
        }
    }

    /// Poll for keyboard / paste input; returns UTF-8 bytes to send remotely.
    pub fn poll_input(&self, timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        if !event::poll(timeout)? {
            return Ok(None);
        }
        let mut out = Vec::new();
        // Drain ready events without waiting further.
        loop {
            match event::read()? {
                Event::Key(key) => {
                    if let Some(bytes) = key_to_bytes(key) {
                        out.extend_from_slice(&bytes);
                    }
                }
                Event::Paste(s) => out.extend_from_slice(s.as_bytes()),
                Event::Resize(_, _) => {
                    // Caller notices via terminal_info() change.
                }
                Event::Mouse(_) | Event::FocusGained | Event::FocusLost => {}
            }
            if !event::poll(Duration::from_millis(0))? {
                break;
            }
        }
        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }

    pub fn write(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut stdout = io::stdout();
        stdout.write_all(data)?;
        stdout.flush()?;
        Ok(())
    }
}

impl Drop for LocalConsole {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn key_to_bytes(key: KeyEvent) -> Option<Vec<u8>> {
    // On Windows, crossterm may emit both Press and Repeat; ignore Release.
    if key.kind == KeyEventKind::Release {
        return None;
    }

    let mods = key.modifiers;
    let ctrl = mods.contains(KeyModifiers::CONTROL);

    match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                let b = (c.to_ascii_lowercase() as u8).wrapping_sub(b'a').wrapping_add(1);
                if (1..=26).contains(&b) {
                    return Some(vec![b]);
                }
            }
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            Some(s.as_bytes().to_vec())
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Insert => Some(b"\x1b[2~".to_vec()),
        KeyCode::F(n) => {
            let seq = match n {
                1 => "\x1bOP",
                2 => "\x1bOQ",
                3 => "\x1bOR",
                4 => "\x1bOS",
                5 => "\x1b[15~",
                6 => "\x1b[17~",
                7 => "\x1b[18~",
                8 => "\x1b[19~",
                9 => "\x1b[20~",
                10 => "\x1b[21~",
                11 => "\x1b[23~",
                12 => "\x1b[24~",
                _ => return None,
            };
            Some(seq.as_bytes().to_vec())
        }
        _ => None,
    }
}

