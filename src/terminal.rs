//! Local console: raw mode, size queries, raw-byte I/O (Windows / Linux / macOS).
//!
//! Input is read as a **byte stream**, not parsed key events. That is required so
//! terminal replies (Device Attributes, cursor position reports, bracketed paste,
//! mouse, etc.) reach the remote app intact. Parsing keys via crossterm was
//! stripping ESC from sequences like `\x1b[?61;…c`, so editors such as `fresh`
//! inserted `[?61;…]` into the buffer as if it were typed text.
//!
//! On Windows, console input is polled carefully: mouse/focus/menu/key-up records
//! are drained with `ReadConsoleInput` before any `ReadFile`. Otherwise
//! `WaitForSingleObject` returns for those records while `ReadFile` blocks until
//! a real key arrives, freezing the session loop so remote output (e.g. the shell
//! prompt after exiting `fresh`) is not drawn until Enter.

use std::io::{self, Write};
use std::time::Duration;

use crate::proto::TerminalInfo;

pub struct LocalConsole {
    enabled: bool,
    #[cfg(windows)]
    saved_in_mode: u32,
    #[cfg(windows)]
    saved_out_mode: u32,
}

impl LocalConsole {
    pub fn new() -> anyhow::Result<Self> {
        let mut c = Self {
            enabled: false,
            #[cfg(windows)]
            saved_in_mode: 0,
            #[cfg(windows)]
            saved_out_mode: 0,
        };
        c.setup()?;
        Ok(c)
    }

    pub fn setup(&mut self) -> anyhow::Result<()> {
        if self.enabled {
            return Ok(());
        }
        platform::enable_raw(&mut *self)?;
        self.enabled = true;
        Ok(())
    }

    pub fn teardown(&mut self) {
        if !self.enabled {
            return;
        }
        let _ = platform::disable_raw(self);
        self.enabled = false;
    }

    pub fn terminal_info(&self) -> TerminalInfo {
        platform::terminal_size()
    }

    /// Poll for input bytes to send to the remote (including VT replies).
    pub fn poll_input(&self, timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        platform::poll_stdin(timeout)
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

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ptr;
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, PeekConsoleInputW,
        ReadConsoleInputW, SetConsoleMode, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        ENABLE_WRAP_AT_EOL_OUTPUT, FOCUS_EVENT, INPUT_RECORD, KEY_EVENT, MENU_EVENT, MOUSE_EVENT,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WINDOW_BUFFER_SIZE_EVENT,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    // DISABLE_NEWLINE_AUTO_RETURN is 0x0008 in recent SDKs (not always in windows-sys).
    const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;

    pub(super) fn enable_raw(console: &mut LocalConsole) -> anyhow::Result<()> {
        unsafe {
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            let h_out = GetStdHandle(STD_OUTPUT_HANDLE);

            let mut in_mode = 0u32;
            let mut out_mode = 0u32;
            if GetConsoleMode(h_in, &mut in_mode) == 0 {
                anyhow::bail!("GetConsoleMode(stdin) failed: {}", GetLastError());
            }
            if GetConsoleMode(h_out, &mut out_mode) == 0 {
                anyhow::bail!("GetConsoleMode(stdout) failed: {}", GetLastError());
            }
            console.saved_in_mode = in_mode;
            console.saved_out_mode = out_mode;

            // Match official ET Windows client: raw input + VT input so host
            // DA/CPR replies and keyboard VT sequences arrive as a byte stream
            // via ReadFile (not KEY_EVENT records alone).
            let raw_in = (in_mode
                & !(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            if SetConsoleMode(h_in, raw_in) == 0 {
                anyhow::bail!("SetConsoleMode(stdin) failed: {}", GetLastError());
            }

            let raw_out = out_mode
                | ENABLE_PROCESSED_OUTPUT
                | ENABLE_WRAP_AT_EOL_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                | DISABLE_NEWLINE_AUTO_RETURN;
            if SetConsoleMode(h_out, raw_out) == 0 {
                // Retry without DISABLE_NEWLINE_AUTO_RETURN on older hosts.
                let raw_out = out_mode
                    | ENABLE_PROCESSED_OUTPUT
                    | ENABLE_WRAP_AT_EOL_OUTPUT
                    | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if SetConsoleMode(h_out, raw_out) == 0 {
                    anyhow::bail!("SetConsoleMode(stdout) failed: {}", GetLastError());
                }
            }

            // Reassert DECAWM (auto-wrap) after DISABLE_NEWLINE_AUTO_RETURN —
            // same as official ET.
            let mut stdout = io::stdout();
            stdout.write_all(b"\x1b[?7h")?;
            stdout.flush()?;
        }
        Ok(())
    }

    pub(super) fn disable_raw(console: &LocalConsole) -> anyhow::Result<()> {
        unsafe {
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
            let _ = SetConsoleMode(h_in, console.saved_in_mode);
            let _ = SetConsoleMode(h_out, console.saved_out_mode);
        }
        Ok(())
    }

    pub(super) fn terminal_size() -> TerminalInfo {
        unsafe {
            let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut csbi: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(h_out, &mut csbi) == 0 {
                return TerminalInfo {
                    id: None,
                    row: Some(24),
                    column: Some(80),
                    width: None,
                    height: None,
                };
            }
            let cols = (csbi.srWindow.Right - csbi.srWindow.Left + 1).max(1) as i32;
            let rows = (csbi.srWindow.Bottom - csbi.srWindow.Top + 1).max(1) as i32;
            TerminalInfo {
                id: None,
                row: Some(rows),
                column: Some(cols),
                width: None,
                height: None,
            }
        }
    }

    /// True when the head of the console input queue is a key-down event.
    ///
    /// With `ENABLE_VIRTUAL_TERMINAL_INPUT`, key-downs (and host DA/CPR replies
    /// injected as key events) are what `ReadFile` will convert into the VT
    /// byte stream. Other record types keep the handle signaled without ever
    /// unblocking `ReadFile`.
    unsafe fn console_has_key_down(h_in: HANDLE) -> anyhow::Result<bool> {
        let mut record: INPUT_RECORD = std::mem::zeroed();
        let mut npeek = 0u32;
        if PeekConsoleInputW(h_in, &mut record, 1, &mut npeek) == 0 {
            anyhow::bail!("PeekConsoleInput failed: {}", GetLastError());
        }
        if npeek == 0 {
            return Ok(false);
        }
        if record.EventType as u32 != KEY_EVENT {
            return Ok(false);
        }
        Ok(record.Event.KeyEvent.bKeyDown != 0)
    }

    /// Discard console input records that signal the handle but never produce
    /// VT bytes from `ReadFile` (mouse/focus/menu/resize/key-up).
    ///
    /// Full-screen remote apps such as `fresh` enable mouse tracking; after
    /// they exit, moving the mouse still queues `MOUSE_EVENT` records. A naive
    /// `WaitForSingleObject` + `ReadFile` then deadlocks: the wait returns,
    /// `ReadFile` blocks until a key is pressed, and the ET session loop stops
    /// draining remote output — so the shell prompt never appears until Enter
    /// (which then often shows two prompts at once).
    unsafe fn drain_non_vt_console_events(h_in: HANDLE) -> anyhow::Result<()> {
        loop {
            let mut record: INPUT_RECORD = std::mem::zeroed();
            let mut npeek = 0u32;
            if PeekConsoleInputW(h_in, &mut record, 1, &mut npeek) == 0 {
                anyhow::bail!("PeekConsoleInput failed: {}", GetLastError());
            }
            if npeek == 0 {
                return Ok(());
            }

            let event_type = record.EventType as u32;
            let drain = match event_type {
                MOUSE_EVENT | FOCUS_EVENT | MENU_EVENT | WINDOW_BUFFER_SIZE_EVENT => true,
                KEY_EVENT => record.Event.KeyEvent.bKeyDown == 0,
                _ => false,
            };
            if !drain {
                return Ok(());
            }

            let mut nread = 0u32;
            if ReadConsoleInputW(h_in, &mut record, 1, &mut nread) == 0 {
                anyhow::bail!("ReadConsoleInput failed: {}", GetLastError());
            }
        }
    }

    unsafe fn read_console_vt_stream(h_in: HANDLE) -> anyhow::Result<Option<Vec<u8>>> {
        // With ENABLE_VIRTUAL_TERMINAL_INPUT, ReadFile returns the VT byte
        // stream (including host replies such as DA / CPR).
        let mut buf = [0u8; 16 * 1024];
        let mut nread = 0u32;
        let ok = ReadFile(
            h_in,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut nread,
            ptr::null_mut(),
        );
        if ok == 0 {
            let err = GetLastError();
            // ERROR_OPERATION_ABORTED / no data edge cases
            if err == 0 || err == 995 {
                return Ok(None);
            }
            anyhow::bail!("ReadFile(stdin) failed: {err}");
        }
        if nread == 0 {
            return Ok(None);
        }
        Ok(Some(buf[..nread as usize].to_vec()))
    }

    pub(super) fn poll_stdin(timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        unsafe {
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            let deadline = Instant::now() + timeout;

            loop {
                // Never call blocking ReadFile while only mouse/focus/etc.
                // records are queued — that freezes the whole session loop.
                drain_non_vt_console_events(h_in)?;

                if console_has_key_down(h_in)? {
                    return read_console_vt_stream(h_in);
                }

                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let remaining = deadline - now;
                let ms = remaining.as_millis().min(u32::MAX as u128) as u32;
                let wait = WaitForSingleObject(h_in, ms);
                if wait == WAIT_TIMEOUT {
                    return Ok(None);
                }
                if wait != WAIT_OBJECT_0 {
                    return Ok(None);
                }
                // Signaled: loop to drain non-VT records and ReadFile only
                // when a key-down (or host reply) is actually present.
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    pub(super) fn enable_raw(_console: &mut LocalConsole) -> anyhow::Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(())
    }

    pub(super) fn disable_raw(_console: &LocalConsole) -> anyhow::Result<()> {
        crossterm::terminal::disable_raw_mode()?;
        Ok(())
    }

    pub(super) fn terminal_size() -> TerminalInfo {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        TerminalInfo {
            id: None,
            row: Some(rows.max(1) as i32),
            column: Some(cols.max(1) as i32),
            width: None,
            height: None,
        }
    }

    pub(super) fn poll_stdin(timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        let fd = io::stdin().as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(err.into());
        }
        if rc == 0 || pfd.revents & libc::POLLIN == 0 {
            return Ok(None);
        }

        let mut buf = [0u8; 16 * 1024];
        // Non-blocking style: after poll said readable, read may still EAGAIN.
        let n = match io::stdin().read(&mut buf) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(buf[..n].to_vec()))
    }
}
