//! EternalTCP backed reader/writer — sequence-numbered encrypted packet streams
//! that can recover after reconnect.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::crypto::CryptoHandler;
use crate::packet::Packet;

const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024; // generous; C++ uses a smaller default
const DISCONNECT_BUFFER_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteState {
    Success,
    BufferedOnly,
    WroteWithFailure,
    Skipped,
}

pub struct BackedWriter {
    crypto: Arc<CryptoHandler>,
    socket: Option<TcpStream>,
    backup: VecDeque<Packet>,
    backup_size: usize,
    disconnected_bytes: usize,
    sequence_number: i64,
    recover_lock: Mutex<()>,
}

impl BackedWriter {
    pub fn new(crypto: Arc<CryptoHandler>, socket: TcpStream) -> Self {
        Self {
            crypto,
            socket: Some(socket),
            backup: VecDeque::new(),
            backup_size: 0,
            disconnected_bytes: 0,
            sequence_number: 0,
            recover_lock: Mutex::new(()),
        }
    }

    pub fn invalidate_socket(&mut self) {
        self.socket = None;
    }

    pub fn write(&mut self, mut packet: Packet) -> WriteState {
        let _guard = self.recover_lock.lock();

        if self.socket.is_none()
            && self.disconnected_bytes + packet.length() > DISCONNECT_BUFFER_BYTES
        {
            return WriteState::Skipped;
        }

        if packet.encrypt(&self.crypto).is_err() {
            return WriteState::WroteWithFailure;
        }

        self.backup.push_front(packet.clone());
        self.backup_size += packet.length();
        self.sequence_number += 1;

        while self.socket.is_some() && self.backup_size > MAX_BACKUP_BYTES {
            if let Some(old) = self.backup.pop_back() {
                self.backup_size = self.backup_size.saturating_sub(old.length());
            } else {
                break;
            }
        }

        if self.socket.is_none() {
            self.disconnected_bytes += packet.length();
            return WriteState::BufferedOnly;
        }

        // Wire format: big-endian u32 length + serialized packet (encrypted).
        let serialized = packet.serialize();
        let len = (serialized.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + serialized.len());
        frame.extend_from_slice(&len);
        frame.extend_from_slice(&serialized);

        match write_all_retry(self.socket.as_mut().unwrap(), &frame) {
            Ok(()) => WriteState::Success,
            Err(_) => {
                self.socket = None;
                WriteState::WroteWithFailure
            }
        }
    }

    /// Return serialized encrypted packets the peer has not yet acknowledged.
    pub fn recover(&self, last_valid_sequence: i64) -> anyhow::Result<Vec<Vec<u8>>> {
        if self.socket.is_some() {
            anyhow::bail!("cannot recover while socket is alive");
        }
        let messages_to_recover = self.sequence_number - last_valid_sequence;
        if messages_to_recover < 0 {
            anyhow::bail!("peer is ahead of local writer");
        }
        if messages_to_recover == 0 {
            return Ok(Vec::new());
        }
        if messages_to_recover as usize > self.backup.len() {
            anyhow::bail!("peer is too far behind (backup exhausted)");
        }

        let mut recovered: Vec<Vec<u8>> = self
            .backup
            .iter()
            .take(messages_to_recover as usize)
            .map(|p| p.serialize())
            .collect();
        recovered.reverse();
        Ok(recovered)
    }

    pub fn revive(&mut self, socket: TcpStream) {
        self.socket = Some(socket);
        self.disconnected_bytes = 0;
    }
}

pub struct BackedReader {
    crypto: Arc<CryptoHandler>,
    socket: Option<TcpStream>,
    sequence_number: i64,
    partial: Vec<u8>,
    local_buffer: VecDeque<Vec<u8>>,
    recover_lock: Mutex<()>,
}

impl BackedReader {
    pub fn new(crypto: Arc<CryptoHandler>, socket: TcpStream) -> Self {
        // Reader needs its own stream handle for independent reads; caller
        // should try_clone the TcpStream.
        Self {
            crypto,
            socket: Some(socket),
            sequence_number: 0,
            partial: Vec::new(),
            local_buffer: VecDeque::new(),
            recover_lock: Mutex::new(()),
        }
    }

    pub fn sequence_number(&self) -> i64 {
        self.sequence_number
    }

    pub fn invalidate_socket(&mut self) {
        self.socket = None;
    }

    /// Try to read one packet. Returns `Ok(None)` if no full packet yet,
    /// `Ok(Some)` on success, `Err` on hard failure (caller should reconnect).
    pub fn read(&mut self) -> anyhow::Result<Option<Packet>> {
        let _g = self.recover_lock.lock();
        if self.socket.is_none() && self.local_buffer.is_empty() {
            return Ok(None);
        }

        if let Some(serialized) = self.local_buffer.pop_front() {
            let mut packet = Packet::from_serialized(&serialized)?;
            packet.decrypt(&self.crypto)?;
            // Sequence already advanced when catchup was applied in revive().
            return Ok(Some(packet));
        }

        let sock = match self.socket.as_mut() {
            Some(s) => s,
            None => return Ok(None),
        };

        // Fill length header
        while self.partial.len() < 4 {
            let mut buf = [0u8; 4];
            let need = 4 - self.partial.len();
            match sock.read(&mut buf[..need]) {
                Ok(0) => anyhow::bail!("connection closed"),
                Ok(n) => self.partial.extend_from_slice(&buf[..n]),
                // Windows SO_RCVTIMEO → TimedOut; Unix nonblock → WouldBlock
                Err(e) if is_transient(&e) => return Ok(None),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let msg_len = u32::from_be_bytes(self.partial[0..4].try_into().unwrap()) as usize;
        let total = 4 + msg_len;

        while self.partial.len() < total {
            let mut buf = vec![0u8; total - self.partial.len()];
            match sock.read(&mut buf) {
                Ok(0) => anyhow::bail!("connection closed"),
                Ok(n) => self.partial.extend_from_slice(&buf[..n]),
                Err(e) if is_transient(&e) => return Ok(None),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let serialized = self.partial[4..total].to_vec();
        self.partial.clear();
        let mut packet = Packet::from_serialized(&serialized)?;
        packet.decrypt(&self.crypto)?;
        self.sequence_number += 1;
        Ok(Some(packet))
    }

    pub fn revive(&mut self, socket: TcpStream, catchup: Vec<Vec<u8>>) {
        self.partial.clear();
        for entry in catchup {
            self.local_buffer.push_back(entry);
            self.sequence_number += 1;
        }
        self.socket = Some(socket);
    }
}

fn is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn write_all_retry(stream: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    use std::time::Duration;
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "socket closed",
                ))
            }
            Ok(n) => data = &data[n..],
            Err(e) if is_transient(&e) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
