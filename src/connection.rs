//! Client connection: ConnectRequest handshake, EternalTCP streams, reconnect.

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use parking_lot::Mutex;

use crate::backed::{BackedReader, BackedWriter, WriteState};
use crate::crypto::{CryptoHandler, CLIENT_SERVER_NONCE_MSB, SERVER_CLIENT_NONCE_MSB};
use crate::packet::Packet;
use crate::proto::{
    self, CatchupBuffer, ConnectRequest, ConnectResponse, ConnectStatus, SequenceHeader,
    PROTOCOL_VERSION,
};

struct Shared {
    host: String,
    port: u16,
    id: String,
    key: Vec<u8>,
    reader: Mutex<Option<BackedReader>>,
    writer: Mutex<Option<BackedWriter>>,
    socket_alive: AtomicBool,
    shutting_down: AtomicBool,
}

pub struct ClientConnection {
    shared: Arc<Shared>,
    reconnect_thread: Mutex<Option<JoinHandle<()>>>,
}

impl ClientConnection {
    pub fn new(host: impl Into<String>, port: u16, id: String, passkey: String) -> Self {
        Self {
            shared: Arc::new(Shared {
                host: host.into(),
                port,
                id,
                key: passkey.into_bytes(),
                reader: Mutex::new(None),
                writer: Mutex::new(None),
                socket_alive: AtomicBool::new(false),
                shutting_down: AtomicBool::new(false),
            }),
            reconnect_thread: Mutex::new(None),
        }
    }

    pub fn id(&self) -> &str {
        &self.shared.id
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shared.shutting_down.load(Ordering::SeqCst)
    }

    pub fn has_socket(&self) -> bool {
        self.shared.socket_alive.load(Ordering::SeqCst)
    }

    pub fn connect(&self) -> anyhow::Result<()> {
        let stream = tcp_connect(&self.shared.host, self.shared.port)?;
        stream.set_nodelay(true)?;
        // Blocking handshake with timeouts, then switch to non-blocking for the run loop.
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        let mut write_half = stream.try_clone()?;
        let mut read_half = stream.try_clone()?;

        let req = ConnectRequest {
            client_id: Some(self.shared.id.clone()),
            version: Some(PROTOCOL_VERSION),
        };
        proto::write_proto(&mut write_half, &req)?;

        let resp: ConnectResponse = proto::read_proto(&mut read_half)?;
        match resp.status {
            Some(ConnectStatus::NewClient) | Some(ConnectStatus::ReturningClient) => {}
            other => {
                anyhow::bail!(
                    "error connecting to server: {:?} {}",
                    other,
                    resp.error.unwrap_or_default()
                );
            }
        }

        // Interactive I/O: non-blocking so the console poll loop stays responsive.
        read_half.set_nonblocking(true)?;
        write_half.set_nonblocking(true)?;
        let _ = read_half.set_read_timeout(None);
        let _ = write_half.set_write_timeout(None);

        let reader_crypto = Arc::new(CryptoHandler::new(
            &self.shared.key,
            SERVER_CLIENT_NONCE_MSB,
        )?);
        let writer_crypto = Arc::new(CryptoHandler::new(
            &self.shared.key,
            CLIENT_SERVER_NONCE_MSB,
        )?);

        *self.shared.reader.lock() = Some(BackedReader::new(reader_crypto, read_half));
        *self.shared.writer.lock() = Some(BackedWriter::new(writer_crypto, write_half));
        self.shared.socket_alive.store(true, Ordering::SeqCst);
        log::info!(
            "client connection established to {}:{}",
            self.shared.host,
            self.shared.port
        );
        Ok(())
    }

    pub fn write_packet(&self, packet: Packet) -> bool {
        loop {
            if self.shared.shutting_down.load(Ordering::SeqCst) {
                return false;
            }
            let state = {
                let mut w = self.shared.writer.lock();
                match w.as_mut() {
                    Some(writer) => writer.write(packet.clone()),
                    None => WriteState::Skipped,
                }
            };
            match state {
                WriteState::Success | WriteState::BufferedOnly => return true,
                WriteState::WroteWithFailure => {
                    self.close_and_maybe_reconnect();
                    thread::sleep(Duration::from_millis(1));
                }
                WriteState::Skipped => {
                    if self.has_socket() {
                        thread::sleep(Duration::from_millis(1));
                    } else {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
    }

    pub fn read_packet(&self) -> anyhow::Result<Option<Packet>> {
        let mut r = self.shared.reader.lock();
        let Some(reader) = r.as_mut() else {
            return Ok(None);
        };
        match reader.read() {
            Ok(p) => Ok(p),
            Err(e) => {
                drop(r);
                log::info!("read failed, will reconnect: {e}");
                self.close_and_maybe_reconnect();
                Ok(None)
            }
        }
    }

    pub fn close_and_maybe_reconnect(&self) {
        self.wait_reconnect();
        {
            let mut r = self.shared.reader.lock();
            if let Some(reader) = r.as_mut() {
                reader.invalidate_socket();
            }
            let mut w = self.shared.writer.lock();
            if let Some(writer) = w.as_mut() {
                writer.invalidate_socket();
            }
        }
        self.shared.socket_alive.store(false, Ordering::SeqCst);

        if !self.shared.shutting_down.load(Ordering::SeqCst) {
            let shared = Arc::clone(&self.shared);
            let handle = thread::Builder::new()
                .name("et-reconnect".into())
                .spawn(move || reconnect_loop(shared))
                .expect("spawn reconnect");
            *self.reconnect_thread.lock() = Some(handle);
        }
    }

    fn wait_reconnect(&self) {
        if let Some(h) = self.reconnect_thread.lock().take() {
            let _ = h.join();
        }
    }

    pub fn shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        self.wait_reconnect();
        {
            let mut r = self.shared.reader.lock();
            if let Some(reader) = r.as_mut() {
                reader.invalidate_socket();
            }
            *r = None;
            let mut w = self.shared.writer.lock();
            if let Some(writer) = w.as_mut() {
                writer.invalidate_socket();
            }
            *w = None;
        }
        self.shared.socket_alive.store(false, Ordering::SeqCst);
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn reconnect_loop(shared: Arc<Shared>) {
    log::info!("trying to reconnect to {}:{}", shared.host, shared.port);

    while !shared.socket_alive.load(Ordering::SeqCst) {
        if shared.shutting_down.load(Ordering::SeqCst) {
            return;
        }

        match try_recover(&shared) {
            Ok(true) => {
                shared.socket_alive.store(true, Ordering::SeqCst);
                log::info!("reconnect complete");
                return;
            }
            Ok(false) => {
                shared.shutting_down.store(true, Ordering::SeqCst);
                return;
            }
            Err(e) => {
                log::debug!("reconnect attempt failed: {e}");
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn try_recover(shared: &Shared) -> anyhow::Result<bool> {
    let stream = tcp_connect(&shared.host, shared.port)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut write_half = stream.try_clone()?;
    let mut read_half = stream.try_clone()?;

    let req = ConnectRequest {
        client_id: Some(shared.id.clone()),
        version: Some(PROTOCOL_VERSION),
    };
    proto::write_proto(&mut write_half, &req)?;
    let resp: ConnectResponse = proto::read_proto(&mut read_half)?;

    match resp.status {
        Some(ConnectStatus::InvalidKey) => {
            log::info!("invalid key on reconnect — server ended the session");
            return Ok(false);
        }
        Some(ConnectStatus::ReturningClient) => {}
        other => {
            anyhow::bail!(
                "unexpected reconnect status: {:?} {}",
                other,
                resp.error.unwrap_or_default()
            );
        }
    }

    let local_seq = {
        let r = shared.reader.lock();
        r.as_ref().map(|r| r.sequence_number()).unwrap_or(0)
    };
    let sh = SequenceHeader {
        sequence_number: Some(local_seq as i32),
    };
    proto::write_proto(&mut write_half, &sh)?;

    let remote: SequenceHeader = proto::read_proto(&mut read_half)?;
    let remote_seq = remote.sequence_number.unwrap_or(0) as i64;

    let catchup_out = {
        let w = shared.writer.lock();
        match w.as_ref() {
            Some(writer) => writer.recover(remote_seq)?,
            None => Vec::new(),
        }
    };
    let cb = CatchupBuffer {
        buffer: catchup_out,
    };
    proto::write_proto(&mut write_half, &cb)?;

    let catchup_in: CatchupBuffer = proto::read_proto(&mut read_half)?;

    read_half.set_nonblocking(true)?;
    write_half.set_nonblocking(true)?;
    let _ = read_half.set_read_timeout(None);
    let _ = write_half.set_write_timeout(None);

    {
        let mut r = shared.reader.lock();
        if let Some(reader) = r.as_mut() {
            reader.revive(read_half, catchup_in.buffer);
        }
    }
    {
        let mut w = shared.writer.lock();
        if let Some(writer) = w.as_mut() {
            writer.revive(write_half);
        }
    }

    Ok(true)
}

fn tcp_connect(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:{port}");
    let mut last_err = None;
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .map(|e| e.into())
        .unwrap_or_else(|| anyhow::anyhow!("could not resolve {addr}")))
}

/// Quick connectivity check used before SSH setup (matches official `ping`).
pub fn ping_server(host: &str, port: u16) -> bool {
    tcp_connect(host, port).is_ok()
}
