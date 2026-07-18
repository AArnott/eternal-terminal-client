//! Minimal protobuf2 encode/decode for Eternal Terminal wire messages.
//!
//! Only field numbers matter on the wire. We intentionally avoid a protoc
//! dependency so the crate builds cleanly on Windows without extra tooling.

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};

use bytes::{Buf, BufMut, BytesMut};
// Read used by Cursor::read_exact
use thiserror::Error;

pub const PROTOCOL_VERSION: i32 = 6;

// --- Packet type constants (match C++ enums) ---

pub mod et_packet {
    pub const HEARTBEAT: u8 = 254;
    pub const INITIAL_PAYLOAD: u8 = 253;
    pub const INITIAL_RESPONSE: u8 = 252;
}

pub mod terminal_packet {
    pub const KEEP_ALIVE: u8 = 0;
    pub const TERMINAL_BUFFER: u8 = 1;
    pub const TERMINAL_INFO: u8 = 2;
    #[allow(dead_code)]
    pub const PORT_FORWARD_DESTINATION_REQUEST: u8 = 5;
    #[allow(dead_code)]
    pub const PORT_FORWARD_DESTINATION_RESPONSE: u8 = 6;
    #[allow(dead_code)]
    pub const PORT_FORWARD_DATA: u8 = 7;
    #[allow(dead_code)]
    pub const TERMINAL_USER_INFO: u8 = 8;
    #[allow(dead_code)]
    pub const TERMINAL_INIT: u8 = 9;
    #[allow(dead_code)]
    pub const JUMPHOST_INIT: u8 = 10;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ConnectStatus {
    NewClient = 1,
    ReturningClient = 2,
    InvalidKey = 3,
    MismatchedProtocol = 4,
}

impl ConnectStatus {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::NewClient),
            2 => Some(Self::ReturningClient),
            3 => Some(Self::InvalidKey),
            4 => Some(Self::MismatchedProtocol),
            _ => None,
        }
    }
}

// --- Messages ---

#[derive(Debug, Clone, Default)]
pub struct ConnectRequest {
    pub client_id: Option<String>,
    pub version: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectResponse {
    pub status: Option<ConnectStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SequenceHeader {
    pub sequence_number: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct CatchupBuffer {
    pub buffer: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct TerminalBuffer {
    pub buffer: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalInfo {
    pub id: Option<String>,
    pub row: Option<i32>,
    pub column: Option<i32>,
    pub width: Option<i32>,
    pub height: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct InitialPayload {
    pub jumphost: Option<bool>,
    pub reverse_tunnels: Vec<PortForwardSourceRequest>,
    pub environment_variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct InitialResponse {
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PortForwardSourceRequest {
    pub source: Option<SocketEndpoint>,
    pub destination: Option<SocketEndpoint>,
    pub environment_variable: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SocketEndpoint {
    pub name: Option<String>,
    pub port: Option<i32>,
}

// --- Errors ---

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid varint")]
    InvalidVarint,
    #[error("truncated protobuf")]
    Truncated,
    #[error("invalid wire type")]
    InvalidWireType,
}

// --- Codec helpers ---

fn write_varint(out: &mut impl BufMut, mut v: u64) {
    while v >= 0x80 {
        out.put_u8((v as u8) | 0x80);
        v >>= 7;
    }
    out.put_u8(v as u8);
}

fn read_varint(buf: &mut impl Buf) -> Result<u64, ProtoError> {
    let mut result = 0u64;
    for shift in (0..64).step_by(7) {
        if !buf.has_remaining() {
            return Err(ProtoError::Truncated);
        }
        let b = buf.get_u8();
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(ProtoError::InvalidVarint)
}

fn write_tag(out: &mut impl BufMut, field: u32, wire_type: u32) {
    write_varint(out, ((field as u64) << 3) | wire_type as u64);
}

fn write_string(out: &mut impl BufMut, field: u32, s: &str) {
    write_tag(out, field, 2);
    write_varint(out, s.len() as u64);
    out.put_slice(s.as_bytes());
}

fn write_bytes(out: &mut impl BufMut, field: u32, b: &[u8]) {
    write_tag(out, field, 2);
    write_varint(out, b.len() as u64);
    out.put_slice(b);
}

fn write_int32(out: &mut impl BufMut, field: u32, v: i32) {
    write_tag(out, field, 0);
    write_varint(out, v as u64);
}

fn write_bool(out: &mut impl BufMut, field: u32, v: bool) {
    write_tag(out, field, 0);
    write_varint(out, if v { 1 } else { 0 });
}

fn write_embedded(out: &mut impl BufMut, field: u32, payload: &[u8]) {
    write_tag(out, field, 2);
    write_varint(out, payload.len() as u64);
    out.put_slice(payload);
}

fn write_map_entry_string_string(out: &mut impl BufMut, field: u32, k: &str, v: &str) {
    let mut entry = BytesMut::new();
    write_string(&mut entry, 1, k);
    write_string(&mut entry, 2, v);
    write_embedded(out, field, &entry);
}

struct Field {
    number: u32,
    wire_type: u32,
    data: Vec<u8>,
}

fn parse_message(mut buf: &[u8]) -> Result<Vec<Field>, ProtoError> {
    let mut fields = Vec::new();
    let mut cursor = Cursor::new(buf);
    while cursor.position() < buf.len() as u64 {
        let tag = read_varint(&mut cursor)?;
        let number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u32;
        let data = match wire_type {
            0 => {
                let v = read_varint(&mut cursor)?;
                let mut tmp = BytesMut::new();
                write_varint(&mut tmp, v);
                tmp.to_vec()
            }
            1 => {
                let mut b = [0u8; 8];
                cursor.read_exact(&mut b)?;
                b.to_vec()
            }
            2 => {
                let len = read_varint(&mut cursor)? as usize;
                let mut b = vec![0u8; len];
                cursor.read_exact(&mut b)?;
                b
            }
            5 => {
                let mut b = [0u8; 4];
                cursor.read_exact(&mut b)?;
                b.to_vec()
            }
            _ => return Err(ProtoError::InvalidWireType),
        };
        fields.push(Field {
            number,
            wire_type,
            data,
        });
        let _ = &mut buf; // silence unused mut on some rustc versions
    }
    Ok(fields)
}

fn field_as_string(f: &Field) -> Option<String> {
    if f.wire_type == 2 {
        String::from_utf8(f.data.clone()).ok()
    } else {
        None
    }
}

fn field_as_bytes(f: &Field) -> Option<Vec<u8>> {
    if f.wire_type == 2 {
        Some(f.data.clone())
    } else {
        None
    }
}

fn field_as_varint(f: &Field) -> Option<u64> {
    if f.wire_type == 0 {
        let mut c = Cursor::new(&f.data[..]);
        read_varint(&mut c).ok()
    } else {
        None
    }
}

// --- Encode / decode ---

pub trait ProtoMessage: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self, ProtoError>;
}

impl ProtoMessage for ConnectRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref id) = self.client_id {
            write_string(&mut out, 1, id);
        }
        if let Some(v) = self.version {
            write_int32(&mut out, 2, v);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => msg.client_id = field_as_string(&f),
                2 => msg.version = field_as_varint(&f).map(|v| v as i32),
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for ConnectResponse {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(s) = self.status {
            write_int32(&mut out, 1, s as i32);
        }
        if let Some(ref e) = self.error {
            write_string(&mut out, 2, e);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => {
                    if let Some(v) = field_as_varint(&f) {
                        msg.status = ConnectStatus::from_i32(v as i32);
                    }
                }
                2 => msg.error = field_as_string(&f),
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for SequenceHeader {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(n) = self.sequence_number {
            write_int32(&mut out, 1, n);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            if f.number == 1 {
                msg.sequence_number = field_as_varint(&f).map(|v| v as i32);
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for CatchupBuffer {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        for b in &self.buffer {
            write_bytes(&mut out, 1, b);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            if f.number == 1 {
                if let Some(b) = field_as_bytes(&f) {
                    msg.buffer.push(b);
                }
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for TerminalBuffer {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref b) = self.buffer {
            write_bytes(&mut out, 1, b);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            if f.number == 1 {
                msg.buffer = field_as_bytes(&f);
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for TerminalInfo {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref id) = self.id {
            write_string(&mut out, 1, id);
        }
        if let Some(v) = self.row {
            write_int32(&mut out, 2, v);
        }
        if let Some(v) = self.column {
            write_int32(&mut out, 3, v);
        }
        if let Some(v) = self.width {
            write_int32(&mut out, 4, v);
        }
        if let Some(v) = self.height {
            write_int32(&mut out, 5, v);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => msg.id = field_as_string(&f),
                2 => msg.row = field_as_varint(&f).map(|v| v as i32),
                3 => msg.column = field_as_varint(&f).map(|v| v as i32),
                4 => msg.width = field_as_varint(&f).map(|v| v as i32),
                5 => msg.height = field_as_varint(&f).map(|v| v as i32),
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for SocketEndpoint {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref n) = self.name {
            write_string(&mut out, 1, n);
        }
        if let Some(p) = self.port {
            write_int32(&mut out, 2, p);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => msg.name = field_as_string(&f),
                2 => msg.port = field_as_varint(&f).map(|v| v as i32),
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for PortForwardSourceRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref s) = self.source {
            write_embedded(&mut out, 1, &s.encode());
        }
        if let Some(ref d) = self.destination {
            write_embedded(&mut out, 2, &d.encode());
        }
        if let Some(ref e) = self.environment_variable {
            write_string(&mut out, 3, e);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => {
                    if let Some(b) = field_as_bytes(&f) {
                        msg.source = Some(SocketEndpoint::decode(&b)?);
                    }
                }
                2 => {
                    if let Some(b) = field_as_bytes(&f) {
                        msg.destination = Some(SocketEndpoint::decode(&b)?);
                    }
                }
                3 => msg.environment_variable = field_as_string(&f),
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for InitialPayload {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        // Only emit jumphost if true (proto2 default false; matches C++ optional)
        if self.jumphost == Some(true) {
            write_bool(&mut out, 1, true);
        }
        for rt in &self.reverse_tunnels {
            write_embedded(&mut out, 2, &rt.encode());
        }
        for (k, v) in &self.environment_variables {
            write_map_entry_string_string(&mut out, 3, k, v);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            match f.number {
                1 => msg.jumphost = field_as_varint(&f).map(|v| v != 0),
                2 => {
                    if let Some(b) = field_as_bytes(&f) {
                        msg.reverse_tunnels
                            .push(PortForwardSourceRequest::decode(&b)?);
                    }
                }
                3 => {
                    if let Some(b) = field_as_bytes(&f) {
                        let mut key = None;
                        let mut val = None;
                        for ef in parse_message(&b)? {
                            match ef.number {
                                1 => key = field_as_string(&ef),
                                2 => val = field_as_string(&ef),
                                _ => {}
                            }
                        }
                        if let (Some(k), Some(v)) = (key, val) {
                            msg.environment_variables.insert(k, v);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(msg)
    }
}

impl ProtoMessage for InitialResponse {
    fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        if let Some(ref e) = self.error {
            write_string(&mut out, 1, e);
        }
        out.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut msg = Self::default();
        for f in parse_message(bytes)? {
            if f.number == 1 {
                msg.error = field_as_string(&f);
            }
        }
        Ok(msg)
    }
}

/// Write a length-prefixed protobuf (Eternal Terminal `writeProto` format).
///
/// Prefix is a host-endian `i64` length, matching the official C++ client on
/// little-endian platforms (x86_64 / aarch64).
pub fn write_proto<W: Write, M: ProtoMessage>(w: &mut W, msg: &M) -> io::Result<()> {
    let payload = msg.encode();
    let len = payload.len() as i64;
    w.write_all(&len.to_ne_bytes())?;
    if !payload.is_empty() {
        w.write_all(&payload)?;
    }
    Ok(())
}

/// Read a length-prefixed protobuf (`readProto`).
pub fn read_proto<R: Read, M: ProtoMessage>(r: &mut R) -> Result<M, anyhow::Error> {
    let mut len_buf = [0u8; 8];
    r.read_exact(&mut len_buf)?;
    let len = i64::from_ne_bytes(len_buf);
    if !(0..=128 * 1024 * 1024).contains(&len) {
        anyhow::bail!("invalid proto length: {len}");
    }
    if len == 0 {
        return Ok(M::decode(&[])?);
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(M::decode(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_roundtrip() {
        let msg = ConnectRequest {
            client_id: Some("XXXabcdefghijkl".into()),
            version: Some(6),
        };
        let bytes = msg.encode();
        let decoded = ConnectRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.client_id, msg.client_id);
        assert_eq!(decoded.version, msg.version);
    }

    #[test]
    fn terminal_buffer_roundtrip() {
        let msg = TerminalBuffer {
            buffer: Some(b"hello".to_vec()),
        };
        let decoded = TerminalBuffer::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.buffer, msg.buffer);
    }
}
