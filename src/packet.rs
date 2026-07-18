//! Eternal Terminal application packet: 1-byte encrypted flag + 1-byte header + payload.

use crate::crypto::CryptoHandler;

#[derive(Debug, Clone)]
pub struct Packet {
    encrypted: bool,
    header: u8,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(header: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            encrypted: false,
            header,
            payload: payload.into(),
        }
    }

    pub fn from_serialized(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 2 {
            anyhow::bail!("packet too short");
        }
        Ok(Self {
            encrypted: data[0] != 0,
            header: data[1],
            payload: data[2..].to_vec(),
        })
    }

    pub fn header(&self) -> u8 {
        self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn length(&self) -> usize {
        2 + self.payload.len()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(self.length());
        s.push(u8::from(self.encrypted));
        s.push(self.header);
        s.extend_from_slice(&self.payload);
        s
    }

    pub fn encrypt(&mut self, crypto: &CryptoHandler) -> anyhow::Result<()> {
        if self.encrypted {
            anyhow::bail!("packet already encrypted");
        }
        self.payload = crypto.encrypt(&self.payload)?;
        self.encrypted = true;
        Ok(())
    }

    pub fn decrypt(&mut self, crypto: &CryptoHandler) -> anyhow::Result<()> {
        if !self.encrypted {
            anyhow::bail!("packet is not encrypted");
        }
        self.payload = crypto.decrypt(&self.payload)?;
        self.encrypted = false;
        Ok(())
    }
}
