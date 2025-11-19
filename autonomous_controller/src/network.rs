//! Network Communication Module
//!
//! **SECURITY WARNING: DEVELOPMENT/TESTING ONLY**
//!
//! This module provides TCP-based networked communication for the CAN bus simulator.
//! It is designed for development, testing, and demonstration purposes.
//!
//! ## Security Model
//!
//! **Network Layer:** NO authentication, NO encryption
//! - TCP connections are unauthenticated (anyone can connect)
//! - ECU names are self-declared (no verification at network layer)
//! - Traffic is plaintext JSON (for debugging/observability)
//!
//! **Application Layer:** Cryptographic authentication (HMAC-SHA256)
//! - All CAN frames must have valid MAC (Message Authentication Code)
//! - MAC keys are pre-shared secrets between trusted ECUs
//! - Even if attacker connects and spoofs ECU name, they cannot forge MACs
//! - Invalid MACs trigger attack detection and fail-safe mode
//!
//! ## Production Use
//!
//! **DO NOT use networked mode in production without additional security:**
//! 1. Prefer in-process mode (VirtualCanBus) - eliminates network attack surface
//! 2. If networked mode required, add TLS with mutual authentication
//! 3. Implement pre-shared key verification during registration
//! 4. Use network segmentation (firewall, VLANs)
//!
//! See CLAUDE.md "Network Security Model" section for full details.

use crate::hsm::{PerformanceSnapshot, SecuredCanFrame};
use crate::types::CanFrame;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Maximum message size in bytes to prevent DoS via memory exhaustion
/// SECURITY FIX: Limit JSON message size to prevent attackers from
/// sending extremely large messages that cause memory exhaustion
const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64 KB - generous for CAN bus messages

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetMessage {
    /// CAN frame message (legacy - unencrypted)
    CanFrame(CanFrame),
    /// Secured CAN frame message (with MAC and CRC)
    SecuredCanFrame(SecuredCanFrame),
    /// Performance statistics snapshot
    PerformanceStats(PerformanceSnapshot),
    /// Client registration
    Register { client_name: String },
    /// Acknowledgment
    Ack,
    /// Error message
    Error(String),
}

/// Network client for communicating with the bus server
pub struct BusClient {
    stream: TcpStream,
    client_name: String,
}

impl BusClient {
    /// Connect to the bus server
    pub async fn connect(
        addr: &str,
        client_name: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = TcpStream::connect(addr).await?;
        let mut client = Self {
            stream,
            client_name: client_name.clone(),
        };

        // Register with the server
        client
            .send_message(&NetMessage::Register { client_name })
            .await?;

        Ok(client)
    }

    /// Send a message to the server
    pub async fn send_message(
        &mut self,
        msg: &NetMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(msg)?;
        self.stream.write_all(json.as_bytes()).await?;
        self.stream.write_all(b"\n").await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Send a CAN frame to the bus
    pub async fn send_frame(
        &mut self,
        frame: CanFrame,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(&NetMessage::CanFrame(frame)).await
    }

    /// Receive a message from the server (blocking)
    ///
    /// SECURITY FIX: Enforces maximum message size to prevent DoS attacks
    pub async fn receive_message(
        &mut self,
    ) -> Result<NetMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();

        // SECURITY: Use read_line with size limit checking
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            return Err("Connection closed".into());
        }

        // SECURITY FIX: Validate message size before deserialization
        if line.len() > MAX_MESSAGE_SIZE {
            return Err(format!(
                "Message too large: {} bytes (max: {} bytes)",
                line.len(),
                MAX_MESSAGE_SIZE
            )
            .into());
        }

        let msg: NetMessage = serde_json::from_str(&line)?;
        Ok(msg)
    }

    /// Split the client into read and write halves
    pub fn split(self) -> (BusReader, BusWriter) {
        let (read_half, write_half) = self.stream.into_split();
        (
            BusReader {
                reader: BufReader::new(read_half),
            },
            BusWriter { writer: write_half },
        )
    }

    /// Get the client name
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
}

/// Read half of the bus client
pub struct BusReader {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
}

impl BusReader {
    /// Receive a message from the server
    ///
    /// SECURITY FIX: Enforces maximum message size to prevent DoS attacks
    pub async fn receive_message(
        &mut self,
    ) -> Result<NetMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            return Err("Connection closed".into());
        }

        // SECURITY FIX: Validate message size before deserialization
        if line.len() > MAX_MESSAGE_SIZE {
            return Err(format!(
                "Message too large: {} bytes (max: {} bytes)",
                line.len(),
                MAX_MESSAGE_SIZE
            )
            .into());
        }

        let msg: NetMessage = serde_json::from_str(&line)?;
        Ok(msg)
    }
}

/// Write half of the bus client
pub struct BusWriter {
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl BusWriter {
    /// Send a message to the server
    pub async fn send_message(
        &mut self,
        msg: &NetMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(msg)?;
        self.writer.write_all(json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Send a CAN frame to the bus
    pub async fn send_frame(
        &mut self,
        frame: CanFrame,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(&NetMessage::CanFrame(frame)).await
    }

    /// Send a secured CAN frame to the bus
    pub async fn send_secured_frame(
        &mut self,
        frame: SecuredCanFrame,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(&NetMessage::SecuredCanFrame(frame)).await
    }

    /// Send performance statistics to the bus
    pub async fn send_performance_stats(
        &mut self,
        stats: PerformanceSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(&NetMessage::PerformanceStats(stats))
            .await
    }
}
