use crate::hsm::{PerformanceSnapshot, SecuredCanFrame};
use crate::types::CanFrame;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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
    pub async fn receive_message(
        &mut self,
    ) -> Result<NetMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        if line.is_empty() {
            return Err("Connection closed".into());
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
    pub async fn receive_message(
        &mut self,
    ) -> Result<NetMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;

        if line.is_empty() {
            return Err("Connection closed".into());
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
