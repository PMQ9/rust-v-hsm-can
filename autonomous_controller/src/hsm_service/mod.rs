// HSM Service Module - Centralized cryptographic service for multi-core architecture
//
// This module provides a centralized HSM service that runs on dedicated Core 3,
// processing cryptographic operations for all ECUs via Unix domain sockets.
//
// Components:
// - `protocol`: Request/Response message definitions for IPC
// - `server`: HSM service server running on Core 3
// - `client`: HsmClient library for ECUs to communicate with service

pub mod client;
pub mod protocol;
pub mod server;

// Re-export main types for convenience
pub use client::HsmClient;
pub use protocol::{HsmRequest, HsmResponse, MAX_MESSAGE_SIZE};
pub use server::HsmServiceServer;
