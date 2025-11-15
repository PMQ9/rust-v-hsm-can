use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::core::VirtualHSM;
use super::crypto;
use super::errors::VerifyError;

/// Secured CAN frame with MAC and CRC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuredCanFrame {
    /// Original CAN ID
    pub can_id: crate::types::CanId,

    /// Payload data (0-8 bytes for CAN)
    pub data: Vec<u8>,

    /// Source ECU identifier
    pub source: String,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Message Authentication Code (HMAC-SHA256, 32 bytes)
    pub mac: [u8; 32],

    /// CRC32 checksum (4 bytes represented as u32)
    pub crc: u32,

    /// Session counter for anti-replay protection
    pub session_counter: u64,
}

impl SecuredCanFrame {
    /// Create a new secured CAN frame with authorization check
    pub fn new(
        can_id: crate::types::CanId,
        data: Vec<u8>,
        source: String,
        hsm: &mut VirtualHSM,
    ) -> Result<Self, String> {
        // Check authorization before creating frame
        hsm.authorize_transmit(can_id.value())?;

        let start = if hsm.is_performance_enabled() {
            Some(Instant::now())
        } else {
            None
        };

        let timestamp = chrono::Utc::now();
        let session_counter = hsm.get_session_counter();
        hsm.increment_session();

        // Prepare data for MAC and CRC calculation
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&can_id.value().to_le_bytes());
        mac_data.extend_from_slice(&data);
        mac_data.extend_from_slice(source.as_bytes());

        // Calculate MAC and CRC
        let mac = crypto::generate_mac(
            &mac_data,
            session_counter,
            hsm.get_symmetric_key(),
            hsm.performance_metrics_ref(),
        );
        let crc = crypto::calculate_crc(&mac_data, hsm.performance_metrics_ref());

        // Record performance metrics
        if let (Some(start), Some(metrics)) = (start, hsm.performance_metrics_ref()) {
            let elapsed = start.elapsed().as_micros() as u64;
            let mut m = metrics.lock().unwrap();
            m.frame_create_count += 1;
            m.frame_create_time_us += elapsed;
        }

        Ok(Self {
            can_id,
            data,
            source,
            timestamp,
            mac,
            crc,
            session_counter,
        })
    }

    /// Verify the frame's MAC and CRC
    pub fn verify(&self, hsm: &mut VirtualHSM) -> Result<(), VerifyError> {
        let start = if hsm.is_performance_enabled() {
            Some(Instant::now())
        } else {
            None
        };

        // Check if MAC is all zeros - this indicates an unsecured frame
        if self.mac == [0u8; 32] && self.crc == 0 {
            return Err(VerifyError::UnsecuredFrame);
        }

        // Reconstruct data for verification
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(&self.can_id.value().to_le_bytes());
        verify_data.extend_from_slice(&self.data);
        verify_data.extend_from_slice(self.source.as_bytes());

        // Verify CRC first (faster check)
        if !crypto::verify_crc(&verify_data, self.crc, hsm.performance_metrics_ref()) {
            return Err(VerifyError::CrcMismatch);
        }

        // Verify MAC (cryptographic check)
        // Get the MAC key for the source ECU
        let verification_key =
            hsm.get_mac_verification_key(&self.source)
                .ok_or(VerifyError::MacMismatch(
                    super::errors::MacFailureReason::NoKeyRegistered,
                ))?;

        crypto::verify_mac(
            &verify_data,
            &self.mac,
            self.session_counter,
            verification_key,
            hsm.performance_metrics_ref(),
        )
        .map_err(VerifyError::MacMismatch)?;

        // Verify replay protection (check session counter)
        let result = hsm
            .validate_counter(self.session_counter, &self.source, self.timestamp)
            .map_err(VerifyError::ReplayDetected);

        // Record performance metrics (only on success)
        if result.is_ok()
            && let (Some(start), Some(metrics)) = (start, hsm.performance_metrics_ref())
        {
            let elapsed = start.elapsed().as_micros() as u64;

            // Calculate end-to-end latency (from frame timestamp to now)
            let now = chrono::Utc::now();
            let e2e_latency_us = (now - self.timestamp)
                .num_microseconds()
                .unwrap_or(0)
                .max(0) as u64;

            let mut m = metrics.lock().unwrap();
            m.frame_verify_count += 1;
            m.frame_verify_time_us += elapsed;
            m.e2e_latency_samples.push(e2e_latency_us);
        }

        result
    }

    /// Verify the frame's MAC, CRC, and receive authorization
    pub fn verify_with_authorization(&self, hsm: &mut VirtualHSM) -> Result<(), VerifyError> {
        // First check receive authorization
        if hsm.authorize_receive(self.can_id.value()).is_err() {
            return Err(VerifyError::UnauthorizedAccess);
        }

        // Then perform standard verification
        self.verify(hsm)
    }

    /// Convert to original CanFrame (for compatibility with existing code)
    pub fn to_can_frame(&self) -> crate::types::CanFrame {
        crate::types::CanFrame {
            id: self.can_id,
            data: self.data.clone(),
            timestamp: self.timestamp,
            source: self.source.clone(),
        }
    }
}
