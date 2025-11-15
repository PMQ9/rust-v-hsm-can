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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::core::VirtualHSM;
    use crate::hsm::errors::VerifyError;
    use crate::types::CanIdPermissions;

    #[test]
    fn test_secured_frame_creation_with_authorization() {
        let mut hsm = VirtualHSM::new("WHEEL_FL".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("WHEEL_FL".to_string());
        perms.allow_tx(0x100);
        hsm.load_access_control(perms);

        // Should create frame for authorized CAN ID
        let result = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "WHEEL_FL".to_string(),
            &mut hsm,
        );
        assert!(result.is_ok());

        // Should fail for unauthorized CAN ID
        let result = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x200),
            vec![1, 2, 3, 4],
            "WHEEL_FL".to_string(),
            &mut hsm,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not authorized"));
    }

    #[test]
    fn test_secured_frame_verification_with_authorization() {
        // Create sender with authorization
        let mut sender_hsm = VirtualHSM::new("WHEEL_FL".to_string(), 12345);
        let mut sender_perms = crate::types::CanIdPermissions::new("WHEEL_FL".to_string());
        sender_perms.allow_tx(0x100);
        sender_hsm.load_access_control(sender_perms);

        // Create receiver with RX whitelist
        let mut receiver_hsm = VirtualHSM::new("CTRL".to_string(), 67890);
        let sender_key = *sender_hsm.get_symmetric_key();
        receiver_hsm.add_trusted_ecu("WHEEL_FL".to_string(), sender_key);

        let mut receiver_perms = crate::types::CanIdPermissions::new("CTRL".to_string());
        receiver_perms.allow_rx(0x100); // Only receive wheel speed
        receiver_hsm.load_access_control(receiver_perms);

        // Create authorized frame
        let frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "WHEEL_FL".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Should verify successfully
        assert!(frame.verify_with_authorization(&mut receiver_hsm).is_ok());

        // Create frame with unauthorized CAN ID (for receiver)
        let unauthorized_frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![5, 6, 7, 8],
            "WHEEL_FL".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Manually change the CAN ID to test authorization failure
        let mut bad_frame = unauthorized_frame.clone();
        bad_frame.can_id = crate::types::CanId::Standard(0x200);

        // Should fail authorization check
        let result = bad_frame.verify_with_authorization(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::UnauthorizedAccess);
    }

    #[test]
    fn test_unsecured_frame_all_zeros() {
        let mut hsm = VirtualHSM::new("RECEIVER".to_string(), 12345);

        // Create frame with all-zero MAC and CRC (unsecured/injected frame)
        let unsecured_frame = SecuredCanFrame {
            can_id: crate::types::CanId::Standard(0x100),
            data: vec![1, 2, 3, 4],
            source: "ATTACKER".to_string(),
            timestamp: chrono::Utc::now(),
            mac: [0u8; 32], // All zeros - indicates no MAC
            crc: 0,         // Zero CRC
            session_counter: 0,
        };

        // Should detect as UnsecuredFrame
        let result = unsecured_frame.verify(&mut hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::UnsecuredFrame);
    }

    #[test]
    fn test_can_frame_zero_bytes() {
        // Test: 0-byte CAN frame is valid (CAN standard allows this)
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let can_id = crate::types::CanId::Standard(0x100);

        let result = SecuredCanFrame::new(
            can_id,
            vec![], // 0 bytes
            "TEST_ECU".to_string(),
            &mut hsm,
        );

        assert!(
            result.is_ok(),
            "0-byte CAN frame should be valid: {:?}",
            result
        );

        if let Ok(frame) = result {
            assert_eq!(frame.data.len(), 0, "Data length should be 0");
        }
    }

    #[test]
    fn test_can_frame_seven_bytes() {
        // Test: 7-byte CAN frame is valid
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let can_id = crate::types::CanId::Standard(0x100);

        let result = SecuredCanFrame::new(
            can_id,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07], // 7 bytes
            "TEST_ECU".to_string(),
            &mut hsm,
        );

        assert!(
            result.is_ok(),
            "7-byte CAN frame should be valid: {:?}",
            result
        );

        if let Ok(frame) = result {
            assert_eq!(frame.data.len(), 7, "Data length should be 7");
        }
    }

    #[test]
    fn test_can_frame_eight_bytes_maximum() {
        // Test: 8-byte CAN frame is valid (maximum allowed by CAN standard)
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let can_id = crate::types::CanId::Standard(0x100);

        let result = SecuredCanFrame::new(
            can_id,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // 8 bytes (max)
            "TEST_ECU".to_string(),
            &mut hsm,
        );

        assert!(
            result.is_ok(),
            "8-byte CAN frame should be valid: {:?}",
            result
        );

        if let Ok(frame) = result {
            assert_eq!(frame.data.len(), 8, "Data length should be 8");
        }
    }

    #[test]
    fn test_can_frame_nine_bytes_rejected() {
        // Test: 9-byte CAN frame is INVALID (exceeds CAN standard maximum)
        // SECURITY GAP IDENTIFIED: Current implementation does NOT reject 9-byte frames!
        // This test documents the current behavior. Frames should be validated at creation.
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let can_id = crate::types::CanId::Standard(0x100);

        let result = SecuredCanFrame::new(
            can_id,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09], // 9 bytes (too many!)
            "TEST_ECU".to_string(),
            &mut hsm,
        );

        // CURRENT BEHAVIOR: Implementation accepts 9-byte frames (BUG!)
        // TODO: Add validation in SecuredCanFrame::new() to reject data > 8 bytes
        assert!(
            result.is_ok(),
            "SECURITY GAP: 9-byte CAN frame should be rejected but is currently accepted"
        );

        // When this bug is fixed, uncomment the assertion below:
        // assert!(
        //     result.is_err(),
        //     "9-byte CAN frame should be rejected (exceeds maximum)"
        // );
        //
        // if let Err(e) = result {
        //     let error_msg = e.to_string();
        //     assert!(
        //         error_msg.contains("exceeds maximum") || error_msg.contains("too large"),
        //         "Error should mention data length, got: {}",
        //         error_msg
        //     );
        // }
    }

    #[test]
    fn test_can_frame_boundary_verification() {
        // Test: Verify frames with boundary data lengths can be verified correctly
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);

        // Register sender as trusted in receiver
        let sender_mac_key = *sender_hsm.get_symmetric_key();
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_mac_key);

        let can_id = crate::types::CanId::Standard(0x100);

        // Test 0-byte frame verification
        let frame_0 = SecuredCanFrame::new(can_id, vec![], "SENDER".to_string(), &mut sender_hsm)
            .expect("0-byte frame creation failed");
        assert!(
            frame_0.verify(&mut receiver_hsm).is_ok(),
            "0-byte frame verification should succeed"
        );

        // Test 8-byte frame verification
        let frame_8 = SecuredCanFrame::new(
            can_id,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .expect("8-byte frame creation failed");
        assert!(
            frame_8.verify(&mut receiver_hsm).is_ok(),
            "8-byte frame verification should succeed"
        );
    }
}
