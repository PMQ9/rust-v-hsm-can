// HSM Module - Virtual Hardware Security Module
// Refactored from single hsm.rs into modular structure

// Private modules
mod crypto;

// Public modules
pub mod core;
pub mod errors;
pub mod firmware;
pub mod key_rotation;
pub mod performance;
pub mod replay;
pub mod secured_frame;

// Re-export public types for backward compatibility
pub use core::VirtualHSM;
pub use errors::{MacFailureReason, ReplayError, VerifyError};
pub use firmware::SignedFirmware;
pub use key_rotation::{
    KeyRotationManager, KeyRotationPolicy, KeyState, SessionKey, derive_session_key_hkdf,
};
pub use performance::{PerformanceMetrics, PerformanceSnapshot};
pub use replay::{ReplayProtectionConfig, ReplayProtectionState};
pub use secured_frame::SecuredCanFrame;

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_generation_and_verification() {
        let mut hsm1 = VirtualHSM::new("ECU1".to_string(), 12345);
        let hsm2_key = *hsm1.get_symmetric_key();

        let mut hsm2 = VirtualHSM::new("ECU2".to_string(), 67890);
        hsm2.add_trusted_ecu("ECU1".to_string(), hsm2_key);

        let data = b"test data";
        let counter = hsm1.get_session_counter();
        let mac = hsm1.generate_mac(data, counter);

        assert!(hsm2.verify_mac(data, &mac, counter, "ECU1").is_ok());
    }

    #[test]
    fn test_crc_calculation() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let data = b"test data";
        let crc = hsm.calculate_crc(data);
        assert!(hsm.verify_crc(data, crc));
    }

    #[test]
    fn test_invalid_crc() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let data = b"test data";
        let crc = hsm.calculate_crc(data);
        let wrong_crc = crc.wrapping_add(1);
        assert!(!hsm.verify_crc(data, wrong_crc));
    }

    #[test]
    fn test_firmware_signing_and_verification() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let firmware = b"firmware binary data";

        let fingerprint = hsm.generate_firmware_fingerprint(firmware);
        let signature = hsm.sign_firmware(&fingerprint);

        assert!(hsm.verify_firmware_signature(&fingerprint, &signature));
    }

    #[test]
    fn test_invalid_firmware_signature() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let firmware = b"firmware binary data";

        let fingerprint = hsm.generate_firmware_fingerprint(firmware);
        let mut bad_signature = hsm.sign_firmware(&fingerprint);
        bad_signature[0] ^= 0xFF; // Corrupt signature

        assert!(!hsm.verify_firmware_signature(&fingerprint, &bad_signature));
    }

    #[test]
    fn test_firmware_update_authorization() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let token = hsm.generate_update_token();
        assert!(hsm.authorize_firmware_update(&token));

        let mut bad_token = token;
        bad_token[0] ^= 0xFF;
        assert!(!hsm.authorize_firmware_update(&bad_token));
    }

    #[test]
    fn test_session_counter_increment() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let counter1 = hsm.get_session_counter();
        hsm.increment_session();
        let counter2 = hsm.get_session_counter();
        assert_eq!(counter2, counter1 + 1);
    }

    #[test]
    fn test_secured_frame_creation_and_verification() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        let can_id = crate::types::CanId::Standard(0x123);
        let data = vec![1, 2, 3, 4];

        let frame =
            SecuredCanFrame::new(can_id, data.clone(), "SENDER".to_string(), &mut sender_hsm)
                .expect("Frame creation failed");

        assert_eq!(frame.can_id, can_id);
        assert_eq!(frame.data, data);
        assert_eq!(frame.source, "SENDER");

        // Verify the frame
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_ok(), "Frame verification failed: {:?}", result);
    }

    #[test]
    fn test_secured_frame_mac_verification_failure() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        // Note: Not adding sender's key to receiver's trusted keys

        let can_id = crate::types::CanId::Standard(0x123);
        let data = vec![1, 2, 3, 4];

        let frame = SecuredCanFrame::new(can_id, data, "SENDER".to_string(), &mut sender_hsm)
            .expect("Frame creation failed");

        // Verify should fail due to no key registered
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifyError::MacMismatch(MacFailureReason::NoKeyRegistered)
        ));
    }

    #[test]
    fn test_secured_frame_crc_corruption() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        let can_id = crate::types::CanId::Standard(0x123);
        let data = vec![1, 2, 3, 4];

        let mut frame = SecuredCanFrame::new(can_id, data, "SENDER".to_string(), &mut sender_hsm)
            .expect("Frame creation failed");

        // Corrupt CRC
        frame.crc ^= 0xFFFFFFFF;

        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifyError::CrcMismatch));
    }

    #[test]
    fn test_unsecured_frame_detection() {
        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);

        let can_id = crate::types::CanId::Standard(0x123);
        let frame = SecuredCanFrame {
            can_id,
            data: vec![1, 2, 3, 4],
            source: "ATTACKER".to_string(),
            timestamp: chrono::Utc::now(),
            mac: [0u8; 32], // All zeros = unsecured
            crc: 0,
            session_counter: 0,
            key_version: 0,
        };

        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifyError::UnsecuredFrame));
    }

    #[test]
    fn test_replay_protection_duplicate_counter() {
        use chrono::Utc;

        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        // First frame with counter=0
        let counter = sender_hsm.get_session_counter();
        assert_eq!(counter, 0);

        let result1 = receiver_hsm.validate_counter(counter, "SENDER", Utc::now());
        assert!(result1.is_ok());

        // Try to replay same counter
        let result2 = receiver_hsm.validate_counter(counter, "SENDER", Utc::now());
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            ReplayError::CounterAlreadySeen { counter: 0 }
        ));
    }

    #[test]
    fn test_replay_protection_old_counter() {
        use chrono::Utc;

        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        // Accept counter 100
        let result1 = receiver_hsm.validate_counter(100, "SENDER", Utc::now());
        assert!(result1.is_ok());

        // Try counter 0 (too old, outside window of 100)
        let result2 = receiver_hsm.validate_counter(0, "SENDER", Utc::now());
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            ReplayError::CounterTooOld { .. }
        ));
    }

    #[test]
    fn test_replay_protection_strict_monotonic() {
        use chrono::Utc;

        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        // Enable strict monotonic mode
        let mut config = ReplayProtectionConfig::default();
        config.strict_monotonic = true;
        receiver_hsm.set_replay_config(config);

        // Accept counter 5
        let result1 = receiver_hsm.validate_counter(5, "SENDER", Utc::now());
        assert!(result1.is_ok());

        // Try counter 3 (not strictly increasing)
        let result2 = receiver_hsm.validate_counter(3, "SENDER", Utc::now());
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            ReplayError::CounterNotIncreasing { .. }
        ));
    }

    #[test]
    fn test_performance_metrics_disabled_by_default() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        assert!(!hsm.is_performance_enabled());
        assert!(hsm.get_performance_snapshot().is_none());
    }

    #[test]
    fn test_performance_metrics_enabled() {
        let mut hsm = VirtualHSM::with_performance("ECU1".to_string(), 12345, true);
        assert!(hsm.is_performance_enabled());

        // Generate some operations
        let data = b"test";
        let counter = hsm.get_session_counter();
        let _mac = hsm.generate_mac(data, counter);
        let _crc = hsm.calculate_crc(data);

        let snapshot = hsm.get_performance_snapshot().unwrap();
        assert_eq!(snapshot.mac_gen_count, 1);
        assert_eq!(snapshot.crc_calc_count, 1);
    }

    #[test]
    fn test_random_generation() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let r1 = hsm.generate_random();
        let r2 = hsm.generate_random();
        assert_ne!(r1, r2); // Random numbers should be different
    }

    #[test]
    fn test_access_control_tx_authorization() {
        use crate::types::CanIdPermissions;
        use std::collections::HashSet;

        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);

        // Load access control - only allow TX on 0x100
        let mut tx_set = HashSet::new();
        tx_set.insert(0x100);
        let permissions = CanIdPermissions {
            ecu_id: "ECU1".to_string(),
            tx_whitelist: tx_set,
            rx_whitelist: None,
        };
        hsm.load_access_control(permissions);

        // Should allow 0x100
        assert!(hsm.authorize_transmit(0x100).is_ok());

        // Should deny 0x200
        assert!(hsm.authorize_transmit(0x200).is_err());
    }

    #[test]
    fn test_access_control_rx_authorization() {
        use crate::types::CanIdPermissions;
        use std::collections::HashSet;

        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);

        // Load access control - only allow RX on 0x300
        let mut rx_set = HashSet::new();
        rx_set.insert(0x300);
        let permissions = CanIdPermissions {
            ecu_id: "ECU1".to_string(),
            tx_whitelist: HashSet::new(),
            rx_whitelist: Some(rx_set),
        };
        hsm.load_access_control(permissions);

        // Should allow 0x300
        assert!(hsm.authorize_receive(0x300).is_ok());

        // Should deny 0x400
        assert!(hsm.authorize_receive(0x400).is_err());
    }

    #[test]
    fn test_signed_firmware_creation() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let firmware_data = vec![0x90, 0x00, 0x01, 0x02]; // Simulated firmware binary
        let firmware = SignedFirmware::new(
            firmware_data.clone(),
            "1.0.0".to_string(),
            "ECU1".to_string(),
            &hsm,
        );

        assert_eq!(firmware.version, "1.0.0");
        assert_eq!(firmware.target_ecu, "ECU1");
        assert_eq!(firmware.data, firmware_data);

        // Verify the firmware can be verified with the same HSM
        assert!(firmware.verify(&hsm).is_ok());
    }
}
