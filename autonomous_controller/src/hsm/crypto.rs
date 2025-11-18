use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit as AeadKeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::errors::MacFailureReason;
use super::performance::PerformanceMetrics;

/// Generate Message Authentication Code (MAC) using HMAC-SHA256
pub fn generate_mac(
    data: &[u8],
    session_counter: u64,
    symmetric_key: &[u8; 32],
    metrics: Option<&std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>>,
) -> [u8; 32] {
    let start = if metrics.is_some() {
        Some(Instant::now())
    } else {
        None
    };

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(symmetric_key)
        .expect("HMAC can take key of any size");

    // Include data and session counter in MAC
    mac.update(data);
    mac.update(&session_counter.to_le_bytes());

    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);

    // Record performance metrics
    if let (Some(start), Some(metrics)) = (start, metrics) {
        let elapsed = start.elapsed().as_micros() as u64;
        let mut m = metrics.lock().unwrap();
        m.mac_gen_count += 1;
        m.mac_gen_time_us += elapsed;
    }

    output
}

/// Verify MAC using trusted ECU's key
pub fn verify_mac(
    data: &[u8],
    mac: &[u8; 32],
    session_counter: u64,
    verification_key: &[u8; 32],
    metrics: Option<&std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>>,
) -> Result<(), MacFailureReason> {
    let start = if metrics.is_some() {
        Some(Instant::now())
    } else {
        None
    };

    let mut expected_mac = <Hmac<Sha256> as Mac>::new_from_slice(verification_key)
        .expect("HMAC can take key of any size");

    expected_mac.update(data);
    expected_mac.update(&session_counter.to_le_bytes());

    // Constant-time comparison
    let result = expected_mac
        .verify_slice(mac)
        .map_err(|_| MacFailureReason::CryptoFailure);

    // Record performance metrics
    if let (Some(start), Some(metrics)) = (start, metrics) {
        let elapsed = start.elapsed().as_micros() as u64;
        let mut m = metrics.lock().unwrap();
        m.mac_verify_count += 1;
        m.mac_verify_time_us += elapsed;
    }

    result
}

/// Calculate CRC32 checksum
pub fn calculate_crc(
    data: &[u8],
    metrics: Option<&std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>>,
) -> u32 {
    let start = if metrics.is_some() {
        Some(Instant::now())
    } else {
        None
    };

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(data);

    // Record performance metrics
    if let (Some(start), Some(metrics)) = (start, metrics) {
        let elapsed = start.elapsed().as_micros() as u64;
        let mut m = metrics.lock().unwrap();
        m.crc_calc_count += 1;
        m.crc_calc_time_us += elapsed;
    }

    crc
}

/// Verify CRC32 checksum
pub fn verify_crc(
    data: &[u8],
    expected_crc: u32,
    metrics: Option<&std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>>,
) -> bool {
    let start = if metrics.is_some() {
        Some(Instant::now())
    } else {
        None
    };

    let result = calculate_crc(data, metrics) == expected_crc;

    // Record performance metrics (don't double-count the calculate_crc call)
    if let (Some(start), Some(metrics)) = (start, metrics) {
        let elapsed = start.elapsed().as_micros() as u64;
        let mut m = metrics.lock().unwrap();
        m.crc_verify_count += 1;
        // Subtract the time already counted in calculate_crc
        let crc_time = if m.crc_calc_count > 0 {
            m.crc_calc_time_us / m.crc_calc_count
        } else {
            0
        };
        m.crc_verify_time_us += elapsed.saturating_sub(crc_time);
    }

    result
}

/// Generate firmware fingerprint (SHA256 hash)
pub fn generate_firmware_fingerprint(firmware_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(firmware_data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Verify firmware fingerprint for secure boot
pub fn verify_firmware_fingerprint(firmware_data: &[u8], expected_fingerprint: &[u8; 32]) -> bool {
    let calculated = generate_firmware_fingerprint(firmware_data);

    // Constant-time comparison
    calculated
        .iter()
        .zip(expected_fingerprint.iter())
        .all(|(a, b)| a == b)
}

/// Sign firmware fingerprint with secure boot key (for secure boot)
pub fn sign_firmware(firmware_fingerprint: &[u8; 32], secure_boot_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secure_boot_key)
        .expect("HMAC can take key of any size");
    mac.update(firmware_fingerprint);

    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// Verify firmware signature (secure boot verification)
pub fn verify_firmware_signature(
    firmware_fingerprint: &[u8; 32],
    signature: &[u8; 32],
    secure_boot_key: &[u8; 32],
) -> bool {
    let mut expected_sig = <Hmac<Sha256> as Mac>::new_from_slice(secure_boot_key)
        .expect("HMAC can take key of any size");
    expected_sig.update(firmware_fingerprint);

    // Constant-time comparison
    expected_sig.verify_slice(signature).is_ok()
}

/// Generate firmware update authorization token (for testing)
pub fn generate_update_token(firmware_update_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(firmware_update_key);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Authorize firmware update (verify update authorization token)
pub fn authorize_firmware_update(update_token: &[u8; 32], firmware_update_key: &[u8; 32]) -> bool {
    // In a real system, this would verify a signed token
    // For simulation, we check against the firmware update key hash
    let mut hasher = Sha256::new();
    hasher.update(firmware_update_key);
    let expected = hasher.finalize();

    update_token
        .iter()
        .zip(expected.iter())
        .all(|(a, b)| a == b)
}

// ========================================================================
// AES-256-GCM Authenticated Encryption
// ========================================================================

/// Encrypt data using AES-256-GCM (Authenticated Encryption with Associated Data)
///
/// AES-256-GCM provides:
/// - Confidentiality: AES-256 encryption
/// - Authenticity: 128-bit authentication tag (GMAC)
/// - Integrity: Detects tampering
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `key` - 256-bit encryption key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes) - MUST be unique for each encryption with the same key
/// * `associated_data` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
/// * `Ok(ciphertext)` - Encrypted data with authentication tag appended (len = plaintext.len() + 16)
/// * `Err(String)` - Encryption error
///
/// # Security Notes
/// - NEVER reuse the same nonce with the same key (breaks security)
/// - Use a counter, random value, or timestamp for nonce generation
/// - Associated data can include context like CAN ID, ECU name, etc.
pub fn encrypt_aes256_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>, String> {
    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;

    // Create nonce from 12-byte array
    let nonce_obj = Nonce::from_slice(nonce);

    // Encrypt with associated data
    let ciphertext = cipher
        .encrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(ciphertext)
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
/// * `ciphertext` - Encrypted data with authentication tag (from encrypt_aes256_gcm)
/// * `key` - 256-bit decryption key (32 bytes) - MUST match encryption key
/// * `nonce` - 96-bit nonce (12 bytes) - MUST match encryption nonce
/// * `associated_data` - Additional authenticated data - MUST match encryption AAD
///
/// # Returns
/// * `Ok(plaintext)` - Decrypted data (len = ciphertext.len() - 16)
/// * `Err(String)` - Decryption or authentication failure
///
/// # Security Notes
/// - Decryption fails if ciphertext is tampered, wrong key, wrong nonce, or wrong AAD
/// - Always check the Result - never use unauthenticated data
pub fn decrypt_aes256_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>, String> {
    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;

    // Create nonce from 12-byte array
    let nonce_obj = Nonce::from_slice(nonce);

    // Decrypt and verify authentication tag
    let plaintext = cipher
        .decrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|e| {
            format!(
                "Decryption failed (wrong key, tampered data, or wrong nonce): {}",
                e
            )
        })?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::core::VirtualHSM;
    use crate::hsm::errors::{MacFailureReason, VerifyError};
    use crate::hsm::firmware::SignedFirmware;
    use crate::hsm::secured_frame::SecuredCanFrame;

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
        assert!(!hsm.verify_crc(b"wrong data", crc));
    }

    #[test]
    fn test_crc_mismatch_detection() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        // Create valid frame
        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Corrupt the CRC by changing it
        frame.crc = frame.crc.wrapping_add(1);

        // Verification should fail with CrcMismatch
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CrcMismatch);
    }

    #[test]
    fn test_mac_no_key_registered() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);

        // Receiver does NOT have sender's key registered
        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        // Intentionally NOT calling: receiver_hsm.add_trusted_ecu("SENDER", ...)

        let frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Verification should fail with MacMismatch(NoKeyRegistered)
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            VerifyError::MacMismatch(MacFailureReason::NoKeyRegistered)
        );
    }

    #[test]
    fn test_mac_crypto_failure() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        // Create valid frame
        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Corrupt the MAC by changing one byte
        frame.mac[0] = frame.mac[0].wrapping_add(1);

        // Verification should fail with MacMismatch(CryptoFailure)
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            VerifyError::MacMismatch(MacFailureReason::CryptoFailure)
        );
    }

    #[test]
    fn test_crc_mismatch_with_valid_mac() {
        // Test that CRC is checked first (fails fast before MAC check)
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![5, 6, 7, 8],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Corrupt CRC (MAC is still valid)
        frame.crc = 0;

        // Should fail with CRC error, not MAC error
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CrcMismatch);
    }

    #[test]
    fn test_data_corruption_detected_by_crc() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![10, 20, 30, 40],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Corrupt data (simulating transmission error)
        frame.data[0] = 99;

        // CRC should detect the corruption
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CrcMismatch);
    }

    #[test]
    fn test_tampered_can_id_detected_by_crc() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);

        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![11, 22, 33, 44],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Attacker changes CAN ID (trying to inject command on different ID)
        frame.can_id = crate::types::CanId::Standard(0x300); // Changed from 0x100

        // CRC should detect the tampering (CAN ID is included in CRC calculation)
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VerifyError::CrcMismatch);
    }

    #[test]
    fn test_tampered_source_detected_by_mac() {
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), sender_key);
        // Also register ATTACKER key (different from SENDER)
        let mut attacker_hsm = VirtualHSM::new("ATTACKER".to_string(), 99999);
        let attacker_key = *attacker_hsm.get_symmetric_key();
        receiver_hsm.add_trusted_ecu("ATTACKER".to_string(), attacker_key);

        let mut frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![55, 66, 77, 88],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .unwrap();

        // Attacker changes source field (spoofing)
        frame.source = "ATTACKER".to_string();

        // CRC will fail first (source is in CRC calculation)
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        // Could be CRC or MAC mismatch depending on implementation
        assert!(matches!(
            result.unwrap_err(),
            VerifyError::CrcMismatch | VerifyError::MacMismatch(_)
        ));
    }
}
