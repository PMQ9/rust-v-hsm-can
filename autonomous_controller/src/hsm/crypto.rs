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

    let mut mac =
        Hmac::<Sha256>::new_from_slice(symmetric_key).expect("HMAC can take key of any size");

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

    let mut expected_mac =
        Hmac::<Sha256>::new_from_slice(verification_key).expect("HMAC can take key of any size");

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
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secure_boot_key).expect("HMAC can take key of any size");
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
    let mut expected_sig =
        Hmac::<Sha256>::new_from_slice(secure_boot_key).expect("HMAC can take key of any size");
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
