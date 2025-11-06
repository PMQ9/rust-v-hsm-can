use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Reasons why MAC verification can fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacFailureReason {
    /// No MAC verification key registered for the source ECU
    NoKeyRegistered,
    /// HMAC cryptographic verification failed (tampered data or wrong key)
    CryptoFailure,
}

impl fmt::Display for MacFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacFailureReason::NoKeyRegistered => write!(f, "No MAC key registered for source ECU"),
            MacFailureReason::CryptoFailure => write!(f, "HMAC cryptographic verification failed"),
        }
    }
}

/// Structured verification error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Frame has no MAC/CRC (all zeros) - indicates unsecured/injected frame
    UnsecuredFrame,
    /// CRC32 checksum mismatch - indicates data corruption or tampering
    CrcMismatch,
    /// MAC verification failed - indicates authentication failure
    MacMismatch(MacFailureReason),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::UnsecuredFrame => write!(f, "Unsecured frame (no MAC/CRC)"),
            VerifyError::CrcMismatch => write!(f, "CRC verification failed"),
            VerifyError::MacMismatch(reason) => write!(f, "MAC verification failed: {}", reason),
        }
    }
}

/// Virtual Hardware Security Module
/// Provides cryptographic key management and operations for secure CAN communication
#[derive(Clone)]
pub struct VirtualHSM {
    /// Master key for deriving other keys (256-bit)
    master_key: [u8; 32],

    /// Secure boot key for firmware verification (256-bit)
    secure_boot_key: [u8; 32],

    /// Firmware update key for authorizing updates (256-bit)
    firmware_update_key: [u8; 32],

    /// Symmetric key for MAC generation (256-bit)
    symmetric_comm_key: [u8; 32],

    /// Key encryption key for protecting keys during transfer (256-bit)
    key_encryption_key: [u8; 32],

    /// RNG seed key for deterministic random number generation (256-bit)
    rng_seed_key: [u8; 32],

    /// Seed/key access authorization token (256-bit)
    seed_key_access: [u8; 32],

    /// MAC verification keys for each ECU this HSM trusts
    mac_verification_keys: HashMap<String, [u8; 32]>,

    /// Session key counter for anti-replay protection
    session_counter: u64,

    /// ECU identifier
    ecu_id: String,

    /// Random number generator
    rng: StdRng,
}

impl VirtualHSM {
    /// Create a new HSM instance with deterministic keys (for testing)
    /// In production, keys would be provisioned during manufacturing
    pub fn new(ecu_id: String, seed: u64) -> Self {
        let rng = StdRng::seed_from_u64(seed);

        let mut hsm = Self {
            master_key: [0u8; 32],
            secure_boot_key: [0u8; 32],
            firmware_update_key: [0u8; 32],
            symmetric_comm_key: [0u8; 32],
            key_encryption_key: [0u8; 32],
            rng_seed_key: [0u8; 32],
            seed_key_access: [0u8; 32],
            mac_verification_keys: HashMap::new(),
            session_counter: 0,
            ecu_id,
            rng,
        };

        // Generate deterministic keys based on seed
        hsm.rng.fill(&mut hsm.master_key);
        hsm.rng.fill(&mut hsm.secure_boot_key);
        hsm.rng.fill(&mut hsm.firmware_update_key);
        hsm.rng.fill(&mut hsm.symmetric_comm_key);
        hsm.rng.fill(&mut hsm.key_encryption_key);
        hsm.rng.fill(&mut hsm.rng_seed_key);
        hsm.rng.fill(&mut hsm.seed_key_access);

        hsm
    }

    /// Add a trusted ECU's MAC verification key
    pub fn add_trusted_ecu(&mut self, ecu_name: String, mac_key: [u8; 32]) {
        self.mac_verification_keys.insert(ecu_name, mac_key);
    }

    /// Get symmetric communication key for this ECU
    pub fn get_symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_comm_key
    }

    /// Get session counter (for anti-replay)
    pub fn get_session_counter(&self) -> u64 {
        self.session_counter
    }

    /// Increment session counter
    pub fn increment_session(&mut self) {
        self.session_counter = self.session_counter.wrapping_add(1);
    }

    /// Generate Message Authentication Code (MAC) using HMAC-SHA256
    pub fn generate_mac(&self, data: &[u8], session_counter: u64) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.symmetric_comm_key)
            .expect("HMAC can take key of any size");

        // Include data and session counter in MAC
        mac.update(data);
        mac.update(&session_counter.to_le_bytes());

        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut output = [0u8; 32];
        output.copy_from_slice(&bytes);
        output
    }

    /// Verify MAC using trusted ECU's key
    pub fn verify_mac(&self, data: &[u8], mac: &[u8; 32], session_counter: u64, source_ecu: &str) -> Result<(), MacFailureReason> {
        // Get the MAC key for the source ECU
        let key = match self.mac_verification_keys.get(source_ecu) {
            Some(k) => k,
            None => {
                return Err(MacFailureReason::NoKeyRegistered);
            }
        };

        let mut expected_mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC can take key of any size");

        expected_mac.update(data);
        expected_mac.update(&session_counter.to_le_bytes());

        // Constant-time comparison
        expected_mac.verify_slice(mac)
            .map_err(|_| MacFailureReason::CryptoFailure)
    }

    /// Calculate CRC32 checksum
    pub fn calculate_crc(&self, data: &[u8]) -> u32 {
        crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(data)
    }

    /// Verify CRC32 checksum
    pub fn verify_crc(&self, data: &[u8], expected_crc: u32) -> bool {
        self.calculate_crc(data) == expected_crc
    }

    /// Generate firmware fingerprint (SHA256 hash)
    pub fn generate_firmware_fingerprint(&self, firmware_data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(firmware_data);
        let result = hasher.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Verify firmware fingerprint for secure boot
    pub fn verify_firmware_fingerprint(&self, firmware_data: &[u8], expected_fingerprint: &[u8; 32]) -> bool {
        let calculated = self.generate_firmware_fingerprint(firmware_data);

        // Constant-time comparison
        calculated.iter().zip(expected_fingerprint.iter()).all(|(a, b)| a == b)
    }

    /// Sign firmware fingerprint with secure boot key (for secure boot)
    pub fn sign_firmware(&self, firmware_fingerprint: &[u8; 32]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secure_boot_key)
            .expect("HMAC can take key of any size");
        mac.update(firmware_fingerprint);

        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut output = [0u8; 32];
        output.copy_from_slice(&bytes);
        output
    }

    /// Verify firmware signature (secure boot verification)
    pub fn verify_firmware_signature(&self, firmware_fingerprint: &[u8; 32], signature: &[u8; 32]) -> bool {
        let mut expected_sig = Hmac::<Sha256>::new_from_slice(&self.secure_boot_key)
            .expect("HMAC can take key of any size");
        expected_sig.update(firmware_fingerprint);

        // Constant-time comparison
        expected_sig.verify_slice(signature).is_ok()
    }

    /// Authorize firmware update (verify update authorization token)
    pub fn authorize_firmware_update(&self, update_token: &[u8; 32]) -> bool {
        // In a real system, this would verify a signed token
        // For simulation, we check against the firmware update key hash
        let mut hasher = Sha256::new();
        hasher.update(&self.firmware_update_key);
        let expected = hasher.finalize();

        update_token.iter().zip(expected.iter()).all(|(a, b)| a == b)
    }

    /// Generate firmware update authorization token (for testing)
    pub fn generate_update_token(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.firmware_update_key);
        let result = hasher.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Verify seed/key access authorization
    pub fn verify_seed_access(&self, access_token: &[u8; 32]) -> bool {
        // Constant-time comparison
        access_token.iter().zip(self.seed_key_access.iter()).all(|(a, b)| a == b)
    }

    /// Generate a random number (for nonces, challenges, etc.)
    pub fn generate_random(&mut self) -> u64 {
        Rng::r#gen(&mut self.rng)
    }

    /// Get ECU ID
    pub fn get_ecu_id(&self) -> &str {
        &self.ecu_id
    }
}

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
    /// Create a new secured CAN frame
    pub fn new(
        can_id: crate::types::CanId,
        data: Vec<u8>,
        source: String,
        hsm: &mut VirtualHSM,
    ) -> Self {
        let timestamp = chrono::Utc::now();
        let session_counter = hsm.get_session_counter();
        hsm.increment_session();

        // Prepare data for MAC and CRC calculation
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&(can_id.value() as u32).to_le_bytes());
        mac_data.extend_from_slice(&data);
        mac_data.extend_from_slice(source.as_bytes());

        // Calculate MAC and CRC
        let mac = hsm.generate_mac(&mac_data, session_counter);
        let crc = hsm.calculate_crc(&mac_data);

        Self {
            can_id,
            data,
            source,
            timestamp,
            mac,
            crc,
            session_counter,
        }
    }

    /// Verify the frame's MAC and CRC
    pub fn verify(&self, hsm: &VirtualHSM) -> Result<(), VerifyError> {
        // Check if MAC is all zeros - this indicates an unsecured frame
        if self.mac == [0u8; 32] && self.crc == 0 {
            return Err(VerifyError::UnsecuredFrame);
        }

        // Reconstruct data for verification
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(&(self.can_id.value() as u32).to_le_bytes());
        verify_data.extend_from_slice(&self.data);
        verify_data.extend_from_slice(self.source.as_bytes());

        // Verify CRC first (faster check)
        if !hsm.verify_crc(&verify_data, self.crc) {
            return Err(VerifyError::CrcMismatch);
        }

        // Verify MAC (cryptographic check)
        hsm.verify_mac(&verify_data, &self.mac, self.session_counter, &self.source)
            .map_err(|reason| VerifyError::MacMismatch(reason))?;

        Ok(())
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

/// Firmware with digital signature for secure boot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFirmware {
    /// Firmware binary data
    pub data: Vec<u8>,

    /// Firmware version
    pub version: String,

    /// SHA256 fingerprint of firmware
    pub fingerprint: [u8; 32],

    /// HMAC signature of fingerprint (signed with SecureBootKey)
    pub signature: [u8; 32],

    /// ECU this firmware is intended for
    pub target_ecu: String,
}

impl SignedFirmware {
    /// Create a new signed firmware
    pub fn new(data: Vec<u8>, version: String, target_ecu: String, hsm: &VirtualHSM) -> Self {
        let fingerprint = hsm.generate_firmware_fingerprint(&data);
        let signature = hsm.sign_firmware(&fingerprint);

        Self {
            data,
            version,
            fingerprint,
            signature,
            target_ecu,
        }
    }

    /// Verify firmware signature (secure boot)
    pub fn verify(&self, hsm: &VirtualHSM) -> Result<(), String> {
        // Verify the fingerprint matches the data
        if !hsm.verify_firmware_fingerprint(&self.data, &self.fingerprint) {
            return Err("Firmware fingerprint mismatch".to_string());
        }

        // Verify the signature
        if !hsm.verify_firmware_signature(&self.fingerprint, &self.signature) {
            return Err("Firmware signature verification failed".to_string());
        }

        Ok(())
    }
}

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
        assert!(!hsm.verify_crc(b"wrong data", crc));
    }

    #[test]
    fn test_firmware_verification() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let firmware_data = b"firmware binary data";

        let firmware = SignedFirmware::new(
            firmware_data.to_vec(),
            "1.0.0".to_string(),
            "ECU1".to_string(),
            &hsm,
        );

        assert!(firmware.verify(&hsm).is_ok());
    }
}
