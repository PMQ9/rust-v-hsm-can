use colored::*;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
    /// Unauthorized CAN ID access - ECU not permitted to use this CAN ID
    UnauthorizedAccess,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::UnsecuredFrame => write!(f, "Unsecured frame (no MAC/CRC)"),
            VerifyError::CrcMismatch => write!(f, "CRC verification failed"),
            VerifyError::MacMismatch(reason) => write!(f, "MAC verification failed: {}", reason),
            VerifyError::UnauthorizedAccess => write!(f, "Unauthorized CAN ID access"),
        }
    }
}

/// Performance metrics for HSM operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    /// Total MAC generation operations
    pub mac_gen_count: u64,
    /// Total time spent generating MACs (microseconds)
    pub mac_gen_time_us: u64,

    /// Total MAC verification operations
    pub mac_verify_count: u64,
    /// Total time spent verifying MACs (microseconds)
    pub mac_verify_time_us: u64,

    /// Total CRC calculation operations
    pub crc_calc_count: u64,
    /// Total time spent calculating CRCs (microseconds)
    pub crc_calc_time_us: u64,

    /// Total CRC verification operations
    pub crc_verify_count: u64,
    /// Total time spent verifying CRCs (microseconds)
    pub crc_verify_time_us: u64,

    /// Total frame creation operations
    pub frame_create_count: u64,
    /// Total time spent creating secured frames (microseconds)
    pub frame_create_time_us: u64,

    /// Total frame verification operations
    pub frame_verify_count: u64,
    /// Total time spent verifying secured frames (microseconds)
    pub frame_verify_time_us: u64,

    /// End-to-end latency samples (microseconds)
    pub e2e_latency_samples: Vec<u64>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Print performance statistics
    pub fn print_stats(&self, ecu_name: &str) {
        println!(
            "\n{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );
        println!(
            "{} HSM Performance Statistics for {}",
            "ℹ".bright_blue(),
            ecu_name.bright_white().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );

        if self.mac_gen_count > 0 {
            let avg_mac_gen = self.mac_gen_time_us as f64 / self.mac_gen_count as f64;
            println!(
                "MAC Generation:    {} ops, avg {:.2} μs/op",
                self.mac_gen_count, avg_mac_gen
            );
        }

        if self.mac_verify_count > 0 {
            let avg_mac_verify = self.mac_verify_time_us as f64 / self.mac_verify_count as f64;
            println!(
                "MAC Verification:  {} ops, avg {:.2} μs/op",
                self.mac_verify_count, avg_mac_verify
            );
        }

        if self.crc_calc_count > 0 {
            let avg_crc_calc = self.crc_calc_time_us as f64 / self.crc_calc_count as f64;
            println!(
                "CRC Calculation:   {} ops, avg {:.2} μs/op",
                self.crc_calc_count, avg_crc_calc
            );
        }

        if self.crc_verify_count > 0 {
            let avg_crc_verify = self.crc_verify_time_us as f64 / self.crc_verify_count as f64;
            println!(
                "CRC Verification:  {} ops, avg {:.2} μs/op",
                self.crc_verify_count, avg_crc_verify
            );
        }

        if self.frame_create_count > 0 {
            let avg_frame_create =
                self.frame_create_time_us as f64 / self.frame_create_count as f64;
            println!(
                "Frame Creation:    {} ops, avg {:.2} μs/op",
                self.frame_create_count, avg_frame_create
            );
        }

        if self.frame_verify_count > 0 {
            let avg_frame_verify =
                self.frame_verify_time_us as f64 / self.frame_verify_count as f64;
            println!(
                "Frame Verification: {} ops, avg {:.2} μs/op",
                self.frame_verify_count, avg_frame_verify
            );
        }

        if !self.e2e_latency_samples.is_empty() {
            let avg_e2e = self.e2e_latency_samples.iter().sum::<u64>() as f64
                / self.e2e_latency_samples.len() as f64;
            let min_e2e = *self.e2e_latency_samples.iter().min().unwrap_or(&0);
            let max_e2e = *self.e2e_latency_samples.iter().max().unwrap_or(&0);
            println!(
                "\nEnd-to-End Latency: {} samples",
                self.e2e_latency_samples.len()
            );
            println!("  Average: {:.2} μs ({:.3} ms)", avg_e2e, avg_e2e / 1000.0);
            println!(
                "  Min:     {} μs ({:.3} ms)",
                min_e2e,
                min_e2e as f64 / 1000.0
            );
            println!(
                "  Max:     {} μs ({:.3} ms)",
                max_e2e,
                max_e2e as f64 / 1000.0
            );
        }

        println!(
            "{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );
    }
}

/// Simplified performance snapshot for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub ecu_name: String,
    pub mac_gen_count: u64,
    pub mac_gen_avg_us: f64,
    pub mac_verify_count: u64,
    pub mac_verify_avg_us: f64,
    pub crc_calc_count: u64,
    pub crc_calc_avg_us: f64,
    pub crc_verify_count: u64,
    pub crc_verify_avg_us: f64,
    pub frame_create_count: u64,
    pub frame_create_avg_us: f64,
    pub frame_verify_count: u64,
    pub frame_verify_avg_us: f64,
    pub e2e_latency_avg_us: f64,
    pub e2e_latency_min_us: u64,
    pub e2e_latency_max_us: u64,
    pub e2e_sample_count: u64,
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

    /// Performance metrics (None if performance tracking disabled)
    performance_metrics: Option<Arc<Mutex<PerformanceMetrics>>>,

    /// CAN ID access control permissions
    can_id_permissions: Option<crate::types::CanIdPermissions>,
}

impl VirtualHSM {
    /// Create a new HSM instance with deterministic keys (for testing)
    /// In production, keys would be provisioned during manufacturing
    pub fn new(ecu_id: String, seed: u64) -> Self {
        Self::with_performance(ecu_id, seed, false)
    }

    /// Create a new HSM instance with optional performance tracking
    pub fn with_performance(ecu_id: String, seed: u64, performance_mode: bool) -> Self {
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
            performance_metrics: if performance_mode {
                Some(Arc::new(Mutex::new(PerformanceMetrics::new())))
            } else {
                None
            },
            can_id_permissions: None,
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

    /// Check if performance tracking is enabled
    pub fn is_performance_enabled(&self) -> bool {
        self.performance_metrics.is_some()
    }

    /// Print performance statistics (if enabled)
    pub fn print_performance_stats(&self) {
        if let Some(metrics) = &self.performance_metrics {
            let metrics = metrics.lock().unwrap();
            metrics.print_stats(&self.ecu_id);
        }
    }

    /// Get a snapshot of performance metrics (if enabled)
    pub fn get_performance_snapshot(&self) -> Option<PerformanceSnapshot> {
        if let Some(metrics) = &self.performance_metrics {
            let m = metrics.lock().unwrap();

            // Calculate summary statistics for e2e latency
            let (avg_e2e, min_e2e, max_e2e) = if !m.e2e_latency_samples.is_empty() {
                let avg = m.e2e_latency_samples.iter().sum::<u64>() as f64
                    / m.e2e_latency_samples.len() as f64;
                let min = *m.e2e_latency_samples.iter().min().unwrap_or(&0);
                let max = *m.e2e_latency_samples.iter().max().unwrap_or(&0);
                (avg, min, max)
            } else {
                (0.0, 0, 0)
            };

            Some(PerformanceSnapshot {
                ecu_name: self.ecu_id.clone(),
                mac_gen_count: m.mac_gen_count,
                mac_gen_avg_us: if m.mac_gen_count > 0 {
                    m.mac_gen_time_us as f64 / m.mac_gen_count as f64
                } else {
                    0.0
                },
                mac_verify_count: m.mac_verify_count,
                mac_verify_avg_us: if m.mac_verify_count > 0 {
                    m.mac_verify_time_us as f64 / m.mac_verify_count as f64
                } else {
                    0.0
                },
                crc_calc_count: m.crc_calc_count,
                crc_calc_avg_us: if m.crc_calc_count > 0 {
                    m.crc_calc_time_us as f64 / m.crc_calc_count as f64
                } else {
                    0.0
                },
                crc_verify_count: m.crc_verify_count,
                crc_verify_avg_us: if m.crc_verify_count > 0 {
                    m.crc_verify_time_us as f64 / m.crc_verify_count as f64
                } else {
                    0.0
                },
                frame_create_count: m.frame_create_count,
                frame_create_avg_us: if m.frame_create_count > 0 {
                    m.frame_create_time_us as f64 / m.frame_create_count as f64
                } else {
                    0.0
                },
                frame_verify_count: m.frame_verify_count,
                frame_verify_avg_us: if m.frame_verify_count > 0 {
                    m.frame_verify_time_us as f64 / m.frame_verify_count as f64
                } else {
                    0.0
                },
                e2e_latency_avg_us: avg_e2e,
                e2e_latency_min_us: min_e2e,
                e2e_latency_max_us: max_e2e,
                e2e_sample_count: m.e2e_latency_samples.len() as u64,
            })
        } else {
            None
        }
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
        let start = if self.performance_metrics.is_some() {
            Some(Instant::now())
        } else {
            None
        };

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.symmetric_comm_key)
            .expect("HMAC can take key of any size");

        // Include data and session counter in MAC
        mac.update(data);
        mac.update(&session_counter.to_le_bytes());

        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut output = [0u8; 32];
        output.copy_from_slice(&bytes);

        // Record performance metrics
        if let (Some(start), Some(metrics)) = (start, &self.performance_metrics) {
            let elapsed = start.elapsed().as_micros() as u64;
            let mut m = metrics.lock().unwrap();
            m.mac_gen_count += 1;
            m.mac_gen_time_us += elapsed;
        }

        output
    }

    /// Verify MAC using trusted ECU's key
    pub fn verify_mac(
        &self,
        data: &[u8],
        mac: &[u8; 32],
        session_counter: u64,
        source_ecu: &str,
    ) -> Result<(), MacFailureReason> {
        let start = if self.performance_metrics.is_some() {
            Some(Instant::now())
        } else {
            None
        };

        // Get the MAC key for the source ECU
        let key = match self.mac_verification_keys.get(source_ecu) {
            Some(k) => k,
            None => {
                return Err(MacFailureReason::NoKeyRegistered);
            }
        };

        let mut expected_mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");

        expected_mac.update(data);
        expected_mac.update(&session_counter.to_le_bytes());

        // Constant-time comparison
        let result = expected_mac
            .verify_slice(mac)
            .map_err(|_| MacFailureReason::CryptoFailure);

        // Record performance metrics
        if let (Some(start), Some(metrics)) = (start, &self.performance_metrics) {
            let elapsed = start.elapsed().as_micros() as u64;
            let mut m = metrics.lock().unwrap();
            m.mac_verify_count += 1;
            m.mac_verify_time_us += elapsed;
        }

        result
    }

    /// Calculate CRC32 checksum
    pub fn calculate_crc(&self, data: &[u8]) -> u32 {
        let start = if self.performance_metrics.is_some() {
            Some(Instant::now())
        } else {
            None
        };

        let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(data);

        // Record performance metrics
        if let (Some(start), Some(metrics)) = (start, &self.performance_metrics) {
            let elapsed = start.elapsed().as_micros() as u64;
            let mut m = metrics.lock().unwrap();
            m.crc_calc_count += 1;
            m.crc_calc_time_us += elapsed;
        }

        crc
    }

    /// Verify CRC32 checksum
    pub fn verify_crc(&self, data: &[u8], expected_crc: u32) -> bool {
        let start = if self.performance_metrics.is_some() {
            Some(Instant::now())
        } else {
            None
        };

        let result = self.calculate_crc(data) == expected_crc;

        // Record performance metrics (don't double-count the calculate_crc call)
        if let (Some(start), Some(metrics)) = (start, &self.performance_metrics) {
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
    pub fn generate_firmware_fingerprint(&self, firmware_data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(firmware_data);
        let result = hasher.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Verify firmware fingerprint for secure boot
    pub fn verify_firmware_fingerprint(
        &self,
        firmware_data: &[u8],
        expected_fingerprint: &[u8; 32],
    ) -> bool {
        let calculated = self.generate_firmware_fingerprint(firmware_data);

        // Constant-time comparison
        calculated
            .iter()
            .zip(expected_fingerprint.iter())
            .all(|(a, b)| a == b)
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
    pub fn verify_firmware_signature(
        &self,
        firmware_fingerprint: &[u8; 32],
        signature: &[u8; 32],
    ) -> bool {
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
        hasher.update(self.firmware_update_key);
        let expected = hasher.finalize();

        update_token
            .iter()
            .zip(expected.iter())
            .all(|(a, b)| a == b)
    }

    /// Generate firmware update authorization token (for testing)
    pub fn generate_update_token(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.firmware_update_key);
        let result = hasher.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Verify seed/key access authorization
    pub fn verify_seed_access(&self, access_token: &[u8; 32]) -> bool {
        // Constant-time comparison
        access_token
            .iter()
            .zip(self.seed_key_access.iter())
            .all(|(a, b)| a == b)
    }

    /// Generate a random number (for nonces, challenges, etc.)
    pub fn generate_random(&mut self) -> u64 {
        Rng::r#gen(&mut self.rng)
    }

    /// Get ECU ID
    pub fn get_ecu_id(&self) -> &str {
        &self.ecu_id
    }

    /// Load CAN ID access control policy
    pub fn load_access_control(&mut self, permissions: crate::types::CanIdPermissions) {
        println!(
            "{} Loading CAN ID access control for {}",
            "→".cyan(),
            permissions.ecu_id
        );
        println!(
            "   • TX whitelist: {} CAN IDs",
            permissions.tx_whitelist.len()
        );
        if let Some(ref rx) = permissions.rx_whitelist {
            println!("   • RX whitelist: {} CAN IDs", rx.len());
        } else {
            println!("   • RX whitelist: ALL (no filtering)");
        }
        self.can_id_permissions = Some(permissions);
    }

    /// Check if this ECU is authorized to transmit on the given CAN ID
    pub fn authorize_transmit(&self, can_id: u32) -> Result<(), String> {
        match &self.can_id_permissions {
            None => Ok(()), // No access control = allow all
            Some(perms) => {
                if perms.can_transmit(can_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "ECU {} not authorized to transmit on CAN ID 0x{:03X}",
                        self.ecu_id, can_id
                    ))
                }
            }
        }
    }

    /// Check if this ECU is authorized to receive the given CAN ID
    pub fn authorize_receive(&self, can_id: u32) -> Result<(), String> {
        match &self.can_id_permissions {
            None => Ok(()), // No access control = receive all
            Some(perms) => {
                if perms.can_receive(can_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "ECU {} not authorized to receive CAN ID 0x{:03X}",
                        self.ecu_id, can_id
                    ))
                }
            }
        }
    }

    /// Get reference to access control permissions
    pub fn get_permissions(&self) -> Option<&crate::types::CanIdPermissions> {
        self.can_id_permissions.as_ref()
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
        let mac = hsm.generate_mac(&mac_data, session_counter);
        let crc = hsm.calculate_crc(&mac_data);

        // Record performance metrics
        if let (Some(start), Some(metrics)) = (start, &hsm.performance_metrics) {
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
    pub fn verify(&self, hsm: &VirtualHSM) -> Result<(), VerifyError> {
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
        if !hsm.verify_crc(&verify_data, self.crc) {
            return Err(VerifyError::CrcMismatch);
        }

        // Verify MAC (cryptographic check)
        let result = hsm
            .verify_mac(&verify_data, &self.mac, self.session_counter, &self.source)
            .map_err(VerifyError::MacMismatch);

        // Record performance metrics (only on success)
        if result.is_ok()
            && let (Some(start), Some(metrics)) = (start, &hsm.performance_metrics)
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
    pub fn verify_with_authorization(&self, hsm: &VirtualHSM) -> Result<(), VerifyError> {
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
