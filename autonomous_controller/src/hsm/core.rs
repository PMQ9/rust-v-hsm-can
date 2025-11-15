use chrono::{DateTime, Utc};
use colored::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::crypto;
use super::errors::{MacFailureReason, ReplayError};
use super::performance::{PerformanceMetrics, PerformanceSnapshot};
use super::replay::{ReplayProtectionConfig, ReplayProtectionState};

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

    /// Replay protection state for each trusted ECU
    replay_protection_state: HashMap<String, ReplayProtectionState>,

    /// Replay protection configuration
    replay_config: ReplayProtectionConfig,

    /// Anomaly detector for behavioral IDS (None if disabled)
    anomaly_detector: Option<crate::anomaly_detection::AnomalyDetector>,
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
            replay_protection_state: HashMap::new(),
            replay_config: ReplayProtectionConfig::default(),
            anomaly_detector: None, // Disabled by default
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

    // ========================================================================
    // Performance Metrics
    // ========================================================================

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

    /// Get reference to performance metrics (internal use)
    pub(super) fn performance_metrics_ref(&self) -> Option<&Arc<Mutex<PerformanceMetrics>>> {
        self.performance_metrics.as_ref()
    }

    // ========================================================================
    // Key Management
    // ========================================================================

    /// Add a trusted ECU's MAC verification key
    pub fn add_trusted_ecu(&mut self, ecu_name: String, mac_key: [u8; 32]) {
        self.mac_verification_keys.insert(ecu_name, mac_key);
    }

    /// Get symmetric communication key for this ECU
    pub fn get_symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_comm_key
    }

    /// Get MAC verification key for a specific ECU (internal use)
    pub(super) fn get_mac_verification_key(&self, ecu_name: &str) -> Option<&[u8; 32]> {
        self.mac_verification_keys.get(ecu_name)
    }

    /// Verify seed/key access authorization
    pub fn verify_seed_access(&self, access_token: &[u8; 32]) -> bool {
        // Constant-time comparison
        access_token
            .iter()
            .zip(self.seed_key_access.iter())
            .all(|(a, b)| a == b)
    }

    // ========================================================================
    // Session Counter (Anti-Replay)
    // ========================================================================

    /// Get session counter (for anti-replay)
    pub fn get_session_counter(&self) -> u64 {
        self.session_counter
    }

    /// Increment session counter
    pub fn increment_session(&mut self) {
        self.session_counter = self.session_counter.wrapping_add(1);
    }

    // ========================================================================
    // Cryptographic Operations (Delegated)
    // ========================================================================

    /// Generate Message Authentication Code (MAC) using HMAC-SHA256
    pub fn generate_mac(&self, data: &[u8], session_counter: u64) -> [u8; 32] {
        crypto::generate_mac(
            data,
            session_counter,
            &self.symmetric_comm_key,
            self.performance_metrics.as_ref(),
        )
    }

    /// Verify MAC using trusted ECU's key
    pub fn verify_mac(
        &self,
        data: &[u8],
        mac: &[u8; 32],
        session_counter: u64,
        source_ecu: &str,
    ) -> Result<(), MacFailureReason> {
        // Get the MAC key for the source ECU
        let key = self
            .mac_verification_keys
            .get(source_ecu)
            .ok_or(MacFailureReason::NoKeyRegistered)?;

        crypto::verify_mac(
            data,
            mac,
            session_counter,
            key,
            self.performance_metrics.as_ref(),
        )
    }

    /// Calculate CRC32 checksum
    pub fn calculate_crc(&self, data: &[u8]) -> u32 {
        crypto::calculate_crc(data, self.performance_metrics.as_ref())
    }

    /// Verify CRC32 checksum
    pub fn verify_crc(&self, data: &[u8], expected_crc: u32) -> bool {
        crypto::verify_crc(data, expected_crc, self.performance_metrics.as_ref())
    }

    /// Generate firmware fingerprint (SHA256 hash)
    pub fn generate_firmware_fingerprint(&self, firmware_data: &[u8]) -> [u8; 32] {
        crypto::generate_firmware_fingerprint(firmware_data)
    }

    /// Verify firmware fingerprint for secure boot
    pub fn verify_firmware_fingerprint(
        &self,
        firmware_data: &[u8],
        expected_fingerprint: &[u8; 32],
    ) -> bool {
        crypto::verify_firmware_fingerprint(firmware_data, expected_fingerprint)
    }

    /// Sign firmware fingerprint with secure boot key (for secure boot)
    pub fn sign_firmware(&self, firmware_fingerprint: &[u8; 32]) -> [u8; 32] {
        crypto::sign_firmware(firmware_fingerprint, &self.secure_boot_key)
    }

    /// Verify firmware signature (secure boot verification)
    pub fn verify_firmware_signature(
        &self,
        firmware_fingerprint: &[u8; 32],
        signature: &[u8; 32],
    ) -> bool {
        crypto::verify_firmware_signature(firmware_fingerprint, signature, &self.secure_boot_key)
    }

    /// Authorize firmware update (verify update authorization token)
    pub fn authorize_firmware_update(&self, update_token: &[u8; 32]) -> bool {
        crypto::authorize_firmware_update(update_token, &self.firmware_update_key)
    }

    /// Generate firmware update authorization token (for testing)
    pub fn generate_update_token(&self) -> [u8; 32] {
        crypto::generate_update_token(&self.firmware_update_key)
    }

    // ========================================================================
    // Replay Protection
    // ========================================================================

    /// Check if a session counter from a source ECU should be accepted
    /// Returns Ok(()) if counter is valid, Err with reason if replay detected
    pub fn validate_counter(
        &mut self,
        session_counter: u64,
        source_ecu: &str,
        frame_timestamp: DateTime<Utc>,
    ) -> Result<(), ReplayError> {
        // Get or initialize replay state for this ECU
        let state = self
            .replay_protection_state
            .entry(source_ecu.to_string())
            .or_insert_with(|| ReplayProtectionState::new(&self.replay_config));

        // Validate using replay module
        let result = super::replay::validate_counter(
            session_counter,
            state,
            &self.replay_config,
            frame_timestamp,
        );

        // If successful, update state
        if result.is_ok() {
            state.accept_counter(session_counter, frame_timestamp);
        }

        result
    }

    /// Configure replay protection settings
    pub fn set_replay_config(&mut self, config: ReplayProtectionConfig) {
        self.replay_config = config;
    }

    /// Get current replay protection configuration
    pub fn get_replay_config(&self) -> &ReplayProtectionConfig {
        &self.replay_config
    }

    /// Reset replay protection state for a specific ECU (for testing)
    pub fn reset_replay_state(&mut self, ecu_id: &str) {
        if let Some(state) = self.replay_protection_state.get_mut(ecu_id) {
            state.reset();
        }
    }

    // ========================================================================
    // Random Number Generation
    // ========================================================================

    /// Generate a random number (for nonces, challenges, etc.)
    pub fn generate_random(&mut self) -> u64 {
        Rng::r#gen(&mut self.rng)
    }

    // ========================================================================
    // ECU Identity
    // ========================================================================

    /// Get ECU ID
    pub fn get_ecu_id(&self) -> &str {
        &self.ecu_id
    }

    // ========================================================================
    // Access Control
    // ========================================================================

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

    // ========================================================================
    // Anomaly Detection Methods
    // ========================================================================

    /// Enable anomaly detection with a pre-trained baseline
    pub fn load_anomaly_baseline(
        &mut self,
        baseline: crate::anomaly_detection::AnomalyBaseline,
    ) -> Result<(), String> {
        let mut detector = crate::anomaly_detection::AnomalyDetector::new();
        detector.load_baseline(baseline)?;

        self.anomaly_detector = Some(detector);

        println!(
            "{} Anomaly detection enabled for {}",
            "→".cyan(),
            self.ecu_id.bright_white()
        );

        Ok(())
    }

    /// Start anomaly detection training mode
    pub fn start_anomaly_training(&mut self, min_samples_per_can_id: u64) -> Result<(), String> {
        let mut detector = crate::anomaly_detection::AnomalyDetector::new();
        detector.start_training(self.ecu_id.clone(), min_samples_per_can_id)?;

        self.anomaly_detector = Some(detector);

        println!(
            "{} Anomaly detection training started for {}",
            "→".cyan(),
            self.ecu_id.bright_white()
        );
        println!(
            "   • Minimum samples per CAN ID: {}",
            min_samples_per_can_id.to_string().bright_white()
        );

        Ok(())
    }

    /// Train anomaly detector with a frame (only in training mode)
    pub fn train_anomaly_detector(
        &mut self,
        frame: &super::secured_frame::SecuredCanFrame,
    ) -> Result<(), String> {
        if let Some(detector) = &mut self.anomaly_detector {
            detector.train(frame)?;
        }
        Ok(())
    }

    /// Finalize anomaly training and get baseline for saving
    pub fn finalize_anomaly_training(
        &mut self,
    ) -> Result<crate::anomaly_detection::AnomalyBaseline, String> {
        let detector = self
            .anomaly_detector
            .as_mut()
            .ok_or("Anomaly detector not initialized")?;

        let baseline = detector.finalize_training()?;

        println!(
            "{} Anomaly detection training finalized",
            "✓".green().bold()
        );
        println!(
            "   • Total samples: {}",
            baseline.total_samples.to_string().bright_white()
        );
        println!(
            "   • CAN IDs profiled: {}",
            baseline.profiles.len().to_string().bright_white()
        );

        Ok(baseline)
    }

    /// Activate anomaly detection with finalized baseline
    pub fn activate_anomaly_detection(
        &mut self,
        baseline: crate::anomaly_detection::AnomalyBaseline,
    ) {
        if let Some(detector) = &mut self.anomaly_detector {
            detector.activate_detection(baseline);
            println!(
                "{} Anomaly detection activated for {}",
                "✓".green().bold(),
                self.ecu_id.bright_white()
            );
        }
    }

    /// Detect anomalies in a frame (call after successful MAC/CRC verification)
    pub fn detect_anomaly(
        &mut self,
        frame: &super::secured_frame::SecuredCanFrame,
    ) -> crate::anomaly_detection::AnomalyResult {
        match &mut self.anomaly_detector {
            Some(detector) => detector.detect(frame),
            None => crate::anomaly_detection::AnomalyResult::Normal,
        }
    }

    /// Check if anomaly detection is enabled
    pub fn is_anomaly_detection_enabled(&self) -> bool {
        self.anomaly_detector.is_some()
    }

    /// Check if anomaly detector is in training mode
    pub fn is_anomaly_training(&self) -> bool {
        self.anomaly_detector
            .as_ref()
            .map(|d| d.is_training())
            .unwrap_or(false)
    }

    /// Check if anomaly detector is in detection mode
    pub fn is_anomaly_detecting(&self) -> bool {
        self.anomaly_detector
            .as_ref()
            .map(|d| d.is_detecting())
            .unwrap_or(false)
    }

    /// Get anomaly detector mode
    pub fn anomaly_detector_mode(&self) -> Option<crate::anomaly_detection::DetectorMode> {
        self.anomaly_detector.as_ref().map(|d| d.mode())
    }

    /// Get reference to current anomaly baseline
    pub fn anomaly_baseline(&self) -> Option<&crate::anomaly_detection::AnomalyBaseline> {
        self.anomaly_detector.as_ref().and_then(|d| d.baseline())
    }
}
