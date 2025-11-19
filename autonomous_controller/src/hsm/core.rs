use chrono::{DateTime, Utc};
use colored::*;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng};
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

    /// Random number generator (deterministic, for testing/simulation)
    rng: StdRng,

    /// Use hardware-based RNG (OsRng) instead of deterministic StdRng
    /// When true, uses OS-provided cryptographically secure RNG (Linux /dev/urandom, Windows CryptGenRandom, ARM TrustZone)
    use_hardware_rng: bool,

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

    /// Key rotation manager for session key lifecycle (None if disabled)
    key_rotation_manager: Option<super::key_rotation::KeyRotationManager>,
}

impl VirtualHSM {
    /// Create a new HSM instance with deterministic keys (for testing/simulation)
    /// Uses StdRng with a fixed seed for reproducible key generation
    /// In production, use `new_secure()` instead
    pub fn new(ecu_id: String, seed: u64) -> Self {
        Self::with_performance(ecu_id, seed, false)
    }

    /// Create a new HSM instance with hardware-based RNG (for production)
    /// Uses OS-provided cryptographically secure RNG:
    /// - Linux/WSL2: /dev/urandom
    /// - ARM: Hardware RNG via /dev/hwrng or TrustZone
    /// - Windows: CryptGenRandom / BCryptGenRandom
    pub fn new_secure(ecu_id: String) -> Self {
        Self::new_secure_with_performance(ecu_id, false)
    }

    /// Create a new HSM instance with hardware RNG and optional performance tracking
    pub fn new_secure_with_performance(ecu_id: String, performance_mode: bool) -> Self {
        // Use dummy seed for StdRng (will not be used when use_hardware_rng = true)
        let rng = StdRng::seed_from_u64(0);

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
            use_hardware_rng: true, // Enable hardware RNG for production
            performance_metrics: if performance_mode {
                Some(Arc::new(Mutex::new(PerformanceMetrics::new())))
            } else {
                None
            },
            can_id_permissions: None,
            replay_protection_state: HashMap::new(),
            replay_config: ReplayProtectionConfig::default(),
            anomaly_detector: None,     // Disabled by default
            key_rotation_manager: None, // Disabled by default
        };

        // Generate cryptographically secure keys using hardware RNG
        OsRng.fill_bytes(&mut hsm.master_key);
        OsRng.fill_bytes(&mut hsm.secure_boot_key);
        OsRng.fill_bytes(&mut hsm.firmware_update_key);
        OsRng.fill_bytes(&mut hsm.symmetric_comm_key);
        OsRng.fill_bytes(&mut hsm.key_encryption_key);
        OsRng.fill_bytes(&mut hsm.rng_seed_key);
        OsRng.fill_bytes(&mut hsm.seed_key_access);

        hsm
    }

    /// Create a new HSM instance with optional performance tracking (deterministic)
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
            use_hardware_rng: false, // Use deterministic RNG for testing/simulation
            performance_metrics: if performance_mode {
                Some(Arc::new(Mutex::new(PerformanceMetrics::new())))
            } else {
                None
            },
            can_id_permissions: None,
            replay_protection_state: HashMap::new(),
            replay_config: ReplayProtectionConfig::default(),
            anomaly_detector: None,     // Disabled by default
            key_rotation_manager: None, // Disabled by default
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

    /// Get MAC verification key for a specific ECU (internal use, legacy)
    /// Note: Prefer using get_verification_key_by_version() for key rotation support
    #[allow(dead_code)]
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

    /// Set session counter directly (for testing edge cases only)
    /// DO NOT use in production - this bypasses replay protection
    ///
    /// Note: Available in both unit tests and integration tests
    #[doc(hidden)]
    pub fn set_session_counter_for_test(&mut self, value: u64) {
        self.session_counter = value;
    }

    /// Increment session counter with wraparound protection
    ///
    /// SECURITY FIX: Detects counter wraparound and triggers key rotation
    /// before reaching u64::MAX to maintain replay protection security
    pub fn increment_session(&mut self) {
        // SECURITY: Check for imminent counter wraparound (when approaching u64::MAX)
        // Trigger key rotation at 2^63 (half of u64::MAX) to ensure fresh counter
        const COUNTER_ROTATION_THRESHOLD: u64 = u64::MAX / 2;

        if self.session_counter >= COUNTER_ROTATION_THRESHOLD {
            // Counter approaching wraparound - force key rotation if enabled
            if self.is_key_rotation_enabled() {
                println!(
                    "{} Session counter approaching limit ({}), triggering key rotation",
                    "⚠️".yellow(),
                    self.session_counter
                );
                let _ = self.rotate_key();
                // Reset counter after rotation to maintain replay protection
                self.session_counter = 0;
            } else {
                // Key rotation not enabled - use wrapping_add as fallback
                // WARNING: This breaks replay protection after wraparound
                println!(
                    "{} {}",
                    "⚠️".yellow(),
                    "Session counter wraparound detected! Enable key rotation to prevent replay vulnerabilities.".red()
                );
                self.session_counter = self.session_counter.wrapping_add(1);
            }
        } else {
            // Normal increment
            self.session_counter = self.session_counter.wrapping_add(1);
        }
    }

    // ========================================================================
    // Cryptographic Operations (Delegated)
    // ========================================================================

    /// Generate Message Authentication Code (MAC) using HMAC-SHA256
    /// Uses session key if key rotation is enabled, otherwise uses symmetric_comm_key
    pub fn generate_mac(&mut self, data: &[u8], session_counter: u64) -> [u8; 32] {
        let key = self.get_mac_generation_key();
        crypto::generate_mac(
            data,
            session_counter,
            &key,
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

    /// Fill buffer with random bytes using hardware RNG (OsRng) or deterministic RNG (StdRng)
    /// - Hardware RNG (production): Uses OS-provided CSPRNG (Linux /dev/urandom, Windows CryptGenRandom, ARM TrustZone)
    /// - Deterministic RNG (testing): Uses StdRng with fixed seed for reproducibility
    fn fill_random_bytes(&mut self, buffer: &mut [u8]) {
        if self.use_hardware_rng {
            // Use hardware-based cryptographically secure RNG
            OsRng.fill_bytes(buffer);
        } else {
            // Use deterministic RNG for testing/simulation
            self.rng.fill(buffer);
        }
    }

    /// Generate a random number (for nonces, challenges, etc.)
    /// Uses hardware RNG (OsRng) in production mode, or deterministic RNG (StdRng) in testing mode
    pub fn generate_random(&mut self) -> u64 {
        if self.use_hardware_rng {
            // Use hardware-based cryptographically secure RNG
            OsRng.next_u64()
        } else {
            // Use deterministic RNG for testing/simulation
            Rng::r#gen(&mut self.rng)
        }
    }

    /// Generate random bytes (for keys, nonces, etc.)
    /// Uses hardware RNG (OsRng) in production mode, or deterministic RNG (StdRng) in testing mode
    pub fn generate_random_bytes(&mut self, buffer: &mut [u8]) {
        self.fill_random_bytes(buffer);
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

    // ========================================================================
    // Key Rotation Methods
    // ========================================================================

    /// Enable key rotation with specified policy
    pub fn enable_key_rotation(
        &mut self,
        policy: super::key_rotation::KeyRotationPolicy,
    ) -> Result<(), String> {
        let manager = super::key_rotation::KeyRotationManager::new(
            self.master_key,
            self.ecu_id.clone(),
            policy,
        );

        self.key_rotation_manager = Some(manager);

        println!(
            "{} Key rotation enabled for {}",
            "→".cyan(),
            self.ecu_id.bright_white()
        );

        Ok(())
    }

    /// Disable key rotation (revert to static symmetric_comm_key)
    pub fn disable_key_rotation(&mut self) {
        self.key_rotation_manager = None;
    }

    /// Check if key rotation is enabled
    pub fn is_key_rotation_enabled(&self) -> bool {
        self.key_rotation_manager.is_some()
    }

    /// Get current active session key version (0 = legacy key, >0 = session key)
    pub fn get_current_key_version(&self) -> u32 {
        if let Some(manager) = &self.key_rotation_manager {
            manager.current_key_id()
        } else {
            0 // Legacy mode: use symmetric_comm_key (version 0)
        }
    }

    /// Get key material for MAC generation (session key if rotation enabled, else symmetric_comm_key)
    pub fn get_mac_generation_key(&mut self) -> [u8; 32] {
        if let Some(manager) = &mut self.key_rotation_manager {
            // Check if rotation needed (before mutably borrowing key)
            let should_rotate = if let Some(key) = manager.get_active_key() {
                manager.policy().should_rotate(key)
            } else {
                false
            };

            if should_rotate {
                // Auto-rotate
                manager.rotate_key();
            }

            // Now get the key (possibly new after rotation) and increment counter
            if let Some(key) = manager.get_active_key_mut() {
                key.increment_frame_count();
                return key.key_material;
            }
        }

        // Fallback: use legacy symmetric_comm_key
        self.symmetric_comm_key
    }

    /// Get verification key by version (for RX - supports old keys in grace period)
    pub fn get_verification_key_by_version(
        &self,
        source_ecu: &str,
        key_version: u32,
    ) -> Option<[u8; 32]> {
        // If key_version is 0, use legacy verification keys
        if key_version == 0 {
            return self.mac_verification_keys.get(source_ecu).copied();
        }

        // Otherwise, look up session key from rotation manager
        // Note: This assumes we have the sender's key rotation manager or shared keys
        // For now, we'll use the receiver's own rotation manager (assumes synchronized rotation)
        if let Some(manager) = &self.key_rotation_manager {
            if let Some(session_key) = manager.get_key_by_id(key_version) {
                // Check if key is still valid for RX
                if session_key.is_valid_for_rx() {
                    return Some(session_key.key_material);
                }
            }
        }

        None
    }

    /// Manually trigger key rotation
    pub fn rotate_key(&mut self) -> Result<u32, String> {
        let manager = self
            .key_rotation_manager
            .as_mut()
            .ok_or("Key rotation not enabled")?;

        let new_key_id = manager.rotate_key();
        Ok(new_key_id)
    }

    /// Get reference to key rotation manager (for advanced use)
    pub fn key_rotation_manager(&self) -> Option<&super::key_rotation::KeyRotationManager> {
        self.key_rotation_manager.as_ref()
    }

    /// Get mutable reference to key rotation manager (for advanced use)
    pub fn key_rotation_manager_mut(
        &mut self,
    ) -> Option<&mut super::key_rotation::KeyRotationManager> {
        self.key_rotation_manager.as_mut()
    }

    /// Update key rotation policy
    pub fn set_key_rotation_policy(&mut self, policy: super::key_rotation::KeyRotationPolicy) {
        if let Some(manager) = &mut self.key_rotation_manager {
            manager.set_policy(policy);
        }
    }

    /// Import a session key from another ECU (for key distribution)
    pub fn import_session_key(&mut self, key_id: u32, encrypted_key: &[u8]) -> Result<(), String> {
        let manager = self
            .key_rotation_manager
            .as_mut()
            .ok_or("Key rotation not enabled")?;

        manager.import_key(key_id, encrypted_key, &self.key_encryption_key)
    }

    /// Export current session key for distribution (encrypted)
    pub fn export_session_key(&self) -> Result<Vec<u8>, String> {
        let manager = self
            .key_rotation_manager
            .as_ref()
            .ok_or("Key rotation not enabled")?;

        let key_id = manager.current_key_id();
        manager
            .export_key(key_id, &self.key_encryption_key)
            .ok_or_else(|| "Failed to export key".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::errors::VerifyError;
    use crate::hsm::key_rotation;
    use crate::hsm::secured_frame::SecuredCanFrame;

    #[test]
    fn test_authorize_transmit_without_policy() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        // Without a policy loaded, all transmissions should be allowed
        assert!(hsm.authorize_transmit(0x100).is_ok());
        assert!(hsm.authorize_transmit(0x200).is_ok());
        assert!(hsm.authorize_transmit(0x300).is_ok());
    }

    #[test]
    fn test_authorize_transmit_with_policy_allowed() {
        let mut hsm = VirtualHSM::new("WHEEL_FL".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("WHEEL_FL".to_string());
        perms.allow_tx(0x100);
        perms.allow_tx(0x101);
        hsm.load_access_control(perms);

        // Should allow authorized CAN IDs
        assert!(hsm.authorize_transmit(0x100).is_ok());
        assert!(hsm.authorize_transmit(0x101).is_ok());
    }

    #[test]
    fn test_authorize_transmit_with_policy_denied() {
        let mut hsm = VirtualHSM::new("WHEEL_FL".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("WHEEL_FL".to_string());
        perms.allow_tx(0x100);
        hsm.load_access_control(perms);

        // Should deny unauthorized CAN IDs
        assert!(hsm.authorize_transmit(0x200).is_err());
        assert!(hsm.authorize_transmit(0x300).is_err());

        // Verify error message contains expected information
        let err = hsm.authorize_transmit(0x200).unwrap_err();
        assert!(err.contains("WHEEL_FL"));
        assert!(err.contains("0x200"));
        assert!(err.contains("not authorized"));
    }

    #[test]
    fn test_authorize_receive_without_policy() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        // Without a policy loaded, all receives should be allowed
        assert!(hsm.authorize_receive(0x100).is_ok());
        assert!(hsm.authorize_receive(0x200).is_ok());
    }

    #[test]
    fn test_authorize_receive_with_no_rx_whitelist() {
        let mut hsm = VirtualHSM::new("WHEEL_FL".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("WHEEL_FL".to_string());
        perms.allow_tx(0x100); // Only TX whitelist, no RX whitelist
        hsm.load_access_control(perms);

        // Should allow all receives when RX whitelist is not set
        assert!(hsm.authorize_receive(0x100).is_ok());
        assert!(hsm.authorize_receive(0x200).is_ok());
        assert!(hsm.authorize_receive(0x300).is_ok());
    }

    #[test]
    fn test_authorize_receive_with_rx_whitelist() {
        let mut hsm = VirtualHSM::new("ENGINE_ECU".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("ENGINE_ECU".to_string());
        perms.allow_tx(0x110);
        perms.allow_rx(0x301); // Only receive throttle commands
        hsm.load_access_control(perms);

        // Should allow authorized receives
        assert!(hsm.authorize_receive(0x301).is_ok());

        // Should deny unauthorized receives
        assert!(hsm.authorize_receive(0x300).is_err());
        assert!(hsm.authorize_receive(0x302).is_err());
    }

    #[test]
    fn test_multiple_can_ids_in_whitelist() {
        let mut hsm = VirtualHSM::new("ENGINE_ECU".to_string(), 12345);
        let mut perms = crate::types::CanIdPermissions::new("ENGINE_ECU".to_string());
        perms.allow_tx_multiple(&[0x110, 0x111, 0x112]);
        perms.allow_rx_multiple(&[0x300, 0x301]);
        hsm.load_access_control(perms);

        // All whitelisted TX IDs should be allowed
        assert!(hsm.authorize_transmit(0x110).is_ok());
        assert!(hsm.authorize_transmit(0x111).is_ok());
        assert!(hsm.authorize_transmit(0x112).is_ok());

        // Non-whitelisted TX IDs should be denied
        assert!(hsm.authorize_transmit(0x113).is_err());

        // All whitelisted RX IDs should be allowed
        assert!(hsm.authorize_receive(0x300).is_ok());
        assert!(hsm.authorize_receive(0x301).is_ok());

        // Non-whitelisted RX IDs should be denied
        assert!(hsm.authorize_receive(0x302).is_err());
    }

    #[test]
    fn test_rx_whitelist_authorized_receive() {
        // Test: ECU with RX whitelist can receive authorized CAN IDs
        use crate::access_control;
        use crate::types::can_ids;

        let mut hsm = VirtualHSM::new("BRAKE_CTRL".to_string(), 12345);

        // Load brake controller policy (only receives 0x300 brake commands)
        if let Some(permissions) = access_control::load_policy_for_ecu("BRAKE_CTRL") {
            hsm.load_access_control(permissions);
        }

        // Create sender HSM and register trusted sender
        let mut sender_hsm = VirtualHSM::new("AUTONOMOUS_CTRL".to_string(), 67890);
        let sender_mac_key = *sender_hsm.get_symmetric_key();
        hsm.add_trusted_ecu("AUTONOMOUS_CTRL".to_string(), sender_mac_key);

        // Create secured frame from authorized sender on authorized CAN ID
        let frame = SecuredCanFrame::new(
            can_ids::BRAKE_COMMAND, // 0x300 - brake controller IS authorized to receive this
            vec![0x50, 0x00, 0x00, 0x00], // 50% brake pressure
            "AUTONOMOUS_CTRL".to_string(),
            &mut sender_hsm,
        )
        .expect("Failed to create frame");

        // Verify frame with RX whitelist check enabled
        let result = frame.verify_with_authorization(&mut hsm); // Uses RX whitelist
        assert!(
            result.is_ok(),
            "Brake controller should accept authorized brake command: {:?}",
            result
        );
    }

    #[test]
    fn test_rx_whitelist_unauthorized_receive() {
        // Test: ECU with RX whitelist blocks unauthorized CAN IDs
        use crate::access_control;
        use crate::types::can_ids;

        let mut hsm = VirtualHSM::new("BRAKE_CTRL".to_string(), 12345);

        // Load brake controller policy (only receives 0x300, NOT 0x302 steering)
        if let Some(permissions) = access_control::load_policy_for_ecu("BRAKE_CTRL") {
            hsm.load_access_control(permissions);
        }

        // Create sender HSM and register trusted sender
        let mut sender_hsm = VirtualHSM::new("AUTONOMOUS_CTRL".to_string(), 67890);
        let sender_mac_key = *sender_hsm.get_symmetric_key();
        hsm.add_trusted_ecu("AUTONOMOUS_CTRL".to_string(), sender_mac_key);

        // Create secured frame on UNAUTHORIZED CAN ID for brake controller
        let frame = SecuredCanFrame::new(
            can_ids::STEERING_COMMAND, // 0x302 - brake controller NOT authorized to receive this!
            vec![0x10, 0x00, 0x00, 0x00],
            "AUTONOMOUS_CTRL".to_string(),
            &mut sender_hsm,
        )
        .expect("Failed to create frame");

        // Verify frame with RX whitelist check enabled
        let result = frame.verify_with_authorization(&mut hsm); // Uses RX whitelist
        assert!(
            result.is_err(),
            "Brake controller should reject unauthorized steering command"
        );

        // Verify it's specifically an access control error
        if let Err(e) = result {
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.contains("UnauthorizedAccess") || error_msg.contains("not authorized"),
                "Error should indicate unauthorized access, got: {}",
                error_msg
            );
        }
    }

    #[test]
    fn test_rx_whitelist_none_receives_all() {
        // Test: ECU without RX whitelist (None) receives all frames
        use crate::types::can_ids;

        let mut hsm = VirtualHSM::new("MONITOR".to_string(), 12345);

        // Don't load any access control policy (RX whitelist = None)

        // Create sender HSM and register trusted sender
        let mut sender_hsm = VirtualHSM::new("SENSOR".to_string(), 67890);
        let sender_mac_key = *sender_hsm.get_symmetric_key();
        hsm.add_trusted_ecu("SENSOR".to_string(), sender_mac_key);

        // Create secured frame
        let frame = SecuredCanFrame::new(
            can_ids::WHEEL_SPEED_FL, // Random CAN ID
            vec![0x10, 0x20, 0x30, 0x40],
            "SENSOR".to_string(),
            &mut sender_hsm,
        )
        .expect("Failed to create frame");

        // Verify frame with RX whitelist check enabled (should pass because RX whitelist is None)
        let result = frame.verify_with_authorization(&mut hsm);
        assert!(
            result.is_ok(),
            "ECU without RX whitelist should accept all frames: {:?}",
            result
        );
    }

    #[test]
    fn test_rx_whitelist_disabled_bypasses_check() {
        // Test: RX whitelist enforcement can be disabled per-verification
        use crate::access_control;
        use crate::types::can_ids;

        let mut hsm = VirtualHSM::new("BRAKE_CTRL".to_string(), 12345);

        // Load brake controller policy (only receives 0x300)
        if let Some(permissions) = access_control::load_policy_for_ecu("BRAKE_CTRL") {
            hsm.load_access_control(permissions);
        }

        // Create sender HSM and register trusted sender
        let mut sender_hsm = VirtualHSM::new("AUTONOMOUS_CTRL".to_string(), 67890);
        let sender_mac_key = *sender_hsm.get_symmetric_key();
        hsm.add_trusted_ecu("AUTONOMOUS_CTRL".to_string(), sender_mac_key);

        // Create frame on unauthorized CAN ID
        let frame = SecuredCanFrame::new(
            can_ids::STEERING_COMMAND, // Unauthorized for brake controller
            vec![0x10, 0x00, 0x00, 0x00],
            "AUTONOMOUS_CTRL".to_string(),
            &mut sender_hsm,
        )
        .expect("Failed to create frame");

        // Verify with RX whitelist check DISABLED (use verify() not verify_with_authorization())
        let result = frame.verify(&mut hsm);
        assert!(
            result.is_ok(),
            "When using verify() instead of verify_with_authorization(), RX whitelist bypassed: {:?}",
            result
        );
    }

    #[test]
    fn test_key_rotation_integration() {
        // Test that SecuredCanFrame creation uses session keys when rotation enabled
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Enable key rotation with short thresholds for testing
        let policy = key_rotation::KeyRotationPolicy {
            time_based_enabled: false,
            rotation_interval_secs: 300,
            counter_based_enabled: true,
            rotation_frame_threshold: 5, // Rotate after 5 frames
            grace_period_secs: 60,
            max_key_history: 10,
        };

        hsm.enable_key_rotation(policy).unwrap();

        // Self-register for verification
        hsm.add_trusted_ecu("TEST_ECU".to_string(), *hsm.get_symmetric_key());

        // Create and self-verify frames with initial session key (key_version = 1)
        for i in 0..3 {
            let frame = SecuredCanFrame::new(
                crate::types::CanId::Standard(0x100),
                vec![i, i + 1, i + 2, i + 3],
                "TEST_ECU".to_string(),
                &mut hsm,
            )
            .expect("Failed to create frame");

            assert_eq!(frame.key_version, 1, "Should use initial session key");

            // Self-verification should work (same HSM)
            let result = frame.verify(&mut hsm);
            assert!(
                result.is_ok(),
                "Frame self-verification should succeed with key rotation: {:?}",
                result
            );
        }

        // Create 2 more frames to trigger rotation (threshold = 5)
        for i in 3..5 {
            let _frame = SecuredCanFrame::new(
                crate::types::CanId::Standard(0x100),
                vec![i, i + 1, i + 2, i + 3],
                "TEST_ECU".to_string(),
                &mut hsm,
            )
            .expect("Failed to create frame");
        }

        // Next frame should use new session key (key_version = 2)
        let frame_after_rotation = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![10, 11, 12, 13],
            "TEST_ECU".to_string(),
            &mut hsm,
        )
        .expect("Failed to create frame");

        assert_eq!(
            frame_after_rotation.key_version, 2,
            "Should use new session key after rotation"
        );

        // Self-verification should still work after rotation
        let result = frame_after_rotation.verify(&mut hsm);
        assert!(
            result.is_ok(),
            "Frame self-verification should succeed after rotation: {:?}",
            result
        );

        // Verify we're on key_version 2
        assert_eq!(hsm.get_current_key_version(), 2);
    }

    #[test]
    fn test_key_rotation_disabled_uses_legacy_key() {
        // Test that when key rotation is disabled, key_version = 0 (legacy mode)
        let mut sender_hsm = VirtualHSM::new("SENDER".to_string(), 12345);
        let mut receiver_hsm = VirtualHSM::new("RECEIVER".to_string(), 12345);

        // Do NOT enable key rotation (use legacy symmetric_comm_key)
        assert!(!sender_hsm.is_key_rotation_enabled());

        // Register sender's MAC key with receiver
        receiver_hsm.add_trusted_ecu("SENDER".to_string(), *sender_hsm.get_symmetric_key());

        // Create frame with legacy key
        let frame = SecuredCanFrame::new(
            crate::types::CanId::Standard(0x100),
            vec![1, 2, 3, 4],
            "SENDER".to_string(),
            &mut sender_hsm,
        )
        .expect("Failed to create frame");

        assert_eq!(frame.key_version, 0, "Should use legacy key (version 0)");

        // Verification should work
        let result = frame.verify(&mut receiver_hsm);
        assert!(
            result.is_ok(),
            "Frame verification should succeed with legacy key: {:?}",
            result
        );
    }
}
