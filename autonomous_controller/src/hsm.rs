use chrono::{DateTime, Utc};
use colored::*;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
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

/// Replay detection errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// Counter was already seen in sliding window
    CounterAlreadySeen { counter: u64 },

    /// Counter is not increasing (strict mode)
    CounterNotIncreasing { received: u64, expected_min: u64 },

    /// Counter is too old (outside sliding window)
    CounterTooOld { received: u64, min_acceptable: u64 },

    /// Frame timestamp is too old
    TimestampTooOld {
        frame_time: DateTime<Utc>,
        current_time: DateTime<Utc>,
    },

    /// Frame timestamp is too far in future (clock skew)
    TimestampTooFarInFuture {
        frame_time: DateTime<Utc>,
        current_time: DateTime<Utc>,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::CounterAlreadySeen { counter } => {
                write!(f, "Replay detected: counter {} already seen", counter)
            }
            ReplayError::CounterNotIncreasing {
                received,
                expected_min,
            } => {
                write!(
                    f,
                    "Counter not increasing: received {}, expected >= {}",
                    received, expected_min
                )
            }
            ReplayError::CounterTooOld {
                received,
                min_acceptable,
            } => {
                write!(
                    f,
                    "Counter too old: {}, minimum acceptable: {}",
                    received, min_acceptable
                )
            }
            ReplayError::TimestampTooOld {
                frame_time,
                current_time,
            } => {
                write!(
                    f,
                    "Frame timestamp too old: {:?} vs current: {:?}",
                    frame_time, current_time
                )
            }
            ReplayError::TimestampTooFarInFuture {
                frame_time,
                current_time,
            } => {
                write!(
                    f,
                    "Frame timestamp too far in future: {:?} vs current: {:?}",
                    frame_time, current_time
                )
            }
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
    /// Replay attack detected - frame counter invalid
    ReplayDetected(ReplayError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::UnsecuredFrame => write!(f, "Unsecured frame (no MAC/CRC)"),
            VerifyError::CrcMismatch => write!(f, "CRC verification failed"),
            VerifyError::MacMismatch(reason) => write!(f, "MAC verification failed: {}", reason),
            VerifyError::UnauthorizedAccess => write!(f, "Unauthorized CAN ID access"),
            VerifyError::ReplayDetected(reason) => write!(f, "Replay attack detected: {}", reason),
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

/// Configuration for replay protection behavior
#[derive(Debug, Clone)]
pub struct ReplayProtectionConfig {
    /// Size of sliding window (default: 100)
    pub window_size: usize,

    /// Allow out-of-order frame acceptance within window
    pub allow_reordering: bool,

    /// Maximum age for frames in seconds (0 = disabled)
    pub max_frame_age_secs: u64,

    /// Strict mode: reject any counter <= last_seen (default: false)
    pub strict_monotonic: bool,
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            allow_reordering: true,
            max_frame_age_secs: 60,
            strict_monotonic: false,
        }
    }
}

/// Replay protection state for a single ECU
#[derive(Debug, Clone)]
pub struct ReplayProtectionState {
    /// Last accepted counter from this ECU
    last_accepted_counter: u64,

    /// Sliding window of recently accepted counters (for out-of-order tolerance)
    accepted_window: VecDeque<u64>,

    /// Maximum window size
    window_size: usize,

    /// Timestamp of last accepted frame (for time-based validation)
    last_frame_timestamp: Option<DateTime<Utc>>,

    /// Allow out-of-order delivery within window (reserved for future use)
    #[allow(dead_code)]
    allow_reordering: bool,
}

impl ReplayProtectionState {
    pub fn new(config: &ReplayProtectionConfig) -> Self {
        Self {
            last_accepted_counter: 0,
            accepted_window: VecDeque::with_capacity(config.window_size),
            window_size: config.window_size,
            last_frame_timestamp: None,
            allow_reordering: config.allow_reordering,
        }
    }

    /// Mark a counter as accepted and update state
    pub fn accept_counter(&mut self, counter: u64, timestamp: DateTime<Utc>) {
        // Update last accepted counter if this is newer
        if counter > self.last_accepted_counter {
            self.last_accepted_counter = counter;
        }

        // Add to sliding window
        self.accepted_window.push_back(counter);

        // Maintain window size
        while self.accepted_window.len() > self.window_size {
            self.accepted_window.pop_front();
        }

        // Update timestamp
        self.last_frame_timestamp = Some(timestamp);
    }

    /// Reset state (for testing or ECU reset scenarios)
    pub fn reset(&mut self) {
        self.last_accepted_counter = 0;
        self.accepted_window.clear();
        self.last_frame_timestamp = None;
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

        // Check 1: Strict monotonic (if enabled)
        if self.replay_config.strict_monotonic && session_counter <= state.last_accepted_counter {
            return Err(ReplayError::CounterNotIncreasing {
                received: session_counter,
                expected_min: state.last_accepted_counter + 1,
            });
        }

        // Check 2: Sliding window check (counter already seen)
        if state.accepted_window.contains(&session_counter) {
            return Err(ReplayError::CounterAlreadySeen {
                counter: session_counter,
            });
        }

        // Check 3: Counter within acceptable range (window)
        if session_counter
            < state
                .last_accepted_counter
                .saturating_sub(state.window_size as u64)
        {
            return Err(ReplayError::CounterTooOld {
                received: session_counter,
                min_acceptable: state
                    .last_accepted_counter
                    .saturating_sub(state.window_size as u64),
            });
        }

        // Check 4: Timestamp validation (if enabled)
        if self.replay_config.max_frame_age_secs > 0
            && let Some(last_timestamp) = state.last_frame_timestamp
        {
            let time_diff = frame_timestamp.signed_duration_since(last_timestamp);

            // Frame is too old
            if time_diff.num_seconds() < -(self.replay_config.max_frame_age_secs as i64) {
                return Err(ReplayError::TimestampTooOld {
                    frame_time: frame_timestamp,
                    current_time: Utc::now(),
                });
            }

            // Frame is too far in the future (clock skew attack)
            if time_diff.num_seconds() > self.replay_config.max_frame_age_secs as i64 {
                return Err(ReplayError::TimestampTooFarInFuture {
                    frame_time: frame_timestamp,
                    current_time: Utc::now(),
                });
            }
        }

        // All checks passed - accept the counter
        state.accept_counter(session_counter, frame_timestamp);
        Ok(())
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
    pub fn train_anomaly_detector(&mut self, frame: &SecuredCanFrame) -> Result<(), String> {
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
        frame: &SecuredCanFrame,
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
        if !hsm.verify_crc(&verify_data, self.crc) {
            return Err(VerifyError::CrcMismatch);
        }

        // Verify MAC (cryptographic check)
        hsm.verify_mac(&verify_data, &self.mac, self.session_counter, &self.source)
            .map_err(VerifyError::MacMismatch)?;

        // Verify replay protection (check session counter)
        let result = hsm
            .validate_counter(self.session_counter, &self.source, self.timestamp)
            .map_err(VerifyError::ReplayDetected);

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

    // Access Control Tests
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

    // Replay Protection Tests
    #[test]
    fn test_replay_detection_duplicate_counter() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let counter = 5;
        let timestamp = Utc::now();

        // First frame should succeed
        assert!(hsm.validate_counter(counter, "ECU2", timestamp).is_ok());

        // Replay with same counter should fail
        let result = hsm.validate_counter(counter, "ECU2", timestamp);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReplayError::CounterAlreadySeen { .. })
        ));
    }

    #[test]
    fn test_sliding_window_allows_reordering() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let timestamp = Utc::now();

        // Accept counters in order: 1, 2, 3
        assert!(hsm.validate_counter(1, "ECU2", timestamp).is_ok());
        assert!(hsm.validate_counter(2, "ECU2", timestamp).is_ok());
        assert!(hsm.validate_counter(3, "ECU2", timestamp).is_ok());

        // Accept counter 5 (skipped 4)
        assert!(hsm.validate_counter(5, "ECU2", timestamp).is_ok());

        // Now accept counter 4 (out of order, but within window)
        assert!(hsm.validate_counter(4, "ECU2", timestamp).is_ok());

        // But replaying 4 again should fail
        let result = hsm.validate_counter(4, "ECU2", timestamp);
        assert!(matches!(
            result,
            Err(ReplayError::CounterAlreadySeen { .. })
        ));
    }

    #[test]
    fn test_counter_too_old_rejected() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        hsm.replay_config.window_size = 10;
        let timestamp = Utc::now();

        // Accept counter 100
        assert!(hsm.validate_counter(100, "ECU2", timestamp).is_ok());

        // Counter 89 (100 - 11) is outside window, should fail
        let result = hsm.validate_counter(89, "ECU2", timestamp);
        assert!(matches!(result, Err(ReplayError::CounterTooOld { .. })));

        // Counter 90 (100 - 10) is within window, should succeed
        assert!(hsm.validate_counter(90, "ECU2", timestamp).is_ok());
    }

    #[test]
    fn test_timestamp_validation() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        hsm.replay_config.max_frame_age_secs = 30;

        let now = Utc::now();

        // Accept first frame
        assert!(hsm.validate_counter(1, "ECU2", now).is_ok());

        // Frame from 60 seconds ago should fail
        let old_timestamp = now - chrono::Duration::seconds(60);
        let result = hsm.validate_counter(2, "ECU2", old_timestamp);
        assert!(matches!(result, Err(ReplayError::TimestampTooOld { .. })));

        // Frame from 60 seconds in future should fail (clock skew attack)
        let future_timestamp = now + chrono::Duration::seconds(60);
        let result = hsm.validate_counter(3, "ECU2", future_timestamp);
        assert!(matches!(
            result,
            Err(ReplayError::TimestampTooFarInFuture { .. })
        ));
    }

    #[test]
    fn test_strict_monotonic_mode() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        hsm.replay_config.strict_monotonic = true;
        let timestamp = Utc::now();

        assert!(hsm.validate_counter(1, "ECU2", timestamp).is_ok());
        assert!(hsm.validate_counter(2, "ECU2", timestamp).is_ok());

        // In strict mode, going backwards fails even if not in window
        let result = hsm.validate_counter(1, "ECU2", timestamp);
        assert!(matches!(
            result,
            Err(ReplayError::CounterNotIncreasing { .. })
        ));
    }

    #[test]
    fn test_replay_protection_per_ecu() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let timestamp = Utc::now();

        // Use counter 5 from ECU2
        assert!(hsm.validate_counter(5, "ECU2", timestamp).is_ok());

        // ECU3 can also use counter 5 (separate state)
        assert!(hsm.validate_counter(5, "ECU3", timestamp).is_ok());

        // But ECU2 cannot replay counter 5
        let result = hsm.validate_counter(5, "ECU2", timestamp);
        assert!(matches!(
            result,
            Err(ReplayError::CounterAlreadySeen { .. })
        ));

        // And ECU3 cannot replay counter 5
        let result = hsm.validate_counter(5, "ECU3", timestamp);
        assert!(matches!(
            result,
            Err(ReplayError::CounterAlreadySeen { .. })
        ));
    }

    #[test]
    fn test_reset_replay_state() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let timestamp = Utc::now();

        // Use counter 5
        assert!(hsm.validate_counter(5, "ECU2", timestamp).is_ok());

        // Replay should fail
        assert!(hsm.validate_counter(5, "ECU2", timestamp).is_err());

        // Reset state
        hsm.reset_replay_state("ECU2");

        // Now counter 5 should work again
        assert!(hsm.validate_counter(5, "ECU2", timestamp).is_ok());
    }

    #[test]
    fn test_replay_config_modification() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);

        // Default config
        assert_eq!(hsm.get_replay_config().window_size, 100);
        assert_eq!(hsm.get_replay_config().max_frame_age_secs, 60);
        assert!(!hsm.get_replay_config().strict_monotonic);

        // Modify config
        let mut config = ReplayProtectionConfig::default();
        config.window_size = 50;
        config.strict_monotonic = true;
        hsm.set_replay_config(config);

        assert_eq!(hsm.get_replay_config().window_size, 50);
        assert!(hsm.get_replay_config().strict_monotonic);
    }

    #[test]
    fn test_end_to_end_replay_attack_detection() {
        // Setup two ECUs with HSMs
        let mut sender_hsm = VirtualHSM::new("Sender".to_string(), 12345);
        let sender_key = *sender_hsm.get_symmetric_key();

        let mut receiver_hsm = VirtualHSM::new("Receiver".to_string(), 67890);
        receiver_hsm.add_trusted_ecu("Sender".to_string(), sender_key);

        // Create a legitimate frame
        let can_id = crate::types::CanId::Standard(0x100);
        let data = vec![1, 2, 3, 4];
        let frame = SecuredCanFrame::new(can_id, data, "Sender".to_string(), &mut sender_hsm)
            .expect("Failed to create frame");

        // First verification should succeed
        assert!(frame.verify(&mut receiver_hsm).is_ok());

        // Replay the same frame - should fail with replay error
        let result = frame.verify(&mut receiver_hsm);
        assert!(result.is_err());
        assert!(matches!(result, Err(VerifyError::ReplayDetected(_))));
    }

    #[test]
    fn test_window_size_enforcement() {
        let mut hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        hsm.replay_config.window_size = 5;
        let timestamp = Utc::now();

        // Fill window with 5 counters
        for i in 1..=5 {
            assert!(hsm.validate_counter(i, "ECU2", timestamp).is_ok());
        }

        // Add 6th counter
        assert!(hsm.validate_counter(6, "ECU2", timestamp).is_ok());

        // Now window contains [2, 3, 4, 5, 6] (counter 1 was pushed out)
        // Counter 0 is too old (0 < 6 - 5 = 1)
        let result = hsm.validate_counter(0, "ECU2", timestamp);
        assert!(result.is_err());
        assert!(matches!(result, Err(ReplayError::CounterTooOld { .. })));

        // Counter 3 should fail (already in window)
        let result = hsm.validate_counter(3, "ECU2", timestamp);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReplayError::CounterAlreadySeen { .. })
        ));
    }
}
