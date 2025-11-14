/// Anomaly-based Intrusion Detection System (IDS)
///
/// This module provides statistical baseline profiling for CAN bus traffic
/// to detect behavioral anomalies that may indicate attacks or ECU failures.
///
/// Key Features:
/// - Message frequency profiling (inter-arrival times)
/// - Data range profiling (min/max/mean/stddev for payload bytes)
/// - Source ECU profiling (expected senders per CAN ID)
/// - Rate anomaly detection (messages per second)
/// - Factory calibration with secure baseline storage
/// - Graduated response levels (80% notify, 99% attack)
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Statistical profile for a single CAN ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanIdProfile {
    /// CAN ID being profiled
    pub can_id: u32,

    /// Total messages observed during training
    pub message_count: u64,

    /// Average inter-arrival time in milliseconds
    pub avg_interval_ms: f64,

    /// Standard deviation of inter-arrival time
    pub interval_std_dev: f64,

    /// Minimum observed interval (ms)
    pub min_interval_ms: f64,

    /// Maximum observed interval (ms)
    pub max_interval_ms: f64,

    /// Expected message rate (messages per second)
    pub expected_rate_per_sec: f64,

    /// Standard deviation of message rate
    pub rate_std_dev: f64,

    /// Last timestamp seen (for interval calculation)
    #[serde(skip)]
    pub last_seen: Option<DateTime<Utc>>,

    /// Interval samples collected during training (cleared after baseline finalization)
    #[serde(skip)]
    interval_samples: Vec<f64>,

    /// Rate samples (messages per second in 1-second windows)
    #[serde(skip)]
    rate_samples: Vec<f64>,

    /// Data range statistics per byte position (0-7 for CAN)
    pub data_stats: Vec<ByteStats>,

    /// ECUs that are expected to send this CAN ID
    pub expected_sources: HashSet<String>,
}

impl CanIdProfile {
    /// Create a new profile for training
    pub fn new(can_id: u32) -> Self {
        Self {
            can_id,
            message_count: 0,
            avg_interval_ms: 0.0,
            interval_std_dev: 0.0,
            min_interval_ms: f64::MAX,
            max_interval_ms: 0.0,
            expected_rate_per_sec: 0.0,
            rate_std_dev: 0.0,
            last_seen: None,
            interval_samples: Vec::new(),
            rate_samples: Vec::new(),
            data_stats: vec![ByteStats::new(); 8],
            expected_sources: HashSet::new(),
        }
    }

    /// Add a training sample
    pub fn add_sample(&mut self, data: &[u8], timestamp: DateTime<Utc>, source: &str) {
        self.message_count += 1;

        // Track source ECUs
        self.expected_sources.insert(source.to_string());

        // Calculate interval if we have a previous timestamp
        if let Some(last_ts) = self.last_seen {
            let interval = (timestamp - last_ts).num_milliseconds() as f64;
            if interval > 0.0 {
                self.interval_samples.push(interval);
                self.min_interval_ms = self.min_interval_ms.min(interval);
                self.max_interval_ms = self.max_interval_ms.max(interval);
            }
        }
        self.last_seen = Some(timestamp);

        // Update data statistics for each byte
        for (i, &byte) in data.iter().enumerate() {
            if i < 8 {
                self.data_stats[i].add_sample(byte);
            }
        }
    }

    /// Finalize statistics after training
    pub fn finalize(&mut self) {
        // Calculate average and standard deviation of intervals
        if !self.interval_samples.is_empty() {
            let sum: f64 = self.interval_samples.iter().sum();
            self.avg_interval_ms = sum / self.interval_samples.len() as f64;

            let variance: f64 = self
                .interval_samples
                .iter()
                .map(|x| (x - self.avg_interval_ms).powi(2))
                .sum::<f64>()
                / self.interval_samples.len() as f64;
            self.interval_std_dev = variance.sqrt();
        }

        // Calculate expected rate (messages per second)
        if self.avg_interval_ms > 0.0 {
            self.expected_rate_per_sec = 1000.0 / self.avg_interval_ms;
        }

        // Finalize byte statistics
        for stat in &mut self.data_stats {
            stat.finalize();
        }

        // Clear sample vectors to save memory
        self.interval_samples.clear();
        self.rate_samples.clear();
    }
}

/// Statistics for a single byte position in CAN data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteStats {
    pub min: u8,
    pub max: u8,
    pub mean: f64,
    pub std_dev: f64,

    #[serde(skip)]
    samples: Vec<u8>,
}

impl ByteStats {
    fn new() -> Self {
        Self {
            min: u8::MAX,
            max: u8::MIN,
            mean: 0.0,
            std_dev: 0.0,
            samples: Vec::new(),
        }
    }

    fn add_sample(&mut self, value: u8) {
        self.samples.push(value);
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    fn finalize(&mut self) {
        if !self.samples.is_empty() {
            let sum: u64 = self.samples.iter().map(|&x| x as u64).sum();
            self.mean = sum as f64 / self.samples.len() as f64;

            let variance: f64 = self
                .samples
                .iter()
                .map(|&x| (x as f64 - self.mean).powi(2))
                .sum::<f64>()
                / self.samples.len() as f64;
            self.std_dev = variance.sqrt();

            // Clear samples to save memory
            self.samples.clear();
        }
    }
}

/// Complete baseline profile for all CAN IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyBaseline {
    /// ECU identifier this baseline is for
    pub ecu_id: String,

    /// Timestamp when baseline was created
    pub created_at: DateTime<Utc>,

    /// Version identifier for baseline format
    pub version: String,

    /// Profiles for each CAN ID observed
    pub profiles: HashMap<u32, CanIdProfile>,

    /// Total samples collected during training
    pub total_samples: u64,

    /// Detection threshold in standard deviations (default: 3.0 for 99.7% confidence)
    pub detection_threshold_sigma: f64,

    /// Warning threshold in standard deviations (default: 1.3 for ~80% confidence)
    pub warning_threshold_sigma: f64,

    /// Signature for baseline integrity verification (set by HSM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<[u8; 32]>,
}

impl AnomalyBaseline {
    pub fn new(ecu_id: String) -> Self {
        Self {
            ecu_id,
            created_at: Utc::now(),
            version: "1.0.0".to_string(),
            profiles: HashMap::new(),
            total_samples: 0,
            detection_threshold_sigma: 3.0, // 99.7% confidence
            warning_threshold_sigma: 1.3,   // ~80% confidence
            signature: None,
        }
    }

    /// Get profile for a CAN ID, creating if needed (training mode)
    pub fn get_or_create_profile(&mut self, can_id: u32) -> &mut CanIdProfile {
        self.profiles
            .entry(can_id)
            .or_insert_with(|| CanIdProfile::new(can_id))
    }

    /// Finalize all profiles after training
    pub fn finalize(&mut self) {
        for profile in self.profiles.values_mut() {
            profile.finalize();
        }
    }
}

/// Anomaly detection result
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyResult {
    /// No anomaly detected
    Normal,

    /// Warning-level anomaly (80-99% confidence)
    Warning(AnomalyReport),

    /// Attack-level anomaly (>99% confidence)
    Attack(AnomalyReport),
}

/// Detailed anomaly report
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyReport {
    pub can_id: u32,
    pub source: String,
    pub anomaly_type: AnomalyType,
    pub confidence_sigma: f64,
    pub severity: AnomalySeverity,
    pub timestamp: DateTime<Utc>,
}

impl fmt::Display for AnomalyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} on CAN ID 0x{:03X} from {} ({:.2}σ, {:?})",
            self.anomaly_type, self.can_id, self.source, self.confidence_sigma, self.severity
        )
    }
}

/// Types of anomalies
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyType {
    /// Message arrived too fast or too slow
    IntervalAnomaly { expected_ms: f64, actual_ms: f64 },

    /// Message rate too high or too low
    RateAnomaly {
        expected_rate: f64,
        actual_rate: f64,
    },

    /// Data byte value outside expected range
    DataRangeAnomaly {
        byte_index: usize,
        value: u8,
        expected_min: u8,
        expected_max: u8,
        expected_mean: f64,
    },

    /// Message from unexpected source ECU
    UnexpectedSource { expected_sources: HashSet<String> },

    /// New CAN ID not seen during training
    UnknownCanId,
}

impl fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnomalyType::IntervalAnomaly {
                expected_ms,
                actual_ms,
            } => write!(
                f,
                "Interval Anomaly (expected: {:.2}ms, actual: {:.2}ms)",
                expected_ms, actual_ms
            ),
            AnomalyType::RateAnomaly {
                expected_rate,
                actual_rate,
            } => write!(
                f,
                "Rate Anomaly (expected: {:.2}/s, actual: {:.2}/s)",
                expected_rate, actual_rate
            ),
            AnomalyType::DataRangeAnomaly {
                byte_index,
                value,
                expected_min,
                expected_max,
                ..
            } => write!(
                f,
                "Data Range Anomaly at byte[{}]: {} (expected: {}-{})",
                byte_index, value, expected_min, expected_max
            ),
            AnomalyType::UnexpectedSource { expected_sources } => {
                write!(f, "Unexpected Source (expected: {:?})", expected_sources)
            }
            AnomalyType::UnknownCanId => write!(f, "Unknown CAN ID (not in baseline)"),
        }
    }
}

/// Anomaly severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    Low,    // < warning threshold
    Medium, // >= warning threshold, < detection threshold
    High,   // >= detection threshold
}

/// Anomaly detector state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorMode {
    /// Training mode - collecting baseline statistics
    Training { samples_collected: u64 },

    /// Detection mode - comparing against baseline
    Detection,

    /// Disabled - no anomaly detection
    Disabled,
}

/// Rate tracking for sliding window rate calculation
#[derive(Debug, Clone)]
struct RateTracker {
    /// Timestamps of recent messages (within window)
    message_times: Vec<DateTime<Utc>>,

    /// Window duration for rate calculation
    window_duration: Duration,
}

impl RateTracker {
    fn new(window_duration_secs: i64) -> Self {
        Self {
            message_times: Vec::new(),
            window_duration: Duration::seconds(window_duration_secs),
        }
    }

    /// Add a message timestamp and calculate current rate
    fn add_message(&mut self, timestamp: DateTime<Utc>) -> f64 {
        // Add new timestamp
        self.message_times.push(timestamp);

        // Remove timestamps outside window
        let cutoff = timestamp - self.window_duration;
        self.message_times.retain(|&ts| ts > cutoff);

        // Calculate rate (messages per second)
        let window_secs = self.window_duration.num_seconds() as f64;
        self.message_times.len() as f64 / window_secs
    }
}

/// Anomaly detector with statistical profiling
#[derive(Clone)]
pub struct AnomalyDetector {
    /// Current detection mode
    mode: DetectorMode,

    /// Baseline profile
    baseline: Option<AnomalyBaseline>,

    /// Training baseline (being built)
    training_baseline: Option<AnomalyBaseline>,

    /// Minimum samples required before finalizing baseline
    min_samples_per_can_id: u64,

    /// Rate trackers for each CAN ID (for real-time rate calculation)
    rate_trackers: HashMap<u32, RateTracker>,

    /// Rate window duration in seconds
    rate_window_secs: i64,
}

impl AnomalyDetector {
    /// Create a new anomaly detector in disabled mode
    pub fn new() -> Self {
        Self {
            mode: DetectorMode::Disabled,
            baseline: None,
            training_baseline: None,
            min_samples_per_can_id: 1000, // Default: 1000 samples per CAN ID
            rate_trackers: HashMap::new(),
            rate_window_secs: 1, // 1-second sliding window for rate calculation
        }
    }

    /// Start training mode to collect baseline
    pub fn start_training(
        &mut self,
        ecu_id: String,
        min_samples_per_can_id: u64,
    ) -> Result<(), String> {
        if !matches!(self.mode, DetectorMode::Disabled) {
            return Err("Cannot start training: detector already active".to_string());
        }

        self.training_baseline = Some(AnomalyBaseline::new(ecu_id));
        self.min_samples_per_can_id = min_samples_per_can_id;
        self.mode = DetectorMode::Training {
            samples_collected: 0,
        };

        Ok(())
    }

    /// Load a pre-trained baseline from factory calibration
    pub fn load_baseline(&mut self, baseline: AnomalyBaseline) -> Result<(), String> {
        if !matches!(self.mode, DetectorMode::Disabled) {
            return Err("Cannot load baseline: detector already active".to_string());
        }

        self.baseline = Some(baseline);
        self.mode = DetectorMode::Detection;

        Ok(())
    }

    /// Get current mode
    pub fn mode(&self) -> DetectorMode {
        self.mode
    }

    /// Check if detector is in training mode
    pub fn is_training(&self) -> bool {
        matches!(self.mode, DetectorMode::Training { .. })
    }

    /// Check if detector is in detection mode
    pub fn is_detecting(&self) -> bool {
        matches!(self.mode, DetectorMode::Detection)
    }

    /// Process a frame during training
    pub fn train(&mut self, frame: &crate::hsm::SecuredCanFrame) -> Result<(), String> {
        let DetectorMode::Training { samples_collected } = self.mode else {
            return Err("Not in training mode".to_string());
        };

        let baseline = self
            .training_baseline
            .as_mut()
            .ok_or("Training baseline not initialized")?;

        let can_id = frame.can_id.value();
        let profile = baseline.get_or_create_profile(can_id);
        profile.add_sample(&frame.data, frame.timestamp, &frame.source);

        baseline.total_samples += 1;
        self.mode = DetectorMode::Training {
            samples_collected: samples_collected + 1,
        };

        Ok(())
    }

    /// Finalize training and switch to detection mode
    pub fn finalize_training(&mut self) -> Result<AnomalyBaseline, String> {
        if !self.is_training() {
            return Err("Not in training mode".to_string());
        }

        let mut baseline = self
            .training_baseline
            .take()
            .ok_or("Training baseline not initialized")?;

        // Check if we have enough samples
        for (can_id, profile) in &baseline.profiles {
            if profile.message_count < self.min_samples_per_can_id {
                return Err(format!(
                    "Insufficient samples for CAN ID 0x{:03X}: {} (minimum: {})",
                    can_id, profile.message_count, self.min_samples_per_can_id
                ));
            }
        }

        // Finalize statistics
        baseline.finalize();

        // Return baseline for saving/signing
        Ok(baseline)
    }

    /// Activate detection mode with finalized baseline
    pub fn activate_detection(&mut self, baseline: AnomalyBaseline) {
        self.baseline = Some(baseline);
        self.mode = DetectorMode::Detection;
    }

    /// Detect anomalies in a frame
    pub fn detect(&mut self, frame: &crate::hsm::SecuredCanFrame) -> AnomalyResult {
        if !self.is_detecting() {
            return AnomalyResult::Normal;
        }

        let baseline = match &self.baseline {
            Some(b) => b,
            None => return AnomalyResult::Normal,
        };

        let can_id = frame.can_id.value();

        // Check 1: Unknown CAN ID
        let profile = match baseline.profiles.get(&can_id) {
            Some(p) => p,
            None => {
                return self.create_anomaly_result(
                    can_id,
                    &frame.source,
                    AnomalyType::UnknownCanId,
                    5.0, // High confidence - definitely not in baseline
                    baseline,
                );
            }
        };

        // Check 2: Unexpected source ECU
        if !profile.expected_sources.contains(&frame.source) {
            return self.create_anomaly_result(
                can_id,
                &frame.source,
                AnomalyType::UnexpectedSource {
                    expected_sources: profile.expected_sources.clone(),
                },
                4.0, // High confidence
                baseline,
            );
        }

        // Check 3: Inter-arrival interval anomaly
        if let Some(last_ts) = profile.last_seen {
            let interval_ms = (frame.timestamp - last_ts).num_milliseconds() as f64;
            if interval_ms > 0.0 && profile.interval_std_dev > 0.0 {
                let deviation = (interval_ms - profile.avg_interval_ms).abs();
                let sigma = deviation / profile.interval_std_dev;

                if sigma >= baseline.warning_threshold_sigma {
                    return self.create_anomaly_result(
                        can_id,
                        &frame.source,
                        AnomalyType::IntervalAnomaly {
                            expected_ms: profile.avg_interval_ms,
                            actual_ms: interval_ms,
                        },
                        sigma,
                        baseline,
                    );
                }
            }
        }

        // Check 4: Message rate anomaly
        let rate_tracker = self
            .rate_trackers
            .entry(can_id)
            .or_insert_with(|| RateTracker::new(self.rate_window_secs));
        let current_rate = rate_tracker.add_message(frame.timestamp);

        if profile.expected_rate_per_sec > 0.0 && profile.rate_std_dev > 0.0 {
            let deviation = (current_rate - profile.expected_rate_per_sec).abs();
            let sigma = deviation / profile.rate_std_dev.max(0.1); // Avoid division by zero

            if sigma >= baseline.warning_threshold_sigma {
                return self.create_anomaly_result(
                    can_id,
                    &frame.source,
                    AnomalyType::RateAnomaly {
                        expected_rate: profile.expected_rate_per_sec,
                        actual_rate: current_rate,
                    },
                    sigma,
                    baseline,
                );
            }
        }

        // Check 5: Data range anomalies
        for (i, &byte) in frame.data.iter().enumerate() {
            if i >= profile.data_stats.len() {
                break;
            }

            let stats = &profile.data_stats[i];
            if stats.std_dev > 0.0 {
                let deviation = (byte as f64 - stats.mean).abs();
                let sigma = deviation / stats.std_dev;

                if sigma >= baseline.warning_threshold_sigma {
                    return self.create_anomaly_result(
                        can_id,
                        &frame.source,
                        AnomalyType::DataRangeAnomaly {
                            byte_index: i,
                            value: byte,
                            expected_min: stats.min,
                            expected_max: stats.max,
                            expected_mean: stats.mean,
                        },
                        sigma,
                        baseline,
                    );
                }
            }
        }

        // No anomalies detected
        AnomalyResult::Normal
    }

    /// Create anomaly result with appropriate severity
    fn create_anomaly_result(
        &self,
        can_id: u32,
        source: &str,
        anomaly_type: AnomalyType,
        sigma: f64,
        baseline: &AnomalyBaseline,
    ) -> AnomalyResult {
        let severity = if sigma >= baseline.detection_threshold_sigma {
            AnomalySeverity::High
        } else if sigma >= baseline.warning_threshold_sigma {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        };

        let report = AnomalyReport {
            can_id,
            source: source.to_string(),
            anomaly_type,
            confidence_sigma: sigma,
            severity,
            timestamp: Utc::now(),
        };

        if severity == AnomalySeverity::High {
            AnomalyResult::Attack(report)
        } else {
            AnomalyResult::Warning(report)
        }
    }

    /// Get reference to current baseline
    pub fn baseline(&self) -> Option<&AnomalyBaseline> {
        self.baseline.as_ref()
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_frame(can_id: u32, data: Vec<u8>, source: &str) -> crate::hsm::SecuredCanFrame {
        crate::hsm::SecuredCanFrame {
            can_id: crate::types::CanId::Standard(can_id as u16),
            data,
            timestamp: Utc::now(),
            source: source.to_string(),
            session_counter: 0,
            mac: [0; 32],
            crc: 0,
        }
    }

    #[test]
    fn test_detector_initialization() {
        let detector = AnomalyDetector::new();
        assert!(!detector.is_training());
        assert!(!detector.is_detecting());
        assert!(detector.baseline().is_none());
    }

    #[test]
    fn test_training_mode() {
        let mut detector = AnomalyDetector::new();
        detector.start_training("TEST_ECU".to_string(), 10).unwrap();
        assert!(detector.is_training());
        assert!(!detector.is_detecting());
    }

    #[test]
    fn test_profile_statistics() {
        let mut profile = CanIdProfile::new(0x100);

        // Add samples
        for i in 0..10 {
            let data = vec![i as u8, 10, 20, 30];
            profile.add_sample(&data, Utc::now(), "TEST_ECU");
        }

        // Finalize statistics
        profile.finalize();

        // Check that statistics were calculated
        assert!(profile.message_count == 10);
        assert!(profile.expected_sources.contains("TEST_ECU"));
    }

    #[test]
    fn test_byte_statistics() {
        let mut stats = ByteStats::new();

        // Add samples
        for i in 0..10 {
            stats.add_sample(i * 10);
        }

        stats.finalize();

        // Check statistics
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 90);
        assert!(stats.mean > 40.0 && stats.mean < 50.0);
        assert!(stats.std_dev > 0.0);
    }

    #[test]
    fn test_unknown_can_id_detection() {
        let mut detector = AnomalyDetector::new();

        // Create baseline with one CAN ID
        let mut baseline = AnomalyBaseline::new("TEST_ECU".to_string());
        let mut profile = CanIdProfile::new(0x100);
        profile.add_sample(&vec![1, 2, 3], Utc::now(), "TEST_ECU");
        profile.finalize();
        baseline.profiles.insert(0x100, profile);

        detector.load_baseline(baseline).unwrap();

        // Test with unknown CAN ID
        let frame = create_test_frame(0x200, vec![1, 2, 3], "TEST_ECU");
        let result = detector.detect(&frame);

        assert!(matches!(result, AnomalyResult::Attack(_)));
    }

    #[test]
    fn test_unexpected_source_detection() {
        let mut detector = AnomalyDetector::new();

        // Create baseline with specific source
        let mut baseline = AnomalyBaseline::new("TEST_ECU".to_string());
        let mut profile = CanIdProfile::new(0x100);
        profile.add_sample(&vec![1, 2, 3], Utc::now(), "SENSOR_A");
        profile.finalize();
        baseline.profiles.insert(0x100, profile);

        detector.load_baseline(baseline).unwrap();

        // Test with different source
        let frame = create_test_frame(0x100, vec![1, 2, 3], "ROGUE_ECU");
        let result = detector.detect(&frame);

        assert!(matches!(result, AnomalyResult::Attack(_)));
    }

    #[test]
    fn test_normal_detection() {
        let mut detector = AnomalyDetector::new();

        // Create baseline
        let mut baseline = AnomalyBaseline::new("TEST_ECU".to_string());
        let mut profile = CanIdProfile::new(0x100);

        // Add consistent samples
        for _ in 0..100 {
            profile.add_sample(&vec![50, 100, 150], Utc::now(), "SENSOR_A");
        }
        profile.finalize();
        baseline.profiles.insert(0x100, profile);

        detector.load_baseline(baseline).unwrap();

        // Test with similar frame
        let frame = create_test_frame(0x100, vec![50, 100, 150], "SENSOR_A");
        let result = detector.detect(&frame);

        assert!(matches!(result, AnomalyResult::Normal));
    }

    #[test]
    fn test_graduated_response_thresholds() {
        let baseline = AnomalyBaseline::new("TEST_ECU".to_string());

        // Test default thresholds
        assert_eq!(baseline.warning_threshold_sigma, 1.3); // ~80%
        assert_eq!(baseline.detection_threshold_sigma, 3.0); // 99.7%
    }

    #[test]
    fn test_baseline_signature() {
        let mut baseline = AnomalyBaseline::new("TEST_ECU".to_string());
        baseline.signature = Some([1; 32]);

        assert!(baseline.signature.is_some());
        assert_eq!(baseline.signature.unwrap()[0], 1);
    }
}
