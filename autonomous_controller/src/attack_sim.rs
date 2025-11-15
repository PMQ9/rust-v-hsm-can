/// Attack Simulation Framework
///
/// This module provides a comprehensive framework for simulating various
/// attack scenarios against the V-HSM CAN bus security system.
///
/// Features:
/// - Fuzzing engines (random, mutation-based, grammar-based)
/// - Injection attacks (unsecured, MAC tampering, CRC corruption)
/// - Replay attacks (simple, delayed, reordered, selective)
/// - Attack orchestration and scheduling
/// - Metrics collection and reporting

pub mod fuzzing;
pub mod injection;
pub mod replay;
pub mod orchestrator;
pub mod metrics;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Attack type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackType {
    /// Random fuzzing of CAN frame data
    FuzzRandom,
    /// Mutation-based fuzzing (flip bits, modify bytes)
    FuzzMutation,
    /// Grammar-based fuzzing (protocol-aware)
    FuzzGrammar,

    /// Inject unsecured frames (no MAC/CRC)
    InjectUnsecured,
    /// Inject frames with tampered MAC
    InjectMacTampered,
    /// Inject frames with corrupted CRC
    InjectCrcCorrupted,
    /// Inject frames with spoofed source ECU
    InjectSpoofedSource,
    /// Flooding attack (DoS)
    InjectFlooding,

    /// Simple replay (duplicate frames)
    ReplaySimple,
    /// Delayed replay (replay old frames)
    ReplayDelayed,
    /// Reordered replay (change frame order)
    ReplayReordered,
    /// Selective replay (replay specific frames)
    ReplaySelective,

    /// Unauthorized CAN ID access
    UnauthorizedAccess,
    /// Man-in-the-middle (modify in transit)
    ManInTheMiddle,
}

impl fmt::Display for AttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackType::FuzzRandom => write!(f, "Random Fuzzing"),
            AttackType::FuzzMutation => write!(f, "Mutation-based Fuzzing"),
            AttackType::FuzzGrammar => write!(f, "Grammar-based Fuzzing"),
            AttackType::InjectUnsecured => write!(f, "Unsecured Frame Injection"),
            AttackType::InjectMacTampered => write!(f, "MAC Tampering"),
            AttackType::InjectCrcCorrupted => write!(f, "CRC Corruption"),
            AttackType::InjectSpoofedSource => write!(f, "Source Spoofing"),
            AttackType::InjectFlooding => write!(f, "Flooding Attack"),
            AttackType::ReplaySimple => write!(f, "Simple Replay"),
            AttackType::ReplayDelayed => write!(f, "Delayed Replay"),
            AttackType::ReplayReordered => write!(f, "Reordered Replay"),
            AttackType::ReplaySelective => write!(f, "Selective Replay"),
            AttackType::UnauthorizedAccess => write!(f, "Unauthorized CAN ID Access"),
            AttackType::ManInTheMiddle => write!(f, "Man-in-the-Middle"),
        }
    }
}

/// Attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Type of attack to perform
    pub attack_type: AttackType,

    /// Target CAN ID (if applicable)
    pub target_can_id: Option<u32>,

    /// Attack duration in seconds
    pub duration_secs: u64,

    /// Attack intensity (0.0-1.0)
    /// 0.0 = minimal, 1.0 = maximum intensity
    pub intensity: f64,

    /// Frames per second for continuous attacks
    pub frames_per_second: Option<u32>,

    /// Number of attack frames to send (for burst attacks)
    pub frame_count: Option<u32>,

    /// Delay between attack frames in milliseconds
    pub delay_ms: Option<u64>,

    /// Source ECU to spoof (for spoofing attacks)
    pub spoofed_source: Option<String>,

    /// Replay buffer size (for replay attacks)
    pub replay_buffer_size: Option<usize>,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            attack_type: AttackType::FuzzRandom,
            target_can_id: None,
            duration_secs: 10,
            intensity: 0.5,
            frames_per_second: Some(10),
            frame_count: None,
            delay_ms: Some(100),
            spoofed_source: None,
            replay_buffer_size: Some(100),
        }
    }
}

/// Attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Attack type executed
    pub attack_type: AttackType,

    /// Start timestamp
    pub start_time: DateTime<Utc>,

    /// End timestamp
    pub end_time: DateTime<Utc>,

    /// Total frames sent
    pub frames_sent: u64,

    /// Frames successfully injected (not rejected immediately)
    pub frames_injected: u64,

    /// Frames rejected by target
    pub frames_rejected: u64,

    /// Attack detected by target
    pub attack_detected: bool,

    /// Time to detection (if detected)
    pub time_to_detection_ms: Option<u64>,

    /// Target ECU state after attack
    pub target_state: Option<String>,

    /// Additional metrics
    pub metrics: std::collections::HashMap<String, f64>,
}

impl AttackResult {
    pub fn new(attack_type: AttackType) -> Self {
        Self {
            attack_type,
            start_time: Utc::now(),
            end_time: Utc::now(),
            frames_sent: 0,
            frames_injected: 0,
            frames_rejected: 0,
            attack_detected: false,
            time_to_detection_ms: None,
            target_state: None,
            metrics: std::collections::HashMap::new(),
        }
    }

    /// Calculate attack success rate (injected / sent)
    pub fn success_rate(&self) -> f64 {
        if self.frames_sent == 0 {
            0.0
        } else {
            self.frames_injected as f64 / self.frames_sent as f64
        }
    }

    /// Calculate attack duration in milliseconds
    pub fn duration_ms(&self) -> i64 {
        (self.end_time - self.start_time).num_milliseconds()
    }
}

/// Attack simulation trait
pub trait AttackSimulator {
    /// Execute the attack
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String>;

    /// Get attack type
    fn attack_type(&self) -> AttackType;

    /// Validate configuration
    fn validate_config(&self, config: &AttackConfig) -> Result<(), String> {
        if config.intensity < 0.0 || config.intensity > 1.0 {
            return Err("Intensity must be between 0.0 and 1.0".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_config_default() {
        let config = AttackConfig::default();
        assert_eq!(config.attack_type, AttackType::FuzzRandom);
        assert_eq!(config.duration_secs, 10);
        assert_eq!(config.intensity, 0.5);
    }

    #[test]
    fn test_attack_result_success_rate() {
        let mut result = AttackResult::new(AttackType::InjectUnsecured);
        result.frames_sent = 100;
        result.frames_injected = 75;

        assert_eq!(result.success_rate(), 0.75);
    }

    #[test]
    fn test_attack_type_display() {
        assert_eq!(
            format!("{}", AttackType::InjectUnsecured),
            "Unsecured Frame Injection"
        );
    }
}
