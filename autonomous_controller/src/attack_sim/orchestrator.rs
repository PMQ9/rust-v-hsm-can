/// Attack Orchestration Framework
///
/// Coordinates multiple attack scenarios, manages scheduling, and collects metrics

use crate::attack_sim::{AttackConfig, AttackResult, AttackSimulator, AttackType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attack scenario definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    /// Scenario name
    pub name: String,

    /// Description of the scenario
    pub description: String,

    /// Ordered list of attacks to execute
    pub attacks: Vec<AttackConfig>,

    /// Delay between attacks in seconds
    pub inter_attack_delay_secs: u64,

    /// Whether to stop on first detected attack
    pub stop_on_detection: bool,
}

impl AttackScenario {
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            attacks: Vec::new(),
            inter_attack_delay_secs: 1,
            stop_on_detection: false,
        }
    }

    /// Add an attack to the scenario
    pub fn add_attack(&mut self, attack: AttackConfig) {
        self.attacks.push(attack);
    }

    /// Get total estimated duration in seconds
    pub fn estimated_duration_secs(&self) -> u64 {
        let attack_duration: u64 = self.attacks.iter().map(|a| a.duration_secs).sum();
        let delay_duration = self.inter_attack_delay_secs * (self.attacks.len() as u64).saturating_sub(1);
        attack_duration + delay_duration
    }
}

/// Scenario execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Scenario name
    pub scenario_name: String,

    /// Start timestamp
    pub start_time: DateTime<Utc>,

    /// End timestamp
    pub end_time: DateTime<Utc>,

    /// Individual attack results
    pub attack_results: Vec<AttackResult>,

    /// Overall detection status
    pub any_attack_detected: bool,

    /// First attack that was detected (if any)
    pub first_detected_attack: Option<usize>,

    /// Scenario execution status
    pub status: ScenarioStatus,
}

impl ScenarioResult {
    pub fn new(scenario_name: String) -> Self {
        Self {
            scenario_name,
            start_time: Utc::now(),
            end_time: Utc::now(),
            attack_results: Vec::new(),
            any_attack_detected: false,
            first_detected_attack: None,
            status: ScenarioStatus::Pending,
        }
    }

    /// Calculate total frames sent across all attacks
    pub fn total_frames_sent(&self) -> u64 {
        self.attack_results.iter().map(|r| r.frames_sent).sum()
    }

    /// Calculate total frames injected across all attacks
    pub fn total_frames_injected(&self) -> u64 {
        self.attack_results.iter().map(|r| r.frames_injected).sum()
    }

    /// Calculate overall success rate
    pub fn overall_success_rate(&self) -> f64 {
        let total_sent = self.total_frames_sent();
        if total_sent == 0 {
            0.0
        } else {
            self.total_frames_injected() as f64 / total_sent as f64
        }
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> i64 {
        (self.end_time - self.start_time).num_milliseconds()
    }
}

/// Scenario execution status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScenarioStatus {
    Pending,
    Running,
    Completed,
    Failed,
    StoppedEarly, // Stopped due to detection
}

/// Attack orchestrator
pub struct AttackOrchestrator {
    /// Predefined scenarios
    scenarios: HashMap<String, AttackScenario>,

    /// Execution history
    results_history: Vec<ScenarioResult>,
}

impl AttackOrchestrator {
    pub fn new() -> Self {
        Self {
            scenarios: HashMap::new(),
            results_history: Vec::new(),
        }
    }

    /// Register a scenario
    pub fn register_scenario(&mut self, scenario: AttackScenario) {
        self.scenarios.insert(scenario.name.clone(), scenario);
    }

    /// Get a scenario by name
    pub fn get_scenario(&self, name: &str) -> Option<&AttackScenario> {
        self.scenarios.get(name)
    }

    /// List all scenario names
    pub fn list_scenarios(&self) -> Vec<String> {
        self.scenarios.keys().cloned().collect()
    }

    /// Execute a scenario (dry run - doesn't actually send frames)
    pub fn execute_scenario_dry_run(&mut self, scenario_name: &str) -> Result<ScenarioResult, String> {
        let scenario = self
            .scenarios
            .get(scenario_name)
            .ok_or_else(|| format!("Scenario '{}' not found", scenario_name))?
            .clone();

        let mut result = ScenarioResult::new(scenario_name.to_string());
        result.status = ScenarioStatus::Running;

        println!("\n========================================");
        println!("Executing Scenario: {}", scenario.name);
        println!("Description: {}", scenario.description);
        println!("Number of Attacks: {}", scenario.attacks.len());
        println!("Estimated Duration: {} seconds", scenario.estimated_duration_secs());
        println!("========================================\n");

        for (idx, attack_config) in scenario.attacks.iter().enumerate() {
            println!("Attack {}/{}: {}", idx + 1, scenario.attacks.len(), attack_config.attack_type);
            println!("  Duration: {} seconds", attack_config.duration_secs);
            println!("  Intensity: {:.1}%", attack_config.intensity * 100.0);

            // Simulate attack execution
            let attack_result = AttackResult::new(attack_config.attack_type.clone());

            // Check for detection
            if attack_result.attack_detected {
                result.any_attack_detected = true;
                if result.first_detected_attack.is_none() {
                    result.first_detected_attack = Some(idx);
                }

                println!("  [!] Attack was DETECTED");

                if scenario.stop_on_detection {
                    println!("\n[!] Stopping scenario early due to detection");
                    result.status = ScenarioStatus::StoppedEarly;
                    result.attack_results.push(attack_result);
                    break;
                }
            } else {
                println!("  [✓] Attack completed");
            }

            result.attack_results.push(attack_result);

            // Simulate delay between attacks
            if idx < scenario.attacks.len() - 1 {
                println!("  Waiting {} seconds before next attack...\n", scenario.inter_attack_delay_secs);
            }
        }

        if result.status != ScenarioStatus::StoppedEarly {
            result.status = ScenarioStatus::Completed;
        }

        result.end_time = Utc::now();

        println!("\n========================================");
        println!("Scenario Execution Summary");
        println!("========================================");
        println!("Status: {:?}", result.status);
        println!("Total Attacks Executed: {}", result.attack_results.len());
        println!("Total Frames Sent: {}", result.total_frames_sent());
        println!("Any Attack Detected: {}", result.any_attack_detected);
        println!("========================================\n");

        self.results_history.push(result.clone());
        Ok(result)
    }

    /// Get execution history
    pub fn get_history(&self) -> &[ScenarioResult] {
        &self.results_history
    }

    /// Clear execution history
    pub fn clear_history(&mut self) {
        self.results_history.clear();
    }
}

impl Default for AttackOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-defined attack scenarios
pub mod scenarios {
    use super::*;

    /// Basic fuzzing scenario
    pub fn basic_fuzzing() -> AttackScenario {
        let mut scenario = AttackScenario::new(
            "basic_fuzzing".to_string(),
            "Test all three fuzzing strategies".to_string(),
        );

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzRandom,
            duration_secs: 5,
            intensity: 0.5,
            frame_count: Some(50),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzMutation,
            duration_secs: 5,
            intensity: 0.5,
            frame_count: Some(50),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzGrammar,
            duration_secs: 5,
            intensity: 0.5,
            frame_count: Some(50),
            ..Default::default()
        });

        scenario.inter_attack_delay_secs = 2;
        scenario
    }

    /// Injection attack suite
    pub fn injection_suite() -> AttackScenario {
        let mut scenario = AttackScenario::new(
            "injection_suite".to_string(),
            "Comprehensive injection attack testing".to_string(),
        );

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectUnsecured,
            target_can_id: Some(0x300), // Brake command
            duration_secs: 10,
            intensity: 0.3,
            frame_count: Some(10),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectMacTampered,
            target_can_id: Some(0x300),
            duration_secs: 10,
            intensity: 0.5,
            frame_count: Some(10),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectCrcCorrupted,
            target_can_id: Some(0x300),
            duration_secs: 10,
            intensity: 0.5,
            frame_count: Some(10),
            ..Default::default()
        });

        scenario.stop_on_detection = true;
        scenario
    }

    /// Replay attack suite
    pub fn replay_suite() -> AttackScenario {
        let mut scenario = AttackScenario::new(
            "replay_suite".to_string(),
            "Test all replay attack variants".to_string(),
        );

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplaySimple,
            duration_secs: 5,
            frame_count: Some(20),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplayDelayed,
            duration_secs: 5,
            frame_count: Some(15),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplayReordered,
            duration_secs: 5,
            intensity: 0.7,
            frame_count: Some(25),
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplaySelective,
            target_can_id: Some(0x300),
            duration_secs: 5,
            frame_count: Some(10),
            ..Default::default()
        });

        scenario
    }

    /// DoS/Flooding attack
    pub fn flooding_attack() -> AttackScenario {
        let mut scenario = AttackScenario::new(
            "flooding_attack".to_string(),
            "Denial-of-service flooding attack".to_string(),
        );

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectFlooding,
            target_can_id: Some(0x300),
            duration_secs: 10,
            intensity: 0.8, // 800 fps
            ..Default::default()
        });

        scenario.stop_on_detection = true;
        scenario
    }

    /// Comprehensive security test
    pub fn comprehensive_security_test() -> AttackScenario {
        let mut scenario = AttackScenario::new(
            "comprehensive_security_test".to_string(),
            "Full security validation with all attack types".to_string(),
        );

        // Phase 1: Fuzzing
        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzRandom,
            duration_secs: 3,
            intensity: 0.3,
            frame_count: Some(30),
            ..Default::default()
        });

        // Phase 2: Injection
        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectUnsecured,
            target_can_id: Some(0x300),
            duration_secs: 5,
            frame_count: Some(5),
            ..Default::default()
        });

        // Phase 3: Replay
        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplaySimple,
            duration_secs: 5,
            frame_count: Some(10),
            ..Default::default()
        });

        // Phase 4: Flooding
        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectFlooding,
            duration_secs: 5,
            intensity: 0.5,
            ..Default::default()
        });

        scenario.inter_attack_delay_secs = 3;
        scenario
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_scenario_creation() {
        let scenario = AttackScenario::new("test".to_string(), "Test scenario".to_string());
        assert_eq!(scenario.name, "test");
        assert_eq!(scenario.attacks.len(), 0);
    }

    #[test]
    fn test_attack_scenario_add_attack() {
        let mut scenario = AttackScenario::new("test".to_string(), "Test".to_string());
        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzRandom,
            duration_secs: 10,
            ..Default::default()
        });

        assert_eq!(scenario.attacks.len(), 1);
        assert_eq!(scenario.attacks[0].attack_type, AttackType::FuzzRandom);
    }

    #[test]
    fn test_scenario_estimated_duration() {
        let mut scenario = AttackScenario::new("test".to_string(), "Test".to_string());
        scenario.inter_attack_delay_secs = 2;

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::FuzzRandom,
            duration_secs: 10,
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::InjectUnsecured,
            duration_secs: 15,
            ..Default::default()
        });

        scenario.add_attack(AttackConfig {
            attack_type: AttackType::ReplaySimple,
            duration_secs: 5,
            ..Default::default()
        });

        // Total: 10 + 15 + 5 + (2 * 2 delays) = 34 seconds
        assert_eq!(scenario.estimated_duration_secs(), 34);
    }

    #[test]
    fn test_orchestrator_register_scenario() {
        let mut orchestrator = AttackOrchestrator::new();
        let scenario = AttackScenario::new("test".to_string(), "Test".to_string());

        orchestrator.register_scenario(scenario);
        assert_eq!(orchestrator.list_scenarios().len(), 1);
        assert!(orchestrator.get_scenario("test").is_some());
    }

    #[test]
    fn test_orchestrator_execute_nonexistent_scenario() {
        let mut orchestrator = AttackOrchestrator::new();
        let result = orchestrator.execute_scenario_dry_run("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_scenario_result_calculations() {
        let mut result = ScenarioResult::new("test".to_string());

        let mut attack1 = AttackResult::new(AttackType::FuzzRandom);
        attack1.frames_sent = 100;
        attack1.frames_injected = 75;

        let mut attack2 = AttackResult::new(AttackType::InjectUnsecured);
        attack2.frames_sent = 50;
        attack2.frames_injected = 25;

        result.attack_results.push(attack1);
        result.attack_results.push(attack2);

        assert_eq!(result.total_frames_sent(), 150);
        assert_eq!(result.total_frames_injected(), 100);
        assert!((result.overall_success_rate() - 0.6667).abs() < 0.001);
    }

    #[test]
    fn test_predefined_scenario_basic_fuzzing() {
        let scenario = scenarios::basic_fuzzing();
        assert_eq!(scenario.attacks.len(), 3);
        assert_eq!(scenario.attacks[0].attack_type, AttackType::FuzzRandom);
        assert_eq!(scenario.attacks[1].attack_type, AttackType::FuzzMutation);
        assert_eq!(scenario.attacks[2].attack_type, AttackType::FuzzGrammar);
    }

    #[test]
    fn test_predefined_scenario_injection_suite() {
        let scenario = scenarios::injection_suite();
        assert_eq!(scenario.attacks.len(), 3);
        assert!(scenario.stop_on_detection);
    }

    #[test]
    fn test_predefined_scenario_replay_suite() {
        let scenario = scenarios::replay_suite();
        assert_eq!(scenario.attacks.len(), 4);
    }

    #[test]
    fn test_predefined_scenario_comprehensive() {
        let scenario = scenarios::comprehensive_security_test();
        assert_eq!(scenario.attacks.len(), 4);
        assert_eq!(scenario.inter_attack_delay_secs, 3);
    }
}
