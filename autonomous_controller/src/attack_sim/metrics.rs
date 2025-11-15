/// Attack Metrics and Reporting
///
/// Provides detailed analysis and reporting capabilities for attack simulations

use crate::attack_sim::{AttackResult, AttackType};
use crate::attack_sim::orchestrator::{ScenarioResult, ScenarioStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Comprehensive attack metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMetrics {
    /// Total attacks executed
    pub total_attacks: usize,

    /// Attacks by type
    pub attacks_by_type: HashMap<String, usize>,

    /// Total frames sent
    pub total_frames_sent: u64,

    /// Total frames injected successfully
    pub total_frames_injected: u64,

    /// Total frames rejected
    pub total_frames_rejected: u64,

    /// Number of attacks detected
    pub attacks_detected: usize,

    /// Detection rate (detected / total)
    pub detection_rate: f64,

    /// Average success rate across attacks
    pub avg_success_rate: f64,

    /// Average time to detection (ms)
    pub avg_time_to_detection_ms: Option<f64>,

    /// Fastest detection time (ms)
    pub fastest_detection_ms: Option<u64>,

    /// Slowest detection time (ms)
    pub slowest_detection_ms: Option<u64>,

    /// Total attack duration (ms)
    pub total_duration_ms: i64,

    /// Custom metrics aggregated from individual attacks
    pub custom_metrics: HashMap<String, f64>,
}

impl AttackMetrics {
    /// Compute metrics from a list of attack results
    pub fn from_results(results: &[AttackResult]) -> Self {
        if results.is_empty() {
            return Self::default();
        }

        let total_attacks = results.len();
        let mut attacks_by_type: HashMap<String, usize> = HashMap::new();
        let mut total_frames_sent = 0u64;
        let mut total_frames_injected = 0u64;
        let mut total_frames_rejected = 0u64;
        let mut attacks_detected = 0usize;
        let mut detection_times: Vec<u64> = Vec::new();
        let mut success_rates: Vec<f64> = Vec::new();
        let mut total_duration_ms = 0i64;
        let mut custom_metrics: HashMap<String, Vec<f64>> = HashMap::new();

        for result in results {
            // Count by type
            *attacks_by_type
                .entry(format!("{}", result.attack_type))
                .or_insert(0) += 1;

            // Aggregate frame counts
            total_frames_sent += result.frames_sent;
            total_frames_injected += result.frames_injected;
            total_frames_rejected += result.frames_rejected;

            // Detection tracking
            if result.attack_detected {
                attacks_detected += 1;
                if let Some(ttd) = result.time_to_detection_ms {
                    detection_times.push(ttd);
                }
            }

            // Success rates
            success_rates.push(result.success_rate());

            // Duration
            total_duration_ms += result.duration_ms();

            // Custom metrics
            for (key, value) in &result.metrics {
                custom_metrics
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push(*value);
            }
        }

        // Calculate averages
        let detection_rate = attacks_detected as f64 / total_attacks as f64;
        let avg_success_rate = success_rates.iter().sum::<f64>() / success_rates.len() as f64;

        let (avg_time_to_detection_ms, fastest_detection_ms, slowest_detection_ms) =
            if detection_times.is_empty() {
                (None, None, None)
            } else {
                let sum: u64 = detection_times.iter().sum();
                let avg = sum as f64 / detection_times.len() as f64;
                let fastest = *detection_times.iter().min().unwrap();
                let slowest = *detection_times.iter().max().unwrap();
                (Some(avg), Some(fastest), Some(slowest))
            };

        // Aggregate custom metrics (average)
        let custom_metrics_avg: HashMap<String, f64> = custom_metrics
            .into_iter()
            .map(|(key, values)| {
                let avg = values.iter().sum::<f64>() / values.len() as f64;
                (key, avg)
            })
            .collect();

        Self {
            total_attacks,
            attacks_by_type,
            total_frames_sent,
            total_frames_injected,
            total_frames_rejected,
            attacks_detected,
            detection_rate,
            avg_success_rate,
            avg_time_to_detection_ms,
            fastest_detection_ms,
            slowest_detection_ms,
            total_duration_ms,
            custom_metrics: custom_metrics_avg,
        }
    }

    /// Generate a text report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("\n");
        report.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        report.push_str("║              ATTACK SIMULATION METRICS REPORT                ║\n");
        report.push_str("╚══════════════════════════════════════════════════════════════╝\n");
        report.push_str("\n");

        // Overview
        report.push_str("OVERVIEW\n");
        report.push_str("--------\n");
        report.push_str(&format!("Total Attacks Executed:    {}\n", self.total_attacks));
        report.push_str(&format!(
            "Total Duration:            {} ms ({:.2} seconds)\n",
            self.total_duration_ms,
            self.total_duration_ms as f64 / 1000.0
        ));
        report.push_str("\n");

        // Frame statistics
        report.push_str("FRAME STATISTICS\n");
        report.push_str("----------------\n");
        report.push_str(&format!("Frames Sent:               {}\n", self.total_frames_sent));
        report.push_str(&format!(
            "Frames Injected:           {}\n",
            self.total_frames_injected
        ));
        report.push_str(&format!(
            "Frames Rejected:           {}\n",
            self.total_frames_rejected
        ));
        report.push_str(&format!(
            "Average Success Rate:      {:.2}%\n",
            self.avg_success_rate * 100.0
        ));
        report.push_str("\n");

        // Detection statistics
        report.push_str("DETECTION STATISTICS\n");
        report.push_str("--------------------\n");
        report.push_str(&format!(
            "Attacks Detected:          {}/{}\n",
            self.attacks_detected, self.total_attacks
        ));
        report.push_str(&format!(
            "Detection Rate:            {:.2}%\n",
            self.detection_rate * 100.0
        ));

        if let Some(avg_ttd) = self.avg_time_to_detection_ms {
            report.push_str(&format!(
                "Avg Time to Detection:     {:.2} ms\n",
                avg_ttd
            ));
        }

        if let Some(fastest) = self.fastest_detection_ms {
            report.push_str(&format!("Fastest Detection:         {} ms\n", fastest));
        }

        if let Some(slowest) = self.slowest_detection_ms {
            report.push_str(&format!("Slowest Detection:         {} ms\n", slowest));
        }
        report.push_str("\n");

        // Attack breakdown by type
        report.push_str("ATTACKS BY TYPE\n");
        report.push_str("---------------\n");
        let mut types: Vec<_> = self.attacks_by_type.iter().collect();
        types.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

        for (attack_type, count) in types {
            report.push_str(&format!("  {:30} {}\n", attack_type, count));
        }
        report.push_str("\n");

        // Custom metrics
        if !self.custom_metrics.is_empty() {
            report.push_str("CUSTOM METRICS\n");
            report.push_str("--------------\n");
            let mut metrics: Vec<_> = self.custom_metrics.iter().collect();
            metrics.sort_by_key(|(name, _)| *name);

            for (name, value) in metrics {
                report.push_str(&format!("  {:30} {:.2}\n", name, value));
            }
            report.push_str("\n");
        }

        report.push_str("══════════════════════════════════════════════════════════════\n");

        report
    }
}

impl Default for AttackMetrics {
    fn default() -> Self {
        Self {
            total_attacks: 0,
            attacks_by_type: HashMap::new(),
            total_frames_sent: 0,
            total_frames_injected: 0,
            total_frames_rejected: 0,
            attacks_detected: 0,
            detection_rate: 0.0,
            avg_success_rate: 0.0,
            avg_time_to_detection_ms: None,
            fastest_detection_ms: None,
            slowest_detection_ms: None,
            total_duration_ms: 0,
            custom_metrics: HashMap::new(),
        }
    }
}

/// Scenario comparison report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioComparison {
    pub scenarios: Vec<ScenarioSummary>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSummary {
    pub name: String,
    pub status: ScenarioStatus,
    pub total_attacks: usize,
    pub frames_sent: u64,
    pub detection_rate: f64,
    pub duration_ms: i64,
}

impl ScenarioComparison {
    pub fn new() -> Self {
        Self {
            scenarios: Vec::new(),
            timestamp: Utc::now(),
        }
    }

    pub fn add_scenario(&mut self, result: &ScenarioResult) {
        let metrics = AttackMetrics::from_results(&result.attack_results);

        self.scenarios.push(ScenarioSummary {
            name: result.scenario_name.clone(),
            status: result.status,
            total_attacks: result.attack_results.len(),
            frames_sent: result.total_frames_sent(),
            detection_rate: metrics.detection_rate,
            duration_ms: result.duration_ms(),
        });
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("\n");
        report.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        report.push_str("║           SCENARIO COMPARISON REPORT                         ║\n");
        report.push_str("╚══════════════════════════════════════════════════════════════╝\n");
        report.push_str("\n");

        report.push_str(&format!("Report Generated: {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("Total Scenarios: {}\n\n", self.scenarios.len()));

        report.push_str("┌────────────────────────────┬────────┬────────┬─────────┬──────────┐\n");
        report.push_str("│ Scenario Name              │ Status │ Attacks│ Frames  │ Detect % │\n");
        report.push_str("├────────────────────────────┼────────┼────────┼─────────┼──────────┤\n");

        for summary in &self.scenarios {
            let status_str = format!("{:?}", summary.status);
            let status_display = if status_str.len() > 6 {
                &status_str[..6]
            } else {
                &status_str
            };

            report.push_str(&format!(
                "│ {:26} │ {:6} │ {:6} │ {:7} │ {:7.1}% │\n",
                truncate_str(&summary.name, 26),
                status_display,
                summary.total_attacks,
                summary.frames_sent,
                summary.detection_rate * 100.0
            ));
        }

        report.push_str("└────────────────────────────┴────────┴────────┴─────────┴──────────┘\n");
        report.push_str("\n");

        report
    }
}

impl Default for ScenarioComparison {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:width$}", s, width = max_len)
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_sim::AttackType;

    fn create_test_result(
        attack_type: AttackType,
        frames_sent: u64,
        frames_injected: u64,
        detected: bool,
    ) -> AttackResult {
        let mut result = AttackResult::new(attack_type);
        result.frames_sent = frames_sent;
        result.frames_injected = frames_injected;
        result.frames_rejected = frames_sent - frames_injected;
        result.attack_detected = detected;

        if detected {
            result.time_to_detection_ms = Some(100);
        }

        result
    }

    #[test]
    fn test_metrics_from_empty_results() {
        let metrics = AttackMetrics::from_results(&[]);
        assert_eq!(metrics.total_attacks, 0);
        assert_eq!(metrics.total_frames_sent, 0);
    }

    #[test]
    fn test_metrics_from_single_result() {
        let result = create_test_result(AttackType::FuzzRandom, 100, 75, true);
        let metrics = AttackMetrics::from_results(&[result]);

        assert_eq!(metrics.total_attacks, 1);
        assert_eq!(metrics.total_frames_sent, 100);
        assert_eq!(metrics.total_frames_injected, 75);
        assert_eq!(metrics.attacks_detected, 1);
        assert_eq!(metrics.detection_rate, 1.0);
        assert_eq!(metrics.avg_success_rate, 0.75);
    }

    #[test]
    fn test_metrics_from_multiple_results() {
        let results = vec![
            create_test_result(AttackType::FuzzRandom, 100, 80, true),
            create_test_result(AttackType::InjectUnsecured, 50, 30, false),
            create_test_result(AttackType::ReplaySimple, 75, 60, true),
        ];

        let metrics = AttackMetrics::from_results(&results);

        assert_eq!(metrics.total_attacks, 3);
        assert_eq!(metrics.total_frames_sent, 225);
        assert_eq!(metrics.total_frames_injected, 170);
        assert_eq!(metrics.attacks_detected, 2);
        assert!((metrics.detection_rate - 0.6667).abs() < 0.001);
    }

    #[test]
    fn test_metrics_attacks_by_type() {
        let results = vec![
            create_test_result(AttackType::FuzzRandom, 100, 80, false),
            create_test_result(AttackType::FuzzRandom, 100, 80, false),
            create_test_result(AttackType::InjectUnsecured, 50, 30, false),
        ];

        let metrics = AttackMetrics::from_results(&results);

        assert_eq!(*metrics.attacks_by_type.get("Random Fuzzing").unwrap(), 2);
        assert_eq!(
            *metrics
                .attacks_by_type
                .get("Unsecured Frame Injection")
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_metrics_detection_times() {
        let mut result1 = create_test_result(AttackType::FuzzRandom, 100, 80, true);
        result1.time_to_detection_ms = Some(100);

        let mut result2 = create_test_result(AttackType::InjectUnsecured, 50, 30, true);
        result2.time_to_detection_ms = Some(200);

        let mut result3 = create_test_result(AttackType::ReplaySimple, 75, 60, true);
        result3.time_to_detection_ms = Some(50);

        let results = vec![result1, result2, result3];
        let metrics = AttackMetrics::from_results(&results);

        assert_eq!(metrics.fastest_detection_ms, Some(50));
        assert_eq!(metrics.slowest_detection_ms, Some(200));
        assert_eq!(
            metrics.avg_time_to_detection_ms,
            Some((100.0 + 200.0 + 50.0) / 3.0)
        );
    }

    #[test]
    fn test_metrics_generate_report() {
        let result = create_test_result(AttackType::FuzzRandom, 100, 75, true);
        let metrics = AttackMetrics::from_results(&[result]);

        let report = metrics.generate_report();
        assert!(report.contains("ATTACK SIMULATION METRICS REPORT"));
        assert!(report.contains("Total Attacks Executed"));
        assert!(report.contains("Frames Sent"));
        assert!(report.contains("Detection Rate"));
    }

    #[test]
    fn test_scenario_comparison() {
        let mut comparison = ScenarioComparison::new();

        let mut result1 = ScenarioResult::new("scenario1".to_string());
        result1.status = ScenarioStatus::Completed;
        result1
            .attack_results
            .push(create_test_result(AttackType::FuzzRandom, 100, 80, true));

        let mut result2 = ScenarioResult::new("scenario2".to_string());
        result2.status = ScenarioStatus::Completed;
        result2
            .attack_results
            .push(create_test_result(AttackType::InjectUnsecured, 50, 30, false));

        comparison.add_scenario(&result1);
        comparison.add_scenario(&result2);

        assert_eq!(comparison.scenarios.len(), 2);
        assert_eq!(comparison.scenarios[0].name, "scenario1");
        assert_eq!(comparison.scenarios[1].name, "scenario2");
    }

    #[test]
    fn test_scenario_comparison_report() {
        let mut comparison = ScenarioComparison::new();

        let mut result = ScenarioResult::new("test_scenario".to_string());
        result.status = ScenarioStatus::Completed;
        result
            .attack_results
            .push(create_test_result(AttackType::FuzzRandom, 100, 80, true));

        comparison.add_scenario(&result);

        let report = comparison.generate_report();
        assert!(report.contains("SCENARIO COMPARISON REPORT"));
        assert!(report.contains("test_scenario"));
        // Status is truncated to 6 characters, so "Completed" becomes "Comple"
        assert!(report.contains("Comple"));
    }

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("hello", 10), "hello     ");
        assert_eq!(truncate_str("hello world test", 10), "hello w...");
        assert_eq!(truncate_str("abc", 5), "abc  ");
    }
}
