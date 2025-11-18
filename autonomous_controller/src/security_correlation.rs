/// ISO 21434 Security Event Correlation Engine
///
/// Analyzes security events across time and ECUs to detect coordinated attack patterns.
/// Provides early warning for sophisticated multi-stage attacks that single-event
/// detection might miss.
///
/// Key ISO 21434 requirements addressed:
/// - 9.4.2: Security event analysis and correlation
/// - 10.4.1: Security monitoring and detection
/// - 10.4.2: Pattern recognition for attack detection
use crate::error_handling::ValidationError;
use crate::incident_response::IncidentSeverity;
use chrono::{DateTime, Duration, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

/// Time window for event correlation (seconds)
const CORRELATION_WINDOW_SECS: i64 = 60;

/// Minimum events required to trigger correlation alert
const MIN_CORRELATED_EVENTS: usize = 3;

/// Security event record for correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventRecord {
    /// Timestamp of event
    pub timestamp: DateTime<Utc>,
    /// Source ECU
    pub ecu_name: String,
    /// Target ECU (if applicable)
    pub target_ecu: Option<String>,
    /// CAN ID involved
    pub can_id: Option<u32>,
    /// Event type (validation error)
    pub event_type: String,
    /// Event severity
    pub severity: IncidentSeverity,
    /// Additional context
    pub context: String,
}

/// Attack pattern detected by correlation engine
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Coordinated attack from multiple sources
    CoordinatedMultiSource,
    /// Progressive attack escalating through multiple stages
    ProgressiveEscalation,
    /// Targeted attack focusing on specific ECU/CAN ID
    TargetedAttack,
    /// Distributed denial of service
    DistributedDenialOfService,
    /// Reconnaissance or scanning behavior
    ReconnaissanceActivity,
    /// Replay attack across multiple ECUs
    MultiEcuReplay,
    /// Authentication/authorization brute force
    BruteForceAttempt,
    /// Bus flooding from multiple sources
    CoordinatedFlooding,
}

impl fmt::Display for AttackPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackPattern::CoordinatedMultiSource => {
                write!(f, "Coordinated Multi-Source Attack")
            }
            AttackPattern::ProgressiveEscalation => {
                write!(f, "Progressive Attack Escalation")
            }
            AttackPattern::TargetedAttack => {
                write!(f, "Targeted Attack")
            }
            AttackPattern::DistributedDenialOfService => {
                write!(f, "Distributed Denial of Service")
            }
            AttackPattern::ReconnaissanceActivity => {
                write!(f, "Reconnaissance/Scanning Activity")
            }
            AttackPattern::MultiEcuReplay => {
                write!(f, "Multi-ECU Replay Attack")
            }
            AttackPattern::BruteForceAttempt => {
                write!(f, "Brute Force Attempt")
            }
            AttackPattern::CoordinatedFlooding => {
                write!(f, "Coordinated Bus Flooding")
            }
        }
    }
}

/// Correlation rule for pattern detection
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    /// Rule name
    pub name: String,
    /// Attack pattern this rule detects
    pub pattern: AttackPattern,
    /// Minimum number of events required
    pub min_events: usize,
    /// Time window for correlation (seconds)
    pub time_window_secs: i64,
    /// Minimum number of unique ECUs involved
    pub min_unique_ecus: Option<usize>,
    /// Minimum number of unique CAN IDs
    pub min_unique_can_ids: Option<usize>,
    /// Event types to match (empty = match all)
    pub event_types: Vec<String>,
    /// Minimum severity level
    pub min_severity: IncidentSeverity,
}

impl CorrelationRule {
    /// Create default rules for common attack patterns
    pub fn default_rules() -> Vec<CorrelationRule> {
        vec![
            // Coordinated Multi-Source Attack
            CorrelationRule {
                name: "Coordinated Multi-Source Attack".to_string(),
                pattern: AttackPattern::CoordinatedMultiSource,
                min_events: 5,
                time_window_secs: 30,
                min_unique_ecus: Some(3),
                min_unique_can_ids: None,
                event_types: vec![
                    "MAC Mismatch".to_string(),
                    "Unsecured Frame (No MAC)".to_string(),
                ],
                min_severity: IncidentSeverity::Medium,
            },
            // Progressive Escalation
            CorrelationRule {
                name: "Progressive Attack Escalation".to_string(),
                pattern: AttackPattern::ProgressiveEscalation,
                min_events: 4,
                time_window_secs: 60,
                min_unique_ecus: Some(1),
                min_unique_can_ids: None,
                event_types: vec![
                    "CRC Mismatch".to_string(),
                    "MAC Mismatch".to_string(),
                    "Unsecured Frame (No MAC)".to_string(),
                ],
                min_severity: IncidentSeverity::Low,
            },
            // Targeted Attack
            CorrelationRule {
                name: "Targeted Attack".to_string(),
                pattern: AttackPattern::TargetedAttack,
                min_events: 6,
                time_window_secs: 45,
                min_unique_ecus: None,
                min_unique_can_ids: Some(1),
                event_types: vec![],
                min_severity: IncidentSeverity::Medium,
            },
            // Multi-ECU Replay
            CorrelationRule {
                name: "Multi-ECU Replay Attack".to_string(),
                pattern: AttackPattern::MultiEcuReplay,
                min_events: 4,
                time_window_secs: 20,
                min_unique_ecus: Some(2),
                min_unique_can_ids: None,
                event_types: vec!["Replay Attack Detected".to_string()],
                min_severity: IncidentSeverity::Medium,
            },
            // Brute Force Attempt
            CorrelationRule {
                name: "Brute Force Attempt".to_string(),
                pattern: AttackPattern::BruteForceAttempt,
                min_events: 10,
                time_window_secs: 30,
                min_unique_ecus: Some(1),
                min_unique_can_ids: None,
                event_types: vec![
                    "MAC Mismatch".to_string(),
                    "Unauthorized CAN ID Access".to_string(),
                ],
                min_severity: IncidentSeverity::Low,
            },
            // Coordinated Flooding
            CorrelationRule {
                name: "Coordinated Bus Flooding".to_string(),
                pattern: AttackPattern::CoordinatedFlooding,
                min_events: 20,
                time_window_secs: 10,
                min_unique_ecus: Some(2),
                min_unique_can_ids: None,
                event_types: vec![],
                min_severity: IncidentSeverity::Low,
            },
        ]
    }
}

/// Correlation alert triggered when pattern detected
#[derive(Debug, Clone)]
pub struct CorrelationAlert {
    /// Alert timestamp
    pub timestamp: DateTime<Utc>,
    /// Attack pattern detected
    pub pattern: AttackPattern,
    /// Number of correlated events
    pub event_count: usize,
    /// ECUs involved
    pub ecus_involved: Vec<String>,
    /// CAN IDs involved
    pub can_ids_involved: Vec<u32>,
    /// Severity of the correlated pattern
    pub severity: IncidentSeverity,
    /// Detailed analysis
    pub analysis: String,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

impl fmt::Display for CorrelationAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CORRELATION ALERT")?;
        writeln!(f, "Timestamp: {}", self.timestamp)?;
        writeln!(f, "Pattern: {}", self.pattern)?;
        writeln!(f, "Severity: {}", self.severity)?;
        writeln!(f, "Events Correlated: {}", self.event_count)?;
        writeln!(f, "ECUs Involved: {}", self.ecus_involved.join(", "))?;
        writeln!(
            f,
            "CAN IDs Involved: {}",
            self.can_ids_involved
                .iter()
                .map(|id| format!("0x{:03X}", id))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(f, "Analysis: {}", self.analysis)?;
        writeln!(f, "Recommended Actions:")?;
        for action in &self.recommended_actions {
            writeln!(f, "  - {}", action)?;
        }
        Ok(())
    }
}

/// Security event correlation engine
pub struct CorrelationEngine {
    /// ECU name
    ecu_name: String,
    /// Event buffer for correlation analysis
    event_buffer: VecDeque<SecurityEventRecord>,
    /// Maximum events to retain in buffer
    max_buffer_size: usize,
    /// Correlation rules
    rules: Vec<CorrelationRule>,
    /// Alerts generated
    alerts: Vec<CorrelationAlert>,
    /// Statistics
    total_events_processed: u64,
    total_alerts_generated: u64,
}

impl CorrelationEngine {
    /// Create new correlation engine with default rules
    pub fn new(ecu_name: String) -> Self {
        Self {
            ecu_name,
            event_buffer: VecDeque::new(),
            max_buffer_size: 1000,
            rules: CorrelationRule::default_rules(),
            alerts: Vec::new(),
            total_events_processed: 0,
            total_alerts_generated: 0,
        }
    }

    /// Create with custom rules
    pub fn with_rules(ecu_name: String, rules: Vec<CorrelationRule>) -> Self {
        Self {
            ecu_name,
            event_buffer: VecDeque::new(),
            max_buffer_size: 1000,
            rules,
            alerts: Vec::new(),
            total_events_processed: 0,
            total_alerts_generated: 0,
        }
    }

    /// Process a security event and check for correlations
    pub fn process_event(
        &mut self,
        error: ValidationError,
        source: &str,
        can_id: Option<u32>,
        severity: IncidentSeverity,
    ) -> Option<CorrelationAlert> {
        let event = SecurityEventRecord {
            timestamp: Utc::now(),
            ecu_name: self.ecu_name.clone(),
            target_ecu: Some(source.to_string()),
            can_id,
            event_type: error.to_string(),
            severity,
            context: format!("Event from {} on CAN ID {:?}", source, can_id),
        };

        self.add_event(event);
        self.check_correlations()
    }

    /// Add event to buffer
    pub fn add_event(&mut self, event: SecurityEventRecord) {
        self.event_buffer.push_back(event);
        self.total_events_processed += 1;

        // Maintain buffer size
        while self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.pop_front();
        }

        // Clean old events outside correlation window
        self.clean_old_events();
    }

    /// Remove events outside the correlation window
    fn clean_old_events(&mut self) {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(CORRELATION_WINDOW_SECS * 2);

        while let Some(event) = self.event_buffer.front() {
            if event.timestamp < cutoff {
                self.event_buffer.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check for attack pattern correlations
    pub fn check_correlations(&mut self) -> Option<CorrelationAlert> {
        let now = Utc::now();

        // Try each rule
        for rule in &self.rules {
            let cutoff = now - Duration::seconds(rule.time_window_secs);

            // Get events within time window
            let relevant_events: Vec<&SecurityEventRecord> = self
                .event_buffer
                .iter()
                .filter(|e| e.timestamp >= cutoff)
                .filter(|e| e.severity >= rule.min_severity)
                .filter(|e| rule.event_types.is_empty() || rule.event_types.contains(&e.event_type))
                .collect();

            if relevant_events.len() < rule.min_events {
                continue;
            }

            // Check unique ECU count
            if let Some(min_unique_ecus) = rule.min_unique_ecus {
                let unique_ecus: std::collections::HashSet<_> = relevant_events
                    .iter()
                    .filter_map(|e| e.target_ecu.as_ref())
                    .collect();

                if unique_ecus.len() < min_unique_ecus {
                    continue;
                }
            }

            // Check unique CAN ID count
            if let Some(min_unique_can_ids) = rule.min_unique_can_ids {
                let unique_can_ids: std::collections::HashSet<_> =
                    relevant_events.iter().filter_map(|e| e.can_id).collect();

                if unique_can_ids.len() < min_unique_can_ids {
                    continue;
                }
            }

            // Pattern matched! Generate alert
            let alert = self.generate_alert(&rule.pattern, &relevant_events);
            self.alerts.push(alert.clone());
            self.total_alerts_generated += 1;

            self.print_correlation_alert(&alert);

            return Some(alert);
        }

        None
    }

    /// Generate correlation alert
    fn generate_alert(
        &self,
        pattern: &AttackPattern,
        events: &[&SecurityEventRecord],
    ) -> CorrelationAlert {
        // Extract ECUs involved
        let ecus_involved: Vec<String> = events
            .iter()
            .filter_map(|e| e.target_ecu.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Extract CAN IDs involved
        let can_ids_involved: Vec<u32> = events
            .iter()
            .filter_map(|e| e.can_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Determine severity
        let max_severity = events
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(IncidentSeverity::Medium);

        // Generate analysis
        let analysis = self.generate_analysis(pattern, events);

        // Generate recommendations
        let recommended_actions = self.generate_recommendations(pattern);

        CorrelationAlert {
            timestamp: Utc::now(),
            pattern: pattern.clone(),
            event_count: events.len(),
            ecus_involved,
            can_ids_involved,
            severity: max_severity,
            analysis,
            recommended_actions,
        }
    }

    /// Generate detailed analysis
    fn generate_analysis(
        &self,
        pattern: &AttackPattern,
        events: &[&SecurityEventRecord],
    ) -> String {
        match pattern {
            AttackPattern::CoordinatedMultiSource => {
                format!(
                    "Detected {} security events from {} unique sources within correlation window. \
                     This suggests a coordinated attack involving multiple compromised ECUs or \
                     external attack infrastructure.",
                    events.len(),
                    events
                        .iter()
                        .filter_map(|e| e.target_ecu.as_ref())
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                )
            }
            AttackPattern::ProgressiveEscalation => {
                format!(
                    "Observed progressive escalation through {} attack stages. Attack started with \
                     lower-severity events ({:?}) and progressed to higher-severity attacks. \
                     This indicates an attacker probing defenses and escalating tactics.",
                    events.len(),
                    events.first().map(|e| &e.event_type)
                )
            }
            AttackPattern::TargetedAttack => {
                let target_can_id = events.iter().filter_map(|e| e.can_id).next().unwrap_or(0);
                format!(
                    "Detected {} focused attacks on CAN ID 0x{:03X}. This targeted behavior \
                     suggests an attacker attempting to compromise or disrupt a specific vehicle \
                     function or ECU.",
                    events.len(),
                    target_can_id
                )
            }
            AttackPattern::MultiEcuReplay => {
                format!(
                    "Replay attacks detected across {} ECUs. This suggests an attacker has \
                     captured legitimate CAN traffic and is attempting to retransmit it to \
                     multiple targets, possibly to bypass authentication or trigger unintended behavior.",
                    events
                        .iter()
                        .filter_map(|e| e.target_ecu.as_ref())
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                )
            }
            AttackPattern::BruteForceAttempt => {
                format!(
                    "Detected {} rapid authentication/authorization attempts. This brute-force \
                     pattern suggests an attacker is attempting to guess valid credentials or \
                     find authorized CAN IDs through systematic trial.",
                    events.len()
                )
            }
            AttackPattern::CoordinatedFlooding => {
                format!(
                    "High-volume traffic detected ({} events in short window) from multiple sources. \
                     This coordinated flooding attack may be attempting to overwhelm the CAN bus \
                     and cause denial of service.",
                    events.len()
                )
            }
            _ => format!(
                "Attack pattern {} detected with {} correlated events.",
                pattern,
                events.len()
            ),
        }
    }

    /// Generate recommended actions
    fn generate_recommendations(&self, pattern: &AttackPattern) -> Vec<String> {
        match pattern {
            AttackPattern::CoordinatedMultiSource => vec![
                "Isolate all affected ECUs immediately".to_string(),
                "Initiate emergency key rotation across all ECUs".to_string(),
                "Review access control policies for all ECUs".to_string(),
                "Collect forensic data from all involved nodes".to_string(),
                "Consider activating backup/redundant systems".to_string(),
            ],
            AttackPattern::ProgressiveEscalation => vec![
                "Enter maximum security mode".to_string(),
                "Increase monitoring and logging verbosity".to_string(),
                "Preemptively strengthen defenses on likely next targets".to_string(),
                "Alert security operations center".to_string(),
            ],
            AttackPattern::TargetedAttack => vec![
                "Identify critical function associated with targeted CAN ID".to_string(),
                "Activate fail-safe mode for affected subsystem".to_string(),
                "Isolate targeted ECU if possible".to_string(),
                "Switch to redundant control path if available".to_string(),
            ],
            AttackPattern::MultiEcuReplay => vec![
                "Reset replay protection counters".to_string(),
                "Force key rotation to invalidate captured traffic".to_string(),
                "Increase replay window strictness".to_string(),
                "Audit for compromised ECUs with key access".to_string(),
            ],
            AttackPattern::BruteForceAttempt => vec![
                "Activate rate limiting on authentication attempts".to_string(),
                "Temporarily block source ECU".to_string(),
                "Rotate authentication keys".to_string(),
                "Increase authentication failure threshold penalties".to_string(),
            ],
            AttackPattern::CoordinatedFlooding => vec![
                "Activate bus arbitration priority for critical messages".to_string(),
                "Throttle non-critical traffic".to_string(),
                "Isolate flooding sources".to_string(),
                "Activate QoS mechanisms if available".to_string(),
            ],
            _ => vec![
                "Investigate and respond according to incident response procedures".to_string(),
            ],
        }
    }

    /// Print correlation alert
    fn print_correlation_alert(&self, alert: &CorrelationAlert) {
        println!();
        println!(
            "{}",
            "═══════════════════════════════════════".magenta().bold()
        );
        println!(
            "{}",
            "   ATTACK PATTERN DETECTED           ".magenta().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════".magenta().bold()
        );
        println!();
        println!(
            "{} Pattern: {}",
            "→".magenta(),
            alert.pattern.to_string().red().bold()
        );
        println!("{} Severity: {}", "→".magenta(), alert.severity);
        println!(
            "{} Correlated Events: {}",
            "→".magenta(),
            alert.event_count.to_string().yellow().bold()
        );
        println!();
        println!(
            "{} ECUs Involved: {}",
            "→".magenta(),
            alert.ecus_involved.join(", ").red()
        );
        println!(
            "{} CAN IDs: {}",
            "→".magenta(),
            alert
                .can_ids_involved
                .iter()
                .map(|id| format!("0x{:03X}", id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!();
        println!("{} {}", "→".magenta(), "ANALYSIS:".bright_white().bold());
        println!("   {}", alert.analysis);
        println!();
        println!(
            "{} {}",
            "→".magenta(),
            "RECOMMENDED ACTIONS:".bright_white().bold()
        );
        for (idx, action) in alert.recommended_actions.iter().enumerate() {
            println!("   {}. {}", idx + 1, action);
        }
        println!();
        println!(
            "{}",
            "═══════════════════════════════════════".magenta().bold()
        );
        println!();
    }

    /// Get statistics
    pub fn get_statistics(&self) -> CorrelationStatistics {
        CorrelationStatistics {
            total_events_processed: self.total_events_processed,
            total_alerts_generated: self.total_alerts_generated,
            current_buffer_size: self.event_buffer.len(),
            active_rules: self.rules.len(),
        }
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[CorrelationAlert] {
        &self.alerts
    }
}

/// Correlation engine statistics
#[derive(Debug, Clone)]
pub struct CorrelationStatistics {
    pub total_events_processed: u64,
    pub total_alerts_generated: u64,
    pub current_buffer_size: usize,
    pub active_rules: usize,
}

impl fmt::Display for CorrelationStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Total Events Processed: {}", self.total_events_processed)?;
        writeln!(f, "Total Alerts Generated: {}", self.total_alerts_generated)?;
        writeln!(f, "Current Buffer Size: {}", self.current_buffer_size)?;
        writeln!(f, "Active Rules: {}", self.active_rules)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_buffering() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());

        // Add events
        engine.process_event(
            ValidationError::MacMismatch,
            "SOURCE1",
            Some(0x300),
            IncidentSeverity::Medium,
        );

        engine.process_event(
            ValidationError::CrcMismatch,
            "SOURCE2",
            Some(0x301),
            IncidentSeverity::Low,
        );

        let stats = engine.get_statistics();
        assert_eq!(stats.total_events_processed, 2);
        assert_eq!(stats.current_buffer_size, 2);
    }

    #[test]
    fn test_coordinated_multi_source_detection() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());

        // Simulate coordinated attack from 3 sources
        for i in 0..5 {
            let source = format!("ATTACKER_{}", i % 3);
            engine.process_event(
                ValidationError::MacMismatch,
                &source,
                Some(0x300),
                IncidentSeverity::Medium,
            );
        }

        // Should detect coordinated multi-source pattern
        let stats = engine.get_statistics();
        assert!(stats.total_alerts_generated >= 1);

        let alerts = engine.get_alerts();
        assert!(!alerts.is_empty());
        assert!(
            alerts
                .iter()
                .any(|a| a.pattern == AttackPattern::CoordinatedMultiSource)
        );
    }

    #[test]
    fn test_targeted_attack_detection() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());

        // Simulate targeted attack on single CAN ID
        for i in 0..6 {
            engine.process_event(
                ValidationError::UnauthorizedAccess,
                &format!("SOURCE{}", i),
                Some(0x300), // Same CAN ID
                IncidentSeverity::High,
            );
        }

        let stats = engine.get_statistics();
        assert_eq!(stats.total_events_processed, 6);
    }

    #[test]
    fn test_replay_attack_correlation() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());

        // Simulate replay attacks across multiple ECUs
        for i in 0..4 {
            let source = format!("ECU_{}", i % 2);
            engine.process_event(
                ValidationError::ReplayDetected,
                &source,
                Some(0x100 + i as u32),
                IncidentSeverity::High,
            );
        }

        let stats = engine.get_statistics();
        assert_eq!(stats.total_events_processed, 4);
    }

    #[test]
    fn test_old_events_cleanup() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());

        // Add old event (simulated)
        let old_event = SecurityEventRecord {
            timestamp: Utc::now() - Duration::seconds(200),
            ecu_name: "TEST_ECU".to_string(),
            target_ecu: Some("SOURCE1".to_string()),
            can_id: Some(0x300),
            event_type: "MAC Mismatch".to_string(),
            severity: IncidentSeverity::Medium,
            context: "Test event".to_string(),
        };

        engine.add_event(old_event);
        engine.clean_old_events();

        // Old event should be removed
        let stats = engine.get_statistics();
        assert_eq!(stats.current_buffer_size, 0);
    }

    #[test]
    fn test_buffer_size_limit() {
        let mut engine = CorrelationEngine::new("TEST_ECU".to_string());
        engine.max_buffer_size = 10;

        // Add more events than buffer size
        for i in 0..20 {
            engine.process_event(
                ValidationError::CrcMismatch,
                "SOURCE",
                Some(i as u32),
                IncidentSeverity::Low,
            );
        }

        let stats = engine.get_statistics();
        assert!(stats.current_buffer_size <= 10);
        assert_eq!(stats.total_events_processed, 20);
    }
}
