/// ISO 21434 Automated Incident Response System
///
/// Provides automated incident detection, classification, and response procedures
/// to ensure rapid recovery from security incidents while maintaining safety.
///
/// Key ISO 21434 requirements addressed:
/// - 8.6: Incident response and recovery
/// - 9.4.3: Automated incident handling
/// - 10.4: Security monitoring and incident management
use crate::error_handling::{SecurityState, ValidationError};
use crate::security_log::SecurityLogger;
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Incident severity levels (ISO 21434 severity classification)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Low severity - minor anomaly, no safety impact
    Low = 1,
    /// Medium severity - security concern, limited safety impact
    Medium = 2,
    /// High severity - active attack, potential safety impact
    High = 3,
    /// Critical severity - confirmed attack, immediate safety risk
    Critical = 4,
}

impl fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncidentSeverity::Low => write!(f, "{}", "LOW".cyan()),
            IncidentSeverity::Medium => write!(f, "{}", "MEDIUM".yellow()),
            IncidentSeverity::High => write!(f, "{}", "HIGH".bright_red()),
            IncidentSeverity::Critical => write!(f, "{}", "CRITICAL".red().bold()),
        }
    }
}

/// Incident categories (ISO 21434 incident classification)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IncidentCategory {
    /// Data corruption or integrity violation
    IntegrityViolation,
    /// Authentication or authorization failure
    AuthenticationFailure,
    /// Replay attack or anti-replay violation
    ReplayAttack,
    /// Injection of unauthorized frames
    FrameInjection,
    /// Behavioral anomaly or IDS detection
    BehavioralAnomaly,
    /// Access control violation
    AccessControlViolation,
    /// Denial of service or flooding
    DenialOfService,
    /// Multiple coordinated attack indicators
    CoordinatedAttack,
}

impl fmt::Display for IncidentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncidentCategory::IntegrityViolation => write!(f, "Integrity Violation"),
            IncidentCategory::AuthenticationFailure => write!(f, "Authentication Failure"),
            IncidentCategory::ReplayAttack => write!(f, "Replay Attack"),
            IncidentCategory::FrameInjection => write!(f, "Frame Injection"),
            IncidentCategory::BehavioralAnomaly => write!(f, "Behavioral Anomaly"),
            IncidentCategory::AccessControlViolation => write!(f, "Access Control Violation"),
            IncidentCategory::DenialOfService => write!(f, "Denial of Service"),
            IncidentCategory::CoordinatedAttack => write!(f, "Coordinated Attack"),
        }
    }
}

/// Automated response actions (ISO 21434 response procedures)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Log the incident for forensic analysis
    LogIncident,
    /// Alert operator/monitoring system
    AlertOperator,
    /// Enter fail-safe mode (maintain last known safe state)
    EnterFailSafe,
    /// Isolate affected ECU (block communications)
    IsolateEcu,
    /// Request key rotation to re-establish trust
    RequestKeyRotation,
    /// Initiate secure restart of ECU
    SecureRestart,
    /// Activate backup/redundant system
    ActivateBackup,
    /// Throttle communication rate (mitigate DoS)
    ThrottleCommunication,
    /// Reset replay protection state
    ResetReplayProtection,
    /// Escalate to higher severity if attacks persist
    EscalateIncident,
}

impl fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseAction::LogIncident => write!(f, "Log Incident"),
            ResponseAction::AlertOperator => write!(f, "Alert Operator"),
            ResponseAction::EnterFailSafe => write!(f, "Enter Fail-Safe Mode"),
            ResponseAction::IsolateEcu => write!(f, "Isolate ECU"),
            ResponseAction::RequestKeyRotation => write!(f, "Request Key Rotation"),
            ResponseAction::SecureRestart => write!(f, "Secure Restart"),
            ResponseAction::ActivateBackup => write!(f, "Activate Backup System"),
            ResponseAction::ThrottleCommunication => write!(f, "Throttle Communication"),
            ResponseAction::ResetReplayProtection => write!(f, "Reset Replay Protection"),
            ResponseAction::EscalateIncident => write!(f, "Escalate Incident"),
        }
    }
}

/// Security incident record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    /// Unique incident identifier
    pub incident_id: String,
    /// Time of incident detection
    pub timestamp: DateTime<Utc>,
    /// ECU where incident was detected
    pub ecu_name: String,
    /// Incident category
    pub category: IncidentCategory,
    /// Incident severity
    pub severity: IncidentSeverity,
    /// Source of attack (if known)
    pub attack_source: Option<String>,
    /// Detailed description
    pub description: String,
    /// CAN ID involved (if applicable)
    pub can_id: Option<u32>,
    /// Validation error that triggered incident
    pub error_type: Option<String>,
    /// Response actions taken
    pub response_actions: Vec<ResponseAction>,
    /// Whether incident is resolved
    pub resolved: bool,
    /// Resolution timestamp
    pub resolution_timestamp: Option<DateTime<Utc>>,
    /// Resolution notes
    pub resolution_notes: Option<String>,
}

/// Incident response manager
pub struct IncidentResponseManager {
    /// ECU identifier
    ecu_name: String,
    /// Active incidents (incident_id -> incident)
    active_incidents: HashMap<String, SecurityIncident>,
    /// Resolved incidents history
    incident_history: Vec<SecurityIncident>,
    /// Incident counter for ID generation
    incident_counter: u64,
    /// Security event logger
    security_logger: Option<SecurityLogger>,
    /// Incident escalation timeout (seconds)
    escalation_timeout_secs: u64,
}

impl IncidentResponseManager {
    /// Create new incident response manager
    pub fn new(ecu_name: String) -> Self {
        Self {
            ecu_name,
            active_incidents: HashMap::new(),
            incident_history: Vec::new(),
            incident_counter: 0,
            security_logger: None,
            escalation_timeout_secs: 30, // Escalate after 30 seconds of unresolved incident
        }
    }

    /// Create new incident response manager with security logging
    pub fn with_logger(ecu_name: String, logger: SecurityLogger) -> Self {
        Self {
            ecu_name,
            active_incidents: HashMap::new(),
            incident_history: Vec::new(),
            incident_counter: 0,
            security_logger: Some(logger),
            escalation_timeout_secs: 30,
        }
    }

    /// Report a security incident and trigger automated response
    pub fn report_incident(
        &mut self,
        error: ValidationError,
        source: Option<String>,
        can_id: Option<u32>,
        security_state: SecurityState,
    ) -> Vec<ResponseAction> {
        // Classify the incident
        let (category, severity) = self.classify_incident(&error, security_state);

        // Generate incident ID
        self.incident_counter += 1;
        let incident_id = format!("{}-INC-{:06}", self.ecu_name, self.incident_counter);

        // Create incident record
        let incident = SecurityIncident {
            incident_id: incident_id.clone(),
            timestamp: Utc::now(),
            ecu_name: self.ecu_name.clone(),
            category: category.clone(),
            severity,
            attack_source: source.clone(),
            description: self.generate_description(&error, source.as_deref()),
            can_id,
            error_type: Some(error.to_string()),
            response_actions: Vec::new(),
            resolved: false,
            resolution_timestamp: None,
            resolution_notes: None,
        };

        // Determine appropriate response actions
        let actions = self.determine_response_actions(&category, severity, security_state);

        println!();
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "   INCIDENT RESPONSE ACTIVATED        "
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!();
        println!(
            "{} Incident ID: {}",
            "→".cyan(),
            incident_id.bright_white().bold()
        );
        println!("{} ECU: {}", "→".cyan(), self.ecu_name.yellow());
        println!("{} Category: {}", "→".cyan(), category);
        println!("{} Severity: {}", "→".cyan(), severity);
        if let Some(ref src) = source {
            println!("{} Attack Source: {}", "→".cyan(), src.red());
        }
        println!("{} Description: {}", "→".cyan(), incident.description);
        println!();
        println!(
            "{} {}",
            "→".cyan(),
            "AUTOMATED RESPONSE ACTIONS:".bright_white().bold()
        );
        for (idx, action) in actions.iter().enumerate() {
            println!("   {}. {}", idx + 1, action);
        }
        println!();
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!();

        // Log incident
        if let Some(ref logger) = self.security_logger {
            logger.log_event(crate::security_log::SecurityEvent::Custom {
                message: format!(
                    "INCIDENT REPORTED: {} - {} - Severity: {:?}",
                    incident_id, category, severity
                ),
            });
        }

        // Store incident
        let mut final_incident = incident;
        final_incident.response_actions = actions.clone();
        self.active_incidents.insert(incident_id, final_incident);

        actions
    }

    /// Classify incident based on validation error and security state
    fn classify_incident(
        &self,
        error: &ValidationError,
        security_state: SecurityState,
    ) -> (IncidentCategory, IncidentSeverity) {
        match error {
            ValidationError::CrcMismatch => {
                let severity = match security_state {
                    SecurityState::Normal => IncidentSeverity::Low,
                    SecurityState::Warning => IncidentSeverity::Medium,
                    SecurityState::UnderAttack => IncidentSeverity::High,
                };
                (IncidentCategory::IntegrityViolation, severity)
            }
            ValidationError::MacMismatch => {
                let severity = match security_state {
                    SecurityState::Normal => IncidentSeverity::Medium,
                    SecurityState::Warning => IncidentSeverity::High,
                    SecurityState::UnderAttack => IncidentSeverity::Critical,
                };
                (IncidentCategory::AuthenticationFailure, severity)
            }
            ValidationError::UnsecuredFrame => {
                (IncidentCategory::FrameInjection, IncidentSeverity::Critical)
            }
            ValidationError::ReplayDetected => {
                (IncidentCategory::ReplayAttack, IncidentSeverity::High)
            }
            ValidationError::UnauthorizedAccess => (
                IncidentCategory::AccessControlViolation,
                IncidentSeverity::Critical,
            ),
            ValidationError::AnomalyDetected(_) => {
                let severity = match security_state {
                    SecurityState::Normal => IncidentSeverity::Medium,
                    SecurityState::Warning => IncidentSeverity::High,
                    SecurityState::UnderAttack => IncidentSeverity::Critical,
                };
                (IncidentCategory::BehavioralAnomaly, severity)
            }
        }
    }

    /// Determine appropriate response actions based on incident classification
    fn determine_response_actions(
        &self,
        category: &IncidentCategory,
        severity: IncidentSeverity,
        security_state: SecurityState,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        // All incidents are logged
        actions.push(ResponseAction::LogIncident);

        // Determine actions based on severity
        match severity {
            IncidentSeverity::Low => {
                // Low severity: log only
            }
            IncidentSeverity::Medium => {
                // Medium severity: alert operator
                actions.push(ResponseAction::AlertOperator);
            }
            IncidentSeverity::High => {
                // High severity: alert and fail-safe
                actions.push(ResponseAction::AlertOperator);
                actions.push(ResponseAction::EnterFailSafe);
            }
            IncidentSeverity::Critical => {
                // Critical severity: full protective measures
                actions.push(ResponseAction::AlertOperator);
                actions.push(ResponseAction::EnterFailSafe);

                // Category-specific responses
                match category {
                    IncidentCategory::FrameInjection => {
                        actions.push(ResponseAction::IsolateEcu);
                    }
                    IncidentCategory::AuthenticationFailure => {
                        actions.push(ResponseAction::RequestKeyRotation);
                    }
                    IncidentCategory::ReplayAttack => {
                        actions.push(ResponseAction::ResetReplayProtection);
                        actions.push(ResponseAction::RequestKeyRotation);
                    }
                    IncidentCategory::AccessControlViolation => {
                        actions.push(ResponseAction::IsolateEcu);
                    }
                    IncidentCategory::DenialOfService => {
                        actions.push(ResponseAction::ThrottleCommunication);
                    }
                    IncidentCategory::CoordinatedAttack => {
                        actions.push(ResponseAction::IsolateEcu);
                        actions.push(ResponseAction::SecureRestart);
                    }
                    _ => {}
                }
            }
        }

        // If already under attack, escalate
        if security_state == SecurityState::UnderAttack && severity < IncidentSeverity::Critical {
            actions.push(ResponseAction::EscalateIncident);
        }

        actions
    }

    /// Generate human-readable incident description
    fn generate_description(&self, error: &ValidationError, source: Option<&str>) -> String {
        let source_str = source.unwrap_or("UNKNOWN");

        match error {
            ValidationError::CrcMismatch => {
                format!("CRC validation failed for frame from {}", source_str)
            }
            ValidationError::MacMismatch => {
                format!("MAC authentication failed for frame from {}", source_str)
            }
            ValidationError::UnsecuredFrame => {
                format!("Unsecured frame (no MAC) received from {}", source_str)
            }
            ValidationError::ReplayDetected => {
                format!("Replay attack detected from {}", source_str)
            }
            ValidationError::UnauthorizedAccess => {
                format!("Unauthorized CAN ID access attempted by {}", source_str)
            }
            ValidationError::AnomalyDetected(desc) => {
                format!("Behavioral anomaly detected: {}", desc)
            }
        }
    }

    /// Resolve an incident
    pub fn resolve_incident(&mut self, incident_id: &str, notes: String) {
        if let Some(mut incident) = self.active_incidents.remove(incident_id) {
            incident.resolved = true;
            incident.resolution_timestamp = Some(Utc::now());
            incident.resolution_notes = Some(notes.clone());

            println!();
            println!(
                "{} Incident {} {}",
                "✓".green(),
                incident_id.bright_white().bold(),
                "RESOLVED".green().bold()
            );
            println!("{} Resolution: {}", "→".green(), notes);
            println!();

            // Log resolution
            if let Some(ref logger) = self.security_logger {
                logger.log_event(crate::security_log::SecurityEvent::Custom {
                    message: format!("INCIDENT RESOLVED: {} - {}", incident_id, notes),
                });
            }

            self.incident_history.push(incident);
        }
    }

    /// Check for incidents requiring escalation
    pub fn check_escalations(&mut self) -> Vec<String> {
        let now = Utc::now();
        let mut escalated = Vec::new();

        for (incident_id, incident) in self.active_incidents.iter_mut() {
            let elapsed = (now - incident.timestamp).num_seconds() as u64;

            if elapsed > self.escalation_timeout_secs
                && incident.severity < IncidentSeverity::Critical
            {
                // Escalate incident
                let old_severity = incident.severity;
                incident.severity = match incident.severity {
                    IncidentSeverity::Low => IncidentSeverity::Medium,
                    IncidentSeverity::Medium => IncidentSeverity::High,
                    IncidentSeverity::High => IncidentSeverity::Critical,
                    IncidentSeverity::Critical => IncidentSeverity::Critical,
                };

                println!();
                println!(
                    "{} Incident {} escalated from {} to {}",
                    "⚠".yellow(),
                    incident_id.bright_white().bold(),
                    old_severity,
                    incident.severity
                );
                println!();

                escalated.push(incident_id.clone());
            }
        }

        escalated
    }

    /// Get active incident count
    pub fn active_incident_count(&self) -> usize {
        self.active_incidents.len()
    }

    /// Get incident history count
    pub fn incident_history_count(&self) -> usize {
        self.incident_history.len()
    }

    /// Get incident statistics
    pub fn get_statistics(&self) -> IncidentStatistics {
        let mut stats = IncidentStatistics {
            total_incidents: self.active_incidents.len() + self.incident_history.len(),
            active_incidents: self.active_incidents.len(),
            resolved_incidents: self.incident_history.len(),
            incidents_by_severity: HashMap::new(),
            incidents_by_category: HashMap::new(),
        };

        // Count by severity and category
        for incident in self
            .active_incidents
            .values()
            .chain(self.incident_history.iter())
        {
            *stats
                .incidents_by_severity
                .entry(incident.severity)
                .or_insert(0) += 1;
            *stats
                .incidents_by_category
                .entry(incident.category.clone())
                .or_insert(0) += 1;
        }

        stats
    }

    /// Export incident report (for forensic analysis)
    pub fn export_incident_report(&self) -> String {
        let mut report = String::new();
        report.push_str("═══════════════════════════════════════════════════════════\n");
        report.push_str("               SECURITY INCIDENT REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════\n\n");

        report.push_str(&format!("ECU: {}\n", self.ecu_name));
        report.push_str(&format!("Report Generated: {}\n\n", Utc::now()));

        report.push_str(&format!(
            "Active Incidents: {}\n",
            self.active_incidents.len()
        ));
        report.push_str(&format!(
            "Resolved Incidents: {}\n\n",
            self.incident_history.len()
        ));

        if !self.active_incidents.is_empty() {
            report.push_str("───────────────────────────────────────────────────────────\n");
            report.push_str("ACTIVE INCIDENTS\n");
            report.push_str("───────────────────────────────────────────────────────────\n\n");

            for incident in self.active_incidents.values() {
                report.push_str(&self.format_incident(incident));
                report.push_str("\n");
            }
        }

        if !self.incident_history.is_empty() {
            report.push_str("───────────────────────────────────────────────────────────\n");
            report.push_str("RESOLVED INCIDENTS\n");
            report.push_str("───────────────────────────────────────────────────────────\n\n");

            for incident in self.incident_history.iter() {
                report.push_str(&self.format_incident(incident));
                report.push_str("\n");
            }
        }

        report.push_str("═══════════════════════════════════════════════════════════\n");

        report
    }

    /// Format incident for report
    fn format_incident(&self, incident: &SecurityIncident) -> String {
        let mut output = String::new();

        output.push_str(&format!("Incident ID: {}\n", incident.incident_id));
        output.push_str(&format!("Timestamp: {}\n", incident.timestamp));
        output.push_str(&format!("Category: {}\n", incident.category));
        output.push_str(&format!("Severity: {:?}\n", incident.severity));
        output.push_str(&format!("Description: {}\n", incident.description));

        if let Some(ref source) = incident.attack_source {
            output.push_str(&format!("Attack Source: {}\n", source));
        }

        if let Some(can_id) = incident.can_id {
            output.push_str(&format!("CAN ID: 0x{:03X}\n", can_id));
        }

        output.push_str("Response Actions:\n");
        for action in &incident.response_actions {
            output.push_str(&format!("  - {}\n", action));
        }

        if incident.resolved {
            output.push_str(&format!("Status: RESOLVED\n"));
            if let Some(ref ts) = incident.resolution_timestamp {
                output.push_str(&format!("Resolution Time: {}\n", ts));
            }
            if let Some(ref notes) = incident.resolution_notes {
                output.push_str(&format!("Resolution Notes: {}\n", notes));
            }
        } else {
            output.push_str("Status: ACTIVE\n");
        }

        output.push_str("\n");
        output
    }
}

/// Incident statistics
#[derive(Debug, Clone)]
pub struct IncidentStatistics {
    pub total_incidents: usize,
    pub active_incidents: usize,
    pub resolved_incidents: usize,
    pub incidents_by_severity: HashMap<IncidentSeverity, usize>,
    pub incidents_by_category: HashMap<IncidentCategory, usize>,
}

impl fmt::Display for IncidentStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Total Incidents: {}", self.total_incidents)?;
        writeln!(
            f,
            "Active: {} | Resolved: {}",
            self.active_incidents, self.resolved_incidents
        )?;
        writeln!(f, "\nBy Severity:")?;
        for (severity, count) in &self.incidents_by_severity {
            writeln!(f, "  {:?}: {}", severity, count)?;
        }
        writeln!(f, "\nBy Category:")?;
        for (category, count) in &self.incidents_by_category {
            writeln!(f, "  {}: {}", category, count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_classification_crc_error() {
        let manager = IncidentResponseManager::new("TEST_ECU".to_string());

        let (category, severity) =
            manager.classify_incident(&ValidationError::CrcMismatch, SecurityState::Normal);

        assert_eq!(category, IncidentCategory::IntegrityViolation);
        assert_eq!(severity, IncidentSeverity::Low);
    }

    #[test]
    fn test_incident_classification_mac_error_escalation() {
        let manager = IncidentResponseManager::new("TEST_ECU".to_string());

        // Normal state: Medium severity
        let (_, severity1) =
            manager.classify_incident(&ValidationError::MacMismatch, SecurityState::Normal);
        assert_eq!(severity1, IncidentSeverity::Medium);

        // Warning state: High severity
        let (_, severity2) =
            manager.classify_incident(&ValidationError::MacMismatch, SecurityState::Warning);
        assert_eq!(severity2, IncidentSeverity::High);

        // Under attack: Critical severity
        let (_, severity3) =
            manager.classify_incident(&ValidationError::MacMismatch, SecurityState::UnderAttack);
        assert_eq!(severity3, IncidentSeverity::Critical);
    }

    #[test]
    fn test_incident_classification_unsecured_frame() {
        let manager = IncidentResponseManager::new("TEST_ECU".to_string());

        let (category, severity) =
            manager.classify_incident(&ValidationError::UnsecuredFrame, SecurityState::Normal);

        assert_eq!(category, IncidentCategory::FrameInjection);
        assert_eq!(severity, IncidentSeverity::Critical);
    }

    #[test]
    fn test_response_actions_low_severity() {
        let manager = IncidentResponseManager::new("TEST_ECU".to_string());

        let actions = manager.determine_response_actions(
            &IncidentCategory::IntegrityViolation,
            IncidentSeverity::Low,
            SecurityState::Normal,
        );

        // Low severity should only log
        assert_eq!(actions.len(), 1);
        assert!(actions.contains(&ResponseAction::LogIncident));
    }

    #[test]
    fn test_response_actions_critical_severity() {
        let manager = IncidentResponseManager::new("TEST_ECU".to_string());

        let actions = manager.determine_response_actions(
            &IncidentCategory::FrameInjection,
            IncidentSeverity::Critical,
            SecurityState::UnderAttack,
        );

        // Critical severity should have multiple actions
        assert!(actions.len() >= 3);
        assert!(actions.contains(&ResponseAction::LogIncident));
        assert!(actions.contains(&ResponseAction::AlertOperator));
        assert!(actions.contains(&ResponseAction::EnterFailSafe));
        assert!(actions.contains(&ResponseAction::IsolateEcu));
    }

    #[test]
    fn test_incident_reporting() {
        let mut manager = IncidentResponseManager::new("TEST_ECU".to_string());

        let actions = manager.report_incident(
            ValidationError::MacMismatch,
            Some("ATTACKER_ECU".to_string()),
            Some(0x300),
            SecurityState::Warning,
        );

        // Should return response actions
        assert!(!actions.is_empty());

        // Should have one active incident
        assert_eq!(manager.active_incident_count(), 1);
        assert_eq!(manager.incident_history_count(), 0);
    }

    #[test]
    fn test_incident_resolution() {
        let mut manager = IncidentResponseManager::new("TEST_ECU".to_string());

        // Report incident
        manager.report_incident(
            ValidationError::CrcMismatch,
            Some("SOURCE_ECU".to_string()),
            None,
            SecurityState::Normal,
        );

        let incident_id = format!("{}-INC-{:06}", "TEST_ECU", 1);

        // Resolve incident
        manager.resolve_incident(&incident_id, "Transient error resolved".to_string());

        // Should move to history
        assert_eq!(manager.active_incident_count(), 0);
        assert_eq!(manager.incident_history_count(), 1);
    }

    #[test]
    fn test_incident_statistics() {
        let mut manager = IncidentResponseManager::new("TEST_ECU".to_string());

        // Report multiple incidents
        manager.report_incident(
            ValidationError::CrcMismatch,
            None,
            None,
            SecurityState::Normal,
        );
        manager.report_incident(
            ValidationError::MacMismatch,
            None,
            None,
            SecurityState::Warning,
        );
        manager.report_incident(
            ValidationError::UnsecuredFrame,
            None,
            None,
            SecurityState::UnderAttack,
        );

        let stats = manager.get_statistics();

        assert_eq!(stats.total_incidents, 3);
        assert_eq!(stats.active_incidents, 3);
        assert!(
            stats
                .incidents_by_severity
                .get(&IncidentSeverity::Low)
                .is_some()
        );
        assert!(
            stats
                .incidents_by_category
                .get(&IncidentCategory::FrameInjection)
                .is_some()
        );
    }
}
