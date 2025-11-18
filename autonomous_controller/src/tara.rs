/// ISO 21434 TARA (Threat Analysis and Risk Assessment) Documentation Generator
///
/// Generates comprehensive threat analysis and risk assessment documentation
/// for automotive cybersecurity compliance.
///
/// Key ISO 21434 requirements addressed:
/// - 8.4: Threat analysis and risk assessment
/// - 8.4.1: Asset identification
/// - 8.4.2: Threat scenario identification
/// - 8.4.3: Impact rating
/// - 8.4.4: Attack path analysis
/// - 8.4.5: Risk determination
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Asset types in the vehicle system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// CAN bus communication channel
    CanBus,
    /// Electronic Control Unit
    Ecu(String),
    /// Cryptographic keys
    CryptographicKeys,
    /// Firmware/software
    Firmware,
    /// Vehicle control functions
    ControlFunction(String),
    /// Safety-critical functions
    SafetyCriticalFunction(String),
    /// User data/privacy
    UserData,
}

impl fmt::Display for AssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetType::CanBus => write!(f, "CAN Bus"),
            AssetType::Ecu(name) => write!(f, "ECU: {}", name),
            AssetType::CryptographicKeys => write!(f, "Cryptographic Keys"),
            AssetType::Firmware => write!(f, "Firmware"),
            AssetType::ControlFunction(name) => write!(f, "Control Function: {}", name),
            AssetType::SafetyCriticalFunction(name) => {
                write!(f, "Safety-Critical Function: {}", name)
            }
            AssetType::UserData => write!(f, "User Data"),
        }
    }
}

/// Threat types (STRIDE model adapted for automotive)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    /// Spoofing (impersonation)
    Spoofing,
    /// Tampering (data modification)
    Tampering,
    /// Repudiation (denial of actions)
    Repudiation,
    /// Information disclosure
    InformationDisclosure,
    /// Denial of service
    DenialOfService,
    /// Elevation of privilege
    ElevationOfPrivilege,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatType::Spoofing => write!(f, "Spoofing"),
            ThreatType::Tampering => write!(f, "Tampering"),
            ThreatType::Repudiation => write!(f, "Repudiation"),
            ThreatType::InformationDisclosure => write!(f, "Information Disclosure"),
            ThreatType::DenialOfService => write!(f, "Denial of Service"),
            ThreatType::ElevationOfPrivilege => write!(f, "Elevation of Privilege"),
        }
    }
}

/// CIA impact rating (Confidentiality, Integrity, Availability)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ImpactLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImpactLevel::None => write!(f, "None"),
            ImpactLevel::Low => write!(f, "Low"),
            ImpactLevel::Medium => write!(f, "Medium"),
            ImpactLevel::High => write!(f, "High"),
            ImpactLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Attack feasibility rating (ISO 21434)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeasibilityLevel {
    VeryLow = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    VeryHigh = 4,
}

impl fmt::Display for FeasibilityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeasibilityLevel::VeryLow => write!(f, "Very Low"),
            FeasibilityLevel::Low => write!(f, "Low"),
            FeasibilityLevel::Medium => write!(f, "Medium"),
            FeasibilityLevel::High => write!(f, "High"),
            FeasibilityLevel::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// Risk level (ISO 21434 risk matrix)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    VeryLow = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    VeryHigh = 4,
}

impl RiskLevel {
    /// Calculate risk level from impact and feasibility
    pub fn calculate(impact: ImpactLevel, feasibility: FeasibilityLevel) -> Self {
        // ISO 21434 risk matrix: Risk = f(Impact, Feasibility)
        let risk_score = (impact as u8 + feasibility as u8) / 2;

        match risk_score {
            0 => RiskLevel::VeryLow,
            1 => RiskLevel::Low,
            2 => RiskLevel::Medium,
            3 => RiskLevel::High,
            _ => RiskLevel::VeryHigh,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::VeryLow => write!(f, "{}", "VERY LOW".green()),
            RiskLevel::Low => write!(f, "{}", "LOW".cyan()),
            RiskLevel::Medium => write!(f, "{}", "MEDIUM".yellow()),
            RiskLevel::High => write!(f, "{}", "HIGH".bright_red()),
            RiskLevel::VeryHigh => write!(f, "{}", "VERY HIGH".red().bold()),
        }
    }
}

/// Threat scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScenario {
    /// Unique threat identifier
    pub threat_id: String,
    /// Threat name/title
    pub name: String,
    /// Threat description
    pub description: String,
    /// Asset being threatened
    pub asset: AssetType,
    /// Threat type (STRIDE)
    pub threat_type: ThreatType,
    /// Attack vector/entry point
    pub attack_vector: String,
    /// Attacker profile (expertise, resources, motivation)
    pub attacker_profile: String,
    /// Confidentiality impact
    pub confidentiality_impact: ImpactLevel,
    /// Integrity impact
    pub integrity_impact: ImpactLevel,
    /// Availability impact
    pub availability_impact: ImpactLevel,
    /// Safety impact
    pub safety_impact: ImpactLevel,
    /// Financial impact
    pub financial_impact: ImpactLevel,
    /// Operational impact
    pub operational_impact: ImpactLevel,
    /// Attack feasibility
    pub feasibility: FeasibilityLevel,
    /// Calculated risk level
    pub risk_level: RiskLevel,
    /// Existing security controls
    pub existing_controls: Vec<String>,
    /// Recommended mitigations
    pub recommended_mitigations: Vec<String>,
    /// Residual risk after mitigation
    pub residual_risk: Option<RiskLevel>,
}

impl ThreatScenario {
    /// Calculate overall impact (maximum of all impact types)
    pub fn overall_impact(&self) -> ImpactLevel {
        *[
            self.confidentiality_impact,
            self.integrity_impact,
            self.availability_impact,
            self.safety_impact,
            self.financial_impact,
            self.operational_impact,
        ]
        .iter()
        .max()
        .unwrap_or(&ImpactLevel::None)
    }
}

/// TARA analysis document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaraAnalysis {
    /// Analysis metadata
    pub generated_at: DateTime<Utc>,
    pub system_name: String,
    pub system_version: String,
    pub analyst_name: String,
    pub organization: String,

    /// Assets identified
    pub assets: Vec<AssetType>,

    /// Threat scenarios
    pub threats: Vec<ThreatScenario>,

    /// Risk summary
    pub risk_summary: RiskSummary,
}

/// Risk summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub total_threats: usize,
    pub threats_by_risk_level: HashMap<String, usize>,
    pub threats_by_type: HashMap<String, usize>,
    pub threats_by_asset: HashMap<String, usize>,
    pub high_risk_count: usize,
    pub medium_risk_count: usize,
    pub low_risk_count: usize,
}

/// TARA generator
pub struct TaraGenerator {
    system_name: String,
    system_version: String,
    analyst_name: String,
    organization: String,
    assets: Vec<AssetType>,
    threats: Vec<ThreatScenario>,
}

impl TaraGenerator {
    /// Create new TARA generator
    pub fn new(
        system_name: String,
        system_version: String,
        analyst_name: String,
        organization: String,
    ) -> Self {
        Self {
            system_name,
            system_version,
            analyst_name,
            organization,
            assets: Vec::new(),
            threats: Vec::new(),
        }
    }

    /// Add asset to analysis
    pub fn add_asset(&mut self, asset: AssetType) {
        if !self.assets.contains(&asset) {
            self.assets.push(asset);
        }
    }

    /// Add threat scenario
    pub fn add_threat(&mut self, threat: ThreatScenario) {
        self.threats.push(threat);
    }

    /// Generate automotive V-HSM threat scenarios
    pub fn generate_automotive_threats(&mut self) {
        // Define automotive-specific assets
        self.add_asset(AssetType::CanBus);
        self.add_asset(AssetType::CryptographicKeys);
        self.add_asset(AssetType::Firmware);
        self.add_asset(AssetType::Ecu("Autonomous Controller".to_string()));
        self.add_asset(AssetType::Ecu("Brake Controller".to_string()));
        self.add_asset(AssetType::Ecu("Steering Controller".to_string()));
        self.add_asset(AssetType::SafetyCriticalFunction(
            "Autonomous Braking".to_string(),
        ));
        self.add_asset(AssetType::SafetyCriticalFunction(
            "Steering Control".to_string(),
        ));

        // Threat 1: CAN Bus Injection Attack
        self.add_threat(ThreatScenario {
            threat_id: "T-001".to_string(),
            name: "Unauthorized CAN Frame Injection".to_string(),
            description:
                "Attacker injects malicious CAN frames onto the bus without valid authentication, \
                          potentially sending unauthorized commands to safety-critical ECUs."
                    .to_string(),
            asset: AssetType::CanBus,
            threat_type: ThreatType::Spoofing,
            attack_vector:
                "Physical access to CAN bus (OBD-II port, spliced wires) or compromised ECU"
                    .to_string(),
            attacker_profile: "Medium expertise, physical access, motivated by theft/sabotage"
                .to_string(),
            confidentiality_impact: ImpactLevel::Low,
            integrity_impact: ImpactLevel::Critical,
            availability_impact: ImpactLevel::Medium,
            safety_impact: ImpactLevel::Critical,
            financial_impact: ImpactLevel::High,
            operational_impact: ImpactLevel::High,
            feasibility: FeasibilityLevel::Medium,
            risk_level: RiskLevel::VeryHigh,
            existing_controls: vec![
                "MAC authentication (HMAC-SHA256)".to_string(),
                "CRC integrity checking".to_string(),
                "Attack detector with threshold-based detection".to_string(),
            ],
            recommended_mitigations: vec![
                "Maintain MAC authentication on all frames".to_string(),
                "Physical tamper detection on OBD-II port".to_string(),
                "Network segmentation for safety-critical buses".to_string(),
            ],
            residual_risk: Some(RiskLevel::Low),
        });

        // Threat 2: Replay Attack
        self.add_threat(ThreatScenario {
            threat_id: "T-002".to_string(),
            name: "CAN Frame Replay Attack".to_string(),
            description:
                "Attacker captures legitimate CAN frames and replays them to trigger unintended \
                          vehicle behavior or bypass authentication."
                    .to_string(),
            asset: AssetType::CanBus,
            threat_type: ThreatType::Tampering,
            attack_vector: "Network sniffing followed by frame retransmission".to_string(),
            attacker_profile:
                "Medium expertise, physical or wireless access, motivated by vehicle theft"
                    .to_string(),
            confidentiality_impact: ImpactLevel::Low,
            integrity_impact: ImpactLevel::High,
            availability_impact: ImpactLevel::Low,
            safety_impact: ImpactLevel::High,
            financial_impact: ImpactLevel::High,
            operational_impact: ImpactLevel::Medium,
            feasibility: FeasibilityLevel::High,
            risk_level: RiskLevel::High,
            existing_controls: vec![
                "Session counter for replay protection".to_string(),
                "Sliding window for out-of-order delivery tolerance".to_string(),
                "Timestamp validation".to_string(),
            ],
            recommended_mitigations: vec![
                "Strict monotonic counter mode for critical functions".to_string(),
                "Reduce replay window size for safety-critical messages".to_string(),
                "Implement challenge-response for high-value operations".to_string(),
            ],
            residual_risk: Some(RiskLevel::Low),
        });

        // Threat 3: Malicious Firmware Update
        self.add_threat(ThreatScenario {
            threat_id: "T-003".to_string(),
            name: "Malicious Firmware Installation".to_string(),
            description: "Attacker installs modified or malicious firmware to gain persistent control \
                          over ECU functionality.".to_string(),
            asset: AssetType::Firmware,
            threat_type: ThreatType::ElevationOfPrivilege,
            attack_vector: "Compromised update server, physical access to debug interface, supply chain attack".to_string(),
            attacker_profile: "High expertise, significant resources, motivated by espionage/sabotage".to_string(),
            confidentiality_impact: ImpactLevel::Critical,
            integrity_impact: ImpactLevel::Critical,
            availability_impact: ImpactLevel::High,
            safety_impact: ImpactLevel::Critical,
            financial_impact: ImpactLevel::Critical,
            operational_impact: ImpactLevel::Critical,
            feasibility: FeasibilityLevel::Low,
            risk_level: RiskLevel::High,
            existing_controls: vec![
                "Firmware signature verification (HMAC-SHA256)".to_string(),
                "Secure boot process".to_string(),
                "Firmware fingerprint validation".to_string(),
                "Automatic rollback on boot failure".to_string(),
            ],
            recommended_mitigations: vec![
                "Hardware-backed secure boot".to_string(),
                "Firmware update authentication with code signing certificates".to_string(),
                "Version rollback prevention".to_string(),
                "Attestation and integrity monitoring".to_string(),
            ],
            residual_risk: Some(RiskLevel::Low),
        });

        // Threat 4: Cryptographic Key Compromise
        self.add_threat(ThreatScenario {
            threat_id: "T-004".to_string(),
            name: "HSM Cryptographic Key Extraction".to_string(),
            description:
                "Attacker extracts cryptographic keys from HSM, enabling full compromise of \
                          security mechanisms."
                    .to_string(),
            asset: AssetType::CryptographicKeys,
            threat_type: ThreatType::InformationDisclosure,
            attack_vector: "Side-channel attacks, memory dumping, physical HSM extraction"
                .to_string(),
            attacker_profile:
                "Very high expertise, specialized equipment, motivated by organized crime"
                    .to_string(),
            confidentiality_impact: ImpactLevel::Critical,
            integrity_impact: ImpactLevel::Critical,
            availability_impact: ImpactLevel::Low,
            safety_impact: ImpactLevel::Critical,
            financial_impact: ImpactLevel::Critical,
            operational_impact: ImpactLevel::Critical,
            feasibility: FeasibilityLevel::VeryLow,
            risk_level: RiskLevel::Medium,
            existing_controls: vec![
                "Key storage in simulated protected memory".to_string(),
                "Key rotation with HKDF derivation".to_string(),
                "Session key lifecycle management".to_string(),
            ],
            recommended_mitigations: vec![
                "Hardware-backed key storage (TPM, secure element)".to_string(),
                "Side-channel attack countermeasures".to_string(),
                "Key zeroization on tamper detection".to_string(),
                "Regular key rotation policy".to_string(),
            ],
            residual_risk: Some(RiskLevel::Low),
        });

        // Threat 5: Denial of Service (Bus Flooding)
        self.add_threat(ThreatScenario {
            threat_id: "T-005".to_string(),
            name: "CAN Bus Flooding (DoS)".to_string(),
            description:
                "Attacker floods CAN bus with high-priority frames, preventing legitimate \
                          messages from being transmitted."
                    .to_string(),
            asset: AssetType::CanBus,
            threat_type: ThreatType::DenialOfService,
            attack_vector: "Compromised ECU or physical access to inject frames at maximum rate"
                .to_string(),
            attacker_profile:
                "Low-medium expertise, physical/wireless access, motivated by disruption"
                    .to_string(),
            confidentiality_impact: ImpactLevel::None,
            integrity_impact: ImpactLevel::Low,
            availability_impact: ImpactLevel::Critical,
            safety_impact: ImpactLevel::High,
            financial_impact: ImpactLevel::Medium,
            operational_impact: ImpactLevel::Critical,
            feasibility: FeasibilityLevel::High,
            risk_level: RiskLevel::High,
            existing_controls: vec![
                "Rate limiting (token bucket, 100 msg/s)".to_string(),
                "Attack detector monitoring for flooding patterns".to_string(),
            ],
            recommended_mitigations: vec![
                "CAN arbitration priority for safety-critical messages".to_string(),
                "Network segmentation to isolate critical functions".to_string(),
                "ECU isolation on flood detection".to_string(),
                "Hardware message filters".to_string(),
            ],
            residual_risk: Some(RiskLevel::Medium),
        });

        // Threat 6: Behavioral Anomaly Attack
        self.add_threat(ThreatScenario {
            threat_id: "T-006".to_string(),
            name: "Compromised ECU Behavioral Anomaly".to_string(),
            description:
                "Compromised ECU with valid keys exhibits abnormal behavior not detected by \
                          cryptographic controls alone."
                    .to_string(),
            asset: AssetType::Ecu("Any ECU".to_string()),
            threat_type: ThreatType::Tampering,
            attack_vector: "Software vulnerability exploitation, supply chain compromise"
                .to_string(),
            attacker_profile: "High expertise, prolonged access, motivated by espionage/sabotage"
                .to_string(),
            confidentiality_impact: ImpactLevel::High,
            integrity_impact: ImpactLevel::High,
            availability_impact: ImpactLevel::Medium,
            safety_impact: ImpactLevel::High,
            financial_impact: ImpactLevel::High,
            operational_impact: ImpactLevel::High,
            feasibility: FeasibilityLevel::Medium,
            risk_level: RiskLevel::High,
            existing_controls: vec![
                "Anomaly-based IDS with statistical profiling".to_string(),
                "Factory-calibrated behavioral baselines".to_string(),
                "Multi-factor anomaly detection (frequency, rate, data range)".to_string(),
                "Graduated response (Warning/Attack thresholds)".to_string(),
            ],
            recommended_mitigations: vec![
                "Machine learning-based anomaly detection".to_string(),
                "Continuous baseline adaptation".to_string(),
                "Cross-ECU correlation for attack pattern detection".to_string(),
                "Runtime attestation and integrity monitoring".to_string(),
            ],
            residual_risk: Some(RiskLevel::Low),
        });
    }

    /// Generate TARA analysis document
    pub fn generate_analysis(&self) -> TaraAnalysis {
        let mut threats_by_risk: HashMap<String, usize> = HashMap::new();
        let mut threats_by_type: HashMap<String, usize> = HashMap::new();
        let mut threats_by_asset: HashMap<String, usize> = HashMap::new();

        let mut high_risk_count = 0;
        let mut medium_risk_count = 0;
        let mut low_risk_count = 0;

        for threat in &self.threats {
            // Count by risk level
            let risk_str = format!("{:?}", threat.risk_level);
            *threats_by_risk.entry(risk_str).or_insert(0) += 1;

            // Count by threat type
            let type_str = threat.threat_type.to_string();
            *threats_by_type.entry(type_str).or_insert(0) += 1;

            // Count by asset
            let asset_str = threat.asset.to_string();
            *threats_by_asset.entry(asset_str).or_insert(0) += 1;

            // Count severity buckets
            match threat.risk_level {
                RiskLevel::High | RiskLevel::VeryHigh => high_risk_count += 1,
                RiskLevel::Medium => medium_risk_count += 1,
                _ => low_risk_count += 1,
            }
        }

        TaraAnalysis {
            generated_at: Utc::now(),
            system_name: self.system_name.clone(),
            system_version: self.system_version.clone(),
            analyst_name: self.analyst_name.clone(),
            organization: self.organization.clone(),
            assets: self.assets.clone(),
            threats: self.threats.clone(),
            risk_summary: RiskSummary {
                total_threats: self.threats.len(),
                threats_by_risk_level: threats_by_risk,
                threats_by_type: threats_by_type,
                threats_by_asset: threats_by_asset,
                high_risk_count,
                medium_risk_count,
                low_risk_count,
            },
        }
    }

    /// Export TARA analysis as formatted report
    pub fn export_report(&self) -> String {
        let analysis = self.generate_analysis();
        let mut report = String::new();

        // Header
        report.push_str("═══════════════════════════════════════════════════════════════════\n");
        report.push_str("           ISO 21434 THREAT ANALYSIS AND RISK ASSESSMENT\n");
        report.push_str("                           (TARA)\n");
        report.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        // Metadata
        report.push_str(&format!(
            "System: {} (Version: {})\n",
            analysis.system_name, analysis.system_version
        ));
        report.push_str(&format!("Organization: {}\n", analysis.organization));
        report.push_str(&format!("Analyst: {}\n", analysis.analyst_name));
        report.push_str(&format!("Generated: {}\n\n", analysis.generated_at));

        // Executive Summary
        report.push_str("───────────────────────────────────────────────────────────────────\n");
        report.push_str("EXECUTIVE SUMMARY\n");
        report.push_str("───────────────────────────────────────────────────────────────────\n\n");

        report.push_str(&format!(
            "Total Threats Identified: {}\n",
            analysis.risk_summary.total_threats
        ));
        report.push_str(&format!(
            "  High/Very High Risk: {}\n",
            analysis.risk_summary.high_risk_count
        ));
        report.push_str(&format!(
            "  Medium Risk: {}\n",
            analysis.risk_summary.medium_risk_count
        ));
        report.push_str(&format!(
            "  Low/Very Low Risk: {}\n\n",
            analysis.risk_summary.low_risk_count
        ));

        // Assets
        report.push_str("───────────────────────────────────────────────────────────────────\n");
        report.push_str("ASSETS IDENTIFIED\n");
        report.push_str("───────────────────────────────────────────────────────────────────\n\n");

        for (idx, asset) in analysis.assets.iter().enumerate() {
            report.push_str(&format!("{}. {}\n", idx + 1, asset));
        }
        report.push_str("\n");

        // Threat Scenarios (sorted by risk level, highest first)
        report.push_str("───────────────────────────────────────────────────────────────────\n");
        report.push_str("THREAT SCENARIOS\n");
        report.push_str("───────────────────────────────────────────────────────────────────\n\n");

        let mut sorted_threats = analysis.threats.clone();
        sorted_threats.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

        for threat in &sorted_threats {
            report.push_str(&format!("[{}] {}\n", threat.threat_id, threat.name));
            report.push_str(&format!("Risk Level: {:?}\n", threat.risk_level));
            report.push_str(&format!("Asset: {}\n", threat.asset));
            report.push_str(&format!("Threat Type: {}\n", threat.threat_type));
            report.push_str(&format!("\nDescription:\n  {}\n", threat.description));
            report.push_str(&format!("\nAttack Vector:\n  {}\n", threat.attack_vector));
            report.push_str(&format!(
                "\nAttacker Profile:\n  {}\n",
                threat.attacker_profile
            ));
            report.push_str("\nImpact Assessment:\n");
            report.push_str(&format!(
                "  Confidentiality: {}\n",
                threat.confidentiality_impact
            ));
            report.push_str(&format!("  Integrity: {}\n", threat.integrity_impact));
            report.push_str(&format!("  Availability: {}\n", threat.availability_impact));
            report.push_str(&format!("  Safety: {}\n", threat.safety_impact));
            report.push_str(&format!("  Financial: {}\n", threat.financial_impact));
            report.push_str(&format!("  Operational: {}\n", threat.operational_impact));
            report.push_str(&format!("\nAttack Feasibility: {}\n", threat.feasibility));
            report.push_str("\nExisting Security Controls:\n");
            for control in &threat.existing_controls {
                report.push_str(&format!("  - {}\n", control));
            }
            report.push_str("\nRecommended Mitigations:\n");
            for mitigation in &threat.recommended_mitigations {
                report.push_str(&format!("  - {}\n", mitigation));
            }
            if let Some(residual) = threat.residual_risk {
                report.push_str(&format!("\nResidual Risk: {:?}\n", residual));
            }
            report.push_str(
                "\n───────────────────────────────────────────────────────────────────\n\n",
            );
        }

        // Risk Summary
        report.push_str("═══════════════════════════════════════════════════════════════════\n");
        report.push_str("RISK SUMMARY\n");
        report.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        report.push_str("Threats by Risk Level:\n");
        for (risk_level, count) in &analysis.risk_summary.threats_by_risk_level {
            report.push_str(&format!("  {}: {}\n", risk_level, count));
        }
        report.push_str("\n");

        report.push_str("Threats by Type:\n");
        for (threat_type, count) in &analysis.risk_summary.threats_by_type {
            report.push_str(&format!("  {}: {}\n", threat_type, count));
        }
        report.push_str("\n");

        report.push_str("Threats by Asset:\n");
        for (asset, count) in &analysis.risk_summary.threats_by_asset {
            report.push_str(&format!("  {}: {}\n", asset, count));
        }
        report.push_str("\n");

        report.push_str("═══════════════════════════════════════════════════════════════════\n");
        report.push_str("                        END OF TARA REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════════════\n");

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_calculation() {
        // High impact + Low feasibility = Medium-High risk
        let risk1 = RiskLevel::calculate(ImpactLevel::Critical, FeasibilityLevel::Low);
        assert!(risk1 >= RiskLevel::Medium);

        // Low impact + High feasibility = Medium risk
        let risk2 = RiskLevel::calculate(ImpactLevel::Low, FeasibilityLevel::High);
        assert_eq!(risk2, RiskLevel::Medium);

        // Critical impact + Very High feasibility = Very High risk
        let risk3 = RiskLevel::calculate(ImpactLevel::Critical, FeasibilityLevel::VeryHigh);
        assert_eq!(risk3, RiskLevel::VeryHigh);
    }

    #[test]
    fn test_tara_generator_basic() {
        let mut generator = TaraGenerator::new(
            "V-HSM CAN Bus Security System".to_string(),
            "1.0.0".to_string(),
            "Security Analyst".to_string(),
            "Automotive OEM".to_string(),
        );

        generator.add_asset(AssetType::CanBus);
        generator.add_asset(AssetType::CryptographicKeys);

        assert_eq!(generator.assets.len(), 2);
    }

    #[test]
    fn test_automotive_threats_generation() {
        let mut generator = TaraGenerator::new(
            "V-HSM CAN Bus Security System".to_string(),
            "1.0.0".to_string(),
            "Security Analyst".to_string(),
            "Automotive OEM".to_string(),
        );

        generator.generate_automotive_threats();

        // Should generate 6 threat scenarios
        assert_eq!(generator.threats.len(), 6);

        // Should have multiple assets
        assert!(generator.assets.len() >= 5);

        // Should have threats with different risk levels
        let high_risk_threats: Vec<_> = generator
            .threats
            .iter()
            .filter(|t| t.risk_level >= RiskLevel::High)
            .collect();

        assert!(!high_risk_threats.is_empty());
    }

    #[test]
    fn test_tara_analysis_generation() {
        let mut generator = TaraGenerator::new(
            "Test System".to_string(),
            "1.0.0".to_string(),
            "Analyst".to_string(),
            "Org".to_string(),
        );

        generator.generate_automotive_threats();
        let analysis = generator.generate_analysis();

        assert_eq!(analysis.threats.len(), 6);
        assert!(analysis.risk_summary.total_threats == 6);
        assert!(analysis.risk_summary.high_risk_count > 0);
    }

    #[test]
    fn test_report_export() {
        let mut generator = TaraGenerator::new(
            "Test System".to_string(),
            "1.0.0".to_string(),
            "Analyst".to_string(),
            "Org".to_string(),
        );

        generator.generate_automotive_threats();
        let report = generator.export_report();

        // Report should contain key sections
        assert!(report.contains("THREAT ANALYSIS AND RISK ASSESSMENT"));
        assert!(report.contains("EXECUTIVE SUMMARY"));
        assert!(report.contains("ASSETS IDENTIFIED"));
        assert!(report.contains("THREAT SCENARIOS"));
        assert!(report.contains("RISK SUMMARY"));
    }
}
