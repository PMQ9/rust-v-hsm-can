// Security Gateway - Zone-based CAN Bus Segmentation
// Implements automotive security gateway with zone isolation and routing policies

use crate::types::CanId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Vehicle security zones (ISO 21434 §8.3.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityZone {
    /// Powertrain zone (engine, transmission, hybrid/EV systems)
    Powertrain,

    /// Chassis zone (brakes, steering, suspension)
    Chassis,

    /// Body zone (doors, lights, climate control)
    Body,

    /// Infotainment zone (head unit, connectivity, navigation)
    Infotainment,

    /// ADAS zone (autonomous driving, sensors, cameras)
    Adas,

    /// Diagnostics zone (OBD-II, workshop tools)
    Diagnostics,
}

/// Routing action for messages crossing zones
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Allow,      // Forward message to destination zone
    Deny,       // Block message
    Audit,      // Forward but log for security audit
}

/// Zone routing rule
#[derive(Debug, Clone)]
pub struct ZoneRoutingRule {
    /// Source zone
    pub from_zone: SecurityZone,

    /// Destination zone
    pub to_zone: SecurityZone,

    /// Default action for this zone pair
    pub default_action: RoutingAction,

    /// Allowed CAN IDs (if Some, only these are allowed; if None, all allowed)
    pub allowed_can_ids: Option<HashSet<u32>>,
}

impl ZoneRoutingRule {
    /// Create a new routing rule
    pub fn new(
        from_zone: SecurityZone,
        to_zone: SecurityZone,
        default_action: RoutingAction,
    ) -> Self {
        Self {
            from_zone,
            to_zone,
            default_action,
            allowed_can_ids: None,
        }
    }

    /// Set allowed CAN IDs for this route
    pub fn with_allowed_can_ids(mut self, can_ids: HashSet<u32>) -> Self {
        self.allowed_can_ids = Some(can_ids);
        self
    }

    /// Check if a CAN ID is allowed on this route
    pub fn is_can_id_allowed(&self, can_id: u32) -> bool {
        match &self.allowed_can_ids {
            Some(allowed) => allowed.contains(&can_id),
            None => self.default_action == RoutingAction::Allow || self.default_action == RoutingAction::Audit,
        }
    }
}

/// Security Gateway configuration
pub struct SecurityGatewayConfig {
    /// ECU to zone mapping
    ecu_zones: HashMap<String, SecurityZone>,

    /// Zone routing rules
    routing_rules: Vec<ZoneRoutingRule>,

    /// Audit log for cross-zone traffic
    audit_log: Vec<AuditEntry>,

    /// Statistics
    messages_forwarded: u64,
    messages_blocked: u64,
    messages_audited: u64,
}

/// Audit entry for security review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_ecu: String,
    pub source_zone: SecurityZone,
    pub destination_zone: SecurityZone,
    pub can_id: u32,
    pub action: String,
}

impl SecurityGatewayConfig {
    /// Create new security gateway configuration
    pub fn new() -> Self {
        Self {
            ecu_zones: HashMap::new(),
            routing_rules: Vec::new(),
            audit_log: Vec::new(),
            messages_forwarded: 0,
            messages_blocked: 0,
            messages_audited: 0,
        }
    }

    /// Register an ECU in a security zone
    pub fn register_ecu(&mut self, ecu_name: String, zone: SecurityZone) {
        self.ecu_zones.insert(ecu_name, zone);
    }

    /// Add a routing rule
    pub fn add_routing_rule(&mut self, rule: ZoneRoutingRule) {
        self.routing_rules.push(rule);
    }

    /// Check if a message should be routed
    pub fn check_routing(
        &mut self,
        source_ecu: &str,
        destination_zone: SecurityZone,
        can_id: CanId,
    ) -> RoutingAction {
        // Get source zone
        let source_zone = match self.ecu_zones.get(source_ecu) {
            Some(zone) => *zone,
            None => {
                // Unknown ECU - deny by default
                self.messages_blocked += 1;
                return RoutingAction::Deny;
            }
        };

        // Same zone - always allow
        if source_zone == destination_zone {
            self.messages_forwarded += 1;
            return RoutingAction::Allow;
        }

        // Convert CAN ID to u32
        let can_id_num = match can_id {
            CanId::Standard(id) => id as u32,
            CanId::Extended(id) => id,
        };

        // Check routing rules
        for rule in &self.routing_rules {
            if rule.from_zone == source_zone && rule.to_zone == destination_zone {
                if !rule.is_can_id_allowed(can_id_num) {
                    self.messages_blocked += 1;
                    return RoutingAction::Deny;
                }

                let action = rule.default_action;

                // Log audit entry if needed
                if action == RoutingAction::Audit {
                    self.audit_log.push(AuditEntry {
                        timestamp: chrono::Utc::now(),
                        source_ecu: source_ecu.to_string(),
                        source_zone,
                        destination_zone,
                        can_id: can_id_num,
                        action: "AUDIT".to_string(),
                    });
                    self.messages_audited += 1;
                }

                match action {
                    RoutingAction::Allow | RoutingAction::Audit => {
                        self.messages_forwarded += 1;
                        return action;
                    }
                    RoutingAction::Deny => {
                        self.messages_blocked += 1;
                        return action;
                    }
                }
            }
        }

        // No matching rule - deny by default (fail-safe)
        self.messages_blocked += 1;
        RoutingAction::Deny
    }

    /// Get ECU zone
    pub fn get_ecu_zone(&self, ecu_name: &str) -> Option<SecurityZone> {
        self.ecu_zones.get(ecu_name).copied()
    }

    /// Get routing statistics
    pub fn stats(&self) -> GatewayStats {
        GatewayStats {
            messages_forwarded: self.messages_forwarded,
            messages_blocked: self.messages_blocked,
            messages_audited: self.messages_audited,
            audit_entries: self.audit_log.len() as u64,
        }
    }

    /// Get audit log (for security review)
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Clear audit log (after export)
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }
}

impl Default for SecurityGatewayConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Gateway statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    pub messages_forwarded: u64,
    pub messages_blocked: u64,
    pub messages_audited: u64,
    pub audit_entries: u64,
}

/// Build default automotive security gateway configuration
pub fn build_automotive_gateway() -> SecurityGatewayConfig {
    let mut gateway = SecurityGatewayConfig::new();

    // Register ECUs in zones
    // Powertrain zone
    gateway.register_ecu("ENGINE_ECU".to_string(), SecurityZone::Powertrain);

    // Chassis zone
    gateway.register_ecu("BRAKE_CTRL".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("STEER_CTRL".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("WHEEL_FL".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("WHEEL_FR".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("WHEEL_RL".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("WHEEL_RR".to_string(), SecurityZone::Chassis);
    gateway.register_ecu("STEER_SENSOR".to_string(), SecurityZone::Chassis);

    // ADAS zone
    gateway.register_ecu("AUTONOMOUS_CTRL".to_string(), SecurityZone::Adas);

    // Define routing rules

    // ADAS → Chassis: Allow (autonomous controller needs to command actuators)
    let mut allowed_chassis_cmds = HashSet::new();
    allowed_chassis_cmds.insert(0x300); // BRAKE_COMMAND
    allowed_chassis_cmds.insert(0x302); // STEERING_COMMAND
    gateway.add_routing_rule(
        ZoneRoutingRule::new(
            SecurityZone::Adas,
            SecurityZone::Chassis,
            RoutingAction::Allow,
        )
        .with_allowed_can_ids(allowed_chassis_cmds),
    );

    // Chassis → ADAS: Allow (sensor data needed for autonomous driving)
    let mut allowed_sensor_ids = HashSet::new();
    allowed_sensor_ids.insert(0x100); // WHEEL_SPEED_FL
    allowed_sensor_ids.insert(0x101); // WHEEL_SPEED_FR
    allowed_sensor_ids.insert(0x102); // WHEEL_SPEED_RL
    allowed_sensor_ids.insert(0x103); // WHEEL_SPEED_RR
    allowed_sensor_ids.insert(0x120); // STEERING_ANGLE
    allowed_sensor_ids.insert(0x121); // STEERING_TORQUE
    gateway.add_routing_rule(
        ZoneRoutingRule::new(
            SecurityZone::Chassis,
            SecurityZone::Adas,
            RoutingAction::Allow,
        )
        .with_allowed_can_ids(allowed_sensor_ids),
    );

    // ADAS → Powertrain: Allow throttle commands
    let mut allowed_powertrain_cmds = HashSet::new();
    allowed_powertrain_cmds.insert(0x301); // THROTTLE_COMMAND
    gateway.add_routing_rule(
        ZoneRoutingRule::new(
            SecurityZone::Adas,
            SecurityZone::Powertrain,
            RoutingAction::Allow,
        )
        .with_allowed_can_ids(allowed_powertrain_cmds),
    );

    // Powertrain → ADAS: Allow sensor data
    let mut allowed_powertrain_sensors = HashSet::new();
    allowed_powertrain_sensors.insert(0x110); // ENGINE_RPM
    allowed_powertrain_sensors.insert(0x111); // ENGINE_THROTTLE
    gateway.add_routing_rule(
        ZoneRoutingRule::new(
            SecurityZone::Powertrain,
            SecurityZone::Adas,
            RoutingAction::Allow,
        )
        .with_allowed_can_ids(allowed_powertrain_sensors),
    );

    // Diagnostics → All zones: Audit (allow diagnostic access but log it)
    for zone in [
        SecurityZone::Powertrain,
        SecurityZone::Chassis,
        SecurityZone::Adas,
        SecurityZone::Body,
        SecurityZone::Infotainment,
    ] {
        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Diagnostics,
            zone,
            RoutingAction::Audit,
        ));
    }

    // Infotainment → ADAS/Chassis/Powertrain: Deny (prevent infotainment compromise)
    for zone in [
        SecurityZone::Powertrain,
        SecurityZone::Chassis,
        SecurityZone::Adas,
    ] {
        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Infotainment,
            zone,
            RoutingAction::Deny,
        ));
    }

    // Body → ADAS/Powertrain: Deny (body systems shouldn't control drivetrain)
    gateway.add_routing_rule(ZoneRoutingRule::new(
        SecurityZone::Body,
        SecurityZone::Adas,
        RoutingAction::Deny,
    ));
    gateway.add_routing_rule(ZoneRoutingRule::new(
        SecurityZone::Body,
        SecurityZone::Powertrain,
        RoutingAction::Deny,
    ));

    gateway
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_zone_allowed() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("ECU1".to_string(), SecurityZone::Chassis);

        let action = gateway.check_routing("ECU1", SecurityZone::Chassis, CanId::Standard(0x100));
        assert_eq!(action, RoutingAction::Allow);
        assert_eq!(gateway.stats().messages_forwarded, 1);
    }

    #[test]
    fn test_unknown_ecu_denied() {
        let mut gateway = SecurityGatewayConfig::new();

        let action = gateway.check_routing("UNKNOWN", SecurityZone::Chassis, CanId::Standard(0x100));
        assert_eq!(action, RoutingAction::Deny);
        assert_eq!(gateway.stats().messages_blocked, 1);
    }

    #[test]
    fn test_allowed_cross_zone_routing() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("SENSOR".to_string(), SecurityZone::Chassis);

        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Chassis,
            SecurityZone::Adas,
            RoutingAction::Allow,
        ));

        let action = gateway.check_routing("SENSOR", SecurityZone::Adas, CanId::Standard(0x100));
        assert_eq!(action, RoutingAction::Allow);
    }

    #[test]
    fn test_denied_cross_zone_routing() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("INFOTAINMENT".to_string(), SecurityZone::Infotainment);

        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Infotainment,
            SecurityZone::Chassis,
            RoutingAction::Deny,
        ));

        let action = gateway.check_routing("INFOTAINMENT", SecurityZone::Chassis, CanId::Standard(0x300));
        assert_eq!(action, RoutingAction::Deny);
        assert_eq!(gateway.stats().messages_blocked, 1);
    }

    #[test]
    fn test_can_id_whitelist() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("CONTROLLER".to_string(), SecurityZone::Adas);

        let mut allowed_ids = HashSet::new();
        allowed_ids.insert(0x300);
        gateway.add_routing_rule(
            ZoneRoutingRule::new(SecurityZone::Adas, SecurityZone::Chassis, RoutingAction::Allow)
                .with_allowed_can_ids(allowed_ids),
        );

        // Allowed ID
        let action1 = gateway.check_routing("CONTROLLER", SecurityZone::Chassis, CanId::Standard(0x300));
        assert_eq!(action1, RoutingAction::Allow);

        // Blocked ID
        let action2 = gateway.check_routing("CONTROLLER", SecurityZone::Chassis, CanId::Standard(0x400));
        assert_eq!(action2, RoutingAction::Deny);
    }

    #[test]
    fn test_audit_logging() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("DIAG_TOOL".to_string(), SecurityZone::Diagnostics);

        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Diagnostics,
            SecurityZone::Chassis,
            RoutingAction::Audit,
        ));

        let action = gateway.check_routing("DIAG_TOOL", SecurityZone::Chassis, CanId::Standard(0x100));
        assert_eq!(action, RoutingAction::Audit);
        assert_eq!(gateway.stats().messages_audited, 1);
        assert_eq!(gateway.audit_log().len(), 1);
    }

    #[test]
    fn test_no_rule_deny_default() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("ECU1".to_string(), SecurityZone::Body);

        // No rule defined for Body → Powertrain
        let action = gateway.check_routing("ECU1", SecurityZone::Powertrain, CanId::Standard(0x100));
        assert_eq!(action, RoutingAction::Deny);
    }

    #[test]
    fn test_automotive_gateway() {
        let mut gateway = build_automotive_gateway();

        // ADAS can send brake commands to chassis
        let action = gateway.check_routing(
            "AUTONOMOUS_CTRL",
            SecurityZone::Chassis,
            CanId::Standard(0x300),
        );
        assert_eq!(action, RoutingAction::Allow);

        // Infotainment cannot send to chassis
        gateway.register_ecu("HEADUNIT".to_string(), SecurityZone::Infotainment);
        let action = gateway.check_routing("HEADUNIT", SecurityZone::Chassis, CanId::Standard(0x300));
        assert_eq!(action, RoutingAction::Deny);
    }

    #[test]
    fn test_statistics() {
        let mut gateway = SecurityGatewayConfig::new();
        gateway.register_ecu("ECU1".to_string(), SecurityZone::Chassis);
        gateway.add_routing_rule(ZoneRoutingRule::new(
            SecurityZone::Chassis,
            SecurityZone::Adas,
            RoutingAction::Allow,
        ));

        gateway.check_routing("ECU1", SecurityZone::Adas, CanId::Standard(0x100));
        gateway.check_routing("ECU1", SecurityZone::Adas, CanId::Standard(0x101));
        gateway.check_routing("UNKNOWN", SecurityZone::Adas, CanId::Standard(0x102));

        let stats = gateway.stats();
        assert_eq!(stats.messages_forwarded, 2);
        assert_eq!(stats.messages_blocked, 1);
    }
}
