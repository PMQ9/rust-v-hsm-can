/// CAN ID Access Control Module (ISO 21434 Authorization Model)
///
/// This module defines authorization policies for each ECU in the autonomous vehicle system.
/// Each ECU has specific CAN IDs it's allowed to transmit and receive, implementing the
/// principle of least privilege.
use crate::types::{CanIdPermissions, can_ids};
use std::collections::HashMap;

/// Build CAN ID access control policies for all ECUs in the autonomous vehicle system
pub fn build_autonomous_vehicle_policies() -> HashMap<String, CanIdPermissions> {
    let mut policies = HashMap::new();

    // Wheel ECUs - can only transmit their respective wheel speed data
    let mut wheel_fl = CanIdPermissions::new("WHEEL_FL".to_string());
    wheel_fl.allow_tx(can_ids::WHEEL_SPEED_FL.value());
    policies.insert("WHEEL_FL".to_string(), wheel_fl);

    let mut wheel_fr = CanIdPermissions::new("WHEEL_FR".to_string());
    wheel_fr.allow_tx(can_ids::WHEEL_SPEED_FR.value());
    policies.insert("WHEEL_FR".to_string(), wheel_fr);

    let mut wheel_rl = CanIdPermissions::new("WHEEL_RL".to_string());
    wheel_rl.allow_tx(can_ids::WHEEL_SPEED_RL.value());
    policies.insert("WHEEL_RL".to_string(), wheel_rl);

    let mut wheel_rr = CanIdPermissions::new("WHEEL_RR".to_string());
    wheel_rr.allow_tx(can_ids::WHEEL_SPEED_RR.value());
    policies.insert("WHEEL_RR".to_string(), wheel_rr);

    // Engine ECU - transmits RPM and throttle status, receives throttle commands
    let mut engine = CanIdPermissions::new("ENGINE_ECU".to_string());
    engine
        .allow_tx(can_ids::ENGINE_RPM.value())
        .allow_tx(can_ids::ENGINE_THROTTLE.value());
    // Only receive throttle commands
    engine.allow_rx(can_ids::THROTTLE_COMMAND.value());
    policies.insert("ENGINE_ECU".to_string(), engine);

    // Steering Sensor - transmits steering data only
    let mut steering_sensor = CanIdPermissions::new("STEERING_SENSOR".to_string());
    steering_sensor
        .allow_tx(can_ids::STEERING_ANGLE.value())
        .allow_tx(can_ids::STEERING_TORQUE.value());
    policies.insert("STEERING_SENSOR".to_string(), steering_sensor);

    // Autonomous Controller - receives sensor data, transmits status and commands
    let mut auto_ctrl = CanIdPermissions::new("AUTONOMOUS_CONTROLLER".to_string());
    auto_ctrl
        .allow_tx(can_ids::AUTO_STATUS.value())
        .allow_tx(can_ids::AUTO_TRAJECTORY.value())
        .allow_tx(can_ids::BRAKE_COMMAND.value())
        .allow_tx(can_ids::THROTTLE_COMMAND.value())
        .allow_tx(can_ids::STEERING_COMMAND.value());
    // Receive all sensor data
    auto_ctrl.allow_rx_multiple(&[
        can_ids::WHEEL_SPEED_FL.value(),
        can_ids::WHEEL_SPEED_FR.value(),
        can_ids::WHEEL_SPEED_RL.value(),
        can_ids::WHEEL_SPEED_RR.value(),
        can_ids::ENGINE_RPM.value(),
        can_ids::ENGINE_THROTTLE.value(),
        can_ids::STEERING_ANGLE.value(),
        can_ids::STEERING_TORQUE.value(),
    ]);
    policies.insert("AUTONOMOUS_CONTROLLER".to_string(), auto_ctrl);

    // Brake Controller - only receives brake commands
    let mut brake_ctrl = CanIdPermissions::new("BRAKE_CTRL".to_string());
    brake_ctrl.allow_rx(can_ids::BRAKE_COMMAND.value());
    policies.insert("BRAKE_CTRL".to_string(), brake_ctrl);

    // Steering Controller - only receives steering commands
    let mut steering_ctrl = CanIdPermissions::new("STEERING_CTRL".to_string());
    steering_ctrl.allow_rx(can_ids::STEERING_COMMAND.value());
    policies.insert("STEERING_CTRL".to_string(), steering_ctrl);

    policies
}

/// Load access control policy for a specific ECU
pub fn load_policy_for_ecu(ecu_name: &str) -> Option<CanIdPermissions> {
    let policies = build_autonomous_vehicle_policies();
    policies.get(ecu_name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wheel_fl_policy() {
        let policy = load_policy_for_ecu("WHEEL_FL").unwrap();
        assert!(policy.can_transmit(can_ids::WHEEL_SPEED_FL.value()));
        assert!(!policy.can_transmit(can_ids::BRAKE_COMMAND.value()));
        assert!(policy.can_receive(can_ids::WHEEL_SPEED_FL.value())); // Can receive anything
    }

    #[test]
    fn test_autonomous_ctrl_policy() {
        let policy = load_policy_for_ecu("AUTONOMOUS_CONTROLLER").unwrap();
        // Can transmit commands
        assert!(policy.can_transmit(can_ids::BRAKE_COMMAND.value()));
        assert!(policy.can_transmit(can_ids::THROTTLE_COMMAND.value()));
        assert!(policy.can_transmit(can_ids::STEERING_COMMAND.value()));
        // Cannot transmit wheel speeds
        assert!(!policy.can_transmit(can_ids::WHEEL_SPEED_FL.value()));
        // Can receive sensor data
        assert!(policy.can_receive(can_ids::WHEEL_SPEED_FL.value()));
        assert!(policy.can_receive(can_ids::ENGINE_RPM.value()));
    }

    #[test]
    fn test_brake_ctrl_policy() {
        let policy = load_policy_for_ecu("BRAKE_CTRL").unwrap();
        // Cannot transmit anything
        assert!(!policy.can_transmit(can_ids::BRAKE_COMMAND.value()));
        // Can only receive brake commands
        assert!(policy.can_receive(can_ids::BRAKE_COMMAND.value()));
        assert!(!policy.can_receive(can_ids::THROTTLE_COMMAND.value()));
    }

    #[test]
    fn test_all_ecus_have_policies() {
        let ecus = vec![
            "WHEEL_FL",
            "WHEEL_FR",
            "WHEEL_RL",
            "WHEEL_RR",
            "ENGINE_ECU",
            "STEERING_SENSOR",
            "AUTONOMOUS_CTRL",
            "BRAKE_CTRL",
            "STEERING_CTRL",
        ];

        for ecu in ecus {
            assert!(
                load_policy_for_ecu(ecu).is_some(),
                "ECU {} missing policy",
                ecu
            );
        }
    }
}
