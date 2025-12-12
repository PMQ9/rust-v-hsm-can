//! Core Affinity Configuration for Multi-Core Architecture
//!
//! This module provides CPU core assignment for the V-HSM automotive simulation.
//! Designed for Raspberry Pi 4 with 4x Cortex-A72 cores.
//!
//! Core Assignment Strategy:
//! - Core 0: Infrastructure (bus_server, monitor)
//! - Core 1: Sensor ECUs (wheels, engine, steering sensor) - TX only
//! - Core 2: Controller ECUs (autonomous, brake, steering controller) - TX+RX
//! - Core 3: HSM Service (dedicated crypto engine)

/// Core assignment for each component type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreAssignment {
    /// Core 0: Bus infrastructure
    Infrastructure = 0,
    /// Core 1: Sensor ECUs (transmit only)
    Sensors = 1,
    /// Core 2: Controller/Actuator ECUs (transmit + receive)
    Controllers = 2,
    /// Core 3: HSM Service (dedicated crypto)
    HsmService = 3,
}

impl CoreAssignment {
    /// Get the core ID for this assignment
    pub fn core_id(&self) -> usize {
        *self as usize
    }
}

/// Get the core assignment for a given component name
///
/// Returns the appropriate core number for each component:
/// - Core 0: bus_server, monitor
/// - Core 1: wheel_fl, wheel_fr, wheel_rl, wheel_rr, engine_ecu, steering_sensor
/// - Core 2: autonomous_controller, brake_controller, steering_controller
/// - Core 3: hsm_service
///
/// Returns `None` if the component name is unknown.
pub fn get_core_assignment(component: &str) -> Option<CoreAssignment> {
    match component {
        // Infrastructure components
        "bus_server" | "monitor" => Some(CoreAssignment::Infrastructure),

        // Sensor ECUs (TX only)
        "wheel_fl" | "wheel_fr" | "wheel_rl" | "wheel_rr" | "engine_ecu" | "steering_sensor" => {
            Some(CoreAssignment::Sensors)
        }

        // Controller/Actuator ECUs (TX + RX)
        "autonomous_controller" | "brake_controller" | "steering_controller" => {
            Some(CoreAssignment::Controllers)
        }

        // HSM Service (dedicated crypto)
        "hsm_service" => Some(CoreAssignment::HsmService),

        _ => None,
    }
}

/// Pin the current process to the specified core
///
/// Returns `Ok(core_id)` on success, `Err(message)` on failure.
///
/// # Example
/// ```no_run
/// use autonomous_vehicle_sim::core_affinity_config::{get_core_assignment, pin_to_core};
///
/// if let Some(assignment) = get_core_assignment("hsm_service") {
///     match pin_to_core(assignment.core_id()) {
///         Ok(core) => println!("Pinned to core {}", core),
///         Err(e) => eprintln!("Failed to pin: {}", e),
///     }
/// }
/// ```
pub fn pin_to_core(core_id: usize) -> Result<usize, String> {
    // Get available cores
    let core_ids = core_affinity::get_core_ids().ok_or("Failed to get core IDs")?;

    // Check if requested core exists
    if core_id >= core_ids.len() {
        return Err(format!(
            "Requested core {} but only {} cores available",
            core_id,
            core_ids.len()
        ));
    }

    // Find the CoreId for the requested core
    let target_core = core_ids
        .iter()
        .find(|c| c.id == core_id)
        .ok_or_else(|| format!("Core {} not found in available cores", core_id))?;

    // Pin to the core
    if core_affinity::set_for_current(*target_core) {
        Ok(core_id)
    } else {
        Err(format!("Failed to set affinity for core {}", core_id))
    }
}

/// Pin the current process by component name
///
/// Convenience function that combines `get_core_assignment` and `pin_to_core`.
///
/// Returns `Ok(core_id)` on success, `Err(message)` on failure.
pub fn pin_by_component(component: &str) -> Result<usize, String> {
    let assignment = get_core_assignment(component)
        .ok_or_else(|| format!("Unknown component: {}", component))?;

    pin_to_core(assignment.core_id())
}

/// Get the number of available CPU cores
pub fn available_cores() -> Option<usize> {
    core_affinity::get_core_ids().map(|ids| ids.len())
}

/// Check if the system has enough cores for the full multi-core architecture
pub fn has_sufficient_cores() -> bool {
    available_cores().map(|n| n >= 4).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_assignment_infrastructure() {
        assert_eq!(
            get_core_assignment("bus_server"),
            Some(CoreAssignment::Infrastructure)
        );
        assert_eq!(
            get_core_assignment("monitor"),
            Some(CoreAssignment::Infrastructure)
        );
    }

    #[test]
    fn test_core_assignment_sensors() {
        assert_eq!(
            get_core_assignment("wheel_fl"),
            Some(CoreAssignment::Sensors)
        );
        assert_eq!(
            get_core_assignment("wheel_fr"),
            Some(CoreAssignment::Sensors)
        );
        assert_eq!(
            get_core_assignment("wheel_rl"),
            Some(CoreAssignment::Sensors)
        );
        assert_eq!(
            get_core_assignment("wheel_rr"),
            Some(CoreAssignment::Sensors)
        );
        assert_eq!(
            get_core_assignment("engine_ecu"),
            Some(CoreAssignment::Sensors)
        );
        assert_eq!(
            get_core_assignment("steering_sensor"),
            Some(CoreAssignment::Sensors)
        );
    }

    #[test]
    fn test_core_assignment_controllers() {
        assert_eq!(
            get_core_assignment("autonomous_controller"),
            Some(CoreAssignment::Controllers)
        );
        assert_eq!(
            get_core_assignment("brake_controller"),
            Some(CoreAssignment::Controllers)
        );
        assert_eq!(
            get_core_assignment("steering_controller"),
            Some(CoreAssignment::Controllers)
        );
    }

    #[test]
    fn test_core_assignment_hsm() {
        assert_eq!(
            get_core_assignment("hsm_service"),
            Some(CoreAssignment::HsmService)
        );
    }

    #[test]
    fn test_core_assignment_unknown() {
        assert_eq!(get_core_assignment("unknown_component"), None);
        assert_eq!(get_core_assignment(""), None);
    }

    #[test]
    fn test_core_id_values() {
        assert_eq!(CoreAssignment::Infrastructure.core_id(), 0);
        assert_eq!(CoreAssignment::Sensors.core_id(), 1);
        assert_eq!(CoreAssignment::Controllers.core_id(), 2);
        assert_eq!(CoreAssignment::HsmService.core_id(), 3);
    }

    #[test]
    fn test_available_cores() {
        // This should return Some value on any system
        let cores = available_cores();
        assert!(cores.is_some());
        assert!(cores.unwrap() >= 1);
    }

    #[test]
    fn test_pin_invalid_core() {
        // Try to pin to a core that doesn't exist
        let result = pin_to_core(999);
        assert!(result.is_err());
    }
}
