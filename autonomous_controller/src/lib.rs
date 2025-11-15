pub mod access_control;
pub mod anomaly_detection;
pub mod attack_framework;
pub mod baseline_persistence;
pub mod can_bus;
pub mod ecu;
pub mod error_handling;
pub mod hsm;
pub mod network;
pub mod protected_memory;
pub mod rate_limiter;
pub mod security_log;
pub mod types;

pub use access_control::{build_autonomous_vehicle_policies, load_policy_for_ecu};
pub use anomaly_detection::{
    AnomalyBaseline, AnomalyDetector, AnomalyReport, AnomalyResult, AnomalySeverity, AnomalyType,
    DetectorMode,
};
pub use attack_framework::{AttackConfig, AttackSimulator, AttackStats, AttackType};
pub use baseline_persistence::{SignedBaseline, load_baseline, save_baseline};
pub use can_bus::VirtualCanBus;
pub use ecu::Ecu;
pub use error_handling::{AttackDetector, SecurityState, ValidationError};
pub use hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
pub use network::{BusClient, BusReader, BusWriter, NetMessage};
pub use protected_memory::{FirmwareInfo, ProtectedMemory};
pub use rate_limiter::RateLimiter;
pub use security_log::{SecurityEvent, SecurityLogger};
pub use types::{ArmVariant, CanFrame, CanId, CanIdPermissions, EcuConfig, VehicleState};
