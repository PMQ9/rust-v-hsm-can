pub mod access_control;
pub mod anomaly_detection;
pub mod attack_framework;
pub mod baseline_persistence;
pub mod can_bus;
pub mod config_management;
pub mod ecu;
pub mod error_handling;
pub mod firmware_rollback;
pub mod hsm;
pub mod incident_response;
pub mod network;
pub mod protected_memory;
pub mod rate_limiter;
pub mod security_correlation;
pub mod security_gateway;
pub mod security_log;
pub mod tara;
pub mod types;
pub mod uds_diagnostics;

pub use access_control::{build_autonomous_vehicle_policies, load_policy_for_ecu};
pub use anomaly_detection::{
    AnomalyBaseline, AnomalyDetector, AnomalyReport, AnomalyResult, AnomalySeverity, AnomalyType,
    DetectorMode,
};
pub use attack_framework::{AttackConfig, AttackSimulator, AttackStats, AttackType};
pub use baseline_persistence::{SignedBaseline, load_baseline, save_baseline};
pub use can_bus::VirtualCanBus;
pub use config_management::{
    ConfigError, ConfigManager, ConfigType, SignedConfig, load_json_config, sign_json_config,
};
pub use ecu::Ecu;
pub use error_handling::{AttackDetector, SecurityState, ValidationError};
pub use firmware_rollback::{FirmwareRollbackManager, FirmwareUpdateRecord, UpdateStatus};
pub use hsm::{
    KeyRotationManager, KeyRotationPolicy, KeyState, SecuredCanFrame, SessionKey, SignedFirmware,
    VirtualHSM, derive_session_key_hkdf,
};
pub use incident_response::{
    IncidentCategory, IncidentResponseManager, IncidentSeverity, ResponseAction, SecurityIncident,
};
pub use network::{BusClient, BusReader, BusWriter, NetMessage};
pub use protected_memory::{FirmwareInfo, ProtectedMemory};
pub use rate_limiter::RateLimiter;
pub use security_correlation::{
    AttackPattern, CorrelationEngine, CorrelationRule, SecurityEventRecord,
};
pub use security_gateway::{
    AuditEntry, GatewayStats, RoutingAction, SecurityGatewayConfig, SecurityZone,
    ZoneRoutingRule, build_automotive_gateway,
};
pub use security_log::{SecurityEvent, SecurityLogger};
pub use tara::{AssetType, RiskLevel, TaraAnalysis, TaraGenerator, ThreatScenario, ThreatType};
pub use types::{ArmVariant, CanFrame, CanId, CanIdPermissions, EcuConfig, VehicleState};
pub use uds_diagnostics::{
    DiagnosticSession, NegativeResponseCode, SecurityAccessRequest, SecurityAccessResponse,
    SecurityLevel, UdsDiagnosticServer, UdsDiagnosticSession, UdsService,
};
