pub mod can_bus;
pub mod ecu;
pub mod error_handling;
pub mod hsm;
pub mod network;
pub mod protected_memory;
pub mod security_log;
pub mod types;

pub use can_bus::VirtualCanBus;
pub use ecu::Ecu;
pub use error_handling::{AttackDetector, SecurityState, ValidationError};
pub use hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
pub use network::{BusClient, BusReader, BusWriter, NetMessage};
pub use protected_memory::{FirmwareInfo, ProtectedMemory};
pub use security_log::{SecurityEvent, SecurityLogger};
pub use types::{ArmVariant, CanFrame, CanId, EcuConfig, VehicleState};
