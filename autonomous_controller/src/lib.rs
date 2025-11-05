pub mod can_bus;
pub mod ecu;
pub mod network;
pub mod types;
pub mod hsm;
pub mod protected_memory;
pub mod error_handling;

pub use can_bus::VirtualCanBus;
pub use ecu::Ecu;
pub use network::{BusClient, BusReader, BusWriter, NetMessage};
pub use types::{ArmVariant, CanFrame, CanId, EcuConfig, VehicleState};
pub use hsm::{VirtualHSM, SecuredCanFrame, SignedFirmware};
pub use protected_memory::{ProtectedMemory, FirmwareInfo};
pub use error_handling::{AttackDetector, ValidationError, SecurityState};
