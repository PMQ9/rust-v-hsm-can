use crate::can_bus::VirtualCanBus;
use crate::types::{CanFrame, CanId, EcuConfig};
use tokio::sync::broadcast;

/// Electronic Control Unit (ECU) Emulator
pub struct Ecu {
    config: EcuConfig,
    bus: VirtualCanBus,
    rx: broadcast::Receiver<CanFrame>,
}

impl Ecu {
    /// Create a new ECU connected to the CAN bus
    pub fn new(config: EcuConfig, bus: VirtualCanBus) -> Self {
        let rx = bus.subscribe();
        Self { config, bus, rx }
    }

    /// Get ECU name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get ARM variant
    pub fn arm_variant(&self) -> &str {
        self.config.arm_variant.as_str()
    }

    /// Send a CAN frame onto the bus
    pub async fn send_frame(&self, id: CanId, data: Vec<u8>) -> Result<(), String> {
        let frame = CanFrame::new(id, data, self.config.name.clone());
        self.bus.send(frame).await
    }

    /// Receive a CAN frame from the bus (non-blocking)
    pub async fn receive_frame(&mut self) -> Result<CanFrame, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// Try to receive a frame without blocking
    pub fn try_receive_frame(&mut self) -> Result<CanFrame, broadcast::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// Get ECU statistics
    pub fn get_stats(&self) -> EcuStats {
        EcuStats {
            name: self.config.name.clone(),
            arm_variant: self.config.arm_variant.as_str().to_string(),
            bus_address: self.config.bus_address.clone(),
        }
    }
}

/// ECU Statistics
#[derive(Debug, Clone)]
pub struct EcuStats {
    pub name: String,
    pub arm_variant: String,
    pub bus_address: String,
}
