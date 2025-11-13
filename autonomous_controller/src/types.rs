use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// CAN Frame identifier (11-bit standard or 29-bit extended)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanId {
    Standard(u16), // 11-bit (0x000 - 0x7FF)
    Extended(u32), // 29-bit (0x00000000 - 0x1FFFFFFF)
}

impl CanId {
    pub fn value(&self) -> u32 {
        match self {
            CanId::Standard(id) => *id as u32,
            CanId::Extended(id) => *id,
        }
    }
}

/// Standard CAN IDs for automotive messages (following typical automotive conventions)
pub mod can_ids {
    use super::CanId;

    // Sensor messages (0x100 - 0x2FF)
    pub const WHEEL_SPEED_FL: CanId = CanId::Standard(0x100);
    pub const WHEEL_SPEED_FR: CanId = CanId::Standard(0x101);
    pub const WHEEL_SPEED_RL: CanId = CanId::Standard(0x102);
    pub const WHEEL_SPEED_RR: CanId = CanId::Standard(0x103);

    pub const ENGINE_RPM: CanId = CanId::Standard(0x110);
    pub const ENGINE_THROTTLE: CanId = CanId::Standard(0x111);

    pub const STEERING_ANGLE: CanId = CanId::Standard(0x120);
    pub const STEERING_TORQUE: CanId = CanId::Standard(0x121);

    // Controller command messages (0x300 - 0x3FF)
    pub const BRAKE_COMMAND: CanId = CanId::Standard(0x300);
    pub const THROTTLE_COMMAND: CanId = CanId::Standard(0x301);
    pub const STEERING_COMMAND: CanId = CanId::Standard(0x302);

    // Autonomous controller messages (0x400 - 0x4FF)
    pub const AUTO_STATUS: CanId = CanId::Standard(0x400);
    pub const AUTO_TRAJECTORY: CanId = CanId::Standard(0x401);
}

/// CAN Frame - standard CAN 2.0B format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanFrame {
    pub id: CanId,
    pub data: Vec<u8>, // 0-8 bytes
    pub timestamp: DateTime<Utc>,
    pub source: String, // ECU identifier
}

impl CanFrame {
    pub fn new(id: CanId, data: Vec<u8>, source: String) -> Self {
        Self {
            id,
            data,
            timestamp: Utc::now(),
            source,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.data.len() <= 8
    }
}

/// Helper functions for encoding/decoding automotive data
pub mod encoding {
    /// Encode wheel speed (in rad/s) to 2 bytes (0-655.35 rad/s, 0.01 resolution)
    pub fn encode_wheel_speed(speed_rad_per_sec: f32) -> [u8; 2] {
        let value = (speed_rad_per_sec * 100.0).clamp(0.0, 65535.0) as u16;
        value.to_be_bytes()
    }

    /// Decode wheel speed from 2 bytes to rad/s
    pub fn decode_wheel_speed(data: &[u8]) -> f32 {
        if data.len() < 2 {
            return 0.0;
        }
        let value = u16::from_be_bytes([data[0], data[1]]);
        value as f32 / 100.0
    }

    /// Encode engine RPM (0-16383 RPM, 0.25 resolution)
    pub fn encode_rpm(rpm: f32) -> [u8; 2] {
        let value = (rpm * 4.0).clamp(0.0, 65535.0) as u16;
        value.to_be_bytes()
    }

    /// Decode engine RPM from 2 bytes
    pub fn decode_rpm(data: &[u8]) -> f32 {
        if data.len() < 2 {
            return 0.0;
        }
        let value = u16::from_be_bytes([data[0], data[1]]);
        value as f32 / 4.0
    }

    /// Encode throttle position (0-100%, 1% resolution)
    pub fn encode_throttle(percent: f32) -> u8 {
        percent.clamp(0.0, 100.0) as u8
    }

    /// Decode throttle position
    pub fn decode_throttle(byte: u8) -> f32 {
        byte as f32
    }

    /// Encode steering angle (-780 to +780 degrees, 0.1 degree resolution)
    pub fn encode_steering_angle(degrees: f32) -> [u8; 2] {
        let value = ((degrees + 780.0) * 10.0).clamp(0.0, 15600.0) as u16;
        value.to_be_bytes()
    }

    /// Decode steering angle from 2 bytes
    pub fn decode_steering_angle(data: &[u8]) -> f32 {
        if data.len() < 2 {
            return 0.0;
        }
        let value = u16::from_be_bytes([data[0], data[1]]);
        (value as f32 / 10.0) - 780.0
    }

    /// Encode steering torque (-32 to +32 Nm, 0.001 resolution)
    pub fn encode_steering_torque(torque_nm: f32) -> [u8; 2] {
        let value = ((torque_nm + 32.0) * 1000.0).clamp(0.0, 64000.0) as u16;
        value.to_be_bytes()
    }

    /// Decode steering torque from 2 bytes
    pub fn decode_steering_torque(data: &[u8]) -> f32 {
        if data.len() < 2 {
            return 0.0;
        }
        let value = u16::from_be_bytes([data[0], data[1]]);
        (value as f32 / 1000.0) - 32.0
    }

    /// Encode brake pressure (0-100%, 1% resolution)
    pub fn encode_brake_pressure(percent: f32) -> u8 {
        percent.clamp(0.0, 100.0) as u8
    }

    /// Decode brake pressure
    pub fn decode_brake_pressure(byte: u8) -> f32 {
        byte as f32
    }
}

/// ECU Configuration
#[derive(Debug, Clone)]
pub struct EcuConfig {
    pub name: String,
    pub bus_address: String, // For network communication
    pub arm_variant: ArmVariant,
}

/// ARM Processor Variants (simplified for emulation)
#[derive(Debug, Clone, Copy)]
pub enum ArmVariant {
    CortexM4,  // Typical for sensor ECUs
    CortexM7,  // Higher-performance sensors/actuators
    CortexA53, // Application processors for autonomous controller
}

impl ArmVariant {
    pub fn as_str(&self) -> &str {
        match self {
            ArmVariant::CortexM4 => "ARM Cortex-M4",
            ArmVariant::CortexM7 => "ARM Cortex-M7",
            ArmVariant::CortexA53 => "ARM Cortex-A53",
        }
    }
}

/// Vehicle state aggregated from sensor data
#[derive(Debug, Clone, Default)]
pub struct VehicleState {
    pub wheel_speeds: [f32; 4], // FL, FR, RL, RR in rad/s
    pub engine_rpm: f32,
    pub throttle_position: f32,
    pub steering_angle: f32,
    pub steering_torque: f32,
    pub brake_pressure: f32,
    pub timestamp: Option<DateTime<Utc>>,
}

impl VehicleState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate average vehicle speed from wheel speeds (simplified)
    pub fn average_wheel_speed(&self) -> f32 {
        self.wheel_speeds.iter().sum::<f32>() / 4.0
    }

    /// Check if vehicle is moving
    pub fn is_moving(&self) -> bool {
        self.average_wheel_speed() > 0.1
    }

    /// Check if there's a wheel speed discrepancy (potential slip/skid)
    pub fn has_wheel_discrepancy(&self, threshold: f32) -> bool {
        let avg = self.average_wheel_speed();
        if avg < 0.1 {
            return false; // Not moving, no discrepancy
        }

        self.wheel_speeds.iter().any(|&speed| {
            let diff = (speed - avg).abs();
            diff / avg > threshold
        })
    }
}

/// CAN ID access control permissions for an ECU (ISO 21434 authorization model)
#[derive(Debug, Clone)]
pub struct CanIdPermissions {
    /// ECU identifier
    pub ecu_id: String,

    /// CAN IDs this ECU is allowed to transmit
    pub tx_whitelist: HashSet<u32>,

    /// CAN IDs this ECU is allowed to receive (None = receive all)
    pub rx_whitelist: Option<HashSet<u32>>,
}

impl CanIdPermissions {
    pub fn new(ecu_id: String) -> Self {
        Self {
            ecu_id,
            tx_whitelist: HashSet::new(),
            rx_whitelist: None, // Default: receive all
        }
    }

    /// Add a CAN ID to the transmit whitelist
    pub fn allow_tx(&mut self, can_id: u32) -> &mut Self {
        self.tx_whitelist.insert(can_id);
        self
    }

    /// Add multiple CAN IDs to the transmit whitelist
    pub fn allow_tx_multiple(&mut self, can_ids: &[u32]) -> &mut Self {
        for &id in can_ids {
            self.tx_whitelist.insert(id);
        }
        self
    }

    /// Add a CAN ID to the receive whitelist
    pub fn allow_rx(&mut self, can_id: u32) -> &mut Self {
        if self.rx_whitelist.is_none() {
            self.rx_whitelist = Some(HashSet::new());
        }
        self.rx_whitelist.as_mut().unwrap().insert(can_id);
        self
    }

    /// Add multiple CAN IDs to the receive whitelist
    pub fn allow_rx_multiple(&mut self, can_ids: &[u32]) -> &mut Self {
        if self.rx_whitelist.is_none() {
            self.rx_whitelist = Some(HashSet::new());
        }
        for &id in can_ids {
            self.rx_whitelist.as_mut().unwrap().insert(id);
        }
        self
    }

    /// Check if ECU is authorized to transmit on this CAN ID
    pub fn can_transmit(&self, can_id: u32) -> bool {
        self.tx_whitelist.contains(&can_id)
    }

    /// Check if ECU is authorized to receive this CAN ID
    pub fn can_receive(&self, can_id: u32) -> bool {
        match &self.rx_whitelist {
            None => true, // No RX filtering = receive all
            Some(whitelist) => whitelist.contains(&can_id),
        }
    }
}
