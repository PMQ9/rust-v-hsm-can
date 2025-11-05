use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// CAN Frame identifier (11-bit standard or 29-bit extended)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    CortexM4,
    CortexM7,
    CortexA53,
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
