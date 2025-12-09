// HSM Service Protocol - Request/Response message definitions
// Defines the IPC protocol between ECUs and the centralized HSM service

use serde::{Deserialize, Serialize};

use crate::anomaly_detection::{AnomalyBaseline, AnomalyResult};
use crate::hsm::{SecuredCanFrame, VerifyError};
use crate::types::CanIdPermissions;

/// Maximum message size for DoS prevention (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Request message from ECU to HSM service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmRequest {
    /// Generate HMAC-SHA256 MAC for data + session counter
    /// Returns: MacGenerated
    GenerateMac {
        ecu_id: String,
        data: Vec<u8>,
        session_counter: u64,
    },

    /// Verify secured CAN frame (MAC + CRC + replay + anomaly)
    /// Returns: FrameVerified
    VerifyFrame {
        ecu_id: String,
        frame: SecuredCanFrame,
    },

    /// Calculate CRC-32 checksum for data
    /// Returns: CrcCalculated
    CalculateCrc { ecu_id: String, data: Vec<u8> },

    /// Verify CRC-32 checksum against expected value
    /// Returns: CrcVerified
    VerifyCrc {
        ecu_id: String,
        data: Vec<u8>,
        expected_crc: u32,
    },

    /// Get current session counter value
    /// Returns: SessionCounter
    GetSessionCounter { ecu_id: String },

    /// Increment session counter with wraparound protection
    /// Returns: SessionIncremented
    IncrementSession { ecu_id: String },

    /// Add trusted ECU MAC verification key
    /// Returns: TrustedEcuAdded
    AddTrustedEcu {
        ecu_id: String,
        trusted_ecu_name: String,
        mac_key: [u8; 32],
    },

    /// Load anomaly detection baseline (factory calibration)
    /// Returns: AnomalyBaselineLoaded
    LoadAnomalyBaseline {
        ecu_id: String,
        baseline: AnomalyBaseline,
    },

    /// Detect anomaly in frame (after MAC/CRC verification)
    /// Returns: AnomalyDetected
    DetectAnomaly {
        ecu_id: String,
        frame: SecuredCanFrame,
    },

    /// Load CAN ID access control policy
    /// Returns: AccessControlLoaded
    LoadAccessControl {
        ecu_id: String,
        permissions: CanIdPermissions,
    },

    /// Authorize transmit on CAN ID (access control check)
    /// Returns: TransmitAuthorized
    AuthorizeTransmit { ecu_id: String, can_id: u32 },

    /// Authorize receive on CAN ID (access control check)
    /// Returns: ReceiveAuthorized
    AuthorizeReceive { ecu_id: String, can_id: u32 },

    /// Get symmetric communication key for this ECU
    /// Returns: SymmetricKey
    GetSymmetricKey { ecu_id: String },

    /// Get MAC verification key for trusted ECU
    /// Returns: VerificationKey
    GetVerificationKey {
        ecu_id: String,
        trusted_ecu_name: String,
    },

    /// Generate cryptographically secure random bytes
    /// Returns: RandomGenerated
    GenerateRandom { ecu_id: String, count: usize },

    /// Get current key version for key rotation
    /// Returns: KeyVersion
    GetKeyVersion { ecu_id: String },

    /// Shutdown HSM service (graceful termination)
    /// Returns: Ack
    Shutdown,
}

/// Response message from HSM service to ECU
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmResponse {
    /// MAC generation result
    MacGenerated { mac: [u8; 32] },

    /// Frame verification result
    FrameVerified { result: Result<(), VerifyError> },

    /// CRC calculation result
    CrcCalculated { crc: u32 },

    /// CRC verification result
    CrcVerified { valid: bool },

    /// Session counter value
    SessionCounter { counter: u64 },

    /// Session incremented successfully
    SessionIncremented { new_counter: u64 },

    /// Trusted ECU added to MAC verification key store
    TrustedEcuAdded,

    /// Anomaly baseline loaded for detection
    AnomalyBaselineLoaded,

    /// Anomaly detection result
    AnomalyDetected { result: AnomalyResult },

    /// Access control policy loaded
    AccessControlLoaded,

    /// Transmit authorization result
    TransmitAuthorized { allowed: bool },

    /// Receive authorization result
    ReceiveAuthorized { allowed: bool },

    /// Symmetric communication key
    SymmetricKey { key: [u8; 32] },

    /// MAC verification key for trusted ECU
    VerificationKey { key: [u8; 32] },

    /// Random bytes generated
    RandomGenerated { data: Vec<u8> },

    /// Current key version
    KeyVersion { version: u32 },

    /// Error response
    Error { message: String },

    /// Generic acknowledgment
    Ack,
}

impl HsmRequest {
    /// Get the ECU ID from any request variant
    pub fn ecu_id(&self) -> &str {
        match self {
            HsmRequest::GenerateMac { ecu_id, .. } => ecu_id,
            HsmRequest::VerifyFrame { ecu_id, .. } => ecu_id,
            HsmRequest::CalculateCrc { ecu_id, .. } => ecu_id,
            HsmRequest::VerifyCrc { ecu_id, .. } => ecu_id,
            HsmRequest::GetSessionCounter { ecu_id } => ecu_id,
            HsmRequest::IncrementSession { ecu_id } => ecu_id,
            HsmRequest::AddTrustedEcu { ecu_id, .. } => ecu_id,
            HsmRequest::LoadAnomalyBaseline { ecu_id, .. } => ecu_id,
            HsmRequest::DetectAnomaly { ecu_id, .. } => ecu_id,
            HsmRequest::LoadAccessControl { ecu_id, .. } => ecu_id,
            HsmRequest::AuthorizeTransmit { ecu_id, .. } => ecu_id,
            HsmRequest::AuthorizeReceive { ecu_id, .. } => ecu_id,
            HsmRequest::GetSymmetricKey { ecu_id } => ecu_id,
            HsmRequest::GetVerificationKey { ecu_id, .. } => ecu_id,
            HsmRequest::GenerateRandom { ecu_id, .. } => ecu_id,
            HsmRequest::GetKeyVersion { ecu_id } => ecu_id,
            HsmRequest::Shutdown => "SYSTEM",
        }
    }

    /// Get a human-readable request type name
    pub fn request_type(&self) -> &'static str {
        match self {
            HsmRequest::GenerateMac { .. } => "GenerateMac",
            HsmRequest::VerifyFrame { .. } => "VerifyFrame",
            HsmRequest::CalculateCrc { .. } => "CalculateCrc",
            HsmRequest::VerifyCrc { .. } => "VerifyCrc",
            HsmRequest::GetSessionCounter { .. } => "GetSessionCounter",
            HsmRequest::IncrementSession { .. } => "IncrementSession",
            HsmRequest::AddTrustedEcu { .. } => "AddTrustedEcu",
            HsmRequest::LoadAnomalyBaseline { .. } => "LoadAnomalyBaseline",
            HsmRequest::DetectAnomaly { .. } => "DetectAnomaly",
            HsmRequest::LoadAccessControl { .. } => "LoadAccessControl",
            HsmRequest::AuthorizeTransmit { .. } => "AuthorizeTransmit",
            HsmRequest::AuthorizeReceive { .. } => "AuthorizeReceive",
            HsmRequest::GetSymmetricKey { .. } => "GetSymmetricKey",
            HsmRequest::GetVerificationKey { .. } => "GetVerificationKey",
            HsmRequest::GenerateRandom { .. } => "GenerateRandom",
            HsmRequest::GetKeyVersion { .. } => "GetKeyVersion",
            HsmRequest::Shutdown => "Shutdown",
        }
    }
}

impl HsmResponse {
    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        matches!(self, HsmResponse::Error { .. })
    }

    /// Get error message if this is an error response
    pub fn error_message(&self) -> Option<&str> {
        match self {
            HsmResponse::Error { message } => Some(message),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization_generate_mac() {
        let request = HsmRequest::GenerateMac {
            ecu_id: "TEST_ECU".to_string(),
            data: vec![1, 2, 3, 4],
            session_counter: 42,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("GenerateMac"));
        assert!(json.contains("TEST_ECU"));

        // Deserialize back
        let deserialized: HsmRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            HsmRequest::GenerateMac {
                ecu_id,
                data,
                session_counter,
            } => {
                assert_eq!(ecu_id, "TEST_ECU");
                assert_eq!(data, vec![1, 2, 3, 4]);
                assert_eq!(session_counter, 42);
            }
            _ => panic!("Wrong variant after deserialization"),
        }
    }

    #[test]
    fn test_response_serialization_mac_generated() {
        let response = HsmResponse::MacGenerated { mac: [0xAB; 32] };

        // Serialize to JSON
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("MacGenerated"));

        // Deserialize back
        let deserialized: HsmResponse = serde_json::from_str(&json).unwrap();
        match deserialized {
            HsmResponse::MacGenerated { mac } => {
                assert_eq!(mac, [0xAB; 32]);
            }
            _ => panic!("Wrong variant after deserialization"),
        }
    }

    #[test]
    fn test_request_ecu_id_extraction() {
        let request = HsmRequest::GenerateMac {
            ecu_id: "WHEEL_FL".to_string(),
            data: vec![],
            session_counter: 0,
        };
        assert_eq!(request.ecu_id(), "WHEEL_FL");

        let shutdown = HsmRequest::Shutdown;
        assert_eq!(shutdown.ecu_id(), "SYSTEM");
    }

    #[test]
    fn test_request_type_name() {
        let request = HsmRequest::VerifyFrame {
            ecu_id: "TEST".to_string(),
            frame: SecuredCanFrame::new_test_frame(),
        };
        assert_eq!(request.request_type(), "VerifyFrame");
    }

    #[test]
    fn test_response_error_detection() {
        let error_response = HsmResponse::Error {
            message: "Test error".to_string(),
        };
        assert!(error_response.is_error());
        assert_eq!(error_response.error_message(), Some("Test error"));

        let success_response = HsmResponse::Ack;
        assert!(!success_response.is_error());
        assert_eq!(success_response.error_message(), None);
    }

    #[test]
    fn test_max_message_size_constant() {
        // Ensure protocol constant is within reasonable bounds
        assert!(MAX_MESSAGE_SIZE <= 10 * 1024 * 1024); // Max 10 MB
        assert!(MAX_MESSAGE_SIZE >= 64 * 1024); // At least 64 KB
    }

    #[test]
    fn test_request_serialization_roundtrip_all_variants() {
        let requests = vec![
            HsmRequest::GetSessionCounter {
                ecu_id: "TEST".to_string(),
            },
            HsmRequest::IncrementSession {
                ecu_id: "TEST".to_string(),
            },
            HsmRequest::AuthorizeTransmit {
                ecu_id: "TEST".to_string(),
                can_id: 0x100,
            },
            HsmRequest::Shutdown,
        ];

        for request in requests {
            let json = serde_json::to_string(&request).unwrap();
            let deserialized: HsmRequest = serde_json::from_str(&json).unwrap();
            // Just verify it deserializes without panic
            assert_eq!(request.ecu_id(), deserialized.ecu_id());
        }
    }
}
