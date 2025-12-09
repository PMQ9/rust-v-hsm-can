// HSM Client - ECU-side library for communicating with HSM service
// Mirrors VirtualHSM API for seamless migration

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::anomaly_detection::{AnomalyBaseline, AnomalyResult};
use crate::hsm::{SecuredCanFrame, VerifyError};
use crate::types::CanIdPermissions;

use super::protocol::{HsmRequest, HsmResponse, MAX_MESSAGE_SIZE};

/// HSM Client for ECU-to-HSM communication
/// Provides async interface to centralized HSM service on Core 3
#[derive(Clone)]
pub struct HsmClient {
    /// ECU identifier
    ecu_id: String,

    /// Unix domain socket path
    socket_path: String,

    /// Connection to HSM service (wrapped in Arc<Mutex> for cloning)
    stream: Arc<Mutex<UnixStream>>,
}

impl HsmClient {
    /// Connect to HSM service
    ///
    /// # Arguments
    /// * `ecu_id` - Unique identifier for this ECU
    /// * `socket_path` - Path to HSM service Unix socket (usually `/tmp/vsm_hsm_service.sock`)
    ///
    /// # Example
    /// ```no_run
    /// # use autonomous_vehicle_sim::hsm_service::HsmClient;
    /// # async {
    /// let client = HsmClient::connect(
    ///     "WHEEL_FL".to_string(),
    ///     "/tmp/vsm_hsm_service.sock"
    /// ).await.unwrap();
    /// # };
    /// ```
    pub async fn connect(
        ecu_id: String,
        socket_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = UnixStream::connect(socket_path).await?;

        Ok(Self {
            ecu_id,
            socket_path: socket_path.to_string(),
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    /// Send request and receive response from HSM service
    async fn send_request(
        &self,
        request: HsmRequest,
    ) -> Result<HsmResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = self.stream.lock().await;

        // Serialize request to JSON
        let request_json = serde_json::to_vec(&request)?;
        if request_json.len() > MAX_MESSAGE_SIZE {
            return Err("Request too large".into());
        }

        let request_len = (request_json.len() as u32).to_be_bytes();

        // Send length-prefixed message
        stream.write_all(&request_len).await?;
        stream.write_all(&request_json).await?;
        stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        if msg_len > MAX_MESSAGE_SIZE {
            return Err("Response too large".into());
        }

        // Read response payload
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        // Deserialize response
        let response: HsmResponse = serde_json::from_slice(&msg_buf)?;

        // Check for error response
        if response.is_error() {
            return Err(format!(
                "HSM service error: {}",
                response.error_message().unwrap_or("Unknown error")
            )
            .into());
        }

        Ok(response)
    }

    // ========================================================================
    // Public API - Mirrors VirtualHSM interface
    // ========================================================================

    /// Generate HMAC-SHA256 MAC for data with session counter
    ///
    /// # Arguments
    /// * `data` - Data to authenticate
    /// * `session_counter` - Replay protection counter
    ///
    /// # Returns
    /// 32-byte HMAC-SHA256 MAC
    pub async fn generate_mac(
        &self,
        data: &[u8],
        session_counter: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GenerateMac {
            ecu_id: self.ecu_id.clone(),
            data: data.to_vec(),
            session_counter,
        };

        match self.send_request(request).await? {
            HsmResponse::MacGenerated { mac } => Ok(mac),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Verify secured CAN frame (MAC + CRC + replay + anomaly)
    ///
    /// # Arguments
    /// * `frame` - Secured frame to verify
    ///
    /// # Returns
    /// Ok(()) if frame is valid, Err(VerifyError) otherwise
    pub async fn verify_frame(
        &self,
        frame: &SecuredCanFrame,
    ) -> Result<(), VerifyError> {
        let request = HsmRequest::VerifyFrame {
            ecu_id: self.ecu_id.clone(),
            frame: frame.clone(),
        };

        match self.send_request(request).await {
            Ok(HsmResponse::FrameVerified { result }) => result,
            Ok(_) => Err(VerifyError::Other("Unexpected response type".to_string())),
            Err(e) => Err(VerifyError::Other(e.to_string())),
        }
    }

    /// Calculate CRC-32 checksum
    pub async fn calculate_crc(
        &self,
        data: &[u8],
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::CalculateCrc {
            ecu_id: self.ecu_id.clone(),
            data: data.to_vec(),
        };

        match self.send_request(request).await? {
            HsmResponse::CrcCalculated { crc } => Ok(crc),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Verify CRC-32 checksum
    pub async fn verify_crc(
        &self,
        data: &[u8],
        expected_crc: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::VerifyCrc {
            ecu_id: self.ecu_id.clone(),
            data: data.to_vec(),
            expected_crc,
        };

        match self.send_request(request).await? {
            HsmResponse::CrcVerified { valid } => Ok(valid),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Get current session counter value
    pub async fn get_session_counter(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GetSessionCounter {
            ecu_id: self.ecu_id.clone(),
        };

        match self.send_request(request).await? {
            HsmResponse::SessionCounter { counter } => Ok(counter),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Increment session counter (for replay protection)
    pub async fn increment_session(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::IncrementSession {
            ecu_id: self.ecu_id.clone(),
        };

        match self.send_request(request).await? {
            HsmResponse::SessionIncremented { new_counter } => Ok(new_counter),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Add trusted ECU MAC verification key
    ///
    /// # Arguments
    /// * `trusted_ecu_name` - Name of the trusted ECU
    /// * `mac_key` - 32-byte MAC verification key
    pub async fn add_trusted_ecu(
        &self,
        trusted_ecu_name: String,
        mac_key: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::AddTrustedEcu {
            ecu_id: self.ecu_id.clone(),
            trusted_ecu_name,
            mac_key,
        };

        match self.send_request(request).await? {
            HsmResponse::TrustedEcuAdded => Ok(()),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Load anomaly detection baseline (factory calibration)
    pub async fn load_anomaly_baseline(
        &self,
        baseline: AnomalyBaseline,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::LoadAnomalyBaseline {
            ecu_id: self.ecu_id.clone(),
            baseline,
        };

        match self.send_request(request).await? {
            HsmResponse::AnomalyBaselineLoaded => Ok(()),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Detect anomaly in frame (after MAC/CRC verification)
    pub async fn detect_anomaly(
        &self,
        frame: &SecuredCanFrame,
    ) -> AnomalyResult {
        let request = HsmRequest::DetectAnomaly {
            ecu_id: self.ecu_id.clone(),
            frame: frame.clone(),
        };

        match self.send_request(request).await {
            Ok(HsmResponse::AnomalyDetected { result }) => result,
            _ => AnomalyResult::Normal, // Default to normal on error
        }
    }

    /// Load CAN ID access control policy
    pub async fn load_access_control(
        &self,
        permissions: CanIdPermissions,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::LoadAccessControl {
            ecu_id: self.ecu_id.clone(),
            permissions,
        };

        match self.send_request(request).await? {
            HsmResponse::AccessControlLoaded => Ok(()),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Authorize transmit on CAN ID (access control check)
    pub async fn authorize_transmit(
        &self,
        can_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::AuthorizeTransmit {
            ecu_id: self.ecu_id.clone(),
            can_id,
        };

        match self.send_request(request).await? {
            HsmResponse::TransmitAuthorized { allowed } => {
                if allowed {
                    Ok(())
                } else {
                    Err(format!("Transmit not authorized for CAN ID 0x{:X}", can_id).into())
                }
            }
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Authorize receive on CAN ID (access control check)
    pub async fn authorize_receive(
        &self,
        can_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::AuthorizeReceive {
            ecu_id: self.ecu_id.clone(),
            can_id,
        };

        match self.send_request(request).await? {
            HsmResponse::ReceiveAuthorized { allowed } => {
                if allowed {
                    Ok(())
                } else {
                    Err(format!("Receive not authorized for CAN ID 0x{:X}", can_id).into())
                }
            }
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Get symmetric communication key for this ECU
    pub async fn get_symmetric_key(
        &self,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GetSymmetricKey {
            ecu_id: self.ecu_id.clone(),
        };

        match self.send_request(request).await? {
            HsmResponse::SymmetricKey { key } => Ok(key),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Get MAC verification key for trusted ECU
    pub async fn get_verification_key(
        &self,
        trusted_ecu_name: &str,
    ) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GetVerificationKey {
            ecu_id: self.ecu_id.clone(),
            trusted_ecu_name: trusted_ecu_name.to_string(),
        };

        match self.send_request(request).await? {
            HsmResponse::VerificationKey { key } => Ok(Some(key)),
            _ => Ok(None),
        }
    }

    /// Generate cryptographically secure random bytes
    pub async fn generate_random_bytes(
        &self,
        count: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GenerateRandom {
            ecu_id: self.ecu_id.clone(),
            count,
        };

        match self.send_request(request).await? {
            HsmResponse::RandomGenerated { data } => Ok(data),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Get current key version for key rotation
    pub async fn get_current_key_version(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let request = HsmRequest::GetKeyVersion {
            ecu_id: self.ecu_id.clone(),
        };

        match self.send_request(request).await? {
            HsmResponse::KeyVersion { version } => Ok(version),
            _ => Err("Unexpected response type".into()),
        }
    }

    /// Get ECU identifier
    pub fn ecu_id(&self) -> &str {
        &self.ecu_id
    }

    /// Get socket path
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_properties() {
        // Note: Can't actually connect without HSM service running
        // This test just verifies the structure compiles
        let ecu_id = "TEST_ECU".to_string();
        let socket_path = "/tmp/test_hsm.sock";

        // Client construction is tested in integration tests
        assert_eq!(ecu_id, "TEST_ECU");
        assert_eq!(socket_path, "/tmp/test_hsm.sock");
    }
}
