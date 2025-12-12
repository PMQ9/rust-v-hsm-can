// HSM Service Server - Centralized cryptographic service running on Core 3
// Handles all MAC generation, verification, and security operations for ECUs

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use colored::*;

use super::protocol::{HsmRequest, HsmResponse, MAX_MESSAGE_SIZE};
use crate::hsm::VirtualHSM;

/// HSM Service Server running on dedicated Core 3
/// Maintains per-ECU HSM instances and processes crypto requests
pub struct HsmServiceServer {
    /// Per-ECU HSM instances (isolated cryptographic state)
    hsm_instances: Arc<Mutex<HashMap<String, VirtualHSM>>>,

    /// Unix domain socket path
    socket_path: String,

    /// Performance tracking mode
    perf_mode: bool,
}

impl HsmServiceServer {
    /// Create new HSM service server
    pub fn new(socket_path: String, perf_mode: bool) -> Self {
        Self {
            hsm_instances: Arc::new(Mutex::new(HashMap::new())),
            socket_path,
            perf_mode,
        }
    }

    /// Start HSM service and listen for connections
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove old socket if exists
        let socket_path_obj = Path::new(&self.socket_path);
        if socket_path_obj.exists() {
            std::fs::remove_file(socket_path_obj)?;
        }

        println!(
            "{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!(
            "{}",
            "        HSM SERVICE (Core 3)           ".cyan().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!("{} Socket: {}", "→".cyan(), self.socket_path.bright_white());
        println!("{} Performance mode: {}", "→".cyan(), self.perf_mode);
        println!();

        // Bind Unix domain socket
        let listener = UnixListener::bind(&self.socket_path)?;
        println!("{} HSM Service listening", "✓".green().bold());
        println!("{} Ready to accept ECU connections", "→".cyan());
        println!();

        // Accept connections loop
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    // Clone Arc pointers for the spawned task
                    let hsm_map = Arc::clone(&self.hsm_instances);
                    let perf_mode = self.perf_mode;

                    // Spawn handler task for this connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, hsm_map, perf_mode).await {
                            eprintln!("{} Connection error: {}", "✗".red(), e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("{} Accept error: {}", "✗".red(), e);
                }
            }
        }
    }

    /// Handle single ECU connection
    async fn handle_connection(
        mut stream: UnixStream,
        hsm_map: Arc<Mutex<HashMap<String, VirtualHSM>>>,
        perf_mode: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            // Read length prefix (4 bytes, big-endian)
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Connection closed gracefully
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > MAX_MESSAGE_SIZE {
                return Err(format!("Message too large: {} bytes", msg_len).into());
            }

            // Read JSON payload
            let mut msg_buf = vec![0u8; msg_len];
            stream.read_exact(&mut msg_buf).await?;

            // Deserialize request
            let request: HsmRequest = match serde_json::from_slice(&msg_buf) {
                Ok(req) => req,
                Err(e) => {
                    // Send error response
                    let error_response = HsmResponse::Error {
                        message: format!("Failed to parse request: {}", e),
                    };
                    Self::send_response(&mut stream, &error_response).await?;
                    continue;
                }
            };

            // Process request
            let response = Self::process_request(request, &hsm_map, perf_mode).await;

            // Send response
            Self::send_response(&mut stream, &response).await?;
        }

        Ok(())
    }

    /// Send response to client (length-prefixed JSON)
    async fn send_response(
        stream: &mut UnixStream,
        response: &HsmResponse,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize response
        let response_json = serde_json::to_vec(response)?;
        let response_len = (response_json.len() as u32).to_be_bytes();

        // Send length prefix + payload
        stream.write_all(&response_len).await?;
        stream.write_all(&response_json).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Process HSM request and generate response
    async fn process_request(
        request: HsmRequest,
        hsm_map: &Arc<Mutex<HashMap<String, VirtualHSM>>>,
        perf_mode: bool,
    ) -> HsmResponse {
        use HsmRequest::*;
        use HsmResponse as Resp;

        match request {
            GenerateMac {
                ecu_id,
                data,
                session_counter,
            } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let mac = hsm.generate_mac(&data, session_counter);
                Resp::MacGenerated { mac }
            }

            VerifyFrame { ecu_id: _, frame } => {
                // IMPORTANT: Use sender's ECU ID (frame.source) for verification,
                // not the receiver's ECU ID. Frames are signed with sender's keys.
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&frame.source, &mut map, perf_mode);
                let result = frame.verify(hsm);
                Resp::FrameVerified { result }
            }

            CalculateCrc { ecu_id: _, data } => {
                // Direct CRC32 calculation (same algorithm as hsm/crypto.rs)
                let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&data);
                Resp::CrcCalculated { crc }
            }

            VerifyCrc {
                ecu_id: _,
                data,
                expected_crc,
            } => {
                // Direct CRC32 verification
                let calculated = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&data);
                let valid = calculated == expected_crc;
                Resp::CrcVerified { valid }
            }

            GetSessionCounter { ecu_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let counter = hsm.get_session_counter();
                Resp::SessionCounter { counter }
            }

            IncrementSession { ecu_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                hsm.increment_session();
                let new_counter = hsm.get_session_counter();
                Resp::SessionIncremented { new_counter }
            }

            AddTrustedEcu {
                ecu_id,
                trusted_ecu_name,
                mac_key,
            } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                hsm.add_trusted_ecu(trusted_ecu_name, mac_key);
                Resp::TrustedEcuAdded
            }

            LoadAnomalyBaseline { ecu_id, baseline } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                match hsm.load_anomaly_baseline(baseline) {
                    Ok(_) => Resp::AnomalyBaselineLoaded,
                    Err(e) => Resp::Error {
                        message: format!("Failed to load baseline: {}", e),
                    },
                }
            }

            DetectAnomaly { ecu_id: _, frame } => {
                // IMPORTANT: Use sender's ECU ID (frame.source) for anomaly detection,
                // since anomaly baselines are trained per sender ECU
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&frame.source, &mut map, perf_mode);
                let result = hsm.detect_anomaly(&frame);
                Resp::AnomalyDetected { result }
            }

            LoadAccessControl {
                ecu_id,
                permissions,
            } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                hsm.load_access_control(permissions);
                Resp::AccessControlLoaded
            }

            AuthorizeTransmit { ecu_id, can_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let allowed = hsm.authorize_transmit(can_id).is_ok();
                Resp::TransmitAuthorized { allowed }
            }

            AuthorizeReceive { ecu_id, can_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let allowed = hsm.authorize_receive(can_id).is_ok();
                Resp::ReceiveAuthorized { allowed }
            }

            GetSymmetricKey { ecu_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let key = *hsm.get_symmetric_key();
                Resp::SymmetricKey { key }
            }

            GetVerificationKey {
                ecu_id,
                trusted_ecu_name,
            } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                // Use key_version=0 for legacy behavior (current key)
                match hsm.get_verification_key_by_version(&trusted_ecu_name, 0) {
                    Some(key) => Resp::VerificationKey { key },
                    None => Resp::Error {
                        message: format!("No verification key for {}", trusted_ecu_name),
                    },
                }
            }

            GenerateRandom { ecu_id, count } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let mut data = vec![0u8; count];
                hsm.generate_random_bytes(&mut data);
                Resp::RandomGenerated { data }
            }

            GetKeyVersion { ecu_id } => {
                let mut map = hsm_map.lock().await;
                let hsm = Self::get_or_create_hsm(&ecu_id, &mut map, perf_mode);
                let version = hsm.get_current_key_version();
                Resp::KeyVersion { version }
            }

            Shutdown => {
                println!("\n{} Shutdown request received", "→".yellow());
                println!("{} HSM Service shutting down", "→".yellow());
                std::process::exit(0);
            }
        }
    }

    /// Get or lazily create HSM instance for ECU
    fn get_or_create_hsm<'a>(
        ecu_id: &str,
        hsm_map: &'a mut HashMap<String, VirtualHSM>,
        perf_mode: bool,
    ) -> &'a mut VirtualHSM {
        hsm_map.entry(ecu_id.to_string()).or_insert_with(|| {
            // Create new HSM instance with hardware RNG for production security
            // Seed is derived from ECU name hash for reproducibility
            let seed = Self::derive_seed_from_ecu_name(ecu_id);

            let hsm = if perf_mode {
                VirtualHSM::with_performance(ecu_id.to_string(), seed, true)
            } else {
                VirtualHSM::new(ecu_id.to_string(), seed)
            };

            println!(
                "{} Created HSM instance for {}",
                "→".cyan(),
                ecu_id.bright_white()
            );

            hsm
        })
    }

    /// Derive deterministic seed from ECU name for HSM initialization
    fn derive_seed_from_ecu_name(ecu_name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        ecu_name.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed_from_ecu_name() {
        let seed1 = HsmServiceServer::derive_seed_from_ecu_name("WHEEL_FL");
        let seed2 = HsmServiceServer::derive_seed_from_ecu_name("WHEEL_FL");
        let seed3 = HsmServiceServer::derive_seed_from_ecu_name("WHEEL_FR");

        // Same name produces same seed (deterministic)
        assert_eq!(seed1, seed2);

        // Different names produce different seeds
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_server_creation() {
        let server = HsmServiceServer::new("/tmp/test_hsm.sock".to_string(), false);
        assert_eq!(server.socket_path, "/tmp/test_hsm.sock");
        assert!(!server.perf_mode);
    }
}
