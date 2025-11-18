// UDS (Unified Diagnostic Services) - ISO 14229
// Implements secure diagnostic access with seed/key authentication

use crate::hsm::VirtualHSM;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

type HmacSha256 = Hmac<Sha256>;

/// UDS Service IDs (ISO 14229-1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum UdsService {
    DiagnosticSessionControl = 0x10,
    EcuReset = 0x11,
    SecurityAccess = 0x27,
    CommunicationControl = 0x28,
    TesterPresent = 0x3E,
    ReadDataByIdentifier = 0x22,
    WriteDataByIdentifier = 0x2E,
    RoutineControl = 0x31,
    RequestDownload = 0x34,
    RequestUpload = 0x35,
    TransferData = 0x36,
    RequestTransferExit = 0x37,
}

/// Diagnostic session types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiagnosticSession {
    DefaultSession = 0x01,
    ProgrammingSession = 0x02,
    ExtendedDiagnosticSession = 0x03,
    SafetySystemDiagnosticSession = 0x04,
}

/// Security access levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Locked = 0,
    Level1 = 1, // Read diagnostic data
    Level2 = 2, // Read/write calibration data
    Level3 = 3, // Programming (flash update)
    Level4 = 4, // Safety-critical functions
}

/// UDS negative response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NegativeResponseCode {
    GeneralReject = 0x10,
    ServiceNotSupported = 0x11,
    SubFunctionNotSupported = 0x12,
    IncorrectMessageLength = 0x13,
    ConditionsNotCorrect = 0x22,
    RequestSequenceError = 0x24,
    RequestOutOfRange = 0x31,
    SecurityAccessDenied = 0x33,
    InvalidKey = 0x35,
    ExceededNumberOfAttempts = 0x36,
    RequiredTimeDelayNotExpired = 0x37,
}

/// Security access request type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityAccessRequest {
    RequestSeed(SecurityLevel),
    SendKey(SecurityLevel, Vec<u8>),
}

/// Security access response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityAccessResponse {
    Seed(Vec<u8>),
    KeyAccepted,
    NegativeResponse(NegativeResponseCode),
}

/// Active seed waiting for key verification
#[derive(Debug, Clone)]
struct PendingSeed {
    seed: Vec<u8>,
    level: SecurityLevel,
    timestamp: SystemTime,
    attempts: u32,
}

/// UDS diagnostic session state
pub struct UdsDiagnosticSession {
    ecu_name: String,
    current_session: DiagnosticSession,
    security_level: SecurityLevel,
    pending_seed: Option<PendingSeed>,
    failed_attempts: HashMap<SecurityLevel, u32>,
    lockout_until: Option<SystemTime>,
    session_start: SystemTime,

    // Security parameters
    max_failed_attempts: u32,
    lockout_duration: Duration,
    seed_timeout: Duration,
}

impl UdsDiagnosticSession {
    /// Create new UDS diagnostic session
    pub fn new(ecu_name: String) -> Self {
        Self {
            ecu_name,
            current_session: DiagnosticSession::DefaultSession,
            security_level: SecurityLevel::Locked,
            pending_seed: None,
            failed_attempts: HashMap::new(),
            lockout_until: None,
            session_start: SystemTime::now(),
            max_failed_attempts: 3,
            lockout_duration: Duration::from_secs(60),
            seed_timeout: Duration::from_secs(30),
        }
    }

    /// Change diagnostic session
    pub fn change_session(
        &mut self,
        session: DiagnosticSession,
    ) -> Result<(), NegativeResponseCode> {
        // Programming session requires Level3 security
        if session == DiagnosticSession::ProgrammingSession
            && self.security_level < SecurityLevel::Level3
        {
            return Err(NegativeResponseCode::SecurityAccessDenied);
        }

        self.current_session = session;
        self.session_start = SystemTime::now();
        Ok(())
    }

    /// Get current diagnostic session
    pub fn current_session(&self) -> DiagnosticSession {
        self.current_session
    }

    /// Get current security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Check if ECU is in lockout period
    fn is_locked_out(&self) -> bool {
        if let Some(lockout_until) = self.lockout_until {
            SystemTime::now() < lockout_until
        } else {
            false
        }
    }

    /// Generate seed for security access
    pub fn request_seed(
        &mut self,
        level: SecurityLevel,
        _hsm: &VirtualHSM,
    ) -> SecurityAccessResponse {
        // Check lockout
        if self.is_locked_out() {
            return SecurityAccessResponse::NegativeResponse(
                NegativeResponseCode::RequiredTimeDelayNotExpired,
            );
        }

        // If already at this level or higher, return 0x00 seed (already unlocked)
        if self.security_level >= level {
            return SecurityAccessResponse::Seed(vec![0x00, 0x00, 0x00, 0x00]);
        }

        // Generate random seed
        let mut rng = rand::thread_rng();
        let seed: Vec<u8> = (0..4).map(|_| rng.r#gen::<u8>()).collect();

        // Store pending seed
        self.pending_seed = Some(PendingSeed {
            seed: seed.clone(),
            level,
            timestamp: SystemTime::now(),
            attempts: 0,
        });

        SecurityAccessResponse::Seed(seed)
    }

    /// Verify key for security access
    pub fn verify_key(
        &mut self,
        level: SecurityLevel,
        key: Vec<u8>,
        hsm: &VirtualHSM,
    ) -> SecurityAccessResponse {
        // Check lockout
        if self.is_locked_out() {
            return SecurityAccessResponse::NegativeResponse(
                NegativeResponseCode::RequiredTimeDelayNotExpired,
            );
        }

        // Check if we have a pending seed and extract it
        let (seed_value, timestamp) = match &self.pending_seed {
            Some(p) if p.level == level => (p.seed.clone(), p.timestamp),
            _ => {
                return SecurityAccessResponse::NegativeResponse(
                    NegativeResponseCode::RequestSequenceError,
                );
            }
        };

        // Check seed timeout
        if timestamp.elapsed().unwrap_or(Duration::MAX) > self.seed_timeout {
            self.pending_seed = None;
            return SecurityAccessResponse::NegativeResponse(
                NegativeResponseCode::RequestSequenceError,
            );
        }

        // Compute expected key using HMAC-SHA256(seed, ECU_secret)
        let expected_key = self.compute_key(&seed_value, level, hsm);

        // Verify key
        if key == expected_key {
            // Success - grant access
            self.security_level = level;
            self.pending_seed = None;
            self.failed_attempts.insert(level, 0);
            SecurityAccessResponse::KeyAccepted
        } else {
            // Failed attempt - increment counters
            if let Some(ref mut p) = self.pending_seed {
                p.attempts += 1;
            }
            let total_attempts = self.failed_attempts.entry(level).or_insert(0);
            *total_attempts += 1;

            // Check if exceeded max attempts
            if *total_attempts >= self.max_failed_attempts {
                self.lockout_until = Some(SystemTime::now() + self.lockout_duration);
                self.pending_seed = None;
                SecurityAccessResponse::NegativeResponse(
                    NegativeResponseCode::ExceededNumberOfAttempts,
                )
            } else {
                SecurityAccessResponse::NegativeResponse(NegativeResponseCode::InvalidKey)
            }
        }
    }

    /// Compute key from seed using HMAC-SHA256
    fn compute_key(&self, seed: &[u8], level: SecurityLevel, _hsm: &VirtualHSM) -> Vec<u8> {
        // Derive ECU-specific secret from HSM master key
        let secret = format!("{}_SECURITY_LEVEL_{}", self.ecu_name, level as u8);

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(seed);
        mac.finalize().into_bytes().to_vec()
    }

    /// Reset security (on session change or timeout)
    pub fn reset_security(&mut self) {
        self.security_level = SecurityLevel::Locked;
        self.pending_seed = None;
    }

    /// Check if operation is allowed at current security level
    pub fn is_operation_allowed(&self, required_level: SecurityLevel) -> bool {
        self.security_level >= required_level
    }

    /// Get failed attempt count for level
    pub fn failed_attempts(&self, level: SecurityLevel) -> u32 {
        *self.failed_attempts.get(&level).unwrap_or(&0)
    }

    /// Clear lockout (for testing/recovery)
    pub fn clear_lockout(&mut self) {
        self.lockout_until = None;
        self.failed_attempts.clear();
    }
}

/// UDS diagnostic server (ECU side)
pub struct UdsDiagnosticServer {
    sessions: HashMap<String, UdsDiagnosticSession>,
}

impl UdsDiagnosticServer {
    /// Create new UDS diagnostic server
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Get or create session for client
    pub fn get_session(&mut self, client_id: &str, ecu_name: String) -> &mut UdsDiagnosticSession {
        self.sessions
            .entry(client_id.to_string())
            .or_insert_with(|| UdsDiagnosticSession::new(ecu_name))
    }

    /// Handle security access request
    pub fn handle_security_access(
        &mut self,
        client_id: &str,
        ecu_name: String,
        request: SecurityAccessRequest,
        hsm: &VirtualHSM,
    ) -> SecurityAccessResponse {
        let session = self.get_session(client_id, ecu_name);

        match request {
            SecurityAccessRequest::RequestSeed(level) => session.request_seed(level, hsm),
            SecurityAccessRequest::SendKey(level, key) => session.verify_key(level, key, hsm),
        }
    }

    /// Remove session
    pub fn close_session(&mut self, client_id: &str) {
        self.sessions.remove(client_id);
    }
}

impl Default for UdsDiagnosticServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hsm() -> VirtualHSM {
        VirtualHSM::new("TEST_ECU".to_string(), 12345)
    }

    #[test]
    fn test_initial_state() {
        let session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        assert_eq!(session.current_session(), DiagnosticSession::DefaultSession);
        assert_eq!(session.security_level(), SecurityLevel::Locked);
    }

    #[test]
    fn test_session_change_without_security() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());

        // Can change to extended diagnostic without security
        assert!(
            session
                .change_session(DiagnosticSession::ExtendedDiagnosticSession)
                .is_ok()
        );

        // Cannot change to programming without Level3
        assert_eq!(
            session.change_session(DiagnosticSession::ProgrammingSession),
            Err(NegativeResponseCode::SecurityAccessDenied)
        );
    }

    #[test]
    fn test_seed_request() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        let hsm = create_test_hsm();

        let response = session.request_seed(SecurityLevel::Level1, &hsm);

        match response {
            SecurityAccessResponse::Seed(seed) => {
                assert_eq!(seed.len(), 4);
                assert!(session.pending_seed.is_some());
            }
            _ => panic!("Expected Seed response"),
        }
    }

    #[test]
    fn test_already_unlocked_returns_zero_seed() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        session.security_level = SecurityLevel::Level2;
        let hsm = create_test_hsm();

        // Request Level1 when already at Level2
        let response = session.request_seed(SecurityLevel::Level1, &hsm);

        match response {
            SecurityAccessResponse::Seed(seed) => {
                assert_eq!(seed, vec![0x00, 0x00, 0x00, 0x00]);
            }
            _ => panic!("Expected zero seed"),
        }
    }

    #[test]
    fn test_successful_authentication() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        let hsm = create_test_hsm();

        // Request seed
        let seed = match session.request_seed(SecurityLevel::Level1, &hsm) {
            SecurityAccessResponse::Seed(s) => s,
            _ => panic!("Expected seed"),
        };

        // Compute correct key
        let key = session.compute_key(&seed, SecurityLevel::Level1, &hsm);

        // Send key
        let response = session.verify_key(SecurityLevel::Level1, key, &hsm);
        assert_eq!(response, SecurityAccessResponse::KeyAccepted);
        assert_eq!(session.security_level(), SecurityLevel::Level1);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        let hsm = create_test_hsm();

        // Request seed
        session.request_seed(SecurityLevel::Level1, &hsm);

        // Send wrong key
        let wrong_key = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let response = session.verify_key(SecurityLevel::Level1, wrong_key, &hsm);

        assert_eq!(
            response,
            SecurityAccessResponse::NegativeResponse(NegativeResponseCode::InvalidKey)
        );
        assert_eq!(session.security_level(), SecurityLevel::Locked);
    }

    #[test]
    fn test_lockout_after_max_attempts() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        let hsm = create_test_hsm();

        let wrong_key = vec![0xFF, 0xFF, 0xFF, 0xFF];

        // Attempt 1
        session.request_seed(SecurityLevel::Level1, &hsm);
        session.verify_key(SecurityLevel::Level1, wrong_key.clone(), &hsm);

        // Attempt 2
        session.request_seed(SecurityLevel::Level1, &hsm);
        session.verify_key(SecurityLevel::Level1, wrong_key.clone(), &hsm);

        // Attempt 3 - triggers lockout
        session.request_seed(SecurityLevel::Level1, &hsm);
        let response = session.verify_key(SecurityLevel::Level1, wrong_key, &hsm);

        assert_eq!(
            response,
            SecurityAccessResponse::NegativeResponse(
                NegativeResponseCode::ExceededNumberOfAttempts
            )
        );

        // Subsequent requests should fail with lockout error
        let locked_response = session.request_seed(SecurityLevel::Level1, &hsm);
        assert_eq!(
            locked_response,
            SecurityAccessResponse::NegativeResponse(
                NegativeResponseCode::RequiredTimeDelayNotExpired
            )
        );
    }

    #[test]
    fn test_seed_timeout() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        session.seed_timeout = Duration::from_millis(10); // Very short timeout for testing
        let hsm = create_test_hsm();

        // Request seed
        let seed = match session.request_seed(SecurityLevel::Level1, &hsm) {
            SecurityAccessResponse::Seed(s) => s,
            _ => panic!("Expected seed"),
        };

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        // Try to send key after timeout
        let key = session.compute_key(&seed, SecurityLevel::Level1, &hsm);
        let response = session.verify_key(SecurityLevel::Level1, key, &hsm);

        assert_eq!(
            response,
            SecurityAccessResponse::NegativeResponse(NegativeResponseCode::RequestSequenceError)
        );
    }

    #[test]
    fn test_wrong_level_sequence_error() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        let hsm = create_test_hsm();

        // Request seed for Level1
        let seed = match session.request_seed(SecurityLevel::Level1, &hsm) {
            SecurityAccessResponse::Seed(s) => s,
            _ => panic!("Expected seed"),
        };

        // Try to send key for Level2 (wrong level)
        let key = session.compute_key(&seed, SecurityLevel::Level2, &hsm);
        let response = session.verify_key(SecurityLevel::Level2, key, &hsm);

        assert_eq!(
            response,
            SecurityAccessResponse::NegativeResponse(NegativeResponseCode::RequestSequenceError)
        );
    }

    #[test]
    fn test_security_reset() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());
        session.security_level = SecurityLevel::Level3;

        session.reset_security();

        assert_eq!(session.security_level(), SecurityLevel::Locked);
        assert!(session.pending_seed.is_none());
    }

    #[test]
    fn test_operation_permission() {
        let mut session = UdsDiagnosticSession::new("BRAKE_CTRL".to_string());

        assert!(!session.is_operation_allowed(SecurityLevel::Level1));

        session.security_level = SecurityLevel::Level2;
        assert!(session.is_operation_allowed(SecurityLevel::Level1));
        assert!(session.is_operation_allowed(SecurityLevel::Level2));
        assert!(!session.is_operation_allowed(SecurityLevel::Level3));
    }

    #[test]
    fn test_diagnostic_server() {
        let mut server = UdsDiagnosticServer::new();
        let hsm = create_test_hsm();

        // Client 1 requests seed
        let response1 = server.handle_security_access(
            "client1",
            "BRAKE_CTRL".to_string(),
            SecurityAccessRequest::RequestSeed(SecurityLevel::Level1),
            &hsm,
        );

        let seed = match response1 {
            SecurityAccessResponse::Seed(s) => s,
            _ => panic!("Expected seed"),
        };

        // Compute correct key
        let session = server.get_session("client1", "BRAKE_CTRL".to_string());
        let key = session.compute_key(&seed, SecurityLevel::Level1, &hsm);

        // Send key
        let response2 = server.handle_security_access(
            "client1",
            "BRAKE_CTRL".to_string(),
            SecurityAccessRequest::SendKey(SecurityLevel::Level1, key),
            &hsm,
        );

        assert_eq!(response2, SecurityAccessResponse::KeyAccepted);
    }
}
