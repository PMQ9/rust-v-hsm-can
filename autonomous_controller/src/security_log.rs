/// Security Event Logging Module (ISO 21434)
///
/// Provides tamper-resistant audit trail for security events using chained hashing.
/// Each log entry includes a hash of the previous entry, making it detectable if
/// entries are modified or deleted.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Types of security events to log
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum SecurityEvent {
    /// ECU started and security system initialized
    SystemStartup { ecu_id: String, hsm_enabled: bool },

    /// Frame verification failed
    VerificationFailure {
        source: String,
        can_id: u32,
        error_type: String,
        consecutive_count: u32,
    },

    /// Frame verification succeeded
    VerificationSuccess { source: String, can_id: u32 },

    /// Security state changed
    StateChange {
        from_state: String,
        to_state: String,
        trigger: String,
    },

    /// Attack detected - threshold exceeded
    AttackDetected {
        attack_type: String,
        consecutive_errors: u32,
        total_errors: u64,
        threshold: u32,
    },

    /// Frame rejected due to security policy
    FrameRejected {
        source: String,
        can_id: u32,
        reason: String,
    },

    /// ECU entered fail-safe mode
    FailSafeActivated { reason: String },

    /// Security system reset
    SecurityReset { reason: String },

    /// Trusted ECU key registered
    KeyRegistration { ecu_name: String },

    /// Security statistics snapshot
    StatisticsSnapshot {
        valid_frames: u64,
        crc_errors: u64,
        mac_errors: u64,
        unsecured_frames: u64,
    },

    /// Unauthorized CAN ID transmission attempt
    UnauthorizedTransmit {
        source: String,
        can_id: u32,
        attempted_action: String,
    },

    /// Unauthorized CAN ID receive attempt
    UnauthorizedReceive {
        source: String,
        can_id: u32,
        blocked: bool,
    },

    /// Access control policy loaded
    AccessControlLoaded {
        ecu_id: String,
        tx_whitelist_size: usize,
        rx_whitelist_size: Option<usize>,
    },
}

/// A single entry in the security log with tamper-resistant chaining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLogEntry {
    /// Sequential entry number
    pub sequence: u64,

    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,

    /// ECU that generated this log entry
    pub ecu_id: String,

    /// The security event
    pub event: SecurityEvent,

    /// Hash of the previous log entry (empty for first entry)
    pub prev_hash: String,

    /// Hash of this entry (for chain verification)
    pub entry_hash: String,
}

impl SecurityLogEntry {
    /// Create a new log entry with chained hash
    fn new(sequence: u64, ecu_id: String, event: SecurityEvent, prev_hash: String) -> Self {
        let timestamp = Utc::now();

        // Calculate hash of this entry (without entry_hash field)
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(ecu_id.as_bytes());
        hasher.update(serde_json::to_string(&event).unwrap_or_default().as_bytes());
        hasher.update(prev_hash.as_bytes());

        let hash_bytes = hasher.finalize();
        let entry_hash = format!("{:x}", hash_bytes);

        Self {
            sequence,
            timestamp,
            ecu_id,
            event,
            prev_hash,
            entry_hash,
        }
    }

    /// Verify this entry's hash is correct
    pub fn verify_hash(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.ecu_id.as_bytes());
        hasher.update(
            serde_json::to_string(&self.event)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(self.prev_hash.as_bytes());

        let hash_bytes = hasher.finalize();
        let expected_hash = format!("{:x}", hash_bytes);

        expected_hash == self.entry_hash
    }

    /// Verify chain link to previous entry
    pub fn verify_chain(&self, prev_entry: &SecurityLogEntry) -> bool {
        self.prev_hash == prev_entry.entry_hash && self.sequence == prev_entry.sequence + 1
    }
}

/// Security logger with tamper-resistant audit trail
pub struct SecurityLogger {
    /// ECU identifier
    ecu_id: String,

    /// Log file path
    log_path: PathBuf,

    /// File writer (protected by mutex for thread-safety)
    writer: Arc<Mutex<BufWriter<File>>>,

    /// Current sequence number
    sequence: Arc<Mutex<u64>>,

    /// Hash of the last entry (for chaining)
    last_hash: Arc<Mutex<String>>,
}

impl SecurityLogger {
    /// Create a new security logger
    pub fn new(ecu_id: String, log_dir: Option<PathBuf>) -> std::io::Result<Self> {
        // Determine log directory (default: ./security_logs/)
        let log_dir = log_dir.unwrap_or_else(|| PathBuf::from("security_logs"));

        // Create log directory if it doesn't exist
        std::fs::create_dir_all(&log_dir)?;

        // Create log file with timestamp in name
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let log_filename = format!("{}_{}.jsonl", ecu_id, timestamp);
        let log_path = log_dir.join(log_filename);

        // Open log file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let writer = Arc::new(Mutex::new(BufWriter::new(file)));

        Ok(Self {
            ecu_id: ecu_id.clone(),
            log_path,
            writer,
            sequence: Arc::new(Mutex::new(0)),
            last_hash: Arc::new(Mutex::new(String::new())),
        })
    }

    /// Log a security event
    pub fn log_event(&self, event: SecurityEvent) {
        let mut seq = self.sequence.lock().unwrap();
        let mut last_hash = self.last_hash.lock().unwrap();

        // Create new entry with chained hash
        let entry = SecurityLogEntry::new(*seq, self.ecu_id.clone(), event, last_hash.clone());

        // Update sequence and last hash
        *seq += 1;
        *last_hash = entry.entry_hash.clone();

        // Write to log file (JSONL format - one JSON object per line)
        if let Ok(mut writer) = self.writer.lock()
            && let Ok(json) = serde_json::to_string(&entry)
        {
            let _ = writeln!(writer, "{}", json);
            let _ = writer.flush();
        }
    }

    /// Log system startup
    pub fn log_startup(&self, hsm_enabled: bool) {
        self.log_event(SecurityEvent::SystemStartup {
            ecu_id: self.ecu_id.clone(),
            hsm_enabled,
        });
    }

    /// Log verification failure
    pub fn log_verification_failure(
        &self,
        source: String,
        can_id: u32,
        error_type: String,
        consecutive_count: u32,
    ) {
        self.log_event(SecurityEvent::VerificationFailure {
            source,
            can_id,
            error_type,
            consecutive_count,
        });
    }

    /// Log verification success
    pub fn log_verification_success(&self, source: String, can_id: u32) {
        self.log_event(SecurityEvent::VerificationSuccess { source, can_id });
    }

    /// Log security state change
    pub fn log_state_change(&self, from_state: String, to_state: String, trigger: String) {
        self.log_event(SecurityEvent::StateChange {
            from_state,
            to_state,
            trigger,
        });
    }

    /// Log attack detection
    pub fn log_attack_detected(
        &self,
        attack_type: String,
        consecutive_errors: u32,
        total_errors: u64,
        threshold: u32,
    ) {
        self.log_event(SecurityEvent::AttackDetected {
            attack_type,
            consecutive_errors,
            total_errors,
            threshold,
        });
    }

    /// Log frame rejection
    pub fn log_frame_rejected(&self, source: String, can_id: u32, reason: String) {
        self.log_event(SecurityEvent::FrameRejected {
            source,
            can_id,
            reason,
        });
    }

    /// Log fail-safe activation
    pub fn log_fail_safe_activated(&self, reason: String) {
        self.log_event(SecurityEvent::FailSafeActivated { reason });
    }

    /// Log security reset
    pub fn log_security_reset(&self, reason: String) {
        self.log_event(SecurityEvent::SecurityReset { reason });
    }

    /// Log key registration
    pub fn log_key_registration(&self, ecu_name: String) {
        self.log_event(SecurityEvent::KeyRegistration { ecu_name });
    }

    /// Log statistics snapshot
    pub fn log_statistics(
        &self,
        valid_frames: u64,
        crc_errors: u64,
        mac_errors: u64,
        unsecured_frames: u64,
    ) {
        self.log_event(SecurityEvent::StatisticsSnapshot {
            valid_frames,
            crc_errors,
            mac_errors,
            unsecured_frames,
        });
    }

    /// Get the log file path
    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        *self.sequence.lock().unwrap()
    }
}

impl Clone for SecurityLogger {
    fn clone(&self) -> Self {
        Self {
            ecu_id: self.ecu_id.clone(),
            log_path: self.log_path.clone(),
            writer: Arc::clone(&self.writer),
            sequence: Arc::clone(&self.sequence),
            last_hash: Arc::clone(&self.last_hash),
        }
    }
}

impl fmt::Debug for SecurityLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityLogger")
            .field("ecu_id", &self.ecu_id)
            .field("log_path", &self.log_path)
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// Verify integrity of an entire log file
pub fn verify_log_file(log_path: PathBuf) -> Result<VerificationResult, String> {
    use std::io::{BufRead, BufReader};

    let file = File::open(&log_path).map_err(|e| format!("Failed to open log: {}", e))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Line {} read error: {}", line_num + 1, e))?;
        let entry: SecurityLogEntry = serde_json::from_str(&line)
            .map_err(|e| format!("Line {} parse error: {}", line_num + 1, e))?;
        entries.push(entry);
    }

    if entries.is_empty() {
        return Ok(VerificationResult {
            total_entries: 0,
            verified: true,
            issues: Vec::new(),
        });
    }

    let mut issues = Vec::new();

    // Verify first entry has empty prev_hash
    if !entries[0].prev_hash.is_empty() {
        issues.push(format!(
            "Entry 0: First entry should have empty prev_hash, got '{}'",
            entries[0].prev_hash
        ));
    }

    // Verify each entry's hash
    for (i, entry) in entries.iter().enumerate() {
        if !entry.verify_hash() {
            issues.push(format!("Entry {}: Hash verification failed (tampered)", i));
        }
    }

    // Verify chain links
    for i in 1..entries.len() {
        if !entries[i].verify_chain(&entries[i - 1]) {
            issues.push(format!(
                "Entry {}: Chain verification failed (missing or reordered entry)",
                i
            ));
        }
    }

    // Verify sequence numbers are sequential
    for (i, entry) in entries.iter().enumerate() {
        if entry.sequence != i as u64 {
            issues.push(format!(
                "Entry {}: Expected sequence {}, got {}",
                i, i, entry.sequence
            ));
        }
    }

    Ok(VerificationResult {
        total_entries: entries.len(),
        verified: issues.is_empty(),
        issues,
    })
}

/// Result of log verification
#[derive(Debug)]
pub struct VerificationResult {
    pub total_entries: usize,
    pub verified: bool,
    pub issues: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_entry_hash_verification() {
        let entry = SecurityLogEntry::new(
            0,
            "TEST_ECU".to_string(),
            SecurityEvent::SystemStartup {
                ecu_id: "TEST_ECU".to_string(),
                hsm_enabled: true,
            },
            String::new(),
        );

        assert!(entry.verify_hash());
    }

    #[test]
    fn test_log_chain_verification() {
        let entry1 = SecurityLogEntry::new(
            0,
            "TEST_ECU".to_string(),
            SecurityEvent::SystemStartup {
                ecu_id: "TEST_ECU".to_string(),
                hsm_enabled: true,
            },
            String::new(),
        );

        let entry2 = SecurityLogEntry::new(
            1,
            "TEST_ECU".to_string(),
            SecurityEvent::VerificationSuccess {
                source: "TEST_ECU".to_string(),
                can_id: 0x100,
            },
            entry1.entry_hash.clone(),
        );

        assert!(entry2.verify_chain(&entry1));
    }

    #[test]
    fn test_security_logger() {
        let temp_dir = TempDir::new().unwrap();
        let logger =
            SecurityLogger::new("TEST_ECU".to_string(), Some(temp_dir.path().to_path_buf()))
                .expect("Failed to create logger");

        logger.log_startup(true);
        logger.log_verification_success("SENSOR".to_string(), 0x100);
        logger.log_verification_failure("SENSOR".to_string(), 0x100, "MAC_MISMATCH".to_string(), 1);

        assert_eq!(logger.sequence(), 3);

        // Verify log file exists
        assert!(logger.log_path().exists());
    }

    #[test]
    fn test_log_file_verification() {
        let temp_dir = TempDir::new().unwrap();
        let logger =
            SecurityLogger::new("TEST_ECU".to_string(), Some(temp_dir.path().to_path_buf()))
                .expect("Failed to create logger");

        logger.log_startup(true);
        logger.log_verification_success("SENSOR".to_string(), 0x100);
        logger.log_verification_failure("SENSOR".to_string(), 0x100, "MAC_MISMATCH".to_string(), 1);

        // Verify the log
        let result = verify_log_file(logger.log_path().clone()).expect("Verification failed");

        assert_eq!(result.total_entries, 3);
        assert!(
            result.verified,
            "Log should be verified: {:?}",
            result.issues
        );
        assert!(result.issues.is_empty());
    }

    #[test]
    fn test_tamper_detection() {
        let temp_dir = TempDir::new().unwrap();
        let logger =
            SecurityLogger::new("TEST_ECU".to_string(), Some(temp_dir.path().to_path_buf()))
                .expect("Failed to create logger");

        logger.log_startup(true);
        logger.log_verification_success("SENSOR".to_string(), 0x100);

        // Tamper with the log file by modifying a line
        let log_path = logger.log_path().clone();
        let content = fs::read_to_string(&log_path).unwrap();
        let tampered = content.replace("SENSOR", "HACKER");
        fs::write(&log_path, tampered).unwrap();

        // Verification should fail
        let result = verify_log_file(log_path).expect("Verification failed");

        assert!(!result.verified, "Tampered log should not verify");
        assert!(!result.issues.is_empty(), "Should detect tampering");
    }
}
