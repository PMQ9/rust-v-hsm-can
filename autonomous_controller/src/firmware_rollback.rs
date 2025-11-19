/// ISO 21434 Firmware Update Rollback Mechanism
///
/// Provides safe firmware updates with automatic rollback capability.
/// Ensures system can recover from failed or malicious firmware updates.
///
/// Key ISO 21434 requirements addressed:
/// - 8.5: Software update security
/// - 8.5.3: Rollback mechanisms
/// - 10.3: Secure software updates
use crate::hsm::SignedFirmware;
use crate::protected_memory::ProtectedMemory;
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of firmware versions to keep in history
///const MAX_FIRMWARE_HISTORY: usize = 3;

/// Firmware update status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateStatus {
    /// Update pending installation
    Pending,
    /// Update being installed
    Installing,
    /// Update installed, awaiting validation
    AwaitingValidation,
    /// Update validated and committed
    Committed,
    /// Update failed validation
    Failed,
    /// Update rolled back
    RolledBack,
}

impl fmt::Display for UpdateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateStatus::Pending => write!(f, "{}", "PENDING".yellow()),
            UpdateStatus::Installing => write!(f, "{}", "INSTALLING".cyan()),
            UpdateStatus::AwaitingValidation => {
                write!(f, "{}", "AWAITING VALIDATION".yellow().bold())
            }
            UpdateStatus::Committed => write!(f, "{}", "COMMITTED".green().bold()),
            UpdateStatus::Failed => write!(f, "{}", "FAILED".red()),
            UpdateStatus::RolledBack => write!(f, "{}", "ROLLED BACK".bright_red().bold()),
        }
    }
}

/// Firmware update record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareUpdateRecord {
    /// Update timestamp
    pub timestamp: DateTime<Utc>,
    /// Firmware version
    pub version: String,
    /// Update status
    pub status: UpdateStatus,
    /// Firmware fingerprint
    pub fingerprint: [u8; 32],
    /// Installation timestamp
    pub install_timestamp: Option<DateTime<Utc>>,
    /// Validation timestamp
    pub validation_timestamp: Option<DateTime<Utc>>,
    /// Rollback timestamp (if rolled back)
    pub rollback_timestamp: Option<DateTime<Utc>>,
    /// Failure reason (if failed)
    pub failure_reason: Option<String>,
    /// Number of boot attempts
    pub boot_attempts: u32,
}

/// Firmware rollback manager
pub struct FirmwareRollbackManager {
    /// ECU identifier
    ecu_name: String,
    /// Current firmware
    current_firmware: Option<SignedFirmware>,
    /// Firmware update history
    update_history: Vec<FirmwareUpdateRecord>,
    /// Rollback candidate (previous known-good firmware)
    rollback_candidate: Option<SignedFirmware>,
    /// Protected memory for firmware storage
    protected_memory: ProtectedMemory,
    /// Maximum boot attempts before automatic rollback
    max_boot_attempts: u32,
    /// Update in progress flag
    update_in_progress: bool,
}

impl FirmwareRollbackManager {
    /// Create new firmware rollback manager
    pub fn new(ecu_name: String) -> Self {
        Self {
            ecu_name: ecu_name.clone(),
            current_firmware: None,
            update_history: Vec::new(),
            rollback_candidate: None,
            protected_memory: ProtectedMemory::new(ecu_name),
            max_boot_attempts: 3,
            update_in_progress: false,
        }
    }

    /// Install initial firmware (first boot)
    pub fn install_initial_firmware(
        &mut self,
        firmware: SignedFirmware,
        hsm: &crate::hsm::VirtualHSM,
    ) -> Result<(), String> {
        // Verify firmware signature
        firmware.verify(hsm)?;

        println!();
        println!(
            "{} Installing initial firmware version {}",
            "→".cyan(),
            firmware.version.bright_white().bold()
        );

        // Install to protected memory
        self.protected_memory
            .provision_firmware(firmware.clone(), hsm)
            .map_err(|e| format!("Failed to provision firmware: {}", e))?;

        // Record in history
        let record = FirmwareUpdateRecord {
            timestamp: Utc::now(),
            version: firmware.version.clone(),
            status: UpdateStatus::Committed,
            fingerprint: firmware.fingerprint,
            install_timestamp: Some(Utc::now()),
            validation_timestamp: Some(Utc::now()),
            rollback_timestamp: None,
            failure_reason: None,
            boot_attempts: 0,
        };

        self.update_history.push(record);
        self.current_firmware = Some(firmware);

        println!("{} Initial firmware installed successfully", "✓".green());
        println!();

        Ok(())
    }

    /// Stage firmware update (does not apply immediately)
    pub fn stage_update(
        &mut self,
        new_firmware: SignedFirmware,
        hsm: &crate::hsm::VirtualHSM,
    ) -> Result<(), String> {
        if self.update_in_progress {
            return Err("Update already in progress".to_string());
        }

        // Verify new firmware signature
        new_firmware.verify(hsm)?;

        // Verify target ECU matches
        if new_firmware.target_ecu != self.ecu_name {
            return Err(format!(
                "Firmware target mismatch: expected {}, got {}",
                self.ecu_name, new_firmware.target_ecu
            ));
        }

        // Verify version progression (no downgrades without explicit rollback)
        if let Some(ref current) = self.current_firmware {
            if !self.is_version_newer(&new_firmware.version, &current.version) {
                return Err(format!(
                    "Version downgrade not allowed: {} -> {}. Use explicit rollback instead.",
                    current.version, new_firmware.version
                ));
            }
        }

        println!();
        println!(
            "{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!("{}", "   FIRMWARE UPDATE STAGED             ".cyan().bold());
        println!(
            "{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!();
        if let Some(ref current) = self.current_firmware {
            println!(
                "{} Current Version: {}",
                "→".cyan(),
                current.version.yellow()
            );
        }
        println!(
            "{} New Version: {}",
            "→".cyan(),
            new_firmware.version.bright_white().bold()
        );
        println!("{} Status: {}", "→".cyan(), UpdateStatus::Pending);
        println!();

        // Save current firmware as rollback candidate
        if let Some(current) = self.current_firmware.take() {
            self.rollback_candidate = Some(current);
        }

        // Create update record
        let record = FirmwareUpdateRecord {
            timestamp: Utc::now(),
            version: new_firmware.version.clone(),
            status: UpdateStatus::Pending,
            fingerprint: new_firmware.fingerprint,
            install_timestamp: None,
            validation_timestamp: None,
            rollback_timestamp: None,
            failure_reason: None,
            boot_attempts: 0,
        };

        self.update_history.push(record);
        self.current_firmware = Some(new_firmware);
        self.update_in_progress = true;

        Ok(())
    }

    /// Apply staged firmware update
    pub fn apply_update(&mut self, hsm: &crate::hsm::VirtualHSM) -> Result<(), String> {
        if !self.update_in_progress {
            return Err("No update in progress".to_string());
        }

        let firmware = self
            .current_firmware
            .as_ref()
            .ok_or("No firmware to apply")?;

        println!();
        println!("{} Applying firmware update...", "→".cyan());

        // Update status to Installing
        if let Some(record) = self.update_history.last_mut() {
            record.status = UpdateStatus::Installing;
        }

        // Authorize firmware update
        let update_token = hsm.generate_update_token();
        self.protected_memory
            .authorize_update(&update_token, hsm)
            .map_err(|e| format!("Authorization failed: {}", e))?;

        // Install to protected memory
        self.protected_memory
            .update_firmware(firmware.clone(), hsm)
            .map_err(|e| {
                // Installation failed - rollback
                if let Some(record) = self.update_history.last_mut() {
                    record.status = UpdateStatus::Failed;
                    record.failure_reason = Some(format!("Installation failed: {}", e));
                }
                self.trigger_rollback(hsm, "Installation failure").ok();
                e
            })?;

        // Update status to AwaitingValidation
        if let Some(record) = self.update_history.last_mut() {
            record.status = UpdateStatus::AwaitingValidation;
            record.install_timestamp = Some(Utc::now());
        }

        println!("{} Firmware installed, awaiting validation", "✓".green());
        println!();

        Ok(())
    }

    /// Validate firmware after installation (called after first boot)
    pub fn validate_update(
        &mut self,
        validation_passed: bool,
        hsm: &crate::hsm::VirtualHSM,
    ) -> Result<(), String> {
        if !self.update_in_progress {
            return Err("No update to validate".to_string());
        }

        if validation_passed {
            // Commit the update
            if let Some(record) = self.update_history.last_mut() {
                record.status = UpdateStatus::Committed;
                record.validation_timestamp = Some(Utc::now());
            }

            self.update_in_progress = false;
            self.rollback_candidate = None; // No longer needed

            println!();
            println!(
                "{} Firmware update committed successfully",
                "✓".green().bold()
            );
            if let Some(ref firmware) = self.current_firmware {
                println!(
                    "{} Version: {}",
                    "→".green(),
                    firmware.version.bright_white().bold()
                );
            }
            println!();

            Ok(())
        } else {
            // Validation failed - rollback
            if let Some(record) = self.update_history.last_mut() {
                record.status = UpdateStatus::Failed;
                record.failure_reason = Some("Validation failed".to_string());
            }

            self.trigger_rollback(hsm, "Validation failure")
        }
    }

    /// Trigger firmware rollback to last known-good version
    pub fn trigger_rollback(
        &mut self,
        hsm: &crate::hsm::VirtualHSM,
        reason: &str,
    ) -> Result<(), String> {
        let rollback_firmware = self
            .rollback_candidate
            .clone()
            .ok_or("No rollback candidate available")?;

        println!();
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_red()
                .bold()
        );
        println!(
            "{}",
            "   FIRMWARE ROLLBACK INITIATED        ".bright_red().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_red()
                .bold()
        );
        println!();
        println!("{} Reason: {}", "→".red(), reason.red().bold());
        if let Some(ref current) = self.current_firmware {
            println!("{} Failed Version: {}", "→".red(), current.version.yellow());
        }
        println!(
            "{} Rolling back to: {}",
            "→".red(),
            rollback_firmware.version.bright_white().bold()
        );
        println!();

        // Authorize firmware update for rollback
        let update_token = hsm.generate_update_token();
        self.protected_memory
            .authorize_update(&update_token, hsm)
            .map_err(|e| format!("Rollback authorization failed: {}", e))?;

        // Install rollback firmware
        self.protected_memory
            .update_firmware(rollback_firmware.clone(), hsm)
            .map_err(|e| format!("Rollback failed: {}", e))?;

        // Update last record as rolled back
        if let Some(record) = self.update_history.last_mut() {
            record.status = UpdateStatus::RolledBack;
            record.rollback_timestamp = Some(Utc::now());
            if record.failure_reason.is_none() {
                record.failure_reason = Some(reason.to_string());
            }
        }

        // Restore rollback candidate as current
        self.current_firmware = Some(rollback_firmware);
        self.rollback_candidate = None;
        self.update_in_progress = false;

        println!(
            "{} Firmware rollback completed successfully",
            "✓".green().bold()
        );
        println!();

        Ok(())
    }

    /// Increment boot attempt counter (called on each boot)
    pub fn record_boot_attempt(&mut self, hsm: &crate::hsm::VirtualHSM) -> Result<(), String> {
        if !self.update_in_progress {
            return Ok(()); // Not during update, nothing to track
        }

        if let Some(record) = self.update_history.last_mut() {
            record.boot_attempts += 1;

            if record.boot_attempts >= self.max_boot_attempts {
                println!();
                println!(
                    "{} Maximum boot attempts ({}) exceeded for firmware version {}",
                    "⚠".yellow(),
                    self.max_boot_attempts,
                    record.version.red()
                );
                println!("{} Triggering automatic rollback", "→".yellow());

                // Automatic rollback
                record.failure_reason = Some(format!(
                    "Exceeded maximum boot attempts ({})",
                    self.max_boot_attempts
                ));

                self.trigger_rollback(hsm, "Exceeded maximum boot attempts")?;
            }
        }

        Ok(())
    }

    /// Check if version is newer (simple semantic versioning)
    fn is_version_newer(&self, new_version: &str, current_version: &str) -> bool {
        // Simple version comparison (assumes semantic versioning)
        // In production, use proper semver crate
        new_version > current_version
    }

    /// Get current firmware version
    pub fn current_version(&self) -> Option<String> {
        self.current_firmware.as_ref().map(|f| f.version.clone())
    }

    /// Get firmware update history
    pub fn get_update_history(&self) -> &[FirmwareUpdateRecord] {
        &self.update_history
    }

    /// Check if update is in progress
    pub fn is_update_in_progress(&self) -> bool {
        self.update_in_progress
    }

    /// Export firmware update report
    pub fn export_update_report(&self) -> String {
        let mut report = String::new();

        report.push_str("═══════════════════════════════════════════════════════════\n");
        report.push_str("           FIRMWARE UPDATE HISTORY REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════\n\n");

        report.push_str(&format!("ECU: {}\n", self.ecu_name));
        if let Some(ref current) = self.current_firmware {
            report.push_str(&format!("Current Version: {}\n", current.version));
        }
        if let Some(ref rollback) = self.rollback_candidate {
            report.push_str(&format!("Rollback Candidate: {}\n", rollback.version));
        }
        report.push_str(&format!(
            "Update In Progress: {}\n\n",
            self.update_in_progress
        ));

        report.push_str("───────────────────────────────────────────────────────────\n");
        report.push_str("UPDATE HISTORY\n");
        report.push_str("───────────────────────────────────────────────────────────\n\n");

        for (idx, record) in self.update_history.iter().rev().enumerate() {
            report.push_str(&format!("Update #{}\n", self.update_history.len() - idx));
            report.push_str(&format!("  Version: {}\n", record.version));
            report.push_str(&format!("  Status: {:?}\n", record.status));
            report.push_str(&format!("  Timestamp: {}\n", record.timestamp));

            if let Some(ref install_ts) = record.install_timestamp {
                report.push_str(&format!("  Installed: {}\n", install_ts));
            }

            if let Some(ref validation_ts) = record.validation_timestamp {
                report.push_str(&format!("  Validated: {}\n", validation_ts));
            }

            if let Some(ref rollback_ts) = record.rollback_timestamp {
                report.push_str(&format!("  Rolled Back: {}\n", rollback_ts));
            }

            if let Some(ref reason) = record.failure_reason {
                report.push_str(&format!("  Failure Reason: {}\n", reason));
            }

            report.push_str(&format!("  Boot Attempts: {}\n", record.boot_attempts));
            report.push_str("\n");
        }

        report.push_str("═══════════════════════════════════════════════════════════\n");

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::VirtualHSM;

    fn create_test_firmware(version: &str, ecu_name: &str, hsm: &VirtualHSM) -> SignedFirmware {
        let data = format!("firmware_data_{}", version).into_bytes();
        SignedFirmware::new(data, version.to_string(), ecu_name.to_string(), hsm)
    }

    #[test]
    fn test_initial_firmware_installation() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);

        // Install initial firmware
        let result = manager.install_initial_firmware(firmware_v1, &hsm);
        assert!(result.is_ok());

        assert_eq!(manager.current_version(), Some("1.0.0".to_string()));
        assert_eq!(manager.get_update_history().len(), 1);
    }

    #[test]
    fn test_firmware_update_staging() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install initial firmware
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Stage update
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        let result = manager.stage_update(firmware_v2, &hsm);
        assert!(result.is_ok());

        assert!(manager.is_update_in_progress());
        assert!(manager.rollback_candidate.is_some());
    }

    #[test]
    fn test_update_validation_success() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install initial firmware
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Stage and apply update
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.stage_update(firmware_v2, &hsm).unwrap();
        manager.apply_update(&hsm).unwrap();

        // Validate successfully
        let result = manager.validate_update(true, &hsm);
        assert!(result.is_ok());

        assert!(!manager.is_update_in_progress());
        assert_eq!(manager.current_version(), Some("2.0.0".to_string()));
        assert!(manager.rollback_candidate.is_none());
    }

    #[test]
    fn test_update_validation_failure_triggers_rollback() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install initial firmware
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Stage and apply update
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.stage_update(firmware_v2, &hsm).unwrap();
        manager.apply_update(&hsm).unwrap();

        // Validation fails - should trigger rollback
        let result = manager.validate_update(false, &hsm);
        assert!(result.is_ok());

        // Should be rolled back to v1.0.0
        assert!(!manager.is_update_in_progress());
        assert_eq!(manager.current_version(), Some("1.0.0".to_string()));
    }

    #[test]
    fn test_manual_rollback() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install initial firmware
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Stage update
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.stage_update(firmware_v2, &hsm).unwrap();

        // Manual rollback
        let result = manager.trigger_rollback(&hsm, "Manual rollback requested");
        assert!(result.is_ok());

        assert!(!manager.is_update_in_progress());
        assert_eq!(manager.current_version(), Some("1.0.0".to_string()));
    }

    #[test]
    fn test_automatic_rollback_on_boot_failure() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        manager.max_boot_attempts = 3;

        // Install initial firmware
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Stage and apply update
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.stage_update(firmware_v2, &hsm).unwrap();
        manager.apply_update(&hsm).unwrap();

        // Simulate failed boot attempts
        manager.record_boot_attempt(&hsm).unwrap(); // Attempt 1
        assert!(manager.is_update_in_progress());

        manager.record_boot_attempt(&hsm).unwrap(); // Attempt 2
        assert!(manager.is_update_in_progress());

        manager.record_boot_attempt(&hsm).unwrap(); // Attempt 3 - should trigger rollback
        assert!(!manager.is_update_in_progress());
        assert_eq!(manager.current_version(), Some("1.0.0".to_string()));
    }

    #[test]
    fn test_version_downgrade_prevention() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install firmware v2.0.0
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v2, &hsm).unwrap();

        // Try to downgrade to v1.0.0 (should fail)
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        let result = manager.stage_update(firmware_v1, &hsm);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("downgrade not allowed"));
    }

    #[test]
    fn test_update_history_tracking() {
        let mut manager = FirmwareRollbackManager::new("TEST_ECU".to_string());
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);

        // Install v1.0.0
        let firmware_v1 = create_test_firmware("1.0.0", "TEST_ECU", &hsm);
        manager.install_initial_firmware(firmware_v1, &hsm).unwrap();

        // Update to v2.0.0
        let firmware_v2 = create_test_firmware("2.0.0", "TEST_ECU", &hsm);
        manager.stage_update(firmware_v2, &hsm).unwrap();
        manager.apply_update(&hsm).unwrap();
        manager.validate_update(true, &hsm).unwrap();

        // Should have 2 records in history
        assert_eq!(manager.get_update_history().len(), 2);

        let history = manager.get_update_history();
        assert_eq!(history[0].version, "1.0.0");
        assert_eq!(history[0].status, UpdateStatus::Committed);
        assert_eq!(history[1].version, "2.0.0");
        assert_eq!(history[1].status, UpdateStatus::Committed);
    }
}
