/// Error Handling and Attack Detection Module
///
/// This module provides attack detection capabilities by tracking CRC and MAC
/// validation failures. It implements tolerance for occasional errors (signal
/// degradation, noise) while detecting sustained attack patterns.
use crate::security_log::SecurityLogger;
use colored::*;
use std::fmt;

/// Thresholds for attack detection
pub const CRC_ERROR_THRESHOLD: u32 = 5; // Allow 5 consecutive CRC errors (noise tolerance)
pub const MAC_ERROR_THRESHOLD: u32 = 3; // Allow 3 consecutive MAC errors (noise tolerance)
pub const UNSECURED_FRAME_THRESHOLD: u32 = 1; // Immediately trigger on unsecured frames (no tolerance)

/// Types of validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    CrcMismatch,
    MacMismatch,
    UnsecuredFrame,
    UnauthorizedAccess,
}

impl ValidationError {
    /// Convert from VerifyError to ValidationError
    pub fn from_verify_error(error: &crate::hsm::VerifyError) -> Self {
        match error {
            crate::hsm::VerifyError::UnsecuredFrame => ValidationError::UnsecuredFrame,
            crate::hsm::VerifyError::CrcMismatch => ValidationError::CrcMismatch,
            crate::hsm::VerifyError::MacMismatch(_) => ValidationError::MacMismatch,
            crate::hsm::VerifyError::UnauthorizedAccess => ValidationError::UnauthorizedAccess,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::CrcMismatch => write!(f, "CRC Mismatch"),
            ValidationError::MacMismatch => write!(f, "MAC Mismatch"),
            ValidationError::UnsecuredFrame => write!(f, "Unsecured Frame (No MAC)"),
            ValidationError::UnauthorizedAccess => write!(f, "Unauthorized CAN ID Access"),
        }
    }
}

/// Attack detection state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    /// Normal operation - no threats detected
    Normal,
    /// Warning state - errors detected but below threshold
    Warning,
    /// Attack detected - threshold exceeded, protective measures active
    UnderAttack,
}

impl fmt::Display for SecurityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityState::Normal => write!(f, "{}", "NORMAL".green().bold()),
            SecurityState::Warning => write!(f, "{}", "WARNING".yellow().bold()),
            SecurityState::UnderAttack => write!(f, "{}", "UNDER ATTACK".red().bold()),
        }
    }
}

/// Attack detector with error tracking and threshold-based detection
#[derive(Debug)]
pub struct AttackDetector {
    /// ECU name for logging
    ecu_name: String,
    /// Consecutive CRC error counter
    crc_error_count: u32,
    /// Consecutive MAC error counter
    mac_error_count: u32,
    /// Consecutive unsecured frame counter
    unsecured_frame_count: u32,
    /// Total CRC errors encountered
    total_crc_errors: u64,
    /// Total MAC errors encountered
    total_mac_errors: u64,
    /// Total unsecured frames encountered
    total_unsecured_frames: u64,
    /// Total unauthorized access attempts
    total_unauthorized_access: u64,
    /// Total frames successfully validated
    total_valid_frames: u64,
    /// Current security state
    state: SecurityState,
    /// Security event logger (optional)
    security_logger: Option<SecurityLogger>,
}

impl AttackDetector {
    /// Create a new attack detector without security logging
    pub fn new(ecu_name: String) -> Self {
        Self {
            ecu_name,
            crc_error_count: 0,
            mac_error_count: 0,
            unsecured_frame_count: 0,
            total_crc_errors: 0,
            total_mac_errors: 0,
            total_unsecured_frames: 0,
            total_unauthorized_access: 0,
            total_valid_frames: 0,
            state: SecurityState::Normal,
            security_logger: None,
        }
    }

    /// Create a new attack detector with security logging
    pub fn with_logger(ecu_name: String, logger: SecurityLogger) -> Self {
        // Log system startup
        logger.log_startup(true);

        Self {
            ecu_name,
            crc_error_count: 0,
            mac_error_count: 0,
            unsecured_frame_count: 0,
            total_crc_errors: 0,
            total_mac_errors: 0,
            total_unsecured_frames: 0,
            total_unauthorized_access: 0,
            total_valid_frames: 0,
            state: SecurityState::Normal,
            security_logger: Some(logger),
        }
    }

    /// Record a validation error and update state
    pub fn record_error(&mut self, error: ValidationError, source: &str) -> bool {
        match error {
            ValidationError::CrcMismatch => {
                self.crc_error_count += 1;
                self.total_crc_errors += 1;

                println!(
                    "{} {} from {} | CRC Error #{} (Total: {})",
                    "⚠️".yellow(),
                    "CRC MISMATCH".red(),
                    source.bright_black(),
                    self.crc_error_count,
                    self.total_crc_errors
                );

                // Log verification failure
                if let Some(logger) = &self.security_logger {
                    logger.log_verification_failure(
                        source.to_string(),
                        0, // CAN ID not available here
                        "CRC_MISMATCH".to_string(),
                        self.crc_error_count,
                    );
                }

                if self.crc_error_count >= CRC_ERROR_THRESHOLD {
                    self.trigger_attack_mode(ValidationError::CrcMismatch);
                    return false; // Reject frame
                } else if self.crc_error_count >= CRC_ERROR_THRESHOLD / 2 {
                    let old_state = self.state;
                    self.state = SecurityState::Warning;

                    // Log state change
                    if let Some(logger) = &self.security_logger {
                        logger.log_state_change(
                            format!("{:?}", old_state),
                            format!("{:?}", self.state),
                            format!(
                                "CRC errors approaching threshold ({}/{})",
                                self.crc_error_count, CRC_ERROR_THRESHOLD
                            ),
                        );
                    }

                    println!(
                        "{} {} - CRC errors approaching threshold ({}/{})",
                        "⚠️".yellow(),
                        "WARNING".yellow().bold(),
                        self.crc_error_count,
                        CRC_ERROR_THRESHOLD
                    );
                }
            }
            ValidationError::MacMismatch => {
                self.mac_error_count += 1;
                self.total_mac_errors += 1;

                println!(
                    "{} {} from {} | MAC Error #{} (Total: {})",
                    "⚠️".yellow(),
                    "MAC MISMATCH".red(),
                    source.bright_black(),
                    self.mac_error_count,
                    self.total_mac_errors
                );

                // Log verification failure
                if let Some(logger) = &self.security_logger {
                    logger.log_verification_failure(
                        source.to_string(),
                        0, // CAN ID not available here
                        "MAC_MISMATCH".to_string(),
                        self.mac_error_count,
                    );
                }

                if self.mac_error_count >= MAC_ERROR_THRESHOLD {
                    self.trigger_attack_mode(ValidationError::MacMismatch);
                    return false; // Reject frame
                } else if self.mac_error_count >= MAC_ERROR_THRESHOLD / 2 {
                    let old_state = self.state;
                    self.state = SecurityState::Warning;

                    // Log state change
                    if let Some(logger) = &self.security_logger {
                        logger.log_state_change(
                            format!("{:?}", old_state),
                            format!("{:?}", self.state),
                            format!(
                                "MAC errors approaching threshold ({}/{})",
                                self.mac_error_count, MAC_ERROR_THRESHOLD
                            ),
                        );
                    }

                    println!(
                        "{} {} - MAC errors approaching threshold ({}/{})",
                        "⚠️".yellow(),
                        "WARNING".yellow().bold(),
                        self.mac_error_count,
                        MAC_ERROR_THRESHOLD
                    );
                }
            }
            ValidationError::UnsecuredFrame => {
                self.unsecured_frame_count += 1;
                self.total_unsecured_frames += 1;

                println!(
                    "{} {} from {} | Unsecured Frame #{} (Total: {})",
                    "⚠️".yellow(),
                    "UNSECURED FRAME (NO MAC)".red().bold(),
                    source.bright_black(),
                    self.unsecured_frame_count,
                    self.total_unsecured_frames
                );

                // Log verification failure
                if let Some(logger) = &self.security_logger {
                    logger.log_verification_failure(
                        source.to_string(),
                        0, // CAN ID not available here
                        "UNSECURED_FRAME".to_string(),
                        self.unsecured_frame_count,
                    );
                }

                // Unsecured frames are IMMEDIATE attack indicators - trigger immediately
                if self.unsecured_frame_count >= UNSECURED_FRAME_THRESHOLD {
                    self.trigger_attack_mode(ValidationError::UnsecuredFrame);
                    return false; // Reject frame
                }
            }
            ValidationError::UnauthorizedAccess => {
                // Unauthorized access is handled separately via handle_unauthorized_access()
                // This case shouldn't normally be reached via record_error
                self.total_unauthorized_access += 1;
                return false; // Always reject unauthorized access
            }
        }

        // Allow recovery for errors below threshold
        true
    }

    /// Record a successful validation (resets consecutive error counters)
    pub fn record_success(&mut self) {
        // Reset consecutive error counters on successful validation
        let had_errors =
            self.crc_error_count > 0 || self.mac_error_count > 0 || self.unsecured_frame_count > 0;

        if had_errors && self.state != SecurityState::UnderAttack {
            println!(
                "{} {} - Errors cleared after successful validation",
                "✓".green(),
                "RECOVERED".green().bold()
            );
        }

        self.crc_error_count = 0;
        self.mac_error_count = 0;
        self.unsecured_frame_count = 0;

        // Return to normal if we were in warning state
        let old_state = self.state;
        if self.state == SecurityState::Warning {
            self.state = SecurityState::Normal;

            // Log state change
            if let Some(logger) = &self.security_logger {
                logger.log_state_change(
                    format!("{:?}", old_state),
                    format!("{:?}", self.state),
                    "Successful frame validation".to_string(),
                );
            }
        }

        self.total_valid_frames += 1;
    }

    /// Trigger attack mode when threshold is exceeded
    fn trigger_attack_mode(&mut self, error_type: ValidationError) {
        let old_state = self.state;
        self.state = SecurityState::UnderAttack;

        // Log attack detection
        if let Some(logger) = &self.security_logger {
            let (attack_type, consecutive_errors, total_errors, threshold) = match error_type {
                ValidationError::CrcMismatch => (
                    "CRC_MISMATCH".to_string(),
                    self.crc_error_count,
                    self.total_crc_errors,
                    CRC_ERROR_THRESHOLD,
                ),
                ValidationError::MacMismatch => (
                    "MAC_MISMATCH".to_string(),
                    self.mac_error_count,
                    self.total_mac_errors,
                    MAC_ERROR_THRESHOLD,
                ),
                ValidationError::UnsecuredFrame => (
                    "UNSECURED_FRAME_INJECTION".to_string(),
                    self.unsecured_frame_count,
                    self.total_unsecured_frames,
                    UNSECURED_FRAME_THRESHOLD,
                ),
                ValidationError::UnauthorizedAccess => (
                    "UNAUTHORIZED_ACCESS".to_string(),
                    1, // Always immediate
                    self.total_unauthorized_access,
                    1, // Immediate threshold
                ),
            };

            logger.log_attack_detected(attack_type, consecutive_errors, total_errors, threshold);
            logger.log_state_change(
                format!("{:?}", old_state),
                format!("{:?}", self.state),
                "Attack threshold exceeded".to_string(),
            );
            logger.log_fail_safe_activated("Attack detected - entering fail-safe mode".to_string());
        }

        println!();
        println!("{}", "═══════════════════════════════════════".red().bold());
        println!("{}", "       ATTACK DETECTED             ".red().bold());
        println!("{}", "═══════════════════════════════════════".red().bold());
        println!();
        println!("{} ECU: {}", "→".red(), self.ecu_name.yellow().bold());
        println!(
            "{} Error Type: {}",
            "→".red(),
            error_type.to_string().red().bold()
        );

        match error_type {
            ValidationError::CrcMismatch => {
                println!(
                    "{} Consecutive CRC errors: {} (Threshold: {})",
                    "→".red(),
                    self.crc_error_count.to_string().red().bold(),
                    CRC_ERROR_THRESHOLD
                );
                println!("{} Total CRC errors: {}", "→".red(), self.total_crc_errors);
            }
            ValidationError::MacMismatch => {
                println!(
                    "{} Consecutive MAC errors: {} (Threshold: {})",
                    "→".red(),
                    self.mac_error_count.to_string().red().bold(),
                    MAC_ERROR_THRESHOLD
                );
                println!("{} Total MAC errors: {}", "→".red(), self.total_mac_errors);
            }
            ValidationError::UnsecuredFrame => {
                println!(
                    "{} Unsecured frames detected: {} (Threshold: {})",
                    "→".red(),
                    self.unsecured_frame_count.to_string().red().bold(),
                    UNSECURED_FRAME_THRESHOLD
                );
                println!(
                    "{} Total unsecured frames: {}",
                    "→".red(),
                    self.total_unsecured_frames
                );
                println!();
                println!(
                    "{} {}",
                    "→".red(),
                    "ATTACK TYPE: Frame Injection".red().bold()
                );
                println!("   • Attacker is sending frames without valid MAC");
                println!("   • This indicates unauthorized ECU on the bus");
            }
            ValidationError::UnauthorizedAccess => {
                println!(
                    "{} Unauthorized access attempts: {}",
                    "→".red(),
                    self.total_unauthorized_access
                );
                println!();
                println!(
                    "{} {}",
                    "→".red(),
                    "ATTACK TYPE: Authorization Violation".red().bold()
                );
                println!("   • ECU attempting to use unauthorized CAN ID");
                println!("   • This indicates compromised or rogue ECU");
                println!("   • Access control whitelist violated");
            }
        }

        println!();
        println!(
            "{} {}",
            "→".red(),
            "PROTECTIVE MEASURES ACTIVATED:".yellow().bold()
        );
        println!("   • Rejecting all unverified frames");
        println!("   • Entering fail-safe mode");
        println!("   • Maintaining last known safe state");
        println!("   • Logging attack details");
        println!();
        println!("{}", "═══════════════════════════════════════".red().bold());
        println!();
    }

    /// Check if ECU should accept frames (not under attack)
    pub fn should_accept_frames(&self) -> bool {
        self.state != SecurityState::UnderAttack
    }

    /// Get current security state
    pub fn state(&self) -> SecurityState {
        self.state
    }

    /// Get current error statistics
    pub fn get_stats(&self) -> AttackDetectorStats {
        AttackDetectorStats {
            crc_error_count: self.crc_error_count,
            mac_error_count: self.mac_error_count,
            unsecured_frame_count: self.unsecured_frame_count,
            total_crc_errors: self.total_crc_errors,
            total_mac_errors: self.total_mac_errors,
            total_unsecured_frames: self.total_unsecured_frames,
            total_unauthorized_access: self.total_unauthorized_access,
            total_valid_frames: self.total_valid_frames,
            state: self.state,
        }
    }

    /// Reset attack state (for testing or manual recovery)
    pub fn reset(&mut self) {
        println!(
            "{} {} - Resetting attack detector",
            "→".cyan(),
            "RESET".cyan().bold()
        );

        // Log security reset
        if let Some(logger) = &self.security_logger {
            logger.log_security_reset("Manual reset".to_string());
            logger.log_statistics(
                self.total_valid_frames,
                self.total_crc_errors,
                self.total_mac_errors,
                self.total_unsecured_frames,
            );
        }

        self.crc_error_count = 0;
        self.mac_error_count = 0;
        self.unsecured_frame_count = 0;
        self.state = SecurityState::Normal;
    }

    /// Handle unauthorized CAN ID access attempt
    pub fn handle_unauthorized_access(&mut self, frame: &crate::hsm::SecuredCanFrame) {
        self.total_unauthorized_access += 1;

        println!(
            "{} {} from {} on CAN ID 0x{:03X}",
            "⚠️".yellow(),
            "UNAUTHORIZED CAN ID ACCESS".red().bold(),
            frame.source.bright_black(),
            frame.can_id.value()
        );

        // Log to security event logger
        if let Some(ref logger) = self.security_logger {
            logger.log_event(crate::security_log::SecurityEvent::FrameRejected {
                source: frame.source.clone(),
                can_id: frame.can_id.value(),
                reason: "Unauthorized CAN ID access".to_string(),
            });
        }

        // Unauthorized access triggers immediate state change to UnderAttack
        let old_state = self.state;
        self.state = SecurityState::UnderAttack;

        if old_state != self.state {
            println!();
            println!("{}", "═══════════════════════════════════════".red().bold());
            println!("{}", "       ATTACK DETECTED             ".red().bold());
            println!("{}", "═══════════════════════════════════════".red().bold());
            println!();
            println!("{} ECU: {}", "→".red(), self.ecu_name.yellow().bold());
            println!(
                "{} Error Type: {}",
                "→".red(),
                "Unauthorized CAN ID Access".red().bold()
            );
            println!(
                "{} Unauthorized attempts: {}",
                "→".red(),
                self.total_unauthorized_access
            );
            println!();
            println!(
                "{} {}",
                "→".red(),
                "ATTACK TYPE: Authorization Violation".red().bold()
            );
            println!("   • ECU attempting to use unauthorized CAN ID");
            println!("   • This indicates compromised or rogue ECU");
            println!("   • Access control whitelist violated");
            println!();
            println!(
                "{} {}",
                "→".red(),
                "PROTECTIVE MEASURES ACTIVATED:".yellow().bold()
            );
            println!("   • Rejecting all unauthorized frames");
            println!("   • Entering fail-safe mode");
            println!("   • Logging violation details");
            println!();
            println!("{}", "═══════════════════════════════════════".red().bold());
            println!();

            // Log state change
            if let Some(ref logger) = self.security_logger {
                logger.log_state_change(
                    format!("{:?}", old_state),
                    format!("{:?}", self.state),
                    "Unauthorized CAN ID access detected".to_string(),
                );
                logger.log_fail_safe_activated(
                    "Unauthorized access - entering fail-safe mode".to_string(),
                );
            }
        }
    }

    /// Get total unauthorized access attempts
    pub fn get_unauthorized_count(&self) -> u64 {
        self.total_unauthorized_access
    }
}

/// Statistics for attack detector
#[derive(Debug, Clone)]
pub struct AttackDetectorStats {
    pub crc_error_count: u32,
    pub mac_error_count: u32,
    pub unsecured_frame_count: u32,
    pub total_crc_errors: u64,
    pub total_mac_errors: u64,
    pub total_unsecured_frames: u64,
    pub total_unauthorized_access: u64,
    pub total_valid_frames: u64,
    pub state: SecurityState,
}

impl fmt::Display for AttackDetectorStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "State: {} | CRC: {}/{} (Total: {}) | MAC: {}/{} (Total: {}) | Unsecured: {}/{} (Total: {}) | Valid: {}",
            self.state,
            self.crc_error_count,
            CRC_ERROR_THRESHOLD,
            self.total_crc_errors,
            self.mac_error_count,
            MAC_ERROR_THRESHOLD,
            self.total_mac_errors,
            self.unsecured_frame_count,
            UNSECURED_FRAME_THRESHOLD,
            self.total_unsecured_frames,
            self.total_valid_frames
        )
    }
}
