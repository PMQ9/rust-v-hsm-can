use chrono::{DateTime, Utc};
use std::fmt;

/// Reasons why MAC verification can fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacFailureReason {
    /// No MAC verification key registered for the source ECU
    NoKeyRegistered,
    /// HMAC cryptographic verification failed (tampered data or wrong key)
    CryptoFailure,
}

impl fmt::Display for MacFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacFailureReason::NoKeyRegistered => write!(f, "No MAC key registered for source ECU"),
            MacFailureReason::CryptoFailure => write!(f, "HMAC cryptographic verification failed"),
        }
    }
}

/// Replay detection errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// Counter was already seen in sliding window
    CounterAlreadySeen { counter: u64 },

    /// Counter is not increasing (strict mode)
    CounterNotIncreasing { received: u64, expected_min: u64 },

    /// Counter is too old (outside sliding window)
    CounterTooOld { received: u64, min_acceptable: u64 },

    /// Frame timestamp is too old
    TimestampTooOld {
        frame_time: DateTime<Utc>,
        current_time: DateTime<Utc>,
    },

    /// Frame timestamp is too far in future (clock skew)
    TimestampTooFarInFuture {
        frame_time: DateTime<Utc>,
        current_time: DateTime<Utc>,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::CounterAlreadySeen { counter } => {
                write!(f, "Replay detected: counter {} already seen", counter)
            }
            ReplayError::CounterNotIncreasing {
                received,
                expected_min,
            } => {
                write!(
                    f,
                    "Counter not increasing: received {}, expected >= {}",
                    received, expected_min
                )
            }
            ReplayError::CounterTooOld {
                received,
                min_acceptable,
            } => {
                write!(
                    f,
                    "Counter too old: {}, minimum acceptable: {}",
                    received, min_acceptable
                )
            }
            ReplayError::TimestampTooOld {
                frame_time,
                current_time,
            } => {
                write!(
                    f,
                    "Frame timestamp too old: {:?} vs current: {:?}",
                    frame_time, current_time
                )
            }
            ReplayError::TimestampTooFarInFuture {
                frame_time,
                current_time,
            } => {
                write!(
                    f,
                    "Frame timestamp too far in future: {:?} vs current: {:?}",
                    frame_time, current_time
                )
            }
        }
    }
}

/// Structured verification error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Frame has no MAC/CRC (all zeros) - indicates unsecured/injected frame
    UnsecuredFrame,
    /// CRC32 checksum mismatch - indicates data corruption or tampering
    CrcMismatch,
    /// MAC verification failed - indicates authentication failure
    MacMismatch(MacFailureReason),
    /// Unauthorized CAN ID access - ECU not permitted to use this CAN ID
    UnauthorizedAccess,
    /// Replay attack detected - frame counter invalid
    ReplayDetected(ReplayError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::UnsecuredFrame => write!(f, "Unsecured frame (no MAC/CRC)"),
            VerifyError::CrcMismatch => write!(f, "CRC verification failed"),
            VerifyError::MacMismatch(reason) => write!(f, "MAC verification failed: {}", reason),
            VerifyError::UnauthorizedAccess => write!(f, "Unauthorized CAN ID access"),
            VerifyError::ReplayDetected(reason) => write!(f, "Replay attack detected: {}", reason),
        }
    }
}
