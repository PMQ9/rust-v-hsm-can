use chrono::{DateTime, Utc};
use std::collections::VecDeque;

use super::errors::ReplayError;

/// Configuration for replay protection behavior
#[derive(Debug, Clone)]
pub struct ReplayProtectionConfig {
    /// Size of sliding window (default: 100)
    pub window_size: usize,

    /// Allow out-of-order frame acceptance within window
    pub allow_reordering: bool,

    /// Maximum age for frames in seconds (0 = disabled)
    pub max_frame_age_secs: u64,

    /// Strict mode: reject any counter <= last_seen (default: false)
    pub strict_monotonic: bool,
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            allow_reordering: true,
            max_frame_age_secs: 60,
            strict_monotonic: false,
        }
    }
}

/// Replay protection state for a single ECU
#[derive(Debug, Clone)]
pub struct ReplayProtectionState {
    /// Last accepted counter from this ECU
    last_accepted_counter: u64,

    /// Sliding window of recently accepted counters (for out-of-order tolerance)
    accepted_window: VecDeque<u64>,

    /// Maximum window size
    window_size: usize,

    /// Timestamp of last accepted frame (for time-based validation)
    last_frame_timestamp: Option<DateTime<Utc>>,

    /// Allow out-of-order delivery within window (reserved for future use)
    #[allow(dead_code)]
    allow_reordering: bool,
}

impl ReplayProtectionState {
    pub fn new(config: &ReplayProtectionConfig) -> Self {
        Self {
            last_accepted_counter: 0,
            accepted_window: VecDeque::with_capacity(config.window_size),
            window_size: config.window_size,
            last_frame_timestamp: None,
            allow_reordering: config.allow_reordering,
        }
    }

    /// Mark a counter as accepted and update state
    pub fn accept_counter(&mut self, counter: u64, timestamp: DateTime<Utc>) {
        // Update last accepted counter if this is newer
        if counter > self.last_accepted_counter {
            self.last_accepted_counter = counter;
        }

        // Add to sliding window
        self.accepted_window.push_back(counter);

        // Maintain window size
        while self.accepted_window.len() > self.window_size {
            self.accepted_window.pop_front();
        }

        // Update timestamp
        self.last_frame_timestamp = Some(timestamp);
    }

    /// Reset state (for testing or ECU reset scenarios)
    pub fn reset(&mut self) {
        self.last_accepted_counter = 0;
        self.accepted_window.clear();
        self.last_frame_timestamp = None;
    }

    /// Get last accepted counter
    pub fn last_accepted_counter(&self) -> u64 {
        self.last_accepted_counter
    }

    /// Get accepted window
    pub fn accepted_window(&self) -> &VecDeque<u64> {
        &self.accepted_window
    }

    /// Get last frame timestamp
    pub fn last_frame_timestamp(&self) -> Option<DateTime<Utc>> {
        self.last_frame_timestamp
    }
}

/// Validate a counter against replay protection state
pub fn validate_counter(
    session_counter: u64,
    state: &ReplayProtectionState,
    config: &ReplayProtectionConfig,
    frame_timestamp: DateTime<Utc>,
) -> Result<(), ReplayError> {
    // Check 1: Strict monotonic (if enabled)
    if config.strict_monotonic && session_counter <= state.last_accepted_counter {
        return Err(ReplayError::CounterNotIncreasing {
            received: session_counter,
            expected_min: state.last_accepted_counter + 1,
        });
    }

    // Check 2: Sliding window check (counter already seen)
    if state.accepted_window.contains(&session_counter) {
        return Err(ReplayError::CounterAlreadySeen {
            counter: session_counter,
        });
    }

    // Check 3: Counter within acceptable range (window)
    // The window allows the last N counters (inclusive), so if window_size=100 and last=100,
    // we accept 1-100 (100 counters). Minimum acceptable is last - window_size + 1.
    let min_acceptable = state
        .last_accepted_counter
        .saturating_sub(state.window_size.saturating_sub(1) as u64);
    if session_counter < min_acceptable && state.last_accepted_counter > 0 {
        return Err(ReplayError::CounterTooOld {
            received: session_counter,
            min_acceptable,
        });
    }

    // Check 4: Timestamp validation (if enabled)
    if config.max_frame_age_secs > 0
        && let Some(last_timestamp) = state.last_frame_timestamp
    {
        let time_diff = frame_timestamp.signed_duration_since(last_timestamp);

        // Frame is too old
        if time_diff.num_seconds() < -(config.max_frame_age_secs as i64) {
            return Err(ReplayError::TimestampTooOld {
                frame_time: frame_timestamp,
                current_time: Utc::now(),
            });
        }

        // Frame is too far in the future (clock skew attack)
        if time_diff.num_seconds() > config.max_frame_age_secs as i64 {
            return Err(ReplayError::TimestampTooFarInFuture {
                frame_time: frame_timestamp,
                current_time: Utc::now(),
            });
        }
    }

    Ok(())
}
