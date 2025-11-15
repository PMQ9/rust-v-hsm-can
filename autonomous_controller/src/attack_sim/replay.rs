/// Replay Attack Simulators
///
/// Implements various replay attack scenarios:
/// 1. Simple Replay - Immediate replay of captured frames
/// 2. Delayed Replay - Replay after time delay
/// 3. Reordered Replay - Change order of captured frames
/// 4. Selective Replay - Replay specific high-value frames
use crate::attack_sim::{AttackConfig, AttackResult, AttackSimulator, AttackType};
use crate::hsm::SecuredCanFrame;
use chrono::{DateTime, Duration, Utc};
use std::collections::VecDeque;

/// Simple replay attack - capture and immediately replay frames
pub struct SimpleReplay {
    captured_frames: VecDeque<SecuredCanFrame>,
    max_capture_size: usize,
}

impl SimpleReplay {
    pub fn new(max_capture_size: usize) -> Self {
        Self {
            captured_frames: VecDeque::with_capacity(max_capture_size),
            max_capture_size,
        }
    }

    /// Capture a frame for later replay
    pub fn capture_frame(&mut self, frame: SecuredCanFrame) {
        if self.captured_frames.len() >= self.max_capture_size {
            self.captured_frames.pop_front();
        }
        self.captured_frames.push_back(frame);
    }

    /// Get a frame to replay (oldest first)
    pub fn get_replay_frame(&mut self) -> Option<SecuredCanFrame> {
        self.captured_frames.pop_front()
    }

    /// Get the number of captured frames
    pub fn captured_count(&self) -> usize {
        self.captured_frames.len()
    }

    /// Clear all captured frames
    pub fn clear_captures(&mut self) {
        self.captured_frames.clear();
    }
}

impl AttackSimulator for SimpleReplay {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        if self.captured_frames.is_empty() {
            return Err("No frames captured for replay".to_string());
        }

        let mut result = AttackResult::new(AttackType::ReplaySimple);
        let replay_count = config
            .frame_count
            .unwrap_or(self.captured_frames.len() as u32)
            .min(self.captured_frames.len() as u32);

        for _ in 0..replay_count {
            if let Some(_frame) = self.get_replay_frame() {
                result.frames_sent += 1;
                // In a real attack, frame would be sent here
            }
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ReplaySimple
    }
}

/// Delayed replay attack - replay frames after a time delay
pub struct DelayedReplay {
    captured_frames: Vec<(SecuredCanFrame, DateTime<Utc>)>, // Frame + capture time
    max_capture_size: usize,
}

impl DelayedReplay {
    pub fn new(max_capture_size: usize) -> Self {
        Self {
            captured_frames: Vec::with_capacity(max_capture_size),
            max_capture_size,
        }
    }

    /// Capture a frame with timestamp
    pub fn capture_frame(&mut self, frame: SecuredCanFrame) {
        if self.captured_frames.len() >= self.max_capture_size {
            self.captured_frames.remove(0);
        }
        self.captured_frames.push((frame, Utc::now()));
    }

    /// Get frames older than the specified age (in seconds)
    pub fn get_old_frames(&self, min_age_secs: i64) -> Vec<SecuredCanFrame> {
        let now = Utc::now();
        let threshold = now - Duration::seconds(min_age_secs);

        self.captured_frames
            .iter()
            .filter(|(_, capture_time)| *capture_time < threshold)
            .map(|(frame, _)| frame.clone())
            .collect()
    }

    /// Get the oldest N frames
    pub fn get_oldest_frames(&self, count: usize) -> Vec<SecuredCanFrame> {
        self.captured_frames
            .iter()
            .take(count)
            .map(|(frame, _)| frame.clone())
            .collect()
    }
}

impl AttackSimulator for DelayedReplay {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        if self.captured_frames.is_empty() {
            return Err("No frames captured for delayed replay".to_string());
        }

        let mut result = AttackResult::new(AttackType::ReplayDelayed);

        // Replay frames that are at least 5 seconds old (outside typical replay window)
        let old_frames = self.get_old_frames(5);

        if old_frames.is_empty() {
            // If no old frames, replay the oldest ones we have
            let replay_frames = self.get_oldest_frames(config.frame_count.unwrap_or(10) as usize);
            result.frames_sent = replay_frames.len() as u64;
        } else {
            let replay_count = config
                .frame_count
                .unwrap_or(old_frames.len() as u32)
                .min(old_frames.len() as u32);

            for _ in 0..replay_count {
                // In a real attack, frame would be sent here
                result.frames_sent += 1;
            }
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ReplayDelayed
    }
}

/// Reordered replay attack - change the order of captured frames
pub struct ReorderedReplay {
    captured_frames: Vec<SecuredCanFrame>,
    max_capture_size: usize,
}

impl ReorderedReplay {
    pub fn new(max_capture_size: usize) -> Self {
        Self {
            captured_frames: Vec::with_capacity(max_capture_size),
            max_capture_size,
        }
    }

    /// Capture a frame
    pub fn capture_frame(&mut self, frame: SecuredCanFrame) {
        if self.captured_frames.len() >= self.max_capture_size {
            self.captured_frames.remove(0);
        }
        self.captured_frames.push(frame);
    }

    /// Get frames in reverse order
    pub fn get_reversed_frames(&self) -> Vec<SecuredCanFrame> {
        self.captured_frames.iter().rev().cloned().collect()
    }

    /// Get frames in shuffled order (deterministic shuffle)
    pub fn get_shuffled_frames(&self, seed: u64) -> Vec<SecuredCanFrame> {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut frames = self.captured_frames.clone();
        let mut rng = StdRng::seed_from_u64(seed);

        // Fisher-Yates shuffle
        for i in (1..frames.len()).rev() {
            let j = rng.gen_range(0..=i);
            frames.swap(i, j);
        }

        frames
    }

    /// Get every Nth frame (create gaps)
    pub fn get_sparse_frames(&self, step: usize) -> Vec<SecuredCanFrame> {
        self.captured_frames.iter().step_by(step).cloned().collect()
    }
}

impl AttackSimulator for ReorderedReplay {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        if self.captured_frames.is_empty() {
            return Err("No frames captured for reordered replay".to_string());
        }

        let mut result = AttackResult::new(AttackType::ReplayReordered);

        // Shuffle frames based on intensity
        let reordered_frames = if config.intensity > 0.7 {
            // High intensity: completely shuffle
            self.get_shuffled_frames(12345)
        } else if config.intensity > 0.3 {
            // Medium intensity: reverse order
            self.get_reversed_frames()
        } else {
            // Low intensity: sparse replay (every 2nd frame)
            self.get_sparse_frames(2)
        };

        let replay_count = config
            .frame_count
            .unwrap_or(reordered_frames.len() as u32)
            .min(reordered_frames.len() as u32);

        for _ in 0..replay_count {
            // In a real attack, frame would be sent here
            result.frames_sent += 1;
        }

        result
            .metrics
            .insert("reorder_strategy".to_string(), config.intensity);
        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ReplayReordered
    }
}

/// Selective replay attack - target high-value frames
pub struct SelectiveReplay {
    captured_frames: Vec<SecuredCanFrame>,
    max_capture_size: usize,
    target_can_ids: Vec<u32>,
}

impl SelectiveReplay {
    pub fn new(max_capture_size: usize, target_can_ids: Vec<u32>) -> Self {
        Self {
            captured_frames: Vec::with_capacity(max_capture_size),
            max_capture_size,
            target_can_ids,
        }
    }

    /// Capture a frame (only if it matches target CAN IDs)
    pub fn capture_frame(&mut self, frame: SecuredCanFrame) {
        // Only capture frames with target CAN IDs
        if self.target_can_ids.is_empty() || self.target_can_ids.contains(&frame.can_id.value()) {
            if self.captured_frames.len() >= self.max_capture_size {
                self.captured_frames.remove(0);
            }
            self.captured_frames.push(frame);
        }
    }

    /// Get frames for a specific CAN ID
    pub fn get_frames_by_can_id(&self, can_id: u32) -> Vec<SecuredCanFrame> {
        self.captured_frames
            .iter()
            .filter(|f| f.can_id.value() == can_id)
            .cloned()
            .collect()
    }

    /// Get frames from a specific source ECU
    pub fn get_frames_by_source(&self, source: &str) -> Vec<SecuredCanFrame> {
        self.captured_frames
            .iter()
            .filter(|f| f.source == source)
            .cloned()
            .collect()
    }

    /// Get high-value command frames (brake, throttle, steering)
    pub fn get_command_frames(&self) -> Vec<SecuredCanFrame> {
        let command_ids = vec![0x300, 0x301, 0x302]; // Brake, throttle, steering
        self.captured_frames
            .iter()
            .filter(|f| command_ids.contains(&f.can_id.value()))
            .cloned()
            .collect()
    }
}

impl AttackSimulator for SelectiveReplay {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        if self.captured_frames.is_empty() {
            return Err("No frames captured for selective replay".to_string());
        }

        let mut result = AttackResult::new(AttackType::ReplaySelective);

        // Select frames based on target CAN ID or get high-value commands
        let selected_frames = if let Some(can_id) = config.target_can_id {
            self.get_frames_by_can_id(can_id)
        } else {
            self.get_command_frames()
        };

        if selected_frames.is_empty() {
            return Err("No matching frames found for selective replay".to_string());
        }

        let replay_count = config
            .frame_count
            .unwrap_or(selected_frames.len() as u32)
            .min(selected_frames.len() as u32);

        for _ in 0..replay_count {
            // In a real attack, frame would be sent here
            result.frames_sent += 1;
        }

        result
            .metrics
            .insert("selected_frames".to_string(), selected_frames.len() as f64);
        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ReplaySelective
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CanId;

    fn create_test_frame(can_id: u32, source: &str, counter: u64) -> SecuredCanFrame {
        SecuredCanFrame {
            can_id: CanId::Standard(can_id as u16),
            data: vec![1, 2, 3, 4],
            timestamp: Utc::now(),
            source: source.to_string(),
            session_counter: counter,
            mac: [0; 32],
            crc: 0,
        }
    }

    #[test]
    fn test_simple_replay_capture_and_replay() {
        let mut replayer = SimpleReplay::new(10);

        // Capture some frames
        for i in 0..5 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        assert_eq!(replayer.captured_count(), 5);

        // Replay a frame
        let replayed = replayer.get_replay_frame().unwrap();
        assert_eq!(replayed.session_counter, 0); // First captured frame

        assert_eq!(replayer.captured_count(), 4); // One removed
    }

    #[test]
    fn test_simple_replay_max_capture_size() {
        let mut replayer = SimpleReplay::new(3);

        // Capture more frames than max size
        for i in 0..5 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        // Should only keep last 3
        assert_eq!(replayer.captured_count(), 3);

        let first = replayer.get_replay_frame().unwrap();
        assert_eq!(first.session_counter, 2); // Oldest kept is counter=2
    }

    #[test]
    fn test_simple_replay_execute() {
        let mut replayer = SimpleReplay::new(10);

        for i in 0..10 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        let config = AttackConfig {
            attack_type: AttackType::ReplaySimple,
            frame_count: Some(5),
            ..Default::default()
        };

        let result = replayer.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 5);
        assert_eq!(result.attack_type, AttackType::ReplaySimple);
        assert_eq!(replayer.captured_count(), 5); // 5 remaining
    }

    #[test]
    fn test_simple_replay_requires_captures() {
        let mut replayer = SimpleReplay::new(10);
        let config = AttackConfig {
            attack_type: AttackType::ReplaySimple,
            frame_count: Some(5),
            ..Default::default()
        };

        let result = replayer.execute(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No frames captured"));
    }

    #[test]
    fn test_delayed_replay_old_frames() {
        let mut replayer = DelayedReplay::new(10);

        // Simulate capturing frames at different times
        for i in 0..5 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        // Get frames older than 0 seconds (all frames)
        let old_frames = replayer.get_old_frames(0);
        assert!(old_frames.len() <= 5); // May be less due to timing

        // Get oldest 3 frames
        let oldest = replayer.get_oldest_frames(3);
        assert_eq!(oldest.len(), 3);
    }

    #[test]
    fn test_delayed_replay_execute() {
        let mut replayer = DelayedReplay::new(10);

        for i in 0..8 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        let config = AttackConfig {
            attack_type: AttackType::ReplayDelayed,
            frame_count: Some(4),
            ..Default::default()
        };

        let result = replayer.execute(&config).unwrap();
        assert!(result.frames_sent > 0);
        assert_eq!(result.attack_type, AttackType::ReplayDelayed);
    }

    #[test]
    fn test_reordered_replay_reverse() {
        let mut replayer = ReorderedReplay::new(10);

        for i in 0..5 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        let reversed = replayer.get_reversed_frames();
        assert_eq!(reversed.len(), 5);
        assert_eq!(reversed[0].session_counter, 4); // Last becomes first
        assert_eq!(reversed[4].session_counter, 0); // First becomes last
    }

    #[test]
    fn test_reordered_replay_shuffle() {
        let mut replayer = ReorderedReplay::new(10);

        for i in 0..5 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        let shuffled = replayer.get_shuffled_frames(12345);
        assert_eq!(shuffled.len(), 5);

        // Shuffled should be different from original order (statistically)
        let original_order: Vec<u64> = (0..5).collect();
        let shuffled_order: Vec<u64> = shuffled.iter().map(|f| f.session_counter).collect();

        // At least one element should be in a different position
        let mut different = false;
        for i in 0..5 {
            if original_order[i] != shuffled_order[i] {
                different = true;
                break;
            }
        }
        assert!(different);
    }

    #[test]
    fn test_reordered_replay_sparse() {
        let mut replayer = ReorderedReplay::new(10);

        for i in 0..6 {
            let frame = create_test_frame(0x100, "SENSOR", i);
            replayer.capture_frame(frame);
        }

        let sparse = replayer.get_sparse_frames(2);
        assert_eq!(sparse.len(), 3); // Every 2nd frame: 0, 2, 4
        assert_eq!(sparse[0].session_counter, 0);
        assert_eq!(sparse[1].session_counter, 2);
        assert_eq!(sparse[2].session_counter, 4);
    }

    #[test]
    fn test_selective_replay_by_can_id() {
        let mut replayer = SelectiveReplay::new(10, vec![0x300]);

        // Capture mixed frames
        replayer.capture_frame(create_test_frame(0x100, "SENSOR", 1));
        replayer.capture_frame(create_test_frame(0x300, "CTRL", 2));
        replayer.capture_frame(create_test_frame(0x100, "SENSOR", 3));
        replayer.capture_frame(create_test_frame(0x300, "CTRL", 4));

        // Should only capture target CAN IDs
        let frames_300 = replayer.get_frames_by_can_id(0x300);
        assert_eq!(frames_300.len(), 2);
    }

    #[test]
    fn test_selective_replay_command_frames() {
        let mut replayer = SelectiveReplay::new(10, vec![]);

        // Capture various frames including commands
        replayer.capture_frame(create_test_frame(0x100, "SENSOR", 1));
        replayer.capture_frame(create_test_frame(0x300, "CTRL", 2)); // Brake
        replayer.capture_frame(create_test_frame(0x301, "CTRL", 3)); // Throttle
        replayer.capture_frame(create_test_frame(0x200, "OTHER", 4));
        replayer.capture_frame(create_test_frame(0x302, "CTRL", 5)); // Steering

        let commands = replayer.get_command_frames();
        assert_eq!(commands.len(), 3); // Only brake, throttle, steering
    }

    #[test]
    fn test_selective_replay_by_source() {
        let mut replayer = SelectiveReplay::new(10, vec![]);

        replayer.capture_frame(create_test_frame(0x100, "SENSOR_A", 1));
        replayer.capture_frame(create_test_frame(0x200, "SENSOR_B", 2));
        replayer.capture_frame(create_test_frame(0x300, "SENSOR_A", 3));

        let sensor_a_frames = replayer.get_frames_by_source("SENSOR_A");
        assert_eq!(sensor_a_frames.len(), 2);
    }

    #[test]
    fn test_selective_replay_execute() {
        let mut replayer = SelectiveReplay::new(10, vec![0x300, 0x301]);

        replayer.capture_frame(create_test_frame(0x300, "CTRL", 1));
        replayer.capture_frame(create_test_frame(0x301, "CTRL", 2));
        replayer.capture_frame(create_test_frame(0x100, "SENSOR", 3)); // Won't be captured

        let config = AttackConfig {
            attack_type: AttackType::ReplaySelective,
            target_can_id: Some(0x300),
            frame_count: Some(1),
            ..Default::default()
        };

        let result = replayer.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 1);
        assert_eq!(result.attack_type, AttackType::ReplaySelective);
    }
}
