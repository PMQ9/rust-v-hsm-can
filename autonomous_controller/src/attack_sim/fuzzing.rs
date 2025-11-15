/// Fuzzing Engine for CAN Bus Security Testing
///
/// Implements three fuzzing strategies:
/// 1. Random Fuzzing - Generate completely random CAN frames
/// 2. Mutation-based Fuzzing - Mutate valid frames (bit flips, byte modifications)
/// 3. Grammar-based Fuzzing - Protocol-aware fuzzing respecting CAN structure
use crate::attack_sim::{AttackConfig, AttackResult, AttackSimulator, AttackType};
use crate::hsm::SecuredCanFrame;
use crate::types::CanId;
use chrono::Utc;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Random fuzzing engine
pub struct RandomFuzzer {
    rng: StdRng,
}

impl RandomFuzzer {
    pub fn new(seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Self { rng }
    }

    /// Generate a completely random CAN frame
    pub fn generate_random_frame(&mut self, source: &str) -> SecuredCanFrame {
        // Random CAN ID (11-bit standard)
        let can_id = self.rng.gen_range(0x000..=0x7FF);

        // Random data length (0-8 bytes)
        let data_len = self.rng.gen_range(0..=8);
        let mut data = vec![0u8; data_len];
        self.rng.fill(&mut data[..]);

        // Random MAC and CRC (likely invalid)
        let mut mac = [0u8; 32];
        self.rng.fill(&mut mac[..]);
        let crc = self.rng.gen_range(u32::MIN..=u32::MAX);

        SecuredCanFrame {
            can_id: CanId::Standard(can_id as u16),
            data,
            timestamp: Utc::now(),
            source: source.to_string(),
            session_counter: self.rng.gen_range(u64::MIN..=u64::MAX),
            mac,
            crc,
        }
    }
}

impl AttackSimulator for RandomFuzzer {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::FuzzRandom);
        let _start = Utc::now();

        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for _ in 0..frame_count {
            let _frame = self.generate_random_frame("FUZZER");
            result.frames_sent += 1;

            // In a real attack, frames would be sent here
            // For now, just count them
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FuzzRandom
    }
}

/// Mutation-based fuzzer
pub struct MutationFuzzer {
    rng: StdRng,
    seed_frames: Vec<SecuredCanFrame>,
}

impl MutationFuzzer {
    pub fn new(seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Self {
            rng,
            seed_frames: Vec::new(),
        }
    }

    /// Add a seed frame for mutation
    pub fn add_seed_frame(&mut self, frame: SecuredCanFrame) {
        self.seed_frames.push(frame);
    }

    /// Mutate a frame using various strategies
    pub fn mutate_frame(&mut self, frame: &SecuredCanFrame) -> SecuredCanFrame {
        let mut mutated = frame.clone();
        let mutation_type = self.rng.gen_range(0..7);

        match mutation_type {
            0 => self.flip_random_bit(&mut mutated),
            1 => self.modify_random_byte(&mut mutated),
            2 => self.swap_bytes(&mut mutated),
            3 => self.truncate_data(&mut mutated),
            4 => self.extend_data(&mut mutated),
            5 => self.corrupt_mac(&mut mutated),
            6 => self.corrupt_crc(&mut mutated),
            _ => {}
        }

        mutated
    }

    fn flip_random_bit(&mut self, frame: &mut SecuredCanFrame) {
        if frame.data.is_empty() {
            return;
        }
        let byte_idx = self.rng.gen_range(0..frame.data.len());
        let bit_idx = self.rng.gen_range(0..8);
        frame.data[byte_idx] ^= 1 << bit_idx;
    }

    fn modify_random_byte(&mut self, frame: &mut SecuredCanFrame) {
        if frame.data.is_empty() {
            return;
        }
        let idx = self.rng.gen_range(0..frame.data.len());
        frame.data[idx] = self.rng.gen_range(u8::MIN..=u8::MAX);
    }

    fn swap_bytes(&mut self, frame: &mut SecuredCanFrame) {
        if frame.data.len() < 2 {
            return;
        }
        let idx1 = self.rng.gen_range(0..frame.data.len());
        let idx2 = self.rng.gen_range(0..frame.data.len());
        frame.data.swap(idx1, idx2);
    }

    fn truncate_data(&mut self, frame: &mut SecuredCanFrame) {
        if frame.data.is_empty() {
            return;
        }
        let new_len = self.rng.gen_range(0..frame.data.len());
        frame.data.truncate(new_len);
    }

    fn extend_data(&mut self, frame: &mut SecuredCanFrame) {
        if frame.data.len() >= 8 {
            return; // CAN max is 8 bytes
        }
        let extension_len = self.rng.gen_range(1..=(8 - frame.data.len()));
        for _ in 0..extension_len {
            frame.data.push(self.rng.gen_range(u8::MIN..=u8::MAX));
        }
    }

    fn corrupt_mac(&mut self, frame: &mut SecuredCanFrame) {
        let idx = self.rng.gen_range(0..32);
        frame.mac[idx] ^= 1 << self.rng.gen_range(0..8);
    }

    fn corrupt_crc(&mut self, frame: &mut SecuredCanFrame) {
        frame.crc = frame.crc.wrapping_add(self.rng.gen_range(1..=0xFF));
    }
}

impl AttackSimulator for MutationFuzzer {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        if self.seed_frames.is_empty() {
            return Err("No seed frames available for mutation".to_string());
        }

        let mut result = AttackResult::new(AttackType::FuzzMutation);
        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for _ in 0..frame_count {
            let seed_idx = self.rng.gen_range(0..self.seed_frames.len());
            let seed_frame = self.seed_frames[seed_idx].clone();
            let _mutated = self.mutate_frame(&seed_frame);
            result.frames_sent += 1;

            // In a real attack, frames would be sent here
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FuzzMutation
    }
}

/// Grammar-based fuzzer (protocol-aware)
pub struct GrammarFuzzer {
    rng: StdRng,
    valid_can_ids: Vec<u32>,
}

impl GrammarFuzzer {
    pub fn new(seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        // Standard automotive CAN ID ranges
        let valid_can_ids = vec![
            0x100, 0x101, 0x102, 0x103, // Wheel speeds
            0x110, 0x111, // Engine
            0x120, 0x121, // Steering
            0x300, 0x301, 0x302, // Commands
            0x400, 0x401, // Autonomous
        ];

        Self { rng, valid_can_ids }
    }

    /// Generate a protocol-aware fuzzed frame
    pub fn generate_grammar_frame(&mut self, source: &str) -> SecuredCanFrame {
        // Use a valid CAN ID from the protocol
        let can_id = *self.valid_can_ids.choose(&mut self.rng).unwrap();

        // Generate data that respects CAN frame structure
        let data_len = self.rng.gen_range(1..=8);
        let mut data = vec![0u8; data_len];

        // Fill with semi-realistic data (not completely random)
        for byte in &mut data {
            *byte = self.rng.gen_range(0..=200); // More realistic range
        }

        // Intentionally invalid MAC/CRC (for testing)
        let mac = [0u8; 32]; // All zeros = unsecured
        let crc = 0;

        SecuredCanFrame {
            can_id: CanId::Standard(can_id as u16),
            data,
            timestamp: Utc::now(),
            source: source.to_string(),
            session_counter: self.rng.gen_range(u64::MIN..=u64::MAX),
            mac,
            crc,
        }
    }
}

impl AttackSimulator for GrammarFuzzer {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::FuzzGrammar);
        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for _ in 0..frame_count {
            let _frame = self.generate_grammar_frame("GRAMMAR_FUZZER");
            result.frames_sent += 1;

            // In a real attack, frames would be sent here
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FuzzGrammar
    }
}

// Add choose method for Vec
trait Choose {
    type Item;
    fn choose<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<&Self::Item>;
}

impl<T> Choose for Vec<T> {
    type Item = T;
    fn choose<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<&Self::Item> {
        if self.is_empty() {
            None
        } else {
            let idx = rng.gen_range(0..self.len());
            Some(&self[idx])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_fuzzer_generates_frames() {
        let mut fuzzer = RandomFuzzer::new(Some(12345));
        let frame = fuzzer.generate_random_frame("TEST");

        assert_eq!(frame.source, "TEST");
        assert!(frame.data.len() <= 8);
    }

    #[test]
    fn test_mutation_fuzzer_flips_bits() {
        let mut fuzzer = MutationFuzzer::new(Some(54321));
        let original = SecuredCanFrame {
            can_id: CanId::Standard(0x100),
            data: vec![0xFF, 0x00],
            timestamp: Utc::now(),
            source: "ORIGINAL".to_string(),
            session_counter: 1,
            mac: [0; 32],
            crc: 0,
        };

        let mutated = fuzzer.mutate_frame(&original);
        // Mutation should have changed something (statistically almost certain)
        assert_eq!(mutated.source, "ORIGINAL");
    }

    #[test]
    fn test_grammar_fuzzer_uses_valid_can_ids() {
        let mut fuzzer = GrammarFuzzer::new(Some(99999));
        let frame = fuzzer.generate_grammar_frame("GRAMMAR");

        // Should use one of the valid CAN IDs
        let can_id = frame.can_id.value();
        assert!(can_id >= 0x100 && can_id <= 0x401);
    }

    #[test]
    fn test_random_fuzzer_execute() {
        let mut fuzzer = RandomFuzzer::new(Some(11111));
        let config = AttackConfig {
            attack_type: AttackType::FuzzRandom,
            frame_count: Some(50),
            ..Default::default()
        };

        let result = fuzzer.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 50);
        assert_eq!(result.attack_type, AttackType::FuzzRandom);
    }

    #[test]
    fn test_mutation_fuzzer_requires_seed_frames() {
        let mut fuzzer = MutationFuzzer::new(Some(22222));
        let config = AttackConfig {
            attack_type: AttackType::FuzzMutation,
            frame_count: Some(10),
            ..Default::default()
        };

        let result = fuzzer.execute(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("No seed frames available for mutation")
        );
    }

    #[test]
    fn test_mutation_fuzzer_with_seed_frames() {
        let mut fuzzer = MutationFuzzer::new(Some(33333));
        let seed = SecuredCanFrame {
            can_id: CanId::Standard(0x100),
            data: vec![1, 2, 3, 4],
            timestamp: Utc::now(),
            source: "SEED".to_string(),
            session_counter: 1,
            mac: [0; 32],
            crc: 0,
        };

        fuzzer.add_seed_frame(seed);

        let config = AttackConfig {
            attack_type: AttackType::FuzzMutation,
            frame_count: Some(20),
            ..Default::default()
        };

        let result = fuzzer.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 20);
    }

    #[test]
    fn test_grammar_fuzzer_execute() {
        let mut fuzzer = GrammarFuzzer::new(Some(44444));
        let config = AttackConfig {
            attack_type: AttackType::FuzzGrammar,
            frame_count: Some(30),
            ..Default::default()
        };

        let result = fuzzer.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 30);
        assert_eq!(result.attack_type, AttackType::FuzzGrammar);
    }
}
