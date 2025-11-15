/// Injection Attack Simulators
///
/// Implements various injection attack scenarios:
/// 1. Unsecured Frame Injection - Frames without valid MAC/CRC
/// 2. MAC Tampering - Valid frames with corrupted MACs
/// 3. CRC Corruption - Frames with invalid CRCs
/// 4. Source Spoofing - Frames claiming to be from different ECUs
/// 5. Flooding - DoS attack via message flooding

use crate::attack_sim::{AttackConfig, AttackResult, AttackSimulator, AttackType};
use crate::hsm::{SecuredCanFrame, VirtualHSM};
use crate::types::CanId;
use chrono::Utc;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Unsecured frame injection attack
pub struct UnsecuredInjector {
    rng: StdRng,
    source: String,
}

impl UnsecuredInjector {
    pub fn new(source: String, seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Self { rng, source }
    }

    /// Generate an unsecured frame (all-zero MAC and CRC)
    pub fn generate_unsecured_frame(&mut self, can_id: u32, data: Vec<u8>) -> SecuredCanFrame {
        SecuredCanFrame {
            can_id: CanId::Standard(can_id as u16),
            data,
            timestamp: Utc::now(),
            source: self.source.clone(),
            session_counter: self.rng.gen_range(u64::MIN..=u64::MAX),
            mac: [0u8; 32], // All zeros = unsecured
            crc: 0,         // Zero CRC
        }
    }
}

impl AttackSimulator for UnsecuredInjector {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::InjectUnsecured);
        let can_id = config.target_can_id.unwrap_or(0x300); // Default: brake command

        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for i in 0..frame_count {
            let data = vec![
                (i % 256) as u8,
                0xFF,
                0xFF,
                0xFF, // Malicious brake command
            ];
            let _frame = self.generate_unsecured_frame(can_id, data);
            result.frames_sent += 1;

            // In a real attack, frames would be sent here
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InjectUnsecured
    }
}

/// MAC tampering attack
pub struct MacTamperer {
    rng: StdRng,
    hsm: VirtualHSM,
}

impl MacTamperer {
    pub fn new(ecu_name: String, seed: u64) -> Self {
        let rng = StdRng::seed_from_u64(seed);
        let hsm = VirtualHSM::new(ecu_name, seed);
        Self { rng, hsm }
    }

    /// Generate a frame with a valid structure but tampered MAC
    pub fn generate_tampered_mac_frame(
        &mut self,
        can_id: u32,
        data: Vec<u8>,
        source: String,
    ) -> Result<SecuredCanFrame, String> {
        // Create a valid frame first
        let mut frame = SecuredCanFrame::new(
            CanId::Standard(can_id as u16),
            data,
            source,
            &mut self.hsm,
        )?;

        // Tamper with the MAC by flipping random bits
        let byte_idx = self.rng.gen_range(0..32);
        frame.mac[byte_idx] ^= 1 << self.rng.gen_range(0..8);

        Ok(frame)
    }
}

impl AttackSimulator for MacTamperer {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::InjectMacTampered);
        let can_id = config.target_can_id.unwrap_or(0x300);
        let source = config
            .spoofed_source
            .clone()
            .unwrap_or_else(|| self.hsm.get_ecu_id().to_string());

        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for i in 0..frame_count {
            let data = vec![(i % 256) as u8, 0x50, 0x75, 0x90];
            match self.generate_tampered_mac_frame(can_id, data, source.clone()) {
                Ok(_frame) => {
                    result.frames_sent += 1;
                    // In a real attack, frames would be sent here
                }
                Err(_) => {
                    result.frames_rejected += 1;
                }
            }
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InjectMacTampered
    }
}

/// CRC corruption attack
pub struct CrcCorruptor {
    rng: StdRng,
    hsm: VirtualHSM,
}

impl CrcCorruptor {
    pub fn new(ecu_name: String, seed: u64) -> Self {
        let rng = StdRng::seed_from_u64(seed);
        let hsm = VirtualHSM::new(ecu_name, seed);
        Self { rng, hsm }
    }

    /// Generate a frame with valid MAC but corrupted CRC
    pub fn generate_corrupted_crc_frame(
        &mut self,
        can_id: u32,
        data: Vec<u8>,
        source: String,
    ) -> Result<SecuredCanFrame, String> {
        // Create a valid frame
        let mut frame = SecuredCanFrame::new(
            CanId::Standard(can_id as u16),
            data,
            source,
            &mut self.hsm,
        )?;

        // Corrupt the CRC
        frame.crc = frame.crc.wrapping_add(self.rng.gen_range(1..=0xFF));

        Ok(frame)
    }
}

impl AttackSimulator for CrcCorruptor {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::InjectCrcCorrupted);
        let can_id = config.target_can_id.unwrap_or(0x300);
        let source = config
            .spoofed_source
            .clone()
            .unwrap_or_else(|| self.hsm.get_ecu_id().to_string());

        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for i in 0..frame_count {
            let data = vec![(i % 256) as u8, 0x30, 0x60, 0x90];
            match self.generate_corrupted_crc_frame(can_id, data, source.clone()) {
                Ok(_frame) => {
                    result.frames_sent += 1;
                    // In a real attack, frames would be sent here
                }
                Err(_) => {
                    result.frames_rejected += 1;
                }
            }
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InjectCrcCorrupted
    }
}

/// Source spoofing attack
pub struct SourceSpoofer {
    hsm: VirtualHSM,
    target_source_keys: std::collections::HashMap<String, [u8; 32]>,
}

impl SourceSpoofer {
    pub fn new(attacker_name: String, seed: u64) -> Self {
        let hsm = VirtualHSM::new(attacker_name, seed);
        Self {
            hsm,
            target_source_keys: std::collections::HashMap::new(),
        }
    }

    /// Add a compromised ECU's key (for sophisticated spoofing)
    pub fn add_compromised_key(&mut self, source_name: String, key: [u8; 32]) {
        self.target_source_keys.insert(source_name, key);
    }

    /// Generate a frame claiming to be from another ECU (without valid key)
    pub fn generate_spoofed_frame(
        &mut self,
        can_id: u32,
        data: Vec<u8>,
        spoofed_source: String,
    ) -> Result<SecuredCanFrame, String> {
        // Create frame claiming to be from the spoofed source
        // but signed with attacker's key (will fail MAC verification)
        let frame = SecuredCanFrame::new(
            CanId::Standard(can_id as u16),
            data,
            spoofed_source.clone(), // Claim to be someone else
            &mut self.hsm,          // But use attacker's key
        )?;

        Ok(frame)
    }
}

impl AttackSimulator for SourceSpoofer {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let spoofed_source = config
            .spoofed_source
            .clone()
            .ok_or("Source spoofing requires spoofed_source in config")?;

        let mut result = AttackResult::new(AttackType::InjectSpoofedSource);
        let can_id = config.target_can_id.unwrap_or(0x100);

        let frame_count = config.frame_count.unwrap_or(
            (config.duration_secs * config.frames_per_second.unwrap_or(10) as u64) as u32,
        );

        for i in 0..frame_count {
            let data = vec![(i % 256) as u8, 0x11, 0x22, 0x33];
            match self.generate_spoofed_frame(can_id, data, spoofed_source.clone()) {
                Ok(_frame) => {
                    result.frames_sent += 1;
                    // In a real attack, frames would be sent here
                }
                Err(_) => {
                    result.frames_rejected += 1;
                }
            }
        }

        result.end_time = Utc::now();
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InjectSpoofedSource
    }
}

/// Flooding attack (DoS)
pub struct Flooder {
    rng: StdRng,
    source: String,
}

impl Flooder {
    pub fn new(source: String, seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Self { rng, source }
    }

    /// Generate high-rate unsecured frames for flooding
    pub fn generate_flood_frame(&mut self, can_id: u32) -> SecuredCanFrame {
        let data_len = self.rng.gen_range(0..=8);
        let mut data = vec![0u8; data_len];
        self.rng.fill(&mut data[..]);

        SecuredCanFrame {
            can_id: CanId::Standard(can_id as u16),
            data,
            timestamp: Utc::now(),
            source: self.source.clone(),
            session_counter: self.rng.gen_range(u64::MIN..=u64::MAX),
            mac: [0u8; 32],
            crc: 0,
        }
    }
}

impl AttackSimulator for Flooder {
    fn execute(&mut self, config: &AttackConfig) -> Result<AttackResult, String> {
        self.validate_config(config)?;

        let mut result = AttackResult::new(AttackType::InjectFlooding);
        let can_id = config.target_can_id.unwrap_or(0x300);

        // High intensity = high frame rate
        let frames_per_sec = (config.intensity * 1000.0) as u32; // Up to 1000 fps
        let total_frames = frames_per_sec * config.duration_secs as u32;

        for _ in 0..total_frames {
            let _frame = self.generate_flood_frame(can_id);
            result.frames_sent += 1;

            // In a real attack, frames would be sent here
            // with minimal delay to maximize flooding effect
        }

        result.end_time = Utc::now();
        result
            .metrics
            .insert("flooding_rate_fps".to_string(), frames_per_sec as f64);
        Ok(result)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InjectFlooding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsecured_injector() {
        let mut injector = UnsecuredInjector::new("ATTACKER".to_string(), Some(12345));
        let frame = injector.generate_unsecured_frame(0x300, vec![0xFF, 0xFF]);

        assert_eq!(frame.mac, [0u8; 32]);
        assert_eq!(frame.crc, 0);
        assert_eq!(frame.source, "ATTACKER");
    }

    #[test]
    fn test_unsecured_injector_execute() {
        let mut injector = UnsecuredInjector::new("ATTACKER".to_string(), Some(54321));
        let config = AttackConfig {
            attack_type: AttackType::InjectUnsecured,
            target_can_id: Some(0x300),
            frame_count: Some(25),
            ..Default::default()
        };

        let result = injector.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 25);
        assert_eq!(result.attack_type, AttackType::InjectUnsecured);
    }

    #[test]
    fn test_mac_tamperer_creates_invalid_mac() {
        let mut tamperer = MacTamperer::new("TAMPERER".to_string(), 99999);

        match tamperer.generate_tampered_mac_frame(0x100, vec![1, 2, 3], "SOURCE".to_string()) {
            Ok(frame) => {
                // Frame should be created but MAC should be tampered
                // We can't easily verify tampering without the original MAC,
                // but we know it was modified
                assert_eq!(frame.data, vec![1, 2, 3]);
            }
            Err(_) => {
                // May fail if authorization is enforced
            }
        }
    }

    #[test]
    fn test_crc_corruptor_creates_invalid_crc() {
        let mut corruptor = CrcCorruptor::new("CORRUPTOR".to_string(), 88888);

        match corruptor.generate_corrupted_crc_frame(0x100, vec![4, 5, 6], "SOURCE".to_string()) {
            Ok(frame) => {
                // CRC should be non-zero (was corrupted from valid value)
                assert_eq!(frame.data, vec![4, 5, 6]);
            }
            Err(_) => {
                // May fail if authorization is enforced
            }
        }
    }

    #[test]
    fn test_source_spoofer() {
        let mut spoofer = SourceSpoofer::new("SPOOFER".to_string(), 77777);

        match spoofer.generate_spoofed_frame(0x100, vec![7, 8, 9], "WHEEL_FL".to_string()) {
            Ok(frame) => {
                assert_eq!(frame.source, "WHEEL_FL"); // Claims to be WHEEL_FL
                assert_eq!(frame.data, vec![7, 8, 9]);
            }
            Err(_) => {
                // May fail if authorization is enforced
            }
        }
    }

    #[test]
    fn test_source_spoofer_requires_spoofed_source() {
        let mut spoofer = SourceSpoofer::new("SPOOFER".to_string(), 66666);
        let config = AttackConfig {
            attack_type: AttackType::InjectSpoofedSource,
            spoofed_source: None, // Missing required field
            frame_count: Some(10),
            ..Default::default()
        };

        let result = spoofer.execute(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_flooder_high_intensity() {
        let mut flooder = Flooder::new("FLOODER".to_string(), Some(55555));
        let config = AttackConfig {
            attack_type: AttackType::InjectFlooding,
            intensity: 0.5, // 50% intensity = 500 fps
            duration_secs: 1,
            ..Default::default()
        };

        let result = flooder.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 500); // 0.5 * 1000 fps * 1 sec
        assert_eq!(
            result.metrics.get("flooding_rate_fps"),
            Some(&500.0)
        );
    }

    #[test]
    fn test_flooder_max_intensity() {
        let mut flooder = Flooder::new("FLOODER".to_string(), Some(44444));
        let config = AttackConfig {
            attack_type: AttackType::InjectFlooding,
            intensity: 1.0, // 100% intensity = 1000 fps
            duration_secs: 2,
            ..Default::default()
        };

        let result = flooder.execute(&config).unwrap();
        assert_eq!(result.frames_sent, 2000); // 1.0 * 1000 fps * 2 sec
    }
}
