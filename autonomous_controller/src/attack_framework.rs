/// Attack Simulation Framework
///
/// This module provides a comprehensive framework for simulating various CAN bus attacks
/// to test the robustness of the Virtual HSM security implementation.
///
/// SECURITY RESEARCH ONLY: This code is for authorized testing and educational purposes.
use crate::hsm::SecuredCanFrame;
use crate::network::{BusClient, BusWriter, NetMessage};
use crate::types::{CanFrame, CanId, can_ids, encoding};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;

/// Types of attacks supported by the framework
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    /// Inject malicious CAN frames with fake data
    Injection,
    /// Capture and replay legitimate frames
    Replay,
    /// Flood the bus with high-priority frames (DoS)
    Flooding,
    /// Spoof legitimate ECU identities
    Spoofing,
    /// Send random/malformed frames (fuzzing)
    Fuzzing,
    /// Combined multi-stage attack
    Combined,
}

/// Attack configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Type of attack to execute
    pub attack_type: AttackType,
    /// Duration of the attack in seconds (None = infinite)
    pub duration_secs: Option<u64>,
    /// Attack intensity (frames per second)
    pub frames_per_second: u64,
    /// Target CAN IDs (empty = all IDs)
    pub target_can_ids: Vec<u32>,
    /// Attacker identifier name
    pub attacker_name: String,
    /// Fuzzing-specific: percentage of malformed frames (0-100)
    pub malform_percentage: u8,
    /// Replay-specific: capture duration before replay
    pub capture_duration_secs: u64,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            attack_type: AttackType::Fuzzing,
            duration_secs: Some(60),
            frames_per_second: 100,
            target_can_ids: vec![],
            attacker_name: "ATTACKER".to_string(),
            malform_percentage: 50,
            capture_duration_secs: 10,
        }
    }
}

/// Attack execution statistics
#[derive(Debug, Default, Clone)]
pub struct AttackStats {
    pub frames_sent: u64,
    pub frames_captured: u64,
    pub errors_encountered: u64,
    pub duration_secs: u64,
}

impl AttackStats {
    pub fn frames_per_second(&self) -> f64 {
        if self.duration_secs == 0 {
            return 0.0;
        }
        self.frames_sent as f64 / self.duration_secs as f64
    }
}

/// Main attack simulator
pub struct AttackSimulator {
    config: AttackConfig,
    stats: AttackStats,
    writer: Option<BusWriter>,
}

impl AttackSimulator {
    /// Create a new attack simulator with the given configuration
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config,
            stats: AttackStats::default(),
            writer: None,
        }
    }

    /// Connect to the CAN bus
    pub async fn connect(
        &mut self,
        bus_address: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = BusClient::connect(bus_address, self.config.attacker_name.clone()).await?;
        let (_reader, writer) = client.split();
        self.writer = Some(writer);
        Ok(())
    }

    /// Execute the configured attack
    pub async fn execute(
        &mut self,
    ) -> Result<AttackStats, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = tokio::time::Instant::now();

        match self.config.attack_type {
            AttackType::Injection => self.execute_injection().await?,
            AttackType::Replay => self.execute_replay().await?,
            AttackType::Flooding => self.execute_flooding().await?,
            AttackType::Spoofing => self.execute_spoofing().await?,
            AttackType::Fuzzing => self.execute_fuzzing().await?,
            AttackType::Combined => self.execute_combined().await?,
        }

        self.stats.duration_secs = start_time.elapsed().as_secs();
        Ok(self.stats.clone())
    }

    /// Execute injection attack
    async fn execute_injection(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let interval = Duration::from_micros(1_000_000 / self.config.frames_per_second);
        let start = tokio::time::Instant::now();

        loop {
            // Check duration limit
            if let Some(duration) = self.config.duration_secs
                && start.elapsed().as_secs() >= duration
            {
                break;
            }

            // Inject fake sensor data
            let fake_frame = self.generate_fake_sensor_frame();
            let writer = self.writer.as_mut().ok_or("Not connected")?;
            if writer.send_frame(fake_frame).await.is_err() {
                self.stats.errors_encountered += 1;
            } else {
                self.stats.frames_sent += 1;
            }

            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// Execute replay attack
    async fn execute_replay(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Replay requires both reader and writer, so we need to reconnect
        let client =
            BusClient::connect("127.0.0.1:9000", self.config.attacker_name.clone()).await?;
        let (mut reader, mut writer) = client.split();

        // Phase 1: Capture frames
        let mut captured_frames: VecDeque<SecuredCanFrame> = VecDeque::new();
        let capture_start = tokio::time::Instant::now();

        while capture_start.elapsed().as_secs() < self.config.capture_duration_secs {
            match tokio::time::timeout(Duration::from_millis(100), reader.receive_message()).await {
                Ok(Ok(NetMessage::SecuredCanFrame(secured))) => {
                    // Filter by target CAN IDs if specified
                    if self.config.target_can_ids.is_empty()
                        || self.config.target_can_ids.contains(&secured.can_id.value())
                    {
                        captured_frames.push_back(secured);
                        self.stats.frames_captured += 1;

                        if captured_frames.len() >= 100 {
                            break;
                        }
                    }
                }
                _ => continue,
            }
        }

        // Phase 2: Replay captured frames
        let interval = Duration::from_micros(1_000_000 / self.config.frames_per_second);
        let start = tokio::time::Instant::now();

        while let Some(frame) = captured_frames.pop_front() {
            // Check duration limit
            if let Some(duration) = self.config.duration_secs
                && start.elapsed().as_secs() >= duration
            {
                break;
            }

            if writer.send_secured_frame(frame.clone()).await.is_err() {
                self.stats.errors_encountered += 1;
            } else {
                self.stats.frames_sent += 1;
            }

            // Re-queue for continuous replay
            captured_frames.push_back(frame);

            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// Execute flooding attack (DoS)
    async fn execute_flooding(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let writer = self.writer.as_mut().ok_or("Not connected")?;
        let interval = Duration::from_micros(1_000_000 / self.config.frames_per_second);
        let start = tokio::time::Instant::now();
        let mut rng = rand::thread_rng();

        loop {
            // Check duration limit
            if let Some(duration) = self.config.duration_secs
                && start.elapsed().as_secs() >= duration
            {
                break;
            }

            // High-priority CAN IDs (low values have higher priority)
            let flood_id = CanId::Standard(rng.gen_range(0x001..=0x010));
            let mut data = vec![0u8; 8];
            rng.fill(&mut data[..]);

            let flood_frame = CanFrame::new(flood_id, data, self.config.attacker_name.clone());

            if writer.send_frame(flood_frame).await.is_err() {
                self.stats.errors_encountered += 1;
            } else {
                self.stats.frames_sent += 1;
            }

            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// Execute spoofing attack
    async fn execute_spoofing(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let writer = self.writer.as_mut().ok_or("Not connected")?;
        let interval = Duration::from_micros(1_000_000 / self.config.frames_per_second);
        let start = tokio::time::Instant::now();

        // Spoof legitimate ECU names
        let spoofed_names = ["WHEEL_FL", "WHEEL_FR", "BRAKE_CTRL", "AUTO_CTRL"];
        let mut name_idx = 0;

        loop {
            // Check duration limit
            if let Some(duration) = self.config.duration_secs
                && start.elapsed().as_secs() >= duration
            {
                break;
            }

            // Send frames pretending to be a legitimate ECU
            let spoofed_name = spoofed_names[name_idx % spoofed_names.len()];
            let fake_frame = CanFrame::new(
                can_ids::WHEEL_SPEED_FL,
                encoding::encode_wheel_speed(100.0).to_vec(),
                spoofed_name.to_string(),
            );

            if writer.send_frame(fake_frame).await.is_err() {
                self.stats.errors_encountered += 1;
            } else {
                self.stats.frames_sent += 1;
            }

            name_idx += 1;
            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// Execute fuzzing attack (random/malformed frames)
    async fn execute_fuzzing(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let interval = Duration::from_micros(1_000_000 / self.config.frames_per_second);
        let start = tokio::time::Instant::now();
        let mut rng = rand::thread_rng();

        loop {
            // Check duration limit
            if let Some(duration) = self.config.duration_secs
                && start.elapsed().as_secs() >= duration
            {
                break;
            }

            let should_malform = rng.gen_range(0..100) < self.config.malform_percentage;

            let fuzz_frame = if should_malform {
                self.generate_malformed_frame(&mut rng)
            } else {
                self.generate_random_valid_frame(&mut rng)
            };

            let writer = self.writer.as_mut().ok_or("Not connected")?;
            if writer.send_frame(fuzz_frame).await.is_err() {
                self.stats.errors_encountered += 1;
            } else {
                self.stats.frames_sent += 1;
            }

            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// Execute combined multi-stage attack
    async fn execute_combined(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Combine multiple attack types in sequence
        let total_duration = self.config.duration_secs.unwrap_or(60);
        let stage_duration = total_duration / 3;

        // Stage 1: Flooding
        let original_duration = self.config.duration_secs;
        self.config.duration_secs = Some(stage_duration);
        self.execute_flooding().await?;

        // Stage 2: Fuzzing
        self.config.duration_secs = Some(stage_duration);
        self.execute_fuzzing().await?;

        // Stage 3: Injection
        self.config.duration_secs = Some(stage_duration);
        self.execute_injection().await?;

        // Restore original duration
        self.config.duration_secs = original_duration;

        Ok(())
    }

    /// Generate a fake sensor frame for injection attacks
    fn generate_fake_sensor_frame(&self) -> CanFrame {
        let mut rng = rand::thread_rng();

        // Random sensor CAN ID
        let can_id = match rng.gen_range(0..6) {
            0 => can_ids::WHEEL_SPEED_FL,
            1 => can_ids::WHEEL_SPEED_FR,
            2 => can_ids::ENGINE_RPM,
            3 => can_ids::ENGINE_THROTTLE,
            4 => can_ids::STEERING_ANGLE,
            _ => can_ids::STEERING_TORQUE,
        };

        // Generate fake data
        let data = match can_id {
            can_ids::WHEEL_SPEED_FL | can_ids::WHEEL_SPEED_FR => {
                // Unrealistic wheel speed
                encoding::encode_wheel_speed(rng.gen_range(200.0..300.0)).to_vec()
            }
            can_ids::ENGINE_RPM => {
                // Excessive RPM
                encoding::encode_rpm(rng.gen_range(8000.0..10000.0)).to_vec()
            }
            can_ids::ENGINE_THROTTLE => {
                // Random throttle
                vec![encoding::encode_throttle(rng.gen_range(0.0..100.0))]
            }
            can_ids::STEERING_ANGLE => {
                // Extreme steering angle
                encoding::encode_steering_angle(rng.gen_range(-500.0..-300.0)).to_vec()
            }
            _ => {
                // Random torque
                encoding::encode_steering_torque(rng.gen_range(-20.0..20.0)).to_vec()
            }
        };

        CanFrame::new(can_id, data, self.config.attacker_name.clone())
    }

    /// Generate a random but valid CAN frame
    fn generate_random_valid_frame(&self, rng: &mut impl Rng) -> CanFrame {
        let can_id = CanId::Standard(rng.gen_range(0x100..=0x7FF));
        let data_len = rng.gen_range(0..=8);
        let mut data = vec![0u8; data_len];
        rng.fill(&mut data[..]);

        CanFrame::new(can_id, data, self.config.attacker_name.clone())
    }

    /// Generate a malformed CAN frame for fuzzing
    fn generate_malformed_frame(&self, rng: &mut impl Rng) -> CanFrame {
        let malform_type = rng.gen_range(0..5);

        match malform_type {
            0 => {
                // Invalid CAN ID (exceeds 11-bit limit)
                let invalid_id = CanId::Standard(rng.gen_range(0x800..=0xFFF));
                CanFrame::new(invalid_id, vec![0; 8], self.config.attacker_name.clone())
            }
            1 => {
                // Oversized data (> 8 bytes)
                let can_id = CanId::Standard(rng.gen_range(0x000..=0x7FF));
                let data_len = rng.gen_range(9..=255);
                let mut data = vec![0u8; data_len];
                rng.fill(&mut data[..]);
                CanFrame::new(can_id, data, self.config.attacker_name.clone())
            }
            2 => {
                // All zeros (potentially triggering edge cases)
                let can_id = CanId::Standard(0);
                CanFrame::new(can_id, vec![0; 8], self.config.attacker_name.clone())
            }
            3 => {
                // All ones (maximum values)
                let can_id = CanId::Standard(0x7FF);
                CanFrame::new(can_id, vec![0xFF; 8], self.config.attacker_name.clone())
            }
            _ => {
                // Random extended ID (less common, may not be handled)
                let can_id = CanId::Extended(rng.gen_range(0..=0x1FFFFFFF));
                let mut data = vec![0u8; 8];
                rng.fill(&mut data[..]);
                CanFrame::new(can_id, data, self.config.attacker_name.clone())
            }
        }
    }

    /// Get current attack statistics
    pub fn stats(&self) -> &AttackStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_config_default() {
        let config = AttackConfig::default();
        assert_eq!(config.attack_type, AttackType::Fuzzing);
        assert_eq!(config.frames_per_second, 100);
        assert_eq!(config.malform_percentage, 50);
    }

    #[test]
    fn test_attack_stats_frames_per_second() {
        let mut stats = AttackStats::default();
        stats.frames_sent = 100;
        stats.duration_secs = 10;
        assert_eq!(stats.frames_per_second(), 10.0);
    }

    #[test]
    fn test_attack_stats_zero_duration() {
        let mut stats = AttackStats::default();
        stats.frames_sent = 100;
        stats.duration_secs = 0;
        assert_eq!(stats.frames_per_second(), 0.0);
    }

    #[test]
    fn test_generate_random_valid_frame() {
        let config = AttackConfig::default();
        let simulator = AttackSimulator::new(config);
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let frame = simulator.generate_random_valid_frame(&mut rng);
            // Valid frames should have <= 8 bytes
            assert!(frame.data.len() <= 8);
        }
    }

    #[test]
    fn test_generate_malformed_frame_oversized() {
        let config = AttackConfig::default();
        let simulator = AttackSimulator::new(config);
        let mut rng = rand::thread_rng();

        // Generate many frames to ensure we hit the oversized case
        let mut found_oversized = false;
        for _ in 0..1000 {
            let frame = simulator.generate_malformed_frame(&mut rng);
            if frame.data.len() > 8 {
                found_oversized = true;
                assert!(!frame.is_valid()); // Should be invalid
                break;
            }
        }
        assert!(
            found_oversized,
            "Should generate at least one oversized frame"
        );
    }

    #[test]
    fn test_generate_fake_sensor_frame() {
        let config = AttackConfig::default();
        let simulator = AttackSimulator::new(config);

        for _ in 0..100 {
            let frame = simulator.generate_fake_sensor_frame();
            // Should have a sensor-range CAN ID
            let id_value = frame.id.value();
            assert!(
                (id_value >= 0x100 && id_value <= 0x121)
                    || (id_value >= 0x300 && id_value <= 0x302)
            );
        }
    }
}
