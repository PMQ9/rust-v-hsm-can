/// ATTACK SCENARIO: Malicious Frame Injection - Burst Attack
///
/// This script demonstrates a CAN bus injection attack that sends a burst
/// of malicious BRAKE COMMANDS with INVALID MACs that exceeds detection thresholds.
/// Targets the brake controller (0x300) with 4 malicious frames in rapid succession.
///
/// EXPECTED BEHAVIOR: Should trigger error (threshold is 3 consecutive MAC failures)
/// PURPOSE: Educational - demonstrates threshold-based detection
/// DEFENSE: HSM with CMAC authentication detects invalid MACs and triggers after threshold

use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::can_ids;
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use chrono::Utc;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_BURST";
const BURST_SIZE: u32 = 6;
const FRAME_DELAY_MS: u64 = 10;   // Delay between frames (must be < 100ms to avoid legitimate frame resets)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═════════════════════════════════════════════".red().bold());
    println!("{}", "   ATTACK: Burst Injection (Above Threshold)   ".red().bold());
    println!("{}", "═════════════════════════════════════════════".red().bold());
    println!();
    println!("{}", "⚠  WARNING: This is a security research tool".yellow());
    println!("{}", "⚠  Only use on authorized test systems".yellow());
    println!();

    println!("{} Connecting to CAN bus...", "→".red());
    let client = BusClient::connect(BUS_ADDRESS, ATTACKER_NAME.to_string()).await?;
    println!("{} Connected as {}!", "✓".red().bold(), ATTACKER_NAME);
    println!();

    let (_reader, mut writer) = client.split();

    // Create a temporary HSM just for calculating CRCs
    let hsm = VirtualHSM::new("TEMP_HSM".to_string(), 0x9999);

    println!("{}", "Attack Strategy:".red().bold());
    println!("{} Target: Brake Controller (CAN ID 0x300)", "→".red());
    println!("{} Sending {} malicious brake commands with INVALID MAC in rapid succession", "→".red(), BURST_SIZE);
    println!("{} Delay between frames: {}ms (faster than legitimate 100ms rate)", "→".red(), FRAME_DELAY_MS);
    println!("{} Detection threshold: 3 consecutive MAC failures", "→".yellow());
    println!("{} Expected: Should TRIGGER error before legitimate frame resets counter", "→".red().bold());
    println!();

    println!(
        "{} Starting Burst Attack",
        "═══".red().bold()
    );

    for frame_num in 1..=BURST_SIZE {
        // Inject fake brake command with INVALID MAC but VALID CRC
        let fake_brake_pressure = 100u8; // Maximum brake pressure

        let data = vec![fake_brake_pressure];

        // Calculate CORRECT CRC (so CRC check passes and MAC check fails)
        let mut crc_data = Vec::new();
        crc_data.extend_from_slice(&(can_ids::BRAKE_COMMAND.value() as u32).to_le_bytes());
        crc_data.extend_from_slice(&data);
        crc_data.extend_from_slice(ATTACKER_NAME.as_bytes());
        let valid_crc = hsm.calculate_crc(&crc_data);

        // Create a SecuredCanFrame with INVALID MAC but CORRECT CRC
        // This will pass CRC check but fail MAC check → triggers MAC error threshold
        let malicious_frame = SecuredCanFrame {
            can_id: can_ids::BRAKE_COMMAND,
            data: data.to_vec(),
            source: ATTACKER_NAME.to_string(),
            timestamp: Utc::now(),
            mac: [0u8; 32],  // Invalid MAC (zeros won't match valid HMAC)
            crc: valid_crc,  // CORRECT CRC so it passes CRC check
            session_counter: frame_num as u64,
        };

        writer.send_secured_frame(malicious_frame).await?;

        let status = if frame_num >= 3 {
            format!("{}", "(Should trigger error after this)".red().bold())
        } else {
            "".to_string()
        };

        println!(
            "{} Frame {}/{}: Injected fake brake command: {}% (Invalid MAC) {}",
            "⚡".red(),
            frame_num,
            BURST_SIZE,
            fake_brake_pressure,
            status
        );

        tokio::time::sleep(Duration::from_millis(FRAME_DELAY_MS)).await;
    }

    println!();
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{} Burst attack complete!", "✓".red().bold());
    println!("{} Sent {} malicious brake commands in 1 cycle", "→".red(), BURST_SIZE);
    println!("{} Exceeded 3-frame threshold", "→".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());

    Ok(())
}
