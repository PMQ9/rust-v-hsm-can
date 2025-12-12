/// Test helper: Sends legitimate brake commands for regression testing
///
/// This binary sends valid, authenticated brake commands at regular intervals
/// to simulate normal system operation during attack tests. This allows testing
/// whether the attack detector properly resets error counters when legitimate
/// frames are received between attack cycles.
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const SENDER_NAME: &str = "AUTONOMOUS_CONTROLLER";
const HSM_SEED: u64 = 0x2001; // Same seed as autonomous_controller
const SEND_INTERVAL_MS: u64 = 100; // Send every 100ms (10 Hz)
const TEST_DURATION_SECS: u64 = 30; // Run for 30 seconds

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("→ Test Legitimate Sender starting...");

    // Connect to bus
    let client = BusClient::connect(BUS_ADDRESS, SENDER_NAME.to_string()).await?;
    let (_reader, mut writer) = client.split();

    // Initialize HSM for this sender (using same seed as autonomous_controller)
    let mut hsm = VirtualHSM::new(SENDER_NAME.to_string(), HSM_SEED);

    println!("✓ Connected to CAN bus");
    println!(
        "→ Sending legitimate brake commands every {}ms for {}s",
        SEND_INTERVAL_MS, TEST_DURATION_SECS
    );

    let start = std::time::Instant::now();
    let mut frame_count = 0u64;

    while start.elapsed() < Duration::from_secs(TEST_DURATION_SECS) {
        // Send a legitimate brake command (moderate pressure)
        let brake_pressure = 30.0f32; // 30% brake pressure
        let brake_data = vec![encoding::encode_brake_pressure(brake_pressure)];

        if let Ok(secured_frame) = SecuredCanFrame::new(
            can_ids::BRAKE_COMMAND,
            brake_data,
            SENDER_NAME.to_string(),
            &mut hsm,
        ) {
            writer.send_secured_frame(secured_frame).await?;
        } else {
            eprintln!("Failed to create secured frame");
            continue;
        }
        frame_count += 1;

        tokio::time::sleep(Duration::from_millis(SEND_INTERVAL_MS)).await;
    }

    println!(
        "✓ Test completed - sent {} legitimate brake commands",
        frame_count
    );

    Ok(())
}
