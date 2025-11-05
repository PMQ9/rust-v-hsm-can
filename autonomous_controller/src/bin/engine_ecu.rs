use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "ENGINE_ECU";
const UPDATE_INTERVAL_MS: u64 = 50; // 20 Hz

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".yellow().bold());
    println!("{}", "          Engine Control Unit          ".yellow().bold());
    println!("{}", "═══════════════════════════════════════".yellow().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let mut client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Sending engine data every {}ms", "→".cyan(), UPDATE_INTERVAL_MS);
    println!();

    let mut rpm = 800.0f32; // Idle RPM
    let mut throttle = 0.0f32; // 0-100%
    let mut direction = 1.0f32;
    let mut counter = 0u32;

    loop {
        // Simulate throttle changes
        throttle += direction * 1.0;

        if throttle >= 80.0 {
            direction = -1.0;
        } else if throttle <= 0.0 {
            throttle = 0.0;
            direction = 1.0;
        }

        // RPM follows throttle with some lag and idle speed
        let target_rpm = 800.0 + (throttle / 100.0) * 5200.0; // 800-6000 RPM
        rpm += (target_rpm - rpm) * 0.1; // Smooth transition

        // Send RPM
        let rpm_data = encoding::encode_rpm(rpm);
        let rpm_frame = CanFrame::new(
            can_ids::ENGINE_RPM,
            rpm_data.to_vec(),
            ECU_NAME.to_string(),
        );
        client.send_frame(rpm_frame).await?;

        // Send throttle position
        let throttle_data = vec![encoding::encode_throttle(throttle)];
        let throttle_frame = CanFrame::new(
            can_ids::ENGINE_THROTTLE,
            throttle_data,
            ECU_NAME.to_string(),
        );
        client.send_frame(throttle_frame).await?;

        if counter % 20 == 0 {
            println!(
                "{} Engine: RPM={:.0}, Throttle={:.0}%",
                "→".bright_black(),
                rpm,
                throttle
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
