use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "WHEEL_FR";
const UPDATE_INTERVAL_MS: u64 = 100; // 10 Hz

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".green().bold());
    println!("{}", "  Front Right Wheel Speed Sensor      ".green().bold());
    println!("{}", "═══════════════════════════════════════".green().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let mut client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Sending wheel speed data every {}ms", "→".cyan(), UPDATE_INTERVAL_MS);
    println!();

    let mut speed = 0.0f32; // rad/s
    let mut direction = 1.0f32;
    let mut counter = 0u32;

    loop {
        // Simulate wheel speed variation (0-100 rad/s, accelerating and decelerating)
        speed += direction * 0.5;

        if speed >= 100.0 {
            direction = -1.0;
        } else if speed <= 0.0 {
            speed = 0.0;
            direction = 1.0;
        }

        // Add some realistic noise (slightly different phase than FL)
        let noise = (counter as f32 * 0.1 + 0.5).sin() * 0.5;
        let actual_speed = (speed + noise).max(0.0);

        // Encode and send
        let data = encoding::encode_wheel_speed(actual_speed);
        let frame = CanFrame::new(
            can_ids::WHEEL_SPEED_FR,
            data.to_vec(),
            ECU_NAME.to_string(),
        );

        client.send_frame(frame).await?;

        if counter % 10 == 0 {
            println!(
                "{} Sent wheel speed: {:.2} rad/s",
                "→".bright_black(),
                actual_speed
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
