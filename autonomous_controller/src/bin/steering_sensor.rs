use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "STEERING_SENSOR";
const UPDATE_INTERVAL_MS: u64 = 50; // 20 Hz

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!("{}", "        Steering Sensor ECU            ".magenta().bold());
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let mut client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Sending steering data every {}ms", "→".cyan(), UPDATE_INTERVAL_MS);
    println!();

    let mut angle = 0.0f32; // degrees
    let mut torque = 0.0f32; // Nm
    let mut direction = 1.0f32;
    let mut counter = 0u32;

    loop {
        // Simulate steering angle changes (-45 to +45 degrees)
        angle += direction * 0.5;

        if angle >= 45.0 {
            direction = -1.0;
        } else if angle <= -45.0 {
            direction = 1.0;
        }

        // Torque is proportional to angle (driver effort)
        // Also add some dynamic component
        torque = angle * 0.1 + (counter as f32 * 0.05).sin() * 2.0;
        torque = torque.clamp(-10.0, 10.0);

        // Send steering angle
        let angle_data = encoding::encode_steering_angle(angle);
        let angle_frame = CanFrame::new(
            can_ids::STEERING_ANGLE,
            angle_data.to_vec(),
            ECU_NAME.to_string(),
        );
        client.send_frame(angle_frame).await?;

        // Send steering torque
        let torque_data = encoding::encode_steering_torque(torque);
        let torque_frame = CanFrame::new(
            can_ids::STEERING_TORQUE,
            torque_data.to_vec(),
            ECU_NAME.to_string(),
        );
        client.send_frame(torque_frame).await?;

        if counter % 20 == 0 {
            println!(
                "{} Steering: Angle={:.1}°, Torque={:.2} Nm",
                "→".bright_black(),
                angle,
                torque
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
