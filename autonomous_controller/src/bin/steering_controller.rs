use colored::*;
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "STEERING_CTRL";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!("{}", "      Steering Controller ECU          ".magenta().bold());
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Listening for steering commands...", "→".cyan());
    println!();

    // Split client into reader and writer
    let (mut reader, _writer) = client.split();

    // Channel for communication
    let (frame_tx, mut frame_rx) = mpsc::channel::<CanFrame>(100);

    // Spawn receiver task
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::CanFrame(frame)) => {
                    if frame_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let mut current_steering_angle = 0.0f32;
    let mut sensor_angle = 0.0f32;

    loop {
        // Process steering commands and sensor feedback
        match tokio::time::timeout(Duration::from_millis(100), frame_rx.recv()).await {
            Ok(Some(frame)) => {
                if frame.id == can_ids::STEERING_COMMAND {
                    let commanded_angle = encoding::decode_steering_angle(&frame.data);

                    // Simulate actuator response (smooth transition with rate limiting)
                    let max_rate = 5.0; // degrees per update
                    let error = commanded_angle - current_steering_angle;
                    let change = error.clamp(-max_rate, max_rate);
                    current_steering_angle += change;

                    // Safety check: limit maximum steering angle
                    current_steering_angle = current_steering_angle.clamp(-45.0, 45.0);

                    let direction = if current_steering_angle > 0.5 {
                        "RIGHT"
                    } else if current_steering_angle < -0.5 {
                        "LEFT"
                    } else {
                        "CENTER"
                    };

                    println!(
                        "{} Steering angle: {:+.1}° ({}) [commanded: {:+.1}°]",
                        "→".magenta(),
                        current_steering_angle,
                        direction.bright_white(),
                        commanded_angle
                    );

                    // Safety: warn on rapid steering changes
                    if change.abs() >= max_rate * 0.9 {
                        println!(
                            "  {} Rate limiting active (max rate: ±{:.1}°/step)",
                            "⚠".yellow().bold(),
                            max_rate
                        );
                    }
                }
                else if frame.id == can_ids::STEERING_ANGLE {
                    // Track actual sensor feedback for comparison
                    sensor_angle = encoding::decode_steering_angle(&frame.data);

                    // Detect discrepancy between commanded and actual
                    let discrepancy = (current_steering_angle - sensor_angle).abs();
                    if discrepancy > 5.0 {
                        println!(
                            "  {} Steering discrepancy: commanded={:.1}°, actual={:.1}° (diff={:.1}°)",
                            "⚠".yellow().bold(),
                            current_steering_angle,
                            sensor_angle,
                            discrepancy
                        );
                    }
                }
            },
            Ok(None) => {
                break; // Channel closed
            },
            Err(_) => {
                // Timeout - no command received, maintain current state
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    Ok(())
}
