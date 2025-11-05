use colored::*;
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "BRAKE_CTRL";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "        Brake Controller ECU           ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Listening for brake commands...", "→".cyan());
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

    let mut current_brake_pressure = 0.0f32;

    loop {
        // Process brake commands
        match tokio::time::timeout(Duration::from_millis(100), frame_rx.recv()).await {
            Ok(Some(frame)) => {
                if frame.id == can_ids::BRAKE_COMMAND && !frame.data.is_empty() {
                    let commanded_pressure = encoding::decode_brake_pressure(frame.data[0]);

                    // Simulate actuator response (smooth transition)
                    current_brake_pressure += (commanded_pressure - current_brake_pressure) * 0.3;

                    // Safety check: limit maximum brake pressure
                    current_brake_pressure = current_brake_pressure.clamp(0.0, 100.0);

                    let color = if current_brake_pressure > 50.0 {
                        "red".to_string()
                    } else if current_brake_pressure > 20.0 {
                        "yellow".to_string()
                    } else {
                        "green".to_string()
                    };

                    println!(
                        "{} {} Brake pressure: {:.0}% (commanded: {:.0}%)",
                        "→".red(),
                        if current_brake_pressure > 50.0 { "🔴" } else if current_brake_pressure > 20.0 { "🟡" } else { "🟢" },
                        current_brake_pressure,
                        commanded_pressure
                    );

                    // Safety: Emergency brake if pressure suddenly drops to zero at high speed
                    if commanded_pressure == 0.0 && current_brake_pressure > 70.0 {
                        println!(
                            "  {} Safety warning: Rapid brake release detected!",
                            "⚠".yellow().bold()
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
