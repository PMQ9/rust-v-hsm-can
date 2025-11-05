use colored::*;
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{can_ids, encoding};
use autonomous_vehicle_sim::hsm::{VirtualHSM, SecuredCanFrame, SignedFirmware};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "STEERING_CTRL";
const HSM_SEED: u64 = 0x3002; // Unique seed for this ECU

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!("{}", "      Steering Controller ECU          ".magenta().bold());
    println!("{}", "═══════════════════════════════════════".magenta().bold());
    println!();

    // Initialize HSM
    println!("{} Initializing Virtual HSM...", "→".cyan());
    let mut hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);

    // Register trusted ECU (autonomous controller)
    println!("{} Registering trusted ECUs...", "→".cyan());
    let autonomous_hsm = VirtualHSM::new("AUTONOMOUS_CTRL".to_string(), 0x2001);
    hsm.add_trusted_ecu("AUTONOMOUS_CTRL".to_string(), *autonomous_hsm.get_symmetric_key());
    println!("  ✓ Registered AUTONOMOUS_CTRL");

    // Initialize protected memory
    println!("{} Initializing protected memory...", "→".cyan());
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"STEERING_CTRL_FIRMWARE_v1.0.0";
    let firmware = SignedFirmware::new(
        firmware_code.to_vec(),
        "1.0.0".to_string(),
        ECU_NAME.to_string(),
        &hsm,
    );

    protected_mem.provision_firmware(firmware, &hsm)
        .expect("Failed to provision firmware");

    // Perform secure boot
    println!("{} Performing secure boot...", "→".cyan());
    protected_mem.secure_boot(&hsm)
        .expect("Secure boot failed");

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Listening for secured steering commands...", "→".cyan());
    println!();

    // Split client into reader and writer
    let (mut reader, _writer) = client.split();

    // Channel for communication
    let (frame_tx, mut frame_rx) = mpsc::channel::<SecuredCanFrame>(100);

    // Clone HSM for receiver task
    let hsm_clone = hsm.clone();

    // Spawn receiver task with MAC/CRC verification
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(secured_frame)) => {
                    // Only verify and process steering command frames
                    if secured_frame.can_id == can_ids::STEERING_COMMAND {
                        // Verify MAC and CRC for frames we care about
                        match secured_frame.verify(&hsm_clone) {
                            Ok(_) => {
                                if frame_tx.send(secured_frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("{} Security verification failed: {}", "⚠".yellow().bold(), e);
                            }
                        }
                    }
                    // Silently ignore other frames (sensor data, etc.)
                }
                Ok(NetMessage::CanFrame(_)) => {
                    eprintln!("{} Received unencrypted frame - rejecting!", "⚠".yellow().bold());
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let mut current_steering_angle = 0.0f32;

    loop {
        // Process steering commands (secured)
        match tokio::time::timeout(Duration::from_millis(100), frame_rx.recv()).await {
            Ok(Some(secured_frame)) => {
                if secured_frame.can_id == can_ids::STEERING_COMMAND {
                    let commanded_angle = encoding::decode_steering_angle(&secured_frame.data);

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
                            "  {} High steering rate detected!",
                            "⚠".yellow().bold()
                        );
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                // Timeout - no command received, gradually return to center
                if current_steering_angle.abs() > 0.1 {
                    let return_rate: f32 = 1.0;
                    if current_steering_angle > 0.0 {
                        current_steering_angle -= return_rate.min(current_steering_angle);
                    } else {
                        current_steering_angle += return_rate.min(current_steering_angle.abs());
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}
