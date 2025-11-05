use colored::*;
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{can_ids, encoding};
use autonomous_vehicle_sim::hsm::{VirtualHSM, SecuredCanFrame, SignedFirmware};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "BRAKE_CTRL";
const HSM_SEED: u64 = 0x3001; // Unique seed for this ECU

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "        Brake Controller ECU           ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
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
    let firmware_code = b"BRAKE_CTRL_FIRMWARE_v1.0.0";
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
    println!("{} Listening for secured brake commands...", "→".cyan());
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
                    // Verify MAC and CRC
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
                Ok(NetMessage::CanFrame(_)) => {
                    eprintln!("{} Received unencrypted frame - rejecting!", "⚠".yellow().bold());
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let mut current_brake_pressure = 0.0f32;

    loop {
        // Process brake commands (secured)
        match tokio::time::timeout(Duration::from_millis(100), frame_rx.recv()).await {
            Ok(Some(secured_frame)) => {
                if secured_frame.can_id == can_ids::BRAKE_COMMAND && !secured_frame.data.is_empty() {
                    let commanded_pressure = encoding::decode_brake_pressure(secured_frame.data[0]);

                    // Simulate actuator response (smooth transition)
                    current_brake_pressure += (commanded_pressure - current_brake_pressure) * 0.3;

                    // Safety check: limit maximum brake pressure
                    current_brake_pressure = current_brake_pressure.clamp(0.0, 100.0);

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
            }
            Ok(None) => break,
            Err(_) => {
                // Timeout - no command received, slowly release brake
                if current_brake_pressure > 0.0 {
                    current_brake_pressure -= 1.0;
                    if current_brake_pressure < 0.0 {
                        current_brake_pressure = 0.0;
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}
