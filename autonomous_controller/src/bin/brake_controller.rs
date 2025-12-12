use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::error_handling::{AttackDetector, ValidationError};
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::security_log::SecurityLogger;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "BRAKE_CTRL";
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x3001; // Unique seed for boot-time HSM

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    // Pin to assigned core (Core 2 for actuators)
    if let Err(e) = pin_by_component(ECU_NAME.to_lowercase().as_str()) {
        eprintln!("{} Core pinning failed: {} (continuing)", "→".yellow(), e);
    }

    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "        Brake Controller ECU           ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
    if perf_mode {
        println!("{} Performance evaluation mode enabled", "ℹ".bright_blue());
    }
    println!();

    // =========================================================================
    // Boot-time security (local HSM for secure boot)
    // =========================================================================
    println!("{} Performing secure boot sequence...", "→".cyan());

    // Use local HSM for boot-time operations (firmware signing, secure boot)
    let boot_hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);

    // Initialize protected memory
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"BRAKE_CTRL_FIRMWARE_v1.0.0";
    let firmware = SignedFirmware::new(
        firmware_code.to_vec(),
        "1.0.0".to_string(),
        ECU_NAME.to_string(),
        &boot_hsm,
    );

    protected_mem
        .provision_firmware(firmware, &boot_hsm)
        .expect("Failed to provision firmware");

    // Perform secure boot
    protected_mem
        .secure_boot(&boot_hsm)
        .expect("Secure boot failed");
    println!("{} Secure boot completed", "✓".green().bold());

    // =========================================================================
    // Runtime security (HsmClient for CAN operations)
    // =========================================================================
    println!("{} Connecting to HSM service...", "→".cyan());

    // Connect to centralized HSM service on Core 3
    let hsm_client = HsmClient::connect(ECU_NAME.to_string(), HSM_SOCKET_PATH).await?;
    println!(
        "{} Connected to HSM service ({})",
        "✓".green().bold(),
        HSM_SOCKET_PATH
    );
    println!();

    // =========================================================================
    // CAN bus connection
    // =========================================================================
    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Listening for secured brake commands...", "→".cyan());
    println!();

    // Initialize security logger
    println!("{} Initializing security event logger...", "→".cyan());
    let security_logger =
        SecurityLogger::new(ECU_NAME.to_string(), None).expect("Failed to create security logger");
    println!("   ✓ Logging to: {:?}", security_logger.log_path());

    // Initialize attack detector with security logging
    let attack_detector = Arc::new(Mutex::new(AttackDetector::with_logger(
        ECU_NAME.to_string(),
        security_logger.clone(),
    )));
    println!("{} Attack detection initialized", "✓".green().bold());
    println!(
        "   • CRC error threshold: {} consecutive errors",
        autonomous_vehicle_sim::error_handling::CRC_ERROR_THRESHOLD
    );
    println!(
        "   • MAC error threshold: {} consecutive errors",
        autonomous_vehicle_sim::error_handling::MAC_ERROR_THRESHOLD
    );
    println!();

    // Split client into reader and writer
    let (mut reader, _writer) = client.split();

    // Channel for communication
    let (frame_tx, mut frame_rx) = mpsc::channel::<SecuredCanFrame>(100);

    // Clone hsm_client and attack detector for receiver task
    let hsm_client_clone = hsm_client.clone();
    let detector_clone = Arc::clone(&attack_detector);

    // Spawn receiver task with MAC/CRC verification and attack detection
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(secured_frame)) => {
                    // Only verify and process brake command frames
                    if secured_frame.can_id == can_ids::BRAKE_COMMAND {
                        // Check if we should still accept frames
                        let should_accept = {
                            let detector = detector_clone.lock().unwrap();
                            detector.should_accept_frames()
                        }; // Lock is dropped here

                        if !should_accept {
                            // Under attack - reject all frames
                            continue;
                        }

                        // Verify MAC and CRC via HSM service
                        match hsm_client_clone.verify_frame(&secured_frame).await {
                            Ok(_) => {
                                // Successful verification - reset error counters
                                {
                                    let mut detector = detector_clone.lock().unwrap();
                                    detector.record_success();
                                } // Lock is dropped here

                                // Process frame normally (anomaly detection handled in HSM service)
                                if frame_tx.send(secured_frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                // Record the error with proper type classification
                                let should_continue = {
                                    let mut detector = detector_clone.lock().unwrap();
                                    let error_type = ValidationError::from_verify_error(&e);
                                    detector.record_error(error_type, &secured_frame.source)
                                }; // Lock is dropped here

                                if !should_continue {
                                    println!(
                                        "{} Frame rejected - security threshold exceeded",
                                        "✗".red()
                                    );
                                }
                            }
                        }
                    }
                    // Silently ignore other frames (sensor data, etc.)
                }
                Ok(NetMessage::CanFrame(unsecured_frame)) => {
                    // Unsecured frame detected - record as attack
                    let should_continue = {
                        let mut detector = detector_clone.lock().unwrap();
                        detector
                            .record_error(ValidationError::UnsecuredFrame, &unsecured_frame.source)
                    };

                    if !should_continue {
                        eprintln!(
                            "{} Unsecured frame rejected - attack threshold exceeded",
                            "✗".red()
                        );
                    }
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let mut current_brake_pressure = 0.0f32;

    // Setup Ctrl+C handler for clean shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down...", "→".yellow());
        std::process::exit(0);
    });

    loop {
        // Process brake commands (secured)
        match tokio::time::timeout(Duration::from_millis(100), frame_rx.recv()).await {
            Ok(Some(secured_frame)) => {
                if secured_frame.can_id == can_ids::BRAKE_COMMAND && !secured_frame.data.is_empty()
                {
                    let commanded_pressure = encoding::decode_brake_pressure(secured_frame.data[0]);

                    // Simulate actuator response (smooth transition)
                    current_brake_pressure += (commanded_pressure - current_brake_pressure) * 0.3;

                    // Safety check: limit maximum brake pressure
                    current_brake_pressure = current_brake_pressure.clamp(0.0, 100.0);

                    println!(
                        "{} {} Brake pressure: {:.0}% (commanded: {:.0}%)",
                        "→".red(),
                        if current_brake_pressure > 50.0 {
                            "🔴"
                        } else if current_brake_pressure > 20.0 {
                            "🟡"
                        } else {
                            "🟢"
                        },
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
