use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::error_handling::{AttackDetector, ValidationError};
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::security_log::SecurityLogger;
use autonomous_vehicle_sim::types::{VehicleState, can_ids, encoding};
use colored::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "AUTONOMOUS_CONTROLLER";
const CONTROL_INTERVAL_MS: u64 = 100; // 10 Hz control loop
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x2001; // Unique seed for boot-time HSM

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    // Pin to assigned core (Core 2 for controllers)
    if let Err(e) = pin_by_component(ECU_NAME.to_lowercase().as_str()) {
        eprintln!("{} Core pinning failed: {} (continuing)", "→".yellow(), e);
    }

    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "         AUTONOMOUS VEHICLE CONTROLLER                 "
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .bright_blue()
            .bold()
    );
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

    // Initialize protected memory with firmware
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision autonomous controller firmware
    let firmware_code = b"AUTONOMOUS_CTRL_FIRMWARE_v1.0.0";
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
    println!(
        "{} Starting secured autonomous control loop ({}ms interval)",
        "→".cyan(),
        CONTROL_INTERVAL_MS
    );
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
    println!(
        "   • Unsecured frame threshold: {} (immediate)",
        autonomous_vehicle_sim::error_handling::UNSECURED_FRAME_THRESHOLD
    );
    println!();

    // Split client into reader and writer
    let (mut reader, mut writer) = client.split();

    // Channel for communication between receiver and control loop
    let (frame_tx, mut frame_rx) = mpsc::channel::<SecuredCanFrame>(100);

    // Clone attack detector and hsm_client for receiver task
    let detector_clone = Arc::clone(&attack_detector);
    let hsm_client_clone = hsm_client.clone();

    // Spawn receiver task with MAC/CRC verification and attack detection
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(secured_frame)) => {
                    // Ignore frames from ourselves (prevent verification loop)
                    if secured_frame.source == ECU_NAME {
                        continue;
                    }

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

    let mut vehicle_state = VehicleState::new();
    let mut counter = 0u32;
    let mut warning_displayed = false;

    // Setup Ctrl+C handler for clean shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down...", "→".yellow());
        std::process::exit(0);
    });

    loop {
        // Process all available sensor messages (secured)
        while let Ok(secured_frame) = frame_rx.try_recv() {
            update_vehicle_state(&mut vehicle_state, &secured_frame);
        }

        // CHECK FOR ATTACK - STOP SENDING COMMANDS IF DETECTED
        let is_under_attack = {
            let detector = attack_detector.lock().unwrap();
            !detector.should_accept_frames()
        };

        if is_under_attack {
            // Display warning message once and broadcast shutdown status
            if !warning_displayed {
                eprintln!();
                eprintln!(
                    "{}",
                    "═══════════════════════════════════════════════════════"
                        .red()
                        .bold()
                );
                eprintln!(
                    "{}",
                    "   AUTONOMOUS CONTROLLER DEACTIVATED            "
                        .red()
                        .bold()
                );
                eprintln!(
                    "{}",
                    "═══════════════════════════════════════════════════════"
                        .red()
                        .bold()
                );
                eprintln!();
                eprintln!("{} Attack detected on CAN bus!", "⚠️".red().bold());
                eprintln!(
                    "{} Controller has been STOPPED for safety.",
                    "⚠️".red().bold()
                );
                eprintln!(
                    "{} Sensor monitoring continues but NO COMMANDS will be sent.",
                    "→".yellow()
                );
                eprintln!();
                eprintln!(
                    "{} {} to resume operation.",
                    "→".yellow(),
                    "RESTART REQUIRED".red().bold()
                );
                eprintln!();
                eprintln!(
                    "{}",
                    "═══════════════════════════════════════════════════════"
                        .red()
                        .bold()
                );
                eprintln!();

                // Broadcast emergency shutdown status on CAN bus (0x400)
                // Status byte: 0xFF = Emergency Shutdown
                let status_data = vec![0xFF];
                if let Ok(status_frame) = hsm_client
                    .create_secured_frame(can_ids::AUTO_STATUS, status_data)
                    .await
                {
                    let _ = writer.send_secured_frame(status_frame).await;
                }

                warning_displayed = true;
            }

            // Periodically re-broadcast shutdown status so monitor always shows it
            if counter.is_multiple_of(10) {
                let status_data = vec![0xFF]; // 0xFF = Emergency Shutdown
                if let Ok(status_frame) = hsm_client
                    .create_secured_frame(can_ids::AUTO_STATUS, status_data)
                    .await
                {
                    let _ = writer.send_secured_frame(status_frame).await;
                }
            }

            // Continue monitoring sensors but DO NOT send control commands
            if counter.is_multiple_of(50) {
                println!(
                    "{} [STOPPED] Monitoring: Avg Wheel Speed={:.1} rad/s",
                    "⚠️".red(),
                    vehicle_state.average_wheel_speed()
                );
            }

            counter += 1;
            tokio::time::sleep(Duration::from_millis(CONTROL_INTERVAL_MS)).await;
            continue; // Skip sending commands
        }

        // Run control algorithm (firmware in protected memory)
        let (brake_cmd, throttle_cmd, steering_cmd) =
            compute_control_commands(&vehicle_state, counter);

        // Send brake command (secured via HSM service)
        let brake_data = vec![encoding::encode_brake_pressure(brake_cmd)];
        if let Ok(brake_frame) = hsm_client
            .create_secured_frame(can_ids::BRAKE_COMMAND, brake_data)
            .await
        {
            writer.send_secured_frame(brake_frame).await?;
        }

        // Send throttle command (secured via HSM service)
        let throttle_data = vec![encoding::encode_throttle(throttle_cmd)];
        if let Ok(throttle_frame) = hsm_client
            .create_secured_frame(can_ids::THROTTLE_COMMAND, throttle_data)
            .await
        {
            writer.send_secured_frame(throttle_frame).await?;
        }

        // Send steering command (secured via HSM service)
        let steering_data = encoding::encode_steering_angle(steering_cmd);
        if let Ok(steering_frame) = hsm_client
            .create_secured_frame(can_ids::STEERING_COMMAND, steering_data.to_vec())
            .await
        {
            writer.send_secured_frame(steering_frame).await?;
        }

        if counter.is_multiple_of(10) {
            println!(
                "{} Control: Brake={:.0}%, Throttle={:.0}%, Steering={:.1}° | Avg Wheel Speed={:.1} rad/s",
                "→".bright_blue(),
                brake_cmd,
                throttle_cmd,
                steering_cmd,
                vehicle_state.average_wheel_speed()
            );

            // Check for anomalies
            if vehicle_state.has_wheel_discrepancy(0.15) {
                println!(
                    "  {} Wheel speed discrepancy detected! Possible slip/skid",
                    "⚠".yellow().bold()
                );
            }
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(CONTROL_INTERVAL_MS)).await;
    }
}

fn update_vehicle_state(state: &mut VehicleState, secured_frame: &SecuredCanFrame) {
    // Extract data from secured frame (already verified)
    match secured_frame.can_id {
        id if id == can_ids::WHEEL_SPEED_FL => {
            state.wheel_speeds[0] = encoding::decode_wheel_speed(&secured_frame.data);
        }
        id if id == can_ids::WHEEL_SPEED_FR => {
            state.wheel_speeds[1] = encoding::decode_wheel_speed(&secured_frame.data);
        }
        id if id == can_ids::WHEEL_SPEED_RL => {
            state.wheel_speeds[2] = encoding::decode_wheel_speed(&secured_frame.data);
        }
        id if id == can_ids::WHEEL_SPEED_RR => {
            state.wheel_speeds[3] = encoding::decode_wheel_speed(&secured_frame.data);
        }
        id if id == can_ids::ENGINE_RPM => {
            state.engine_rpm = encoding::decode_rpm(&secured_frame.data);
        }
        id if id == can_ids::ENGINE_THROTTLE => {
            if !secured_frame.data.is_empty() {
                state.throttle_position = encoding::decode_throttle(secured_frame.data[0]);
            }
        }
        id if id == can_ids::STEERING_ANGLE => {
            state.steering_angle = encoding::decode_steering_angle(&secured_frame.data);
        }
        id if id == can_ids::STEERING_TORQUE => {
            state.steering_torque = encoding::decode_steering_torque(&secured_frame.data);
        }
        _ => {}
    }
    state.timestamp = Some(secured_frame.timestamp);
}

fn compute_control_commands(state: &VehicleState, counter: u32) -> (f32, f32, f32) {
    // Simple demonstration control algorithm
    // In a real system, this would implement path planning, obstacle avoidance, etc.

    let avg_speed = state.average_wheel_speed();

    // Target speed profile: accelerate to ~50 rad/s, then maintain
    let target_speed = 50.0;
    let speed_error = target_speed - avg_speed;

    // Simple proportional control for throttle/brake
    let (brake_cmd, throttle_cmd) = if speed_error > 5.0 {
        // Need to accelerate
        (0.0, (speed_error * 2.0).min(50.0))
    } else if speed_error < -5.0 {
        // Need to brake
        ((-speed_error * 1.5).min(30.0), 0.0)
    } else {
        // Maintain speed
        (0.0, 10.0)
    };

    // Steering: simple sinusoidal pattern for demonstration
    let steering_cmd = (counter as f32 * 0.05).sin() * 10.0;

    (brake_cmd, throttle_cmd, steering_cmd)
}
