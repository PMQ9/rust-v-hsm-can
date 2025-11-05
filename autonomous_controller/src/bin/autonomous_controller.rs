use colored::*;
use std::time::Duration;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{can_ids, encoding, VehicleState};
use autonomous_vehicle_sim::hsm::{VirtualHSM, SecuredCanFrame, SignedFirmware};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "AUTONOMOUS_CTRL";
const CONTROL_INTERVAL_MS: u64 = 100; // 10 Hz control loop
const HSM_SEED: u64 = 0x2001; // Unique seed for autonomous controller

// HSM seeds for all ECUs (in production, these would be securely stored)
const ECU_SEEDS: &[(& str, u64)] = &[
    ("WHEEL_FL", 0x1001),
    ("WHEEL_FR", 0x1002),
    ("WHEEL_RL", 0x1003),
    ("WHEEL_RR", 0x1004),
    ("ENGINE_ECU", 0x1005),
    ("STEERING_SENSOR", 0x1006),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════════════════════".bright_blue().bold());
    println!("{}", "         AUTONOMOUS VEHICLE CONTROLLER                 ".bright_blue().bold());
    println!("{}", "═══════════════════════════════════════════════════════".bright_blue().bold());
    println!();

    // Initialize HSM
    println!("{} Initializing Virtual HSM...", "→".cyan());
    let mut hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);

    // Register trusted ECUs (add their MAC keys to our HSM)
    println!("{} Registering trusted ECUs...", "→".cyan());
    for (ecu_name, seed) in ECU_SEEDS {
        let trusted_hsm = VirtualHSM::new(ecu_name.to_string(), *seed);
        hsm.add_trusted_ecu(ecu_name.to_string(), *trusted_hsm.get_symmetric_key());
        println!("  ✓ Registered {}", ecu_name);
    }

    // Initialize protected memory with firmware
    println!("{} Initializing protected memory...", "→".cyan());
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision autonomous controller firmware
    let firmware_code = b"AUTONOMOUS_CTRL_FIRMWARE_v1.0.0";
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
    println!("{} Starting secured autonomous control loop ({}ms interval)", "→".cyan(), CONTROL_INTERVAL_MS);
    println!();

    // Split client into reader and writer
    let (mut reader, mut writer) = client.split();

    // Channel for communication between receiver and control loop
    let (frame_tx, mut frame_rx) = mpsc::channel::<SecuredCanFrame>(100);

    // Attack detection flag (shared between receiver task and control loop)
    let attack_detected = Arc::new(AtomicBool::new(false));
    let attack_detected_clone = attack_detected.clone();

    // Clone HSM for the receiver task
    let hsm_clone = hsm.clone();

    // Spawn receiver task with MAC/CRC verification
    tokio::spawn(async move {
        let mut verified_count = 0u64;
        let mut failed_count = 0u64;
        let mut attack_warning_shown = false;

        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(secured_frame)) => {
                    // Ignore frames from ourselves (prevent verification loop)
                    if secured_frame.source == ECU_NAME {
                        continue;
                    }

                    // Verify MAC and CRC
                    match secured_frame.verify(&hsm_clone) {
                        Ok(_) => {
                            verified_count += 1;
                            if frame_tx.send(secured_frame).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            failed_count += 1;

                            // Check if this is an unsecured frame attack
                            if e.contains("UNSECURED FRAME") {
                                // SET ATTACK FLAG - STOP CONTROLLER!
                                attack_detected_clone.store(true, Ordering::SeqCst);

                                // Only display warning once to prevent flickering
                                if !attack_warning_shown {
                                    eprintln!();
                                    eprintln!("{} {}", "ATTACK DETECTED:".red().bold(), "Unsecured Frame Injection".red());
                                    eprintln!("  {}", e.red());
                                    eprintln!("  CAN ID: 0x{:03X}", secured_frame.can_id.value());
                                    eprintln!("  Frame has NO MAC/CRC - unauthorized ECU on bus!");
                                    eprintln!("  Verified: {}, Failed: {}", verified_count, failed_count);
                                    eprintln!("  {} Attack flag set to TRUE - Controller will shutdown", "→".yellow().bold());
                                    eprintln!("  {} Suppressing further attack messages to prevent spam", "→".yellow());
                                    eprintln!();
                                    attack_warning_shown = true;
                                }
                            } else {
                                eprintln!("{} Security verification failed: {}", "⚠".yellow().bold(), e);
                                eprintln!("  Verified: {}, Failed: {}", verified_count, failed_count);
                            }
                        }
                    }
                }
                Ok(NetMessage::CanFrame(unsecured_frame)) => {
                    // Unsecured frame detected - this is a potential attack!
                    // SET ATTACK FLAG - STOP CONTROLLER!
                    attack_detected_clone.store(true, Ordering::SeqCst);

                    failed_count += 1;

                    // Only display warning once to prevent flickering
                    if !attack_warning_shown {
                        eprintln!();
                        eprintln!("{} {} ATTACK: Unsecured frame detected!", "⚠️".red().bold(), "SECURITY".red().bold());
                        eprintln!("  Source: {}", unsecured_frame.source.red());
                        eprintln!("  CAN ID: 0x{:03X}", unsecured_frame.id.value());
                        eprintln!("  Frame has NO MAC - potential injection attack!");
                        eprintln!("  Verified: {}, Failed: {}", verified_count, failed_count);
                        eprintln!("  {} Suppressing further attack messages to prevent spam", "→".yellow());
                        eprintln!();
                        attack_warning_shown = true;
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

    loop {
        // Process all available sensor messages (secured)
        while let Ok(secured_frame) = frame_rx.try_recv() {
            update_vehicle_state(&mut vehicle_state, &secured_frame);
        }

        // CHECK FOR ATTACK - STOP SENDING COMMANDS IF DETECTED
        let is_under_attack = attack_detected.load(Ordering::SeqCst);
        if is_under_attack {
            // Display warning message once
            if !warning_displayed {
                eprintln!();
                eprintln!("{}", "═══════════════════════════════════════════════════════".red().bold());
                eprintln!("{}", "  🚨 AUTONOMOUS CONTROLLER DEACTIVATED 🚨           ".red().bold());
                eprintln!("{}", "═══════════════════════════════════════════════════════".red().bold());
                eprintln!();
                eprintln!("{} Attack detected on CAN bus!", "⚠️".red().bold());
                eprintln!("{} Controller has been STOPPED for safety.", "⚠️".red().bold());
                eprintln!("{} Sensor monitoring continues but NO COMMANDS will be sent.", "→".yellow());
                eprintln!();
                eprintln!("{} {} to resume operation.", "→".yellow(), "RESTART REQUIRED".red().bold());
                eprintln!();
                eprintln!("{}", "═══════════════════════════════════════════════════════".red().bold());
                eprintln!();
                warning_displayed = true;
            }

            // Continue monitoring sensors but DO NOT send control commands
            if counter % 50 == 0 {
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
        let (brake_cmd, throttle_cmd, steering_cmd) = compute_control_commands(&vehicle_state, counter);

        // Send brake command (secured)
        let brake_data = vec![encoding::encode_brake_pressure(brake_cmd)];
        let brake_frame = SecuredCanFrame::new(
            can_ids::BRAKE_COMMAND,
            brake_data,
            ECU_NAME.to_string(),
            &mut hsm,
        );
        writer.send_secured_frame(brake_frame).await?;

        // Send throttle command (secured)
        let throttle_data = vec![encoding::encode_throttle(throttle_cmd)];
        let throttle_frame = SecuredCanFrame::new(
            can_ids::THROTTLE_COMMAND,
            throttle_data,
            ECU_NAME.to_string(),
            &mut hsm,
        );
        writer.send_secured_frame(throttle_frame).await?;

        // Send steering command (secured)
        let steering_data = encoding::encode_steering_angle(steering_cmd);
        let steering_frame = SecuredCanFrame::new(
            can_ids::STEERING_COMMAND,
            steering_data.to_vec(),
            ECU_NAME.to_string(),
            &mut hsm,
        );
        writer.send_secured_frame(steering_frame).await?;

        if counter % 10 == 0 {
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
        },
        id if id == can_ids::WHEEL_SPEED_FR => {
            state.wheel_speeds[1] = encoding::decode_wheel_speed(&secured_frame.data);
        },
        id if id == can_ids::WHEEL_SPEED_RL => {
            state.wheel_speeds[2] = encoding::decode_wheel_speed(&secured_frame.data);
        },
        id if id == can_ids::WHEEL_SPEED_RR => {
            state.wheel_speeds[3] = encoding::decode_wheel_speed(&secured_frame.data);
        },
        id if id == can_ids::ENGINE_RPM => {
            state.engine_rpm = encoding::decode_rpm(&secured_frame.data);
        },
        id if id == can_ids::ENGINE_THROTTLE => {
            if !secured_frame.data.is_empty() {
                state.throttle_position = encoding::decode_throttle(secured_frame.data[0]);
            }
        },
        id if id == can_ids::STEERING_ANGLE => {
            state.steering_angle = encoding::decode_steering_angle(&secured_frame.data);
        },
        id if id == can_ids::STEERING_TORQUE => {
            state.steering_torque = encoding::decode_steering_torque(&secured_frame.data);
        },
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
