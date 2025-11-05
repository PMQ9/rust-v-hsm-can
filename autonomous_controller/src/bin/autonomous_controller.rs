use colored::*;
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{CanFrame, can_ids, encoding, VehicleState};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "AUTONOMOUS_CTRL";
const CONTROL_INTERVAL_MS: u64 = 100; // 10 Hz control loop

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════════════════════".bright_blue().bold());
    println!("{}", "         AUTONOMOUS VEHICLE CONTROLLER                 ".bright_blue().bold());
    println!("{}", "═══════════════════════════════════════════════════════".bright_blue().bold());
    println!();

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!("{} Starting autonomous control loop ({}ms interval)", "→".cyan(), CONTROL_INTERVAL_MS);
    println!();

    // Split client into reader and writer
    let (mut reader, mut writer) = client.split();

    // Channel for communication between receiver and control loop
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

    let mut vehicle_state = VehicleState::new();
    let mut counter = 0u32;

    loop {
        // Process all available sensor messages
        while let Ok(frame) = frame_rx.try_recv() {
            update_vehicle_state(&mut vehicle_state, &frame);
        }

        // Run control algorithm
        let (brake_cmd, throttle_cmd, steering_cmd) = compute_control_commands(&vehicle_state, counter);

        // Send brake command
        let brake_data = vec![encoding::encode_brake_pressure(brake_cmd)];
        let brake_frame = CanFrame::new(
            can_ids::BRAKE_COMMAND,
            brake_data,
            ECU_NAME.to_string(),
        );
        writer.send_frame(brake_frame).await?;

        // Send throttle command
        let throttle_data = vec![encoding::encode_throttle(throttle_cmd)];
        let throttle_frame = CanFrame::new(
            can_ids::THROTTLE_COMMAND,
            throttle_data,
            ECU_NAME.to_string(),
        );
        writer.send_frame(throttle_frame).await?;

        // Send steering command
        let steering_data = encoding::encode_steering_angle(steering_cmd);
        let steering_frame = CanFrame::new(
            can_ids::STEERING_COMMAND,
            steering_data.to_vec(),
            ECU_NAME.to_string(),
        );
        writer.send_frame(steering_frame).await?;

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

fn update_vehicle_state(state: &mut VehicleState, frame: &CanFrame) {
    match frame.id {
        id if id == can_ids::WHEEL_SPEED_FL => {
            state.wheel_speeds[0] = encoding::decode_wheel_speed(&frame.data);
        },
        id if id == can_ids::WHEEL_SPEED_FR => {
            state.wheel_speeds[1] = encoding::decode_wheel_speed(&frame.data);
        },
        id if id == can_ids::WHEEL_SPEED_RL => {
            state.wheel_speeds[2] = encoding::decode_wheel_speed(&frame.data);
        },
        id if id == can_ids::WHEEL_SPEED_RR => {
            state.wheel_speeds[3] = encoding::decode_wheel_speed(&frame.data);
        },
        id if id == can_ids::ENGINE_RPM => {
            state.engine_rpm = encoding::decode_rpm(&frame.data);
        },
        id if id == can_ids::ENGINE_THROTTLE => {
            if !frame.data.is_empty() {
                state.throttle_position = encoding::decode_throttle(frame.data[0]);
            }
        },
        id if id == can_ids::STEERING_ANGLE => {
            state.steering_angle = encoding::decode_steering_angle(&frame.data);
        },
        id if id == can_ids::STEERING_TORQUE => {
            state.steering_torque = encoding::decode_steering_torque(&frame.data);
        },
        _ => {}
    }
    state.timestamp = Some(frame.timestamp);
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
