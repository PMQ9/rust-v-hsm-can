use autonomous_vehicle_sim::hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "STEERING_SENSOR";
const UPDATE_INTERVAL_MS: u64 = 50; // 20 Hz
const HSM_SEED: u64 = 0x1006; // Unique seed for this ECU

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    println!(
        "{}",
        "═══════════════════════════════════════".magenta().bold()
    );
    println!(
        "{}",
        "        Steering Sensor ECU            ".magenta().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════".magenta().bold()
    );
    if perf_mode {
        println!("{} Performance evaluation mode enabled", "ℹ".bright_blue());
    }
    println!();

    // Initialize HSM with optional performance tracking
    println!("{} Initializing Virtual HSM...", "→".cyan());
    let mut hsm = VirtualHSM::with_performance(ECU_NAME.to_string(), HSM_SEED, perf_mode);

    // Initialize protected memory
    println!("{} Initializing protected memory...", "→".cyan());
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"STEERING_SENSOR_FIRMWARE_v1.0.0";
    let firmware = SignedFirmware::new(
        firmware_code.to_vec(),
        "1.0.0".to_string(),
        ECU_NAME.to_string(),
        &hsm,
    );

    protected_mem
        .provision_firmware(firmware, &hsm)
        .expect("Failed to provision firmware");

    // Perform secure boot
    println!("{} Performing secure boot...", "→".cyan());
    protected_mem.secure_boot(&hsm).expect("Secure boot failed");

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!(
        "{} Sending secured steering data every {}ms",
        "→".cyan(),
        UPDATE_INTERVAL_MS
    );
    println!();

    // Split client for concurrent reading/writing
    let (_reader, mut writer) = client.split();

    let mut angle = 0.0f32; // degrees
    let mut direction = 1.0f32;
    let mut counter = 0u32;

    // Setup Ctrl+C handler for clean shutdown with performance stats
    let hsm_clone = hsm.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down...", "→".yellow());
        hsm_clone.print_performance_stats();
        std::process::exit(0);
    });

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
        let torque = angle * 0.1 + (counter as f32 * 0.05).sin() * 2.0;
        let torque = torque.clamp(-10.0, 10.0);

        // Send steering angle (secured)
        let angle_data = encoding::encode_steering_angle(angle);
        let angle_frame = SecuredCanFrame::new(
            can_ids::STEERING_ANGLE,
            angle_data.to_vec(),
            ECU_NAME.to_string(),
            &mut hsm,
        );
        writer.send_secured_frame(angle_frame).await?;

        // Send steering torque (secured)
        let torque_data = encoding::encode_steering_torque(torque);
        let torque_frame = SecuredCanFrame::new(
            can_ids::STEERING_TORQUE,
            torque_data.to_vec(),
            ECU_NAME.to_string(),
            &mut hsm,
        );
        writer.send_secured_frame(torque_frame).await?;

        if counter.is_multiple_of(20) {
            println!(
                "{} Steering: Angle={:.1}°, Torque={:.2} Nm",
                "→".bright_black(),
                angle,
                torque
            );
        }

        // Periodically send performance stats to monitor (if enabled)
        if perf_mode
            && counter.is_multiple_of(100)
            && counter > 0
            && let Some(snapshot) = hsm.get_performance_snapshot()
        {
            let _ = writer.send_performance_stats(snapshot).await;
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
