use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::hsm::{SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "STEERING_SENSOR";
const UPDATE_INTERVAL_MS: u64 = 50; // 20 Hz
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x1006; // Unique seed for boot-time HSM

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    // Pin to assigned core (Core 1 for sensors)
    if let Err(e) = pin_by_component(ECU_NAME.to_lowercase().as_str()) {
        eprintln!("{} Core pinning failed: {} (continuing)", "→".yellow(), e);
    }

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

    // =========================================================================
    // Boot-time security (local HSM for secure boot)
    // =========================================================================
    println!("{} Performing secure boot sequence...", "→".cyan());

    // Use local HSM for boot-time operations (firmware signing, secure boot)
    let boot_hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);

    // Initialize protected memory
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"STEERING_SENSOR_FIRMWARE_v1.0.0";
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

    // Setup Ctrl+C handler for clean shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down...", "→".yellow());
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

        // Send steering angle (secured via HSM service)
        let angle_data = encoding::encode_steering_angle(angle);
        match hsm_client
            .create_secured_frame(can_ids::STEERING_ANGLE, angle_data.to_vec())
            .await
        {
            Ok(angle_frame) => {
                writer.send_secured_frame(angle_frame).await?;
            }
            Err(e) => {
                eprintln!("{} Failed to create angle frame: {}", "✗".red().bold(), e);
                continue;
            }
        }

        // Send steering torque (secured via HSM service)
        let torque_data = encoding::encode_steering_torque(torque);
        match hsm_client
            .create_secured_frame(can_ids::STEERING_TORQUE, torque_data.to_vec())
            .await
        {
            Ok(torque_frame) => {
                writer.send_secured_frame(torque_frame).await?;
            }
            Err(e) => {
                eprintln!("{} Failed to create torque frame: {}", "✗".red().bold(), e);
                continue;
            }
        }

        if counter.is_multiple_of(20) {
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
