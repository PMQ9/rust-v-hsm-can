use autonomous_vehicle_sim::access_control;
use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::hsm::{SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "WHEEL_FL";
const UPDATE_INTERVAL_MS: u64 = 100; // 10 Hz
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x1001; // Unique seed for boot-time HSM

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
        "═══════════════════════════════════════".green().bold()
    );
    println!(
        "{}",
        "   Front Left Wheel Speed Sensor      ".green().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════".green().bold()
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
    let firmware_code = b"WHEEL_FL_FIRMWARE_v1.0.0";
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

    // Load CAN ID access control policy
    println!("{} Loading CAN ID access control policy...", "→".cyan());
    if let Some(permissions) = access_control::load_policy_for_ecu(ECU_NAME) {
        hsm_client.load_access_control(permissions).await?;
        println!("{} Access control policy loaded", "✓".green().bold());
    } else {
        println!(
            "{} No access control policy found - using permissive mode",
            "⚠".yellow()
        );
    }
    println!();

    // =========================================================================
    // CAN bus connection
    // =========================================================================
    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    println!("{} Connected to CAN bus!", "✓".green().bold());
    println!(
        "{} Sending secured wheel speed data every {}ms",
        "→".cyan(),
        UPDATE_INTERVAL_MS
    );
    println!();

    // Split client for concurrent reading/writing
    let (_reader, mut writer) = client.split();

    let mut speed = 0.0f32; // rad/s
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
        // Simulate wheel speed variation (0-100 rad/s, accelerating and decelerating)
        speed += direction * 0.5;

        if speed >= 100.0 {
            direction = -1.0;
        } else if speed <= 0.0 {
            speed = 0.0;
            direction = 1.0;
        }

        // Add some realistic noise
        let noise = (counter as f32 * 0.1).sin() * 0.5;
        let actual_speed = (speed + noise).max(0.0);

        // Encode and send with HSM security (via HSM service)
        let data = encoding::encode_wheel_speed(actual_speed);
        match hsm_client
            .create_secured_frame(can_ids::WHEEL_SPEED_FL, data.to_vec())
            .await
        {
            Ok(secured_frame) => {
                writer.send_secured_frame(secured_frame).await?;
            }
            Err(e) => {
                eprintln!("{} Failed to create secured frame: {}", "✗".red().bold(), e);
                // Authorization failed - this shouldn't happen in normal operation
                continue;
            }
        }

        if counter.is_multiple_of(10) {
            println!(
                "{} Sent wheel speed: {:.2} rad/s",
                "→".bright_black(),
                actual_speed
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
