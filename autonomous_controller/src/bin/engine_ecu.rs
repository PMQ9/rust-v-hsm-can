use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::hsm::{SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "ENGINE_ECU";
const UPDATE_INTERVAL_MS: u64 = 50; // 20 Hz
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x1005; // Unique seed for boot-time HSM

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
        "═══════════════════════════════════════".yellow().bold()
    );
    println!(
        "{}",
        "          Engine Control Unit          ".yellow().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════".yellow().bold()
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
    let firmware_code = b"ENGINE_ECU_FIRMWARE_v1.0.0";
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
        "{} Sending secured engine data every {}ms",
        "→".cyan(),
        UPDATE_INTERVAL_MS
    );
    println!();

    // Split client for concurrent reading/writing
    let (_reader, mut writer) = client.split();

    let mut rpm = 800.0f32; // Idle RPM
    let mut throttle = 0.0f32; // 0-100%
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
        // Simulate throttle changes
        throttle += direction * 1.0;

        if throttle >= 80.0 {
            direction = -1.0;
        } else if throttle <= 0.0 {
            throttle = 0.0;
            direction = 1.0;
        }

        // RPM follows throttle with some lag and idle speed
        let target_rpm = 800.0 + (throttle / 100.0) * 5200.0; // 800-6000 RPM
        rpm += (target_rpm - rpm) * 0.1; // Smooth transition

        // Send RPM (secured via HSM service)
        let rpm_data = encoding::encode_rpm(rpm);
        match hsm_client
            .create_secured_frame(can_ids::ENGINE_RPM, rpm_data.to_vec())
            .await
        {
            Ok(rpm_frame) => {
                writer.send_secured_frame(rpm_frame).await?;
            }
            Err(e) => {
                eprintln!("{} Failed to create RPM frame: {}", "✗".red().bold(), e);
                continue;
            }
        }

        // Send throttle position (secured via HSM service)
        let throttle_data = vec![encoding::encode_throttle(throttle)];
        match hsm_client
            .create_secured_frame(can_ids::ENGINE_THROTTLE, throttle_data)
            .await
        {
            Ok(throttle_frame) => {
                writer.send_secured_frame(throttle_frame).await?;
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to create throttle frame: {}",
                    "✗".red().bold(),
                    e
                );
                continue;
            }
        }

        if counter.is_multiple_of(20) {
            println!(
                "{} Engine: RPM={:.0}, Throttle={:.0}%",
                "→".bright_black(),
                rpm,
                throttle
            );
        }

        counter += 1;
        tokio::time::sleep(Duration::from_millis(UPDATE_INTERVAL_MS)).await;
    }
}
