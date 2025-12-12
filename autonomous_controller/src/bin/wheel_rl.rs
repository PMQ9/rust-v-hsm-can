use autonomous_vehicle_sim::core_affinity_config::pin_by_component;
use autonomous_vehicle_sim::hsm::{SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::hsm_service::HsmClient;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "WHEEL_RL";
const UPDATE_INTERVAL_MS: u64 = 100; // 10 Hz
const HSM_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";
const HSM_SEED: u64 = 0x1003; // Unique seed for boot-time HSM

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
        "   Rear Left Wheel Speed Sensor       ".green().bold()
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
    let boot_hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    let firmware_code = b"WHEEL_RL_FIRMWARE_v1.0.0";
    let firmware = SignedFirmware::new(
        firmware_code.to_vec(),
        "1.0.0".to_string(),
        ECU_NAME.to_string(),
        &boot_hsm,
    );

    protected_mem
        .provision_firmware(firmware, &boot_hsm)
        .expect("Failed to provision firmware");
    protected_mem
        .secure_boot(&boot_hsm)
        .expect("Secure boot failed");
    println!("{} Secure boot completed", "✓".green().bold());

    // =========================================================================
    // Runtime security (HsmClient for CAN operations)
    // =========================================================================
    println!("{} Connecting to HSM service...", "→".cyan());
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
        "{} Sending secured wheel speed data every {}ms",
        "→".cyan(),
        UPDATE_INTERVAL_MS
    );
    println!();

    let (_reader, mut writer) = client.split();

    let mut speed = 0.0f32;
    let mut direction = 1.0f32;
    let mut counter = 0u32;

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down...", "→".yellow());
        std::process::exit(0);
    });

    loop {
        speed += direction * 0.5;

        if speed >= 100.0 {
            direction = -1.0;
        } else if speed <= 0.0 {
            speed = 0.0;
            direction = 1.0;
        }

        // Slightly different noise phase
        let noise = (counter as f32 * 0.1 + 1.0).sin() * 0.5;
        let actual_speed = (speed + noise).max(0.0);

        let data = encoding::encode_wheel_speed(actual_speed);
        match hsm_client
            .create_secured_frame(can_ids::WHEEL_SPEED_RL, data.to_vec())
            .await
        {
            Ok(secured_frame) => {
                writer.send_secured_frame(secured_frame).await?;
            }
            Err(e) => {
                eprintln!("{} Failed to create secured frame: {}", "✗".red().bold(), e);
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
