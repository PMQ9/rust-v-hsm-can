use autonomous_vehicle_sim::hsm::{SecuredCanFrame, SignedFirmware, VirtualHSM};
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use colored::*;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "WHEEL_RL";
const UPDATE_INTERVAL_MS: u64 = 100; // 10 Hz
const HSM_SEED: u64 = 0x1003; // Unique seed for this ECU

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

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

    // Initialize HSM with optional performance tracking
    println!("{} Initializing Virtual HSM...", "→".cyan());
    let mut hsm = VirtualHSM::with_performance(ECU_NAME.to_string(), HSM_SEED, perf_mode);

    // Initialize protected memory
    println!("{} Initializing protected memory...", "→".cyan());
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"WHEEL_RL_FIRMWARE_v1.0.0";
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
        // Simulate wheel speed variation (0-100 rad/s, accelerating and decelerating)
        speed += direction * 0.5;

        if speed >= 100.0 {
            direction = -1.0;
        } else if speed <= 0.0 {
            speed = 0.0;
            direction = 1.0;
        }

        // Add some realistic noise (slightly different phase)
        let noise = (counter as f32 * 0.1 + 1.0).sin() * 0.5;
        let actual_speed = (speed + noise).max(0.0);

        // Encode and send with HSM security
        let data = encoding::encode_wheel_speed(actual_speed);
        let secured_frame = SecuredCanFrame::new(
            can_ids::WHEEL_SPEED_RL,
            data.to_vec(),
            ECU_NAME.to_string(),
            &mut hsm,
        );

        writer.send_secured_frame(secured_frame).await?;

        if counter.is_multiple_of(10) {
            println!(
                "{} Sent wheel speed: {:.2} rad/s",
                "→".bright_black(),
                actual_speed
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
