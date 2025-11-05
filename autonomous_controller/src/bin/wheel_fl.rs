use colored::*;
use std::time::Duration;
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::{can_ids, encoding};
use autonomous_vehicle_sim::hsm::{VirtualHSM, SecuredCanFrame, SignedFirmware};
use autonomous_vehicle_sim::protected_memory::ProtectedMemory;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "WHEEL_FL";
const UPDATE_INTERVAL_MS: u64 = 100; // 10 Hz
const HSM_SEED: u64 = 0x1001; // Unique seed for this ECU

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", "═══════════════════════════════════════".green().bold());
    println!("{}", "   Front Left Wheel Speed Sensor      ".green().bold());
    println!("{}", "═══════════════════════════════════════".green().bold());
    println!();

    // Initialize HSM
    println!("{} Initializing Virtual HSM...", "→".cyan());
    let mut hsm = VirtualHSM::new(ECU_NAME.to_string(), HSM_SEED);

    // Initialize protected memory
    println!("{} Initializing protected memory...", "→".cyan());
    let mut protected_mem = ProtectedMemory::new(ECU_NAME.to_string());

    // Create and provision firmware
    let firmware_code = b"WHEEL_FL_FIRMWARE_v1.0.0";
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
    println!("{} Sending secured wheel speed data every {}ms", "→".cyan(), UPDATE_INTERVAL_MS);
    println!();

    // Split client for concurrent reading/writing
    let (_reader, mut writer) = client.split();

    let mut speed = 0.0f32; // rad/s
    let mut direction = 1.0f32;
    let mut counter = 0u32;

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

        // Encode and send with HSM security
        let data = encoding::encode_wheel_speed(actual_speed);
        let secured_frame = SecuredCanFrame::new(
            can_ids::WHEEL_SPEED_FL,
            data.to_vec(),
            ECU_NAME.to_string(),
            &mut hsm,
        );

        writer.send_secured_frame(secured_frame).await?;

        if counter % 10 == 0 {
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
