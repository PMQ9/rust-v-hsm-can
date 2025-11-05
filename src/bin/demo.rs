use colored::*;
use std::time::Duration;
use tokio::time::sleep;
use vhsm_can::can_bus::VirtualCanBus;
use vhsm_can::ecu::Ecu;
use vhsm_can::types::{ArmVariant, CanId, EcuConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!("{}", "     Virtual CAN Bus Demo - Single Process                    ".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!();

    // Create the virtual CAN bus
    println!("{} Creating virtual CAN bus...", "→".green());
    let bus = VirtualCanBus::new(100);
    println!("{} CAN bus created with 100-message buffer", "✓".green());
    println!();

    // Create Input ECU
    println!("{} Creating Input ECU (ARM Cortex-M4)...", "→".green());
    let input_config = EcuConfig {
        name: "INPUT_ECU".to_string(),
        bus_address: "127.0.0.1:9001".to_string(),
        arm_variant: ArmVariant::CortexM4,
    };
    let input_ecu = Ecu::new(input_config.clone(), bus.clone());
    println!("  - Name: {}", input_config.name.bright_cyan());
    println!("  - Processor: {}", input_config.arm_variant.as_str().bright_cyan());
    println!("{} Input ECU ready", "✓".green());
    println!();

    // Create Output ECU
    println!("{} Creating Output ECU (ARM Cortex-M7)...", "→".green());
    let output_config = EcuConfig {
        name: "OUTPUT_ECU".to_string(),
        bus_address: "127.0.0.1:9002".to_string(),
        arm_variant: ArmVariant::CortexM7,
    };
    let mut output_ecu = Ecu::new(output_config.clone(), bus.clone());
    println!("  - Name: {}", output_config.name.bright_cyan());
    println!("  - Processor: {}", output_config.arm_variant.as_str().bright_cyan());
    println!("{} Output ECU ready", "✓".green());
    println!();

    // Create Monitor
    println!("{} Creating CAN bus monitor...", "→".green());
    let mut monitor_rx = bus.subscribe();
    println!("{} Monitor ready", "✓".green());
    println!();

    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "                  Starting Simulation                          ".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!();

    // Spawn monitor task
    let monitor_task = tokio::spawn(async move {
        let mut count = 0;
        loop {
            match monitor_rx.try_recv() {
                Ok(frame) => {
                    count += 1;
                    let id_str = match frame.id {
                        CanId::Standard(id) => format!("{:03X}", id).yellow(),
                        CanId::Extended(id) => format!("{:08X}", id).magenta(),
                    };

                    let data_str = frame
                        .data
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    println!(
                        "{} [{}] ID: {} │ DLC: {} │ Data: [{}] │ Src: {}",
                        "MONITOR:".cyan().bold(),
                        format!("#{:03}", count).blue(),
                        id_str,
                        format!("{}", frame.data.len()).green(),
                        data_str.bright_white(),
                        frame.source.bright_cyan()
                    );
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(_) => break,
            }
        }
    });

    // Spawn output ECU task
    let output_task = tokio::spawn(async move {
        let mut count = 0;
        loop {
            match output_ecu.try_receive_frame() {
                Ok(frame) => {
                    count += 1;
                    let id_str = match frame.id {
                        CanId::Standard(id) => format!("{:03X}", id),
                        CanId::Extended(id) => format!("{:08X}", id),
                    };

                    let data_str = frame
                        .data
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    println!(
                        "{} Received frame #{:03} - ID: {} │ Data: [{}] │ From: {}",
                        "OUTPUT:".blue().bold(),
                        count,
                        id_str,
                        data_str,
                        frame.source
                    );
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    sleep(Duration::from_millis(10)).await;
                }
                Err(_) => break,
            }
        }
    });

    // Simulate Input ECU sending messages
    println!("{} Input ECU sending test frames...", "→".green().bold());
    println!();
    sleep(Duration::from_millis(500)).await;

    // Send some sample CAN frames
    let test_frames = vec![
        (CanId::Standard(0x100), vec![0x01, 0x02, 0x03, 0x04]),
        (CanId::Standard(0x200), vec![0xAA, 0xBB, 0xCC]),
        (CanId::Standard(0x123), vec![0x11, 0x22, 0x33, 0x44, 0x55]),
        (CanId::Extended(0x12345678), vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]),
        (CanId::Standard(0x7FF), vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    ];

    for (i, (id, data)) in test_frames.iter().enumerate() {
        println!("{} Sending frame #{:03}...", "INPUT:".green().bold(), i + 1);
        input_ecu.send_frame(*id, data.clone()).await?;
        sleep(Duration::from_millis(800)).await;
    }

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!("{} Test completed! Sent {} frames", "✓".green().bold(), test_frames.len());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());

    // Give tasks time to finish processing
    sleep(Duration::from_millis(500)).await;

    // Cancel tasks
    monitor_task.abort();
    output_task.abort();

    println!();
    println!("Demo finished. System statistics:");
    println!("  - Bus receivers: {}", bus.receiver_count());
    println!("  - Total frames sent: {}", test_frames.len());
    println!();

    Ok(())
}
