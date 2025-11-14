/// Anomaly Detection Baseline Calibration Tool
///
/// This binary runs the autonomous vehicle simulation in calibration mode
/// to collect CAN bus traffic and generate statistical baseline profiles
/// for anomaly detection.
///
/// Usage:
///   cargo run --bin calibrate_anomaly_baseline -- [OPTIONS]
///
/// Options:
///   --ecu <NAME>           ECU to calibrate (e.g., BRAKE_CTRL, STEERING_CTRL, AUTO_CTRL)
///   --samples <N>          Minimum samples per CAN ID (default: 5000)
///   --output <PATH>        Output file for signed baseline (default: baseline_<ecu>.json)
///   --duration <SECONDS>   Calibration duration in seconds (default: 300)
use autonomous_vehicle_sim::*;
use colored::*;
use std::env;
use std::time::Duration;
use tokio::time::{Instant, sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut ecu_name = "BRAKE_CTRL".to_string();
    let mut min_samples = 5000u64;
    let mut output_path: Option<String> = None;
    let mut calibration_duration_secs = 300u64; // 5 minutes default

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ecu" => {
                i += 1;
                if i < args.len() {
                    ecu_name = args[i].clone();
                }
            }
            "--samples" => {
                i += 1;
                if i < args.len() {
                    min_samples = args[i].parse()?;
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output_path = Some(args[i].clone());
                }
            }
            "--duration" => {
                i += 1;
                if i < args.len() {
                    calibration_duration_secs = args[i].parse()?;
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Default output path if not specified
    let output_file =
        output_path.unwrap_or_else(|| format!("baseline_{}.json", ecu_name.to_lowercase()));

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "   Anomaly Detection Baseline Calibration"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .bright_blue()
            .bold()
    );
    println!();
    println!("{} ECU: {}", "→".cyan(), ecu_name.bright_white().bold());
    println!(
        "{} Minimum samples per CAN ID: {}",
        "→".cyan(),
        min_samples.to_string().bright_white()
    );
    println!(
        "{} Calibration duration: {} seconds",
        "→".cyan(),
        calibration_duration_secs.to_string().bright_white()
    );
    println!("{} Output file: {}", "→".cyan(), output_file.bright_white());
    println!();

    // Create HSM for the ECU
    let ecu_seed = match ecu_name.as_str() {
        "BRAKE_CTRL" => 50,
        "STEERING_CTRL" => 60,
        "AUTO_CTRL" => 70,
        _ => 100,
    };

    let mut hsm = VirtualHSM::new(ecu_name.clone(), ecu_seed);

    // Start anomaly detection training
    hsm.start_anomaly_training(min_samples)?;

    println!("{} Connecting to CAN bus server...", "→".cyan());

    // Connect to bus server
    let bus_addr = "127.0.0.1:9000";
    let bus_client = BusClient::connect(bus_addr, ecu_name.clone())
        .await
        .map_err(|e| format!("Failed to connect to bus: {}", e))?;
    let (mut bus_reader, _bus_writer) = bus_client.split();

    println!("{} Connected to CAN bus", "✓".green().bold());
    println!();
    println!(
        "{} Starting calibration data collection...",
        "→".cyan().bold()
    );
    println!("   Press Ctrl+C to stop early and finalize baseline");
    println!();

    let start_time = Instant::now();
    let mut frame_count = 0u64;
    let mut last_update = Instant::now();

    // Calibration loop
    loop {
        // Check if duration elapsed
        if start_time.elapsed() >= Duration::from_secs(calibration_duration_secs) {
            println!();
            println!("{} Calibration duration reached", "✓".green().bold());
            break;
        }

        // Receive frames with timeout
        match tokio::time::timeout(Duration::from_millis(100), bus_reader.receive_message()).await {
            Ok(Ok(NetMessage::SecuredCanFrame(secured_frame))) => {
                // Train anomaly detector
                if let Err(e) = hsm.train_anomaly_detector(&secured_frame) {
                    eprintln!("{} Training error: {}", "⚠️".yellow(), e);
                    continue;
                }

                frame_count += 1;

                // Print progress update every 5 seconds
                if last_update.elapsed() >= Duration::from_secs(5) {
                    let elapsed = start_time.elapsed().as_secs();
                    let remaining = calibration_duration_secs.saturating_sub(elapsed);
                    println!(
                        "{} Frames collected: {} | Elapsed: {}s | Remaining: {}s",
                        "ℹ".bright_blue(),
                        frame_count.to_string().bright_white(),
                        elapsed.to_string().bright_black(),
                        remaining.to_string().bright_black()
                    );
                    last_update = Instant::now();
                }
            }
            Ok(Ok(_)) => {
                // Ignore other message types (Ack, Register, Error)
            }
            Ok(Err(e)) => {
                eprintln!("{} Error receiving message: {}", "⚠️".yellow(), e);
                sleep(Duration::from_millis(100)).await;
            }
            Err(_) => {
                // Timeout - no message received, continue
            }
        }
    }

    println!();
    println!("{} Finalizing baseline...", "→".cyan().bold());
    println!(
        "   Total frames collected: {}",
        frame_count.to_string().bright_white()
    );
    println!();

    // Finalize training
    let baseline = match hsm.finalize_anomaly_training() {
        Ok(b) => b,
        Err(e) => {
            eprintln!();
            eprintln!(
                "{} {}",
                "✗".red().bold(),
                "Failed to finalize baseline:".red()
            );
            eprintln!("   {}", e);
            eprintln!();
            eprintln!("{} Possible causes:", "→".yellow());
            eprintln!(
                "   • Insufficient samples collected (minimum: {} per CAN ID)",
                min_samples
            );
            eprintln!("   • CAN bus server not running");
            eprintln!("   • No traffic on the CAN bus");
            eprintln!();
            eprintln!("{} Suggestions:", "→".cyan());
            eprintln!("   • Increase calibration duration: --duration <SECONDS>");
            eprintln!("   • Reduce minimum samples: --samples <N>");
            eprintln!("   • Ensure autonomous vehicle simulation is running");
            eprintln!();
            return Err(e.into());
        }
    };

    println!();
    println!("{} Signing baseline...", "→".cyan());

    // Save baseline with HSM signature
    baseline_persistence::save_baseline(baseline, &output_file, &hsm)?;

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!("{}", "   Baseline Calibration Complete".green().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!();
    println!(
        "{} Baseline saved to: {}",
        "✓".green().bold(),
        output_file.bright_white()
    );
    println!("{} Deploy this file to production ECUs", "→".cyan());
    println!(
        "{} Load at runtime with HSM signature verification",
        "→".cyan()
    );
    println!();

    Ok(())
}
