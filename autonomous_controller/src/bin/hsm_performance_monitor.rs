/// HSM Performance Monitor
///
/// Standalone tool to monitor and display HSM processing performance across all ECUs.
/// This tool periodically displays statistics about HSM operations (MAC generation,
/// MAC verification, CRC calculation, and CRC verification) to help identify performance
/// bottlenecks and evaluate cryptographic overhead.

use autonomous_vehicle_sim::{
    BusClient, HsmPerformanceEvaluator, NetMessage, VirtualHSM,
};
use std::time::Duration;
use tokio::time;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const STATS_DISPLAY_INTERVAL: Duration = Duration::from_secs(5);
const MONITOR_NAME: &str = "HSM_PERF_MONITOR";

#[tokio::main]
async fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│   HSM Performance Monitor                      │");
    println!("│   Monitoring HSM processing times              │");
    println!("└────────────────────────────────────────────────┘\n");

    // Create a performance evaluator to track all operations
    let performance_evaluator = HsmPerformanceEvaluator::new(50000); // Keep last 50k measurements

    // Create HSM for this monitor (we'll use it to track verification stats)
    let mut hsm = VirtualHSM::new(MONITOR_NAME.to_string(), 0x9000);

    // Register trusted ECUs (using standard seeds from the system)
    register_trusted_ecus(&mut hsm);

    println!("Connecting to CAN bus at {}...", BUS_ADDRESS);

    // Connect to bus
    let client = match BusClient::connect(BUS_ADDRESS, MONITOR_NAME.to_string()).await {
        Ok(c) => {
            println!("✓ Connected successfully\n");
            c
        }
        Err(e) => {
            eprintln!("✗ Failed to connect: {}", e);
            std::process::exit(1);
        }
    };

    // Split into reader and writer
    let (mut reader, _writer) = client.split();

    // Spawn stats display task
    let perf_eval_clone = performance_evaluator.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(STATS_DISPLAY_INTERVAL);
        loop {
            interval.tick().await;
            display_stats(&perf_eval_clone);
        }
    });

    // Spawn message processing task
    let perf_eval_clone = performance_evaluator.clone();
    tokio::spawn(async move {
        let mut local_hsm = hsm.clone();

        // Replace HSM's performance evaluator with our shared one
        *local_hsm.performance_evaluator_mut() = perf_eval_clone.clone();

        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(frame)) => {
                    // Verify the frame - this will automatically record performance metrics
                    let _ = frame.verify(&local_hsm);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error receiving message: {}", e);
                    break;
                }
            }
        }
    });

    // Keep the main task alive
    loop {
        time::sleep(Duration::from_secs(60)).await;
    }
}

/// Register all trusted ECUs with their MAC verification keys
fn register_trusted_ecus(hsm: &mut VirtualHSM) {
    // ECU seeds from the system
    let ecus = vec![
        ("WHEEL_FL", 0x1001_u64),
        ("WHEEL_FR", 0x1002),
        ("WHEEL_RL", 0x1003),
        ("WHEEL_RR", 0x1004),
        ("ENGINE_ECU", 0x2001),
        ("STEERING_SENSOR", 0x2002),
        ("AUTONOMOUS_CTRL", 0x3001),
        ("BRAKE_CTRL", 0x4001),
        ("STEERING_CTRL", 0x4002),
    ];

    for (ecu_name, seed) in ecus {
        // Create temporary HSM to get the ECU's symmetric key
        let ecu_hsm = VirtualHSM::new(ecu_name.to_string(), seed);
        let key = *ecu_hsm.get_symmetric_key();
        hsm.add_trusted_ecu(ecu_name.to_string(), key);
    }
}

/// Display performance statistics
fn display_stats(evaluator: &HsmPerformanceEvaluator) {
    // Clear screen (ANSI escape sequence)
    print!("\x1B[2J\x1B[1;1H");

    println!("┌────────────────────────────────────────────────┐");
    println!("│   HSM Performance Monitor                      │");
    println!("└────────────────────────────────────────────────┘");
    println!();

    let measurement_count = evaluator.measurement_count();
    println!("Total measurements: {}\n", measurement_count);

    if measurement_count == 0 {
        println!("⏳ Waiting for HSM operations to measure...\n");
        println!("Make sure ECUs are running and sending messages.");
        return;
    }

    // Display statistics
    evaluator.display_stats();

    // Display summary
    println!("┌────────────────────────────────────────────────┐");
    println!("│   Summary                                      │");
    println!("└────────────────────────────────────────────────┘");
    println!("  {}", evaluator.get_summary());
    println!();

    // Performance insights
    println!("┌────────────────────────────────────────────────┐");
    println!("│   Performance Insights                         │");
    println!("└────────────────────────────────────────────────┘");

    let stats = evaluator.get_all_stats();
    for stat in stats {
        let avg_micros = stat.avg.as_micros();
        let status = if avg_micros < 50 {
            "✓ Excellent"
        } else if avg_micros < 100 {
            "✓ Good"
        } else if avg_micros < 200 {
            "⚠ Acceptable"
        } else {
            "✗ Slow"
        };

        println!("  {}: {} (avg: {}μs)", stat.operation.as_str(), status, avg_micros);
    }

    println!();
    println!("Press Ctrl+C to exit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecu_registration() {
        let mut hsm = VirtualHSM::new("TEST".to_string(), 0x9999);
        register_trusted_ecus(&mut hsm);
        // Should be able to verify messages from registered ECUs
    }
}
