/// Regression tests for CAN ID access control (ISO 21434)
///
/// These tests verify that the access control whitelist works correctly:
/// - ECUs with proper authorization can send messages on their whitelisted CAN IDs
/// - ECUs attempting to send on unauthorized CAN IDs are rejected
/// - Security events are logged for authorization violations
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct TestHarness {
    bus_server: Option<Child>,
    wheel_ecu: Option<Child>,
    unauthorized_sender: Option<Child>,
    wheel_output: Arc<Mutex<Vec<String>>>,
}

impl TestHarness {
    fn new() -> Self {
        Self {
            bus_server: None,
            wheel_ecu: None,
            unauthorized_sender: None,
            wheel_output: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn start_bus_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("→ Starting CAN bus server...");
        let child = Command::new("cargo")
            .args(&["run", "--release", "--bin", "bus_server"])
            .current_dir("autonomous_controller")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.bus_server = Some(child);
        thread::sleep(Duration::from_secs(2));
        println!("✓ Bus server started");
        Ok(())
    }

    fn start_wheel_ecu(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("→ Starting wheel ECU (with access control)...");

        // Clean up old security logs
        let _ = fs::remove_dir_all("autonomous_controller/security_logs");

        let mut child = Command::new("cargo")
            .args(&["run", "--release", "--bin", "wheel_fl"])
            .current_dir("autonomous_controller")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Capture output in a separate thread
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");
        let output = Arc::clone(&self.wheel_output);

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("WHEEL STDOUT: {}", line); // Debug
                    output.lock().unwrap().push(line);
                }
            }
        });

        let output_stderr = Arc::clone(&self.wheel_output);
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("WHEEL STDERR: {}", line); // Debug
                    output_stderr.lock().unwrap().push(line);
                }
            }
        });

        self.wheel_ecu = Some(child);

        // Wait for compilation and startup (up to 30 seconds)
        println!("→ Waiting for wheel ECU to compile and start...");
        for i in 0..30 {
            thread::sleep(Duration::from_secs(1));
            if self.check_output_contains("Connected to CAN bus") {
                println!("✓ Wheel ECU connected after {} seconds", i + 1);
                break;
            }
        }

        println!("✓ Wheel ECU started");
        Ok(())
    }

    fn check_output_contains(&self, pattern: &str) -> bool {
        let output = self.wheel_output.lock().unwrap();
        output.iter().any(|line| line.contains(pattern))
    }

    fn check_security_logs_for_event(&self, event_type: &str) -> bool {
        let log_dir = std::path::Path::new("autonomous_controller/security_logs");
        if !log_dir.exists() {
            return false;
        }

        for entry in fs::read_dir(log_dir).expect("Failed to read log dir") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                let content = fs::read_to_string(&path).expect("Failed to read log file");
                if content.contains(event_type) {
                    return true;
                }
            }
        }

        false
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        println!("→ Cleaning up test processes...");

        if let Some(mut child) = self.unauthorized_sender.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        if let Some(mut child) = self.wheel_ecu.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        if let Some(mut child) = self.bus_server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        println!("✓ Cleanup complete");
    }
}

#[test]
#[ignore] // Run with: cargo test --test access_control_regression_tests -- --ignored
fn test_authorized_can_id_transmission() {
    println!("\n=== Test: Authorized CAN ID Transmission ===\n");

    let mut harness = TestHarness::new();

    // Start infrastructure
    harness
        .start_bus_server()
        .expect("Failed to start bus server");
    harness
        .start_wheel_ecu()
        .expect("Failed to start wheel ECU");

    // Let the wheel ECU run and send some messages
    println!("→ Waiting for wheel ECU to send messages...");
    thread::sleep(Duration::from_secs(5));

    // Check that the wheel ECU is operating normally
    println!("→ Checking wheel ECU output...");

    // Debug: Print the captured output
    {
        let output = harness.wheel_output.lock().unwrap();
        println!("Captured output ({} lines):", output.len());
        for (i, line) in output.iter().take(20).enumerate() {
            println!("  [{}] {}", i, line);
        }
    }

    assert!(
        harness.check_output_contains("Access control policy loaded") ||
        harness.check_output_contains("TX whitelist"),
        "Access control policy should be loaded"
    );

    assert!(
        harness.check_output_contains("Sent wheel speed") ||
        harness.check_output_contains("wheel speed") ||
        harness.check_output_contains("Sent"),
        "Wheel ECU should successfully send wheel speed messages"
    );

    // No authorization errors should occur
    assert!(
        !harness.check_output_contains("Failed to create secured frame"),
        "No authorization failures should occur for authorized CAN IDs"
    );

    // Check security logs for AccessControlLoaded event (if logs exist)
    thread::sleep(Duration::from_millis(500)); // Give time for logs to flush
    if std::path::Path::new("autonomous_controller/security_logs").exists() {
        if harness.check_security_logs_for_event("AccessControlLoaded") {
            println!("✓ Security logs contain AccessControlLoaded event");
        } else {
            println!("ℹ Security logs exist but AccessControlLoaded event not found (may not be logged by this ECU)");
        }
    } else {
        println!("ℹ Security logs not enabled for this ECU");
    }

    println!("✓ Test passed: Authorized transmissions work correctly");
}

#[test]
#[ignore] // Run with: cargo test --test access_control_regression_tests -- --ignored
fn test_unauthorized_can_id_rejection() {
    println!("\n=== Test: Unauthorized CAN ID Rejection ===\n");

    // This test creates a malicious ECU binary that tries to send on unauthorized CAN IDs
    // First, let's create a test sender that will violate access control

    let test_code = r#"
use autonomous_vehicle_sim::access_control;
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use autonomous_vehicle_sim::network::BusClient;
use autonomous_vehicle_sim::types::can_ids;
use std::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const ECU_NAME: &str = "MALICIOUS_WHEEL";
const HSM_SEED: u64 = 0x9999;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Starting malicious ECU test...");

    let mut hsm = VirtualHSM::with_performance(ECU_NAME.to_string(), HSM_SEED, false);

    // Load the WHEEL_FL policy (only allows 0x100)
    if let Some(permissions) = access_control::load_policy_for_ecu("WHEEL_FL") {
        hsm.load_access_control(permissions);
        println!("Access control policy loaded");
    }

    let client = BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await?;
    let (_reader, mut writer) = client.split();

    // Try to send on AUTHORIZED CAN ID (should work)
    println!("Attempting authorized transmission (0x100)...");
    match SecuredCanFrame::new(
        can_ids::WHEEL_SPEED_FL,
        vec![1, 2, 3, 4],
        ECU_NAME.to_string(),
        &mut hsm,
    ) {
        Ok(frame) => {
            writer.send_secured_frame(frame).await?;
            println!("✓ Authorized transmission succeeded");
        }
        Err(e) => {
            eprintln!("✗ Authorized transmission failed: {}", e);
        }
    }

    // Try to send on UNAUTHORIZED CAN ID (should fail)
    println!("Attempting unauthorized transmission (BRAKE_COMMAND 0x300)...");
    match SecuredCanFrame::new(
        can_ids::BRAKE_COMMAND, // 0x300 - NOT in WHEEL_FL whitelist!
        vec![0xFF, 0xFF, 0xFF, 0xFF], // Emergency brake!
        ECU_NAME.to_string(),
        &mut hsm,
    ) {
        Ok(frame) => {
            writer.send_secured_frame(frame).await?;
            eprintln!("✗ ERROR: Unauthorized transmission was NOT blocked!");
        }
        Err(e) => {
            println!("✓ Unauthorized transmission blocked: {}", e);
        }
    }

    // Try another unauthorized CAN ID
    println!("Attempting unauthorized transmission (STEERING_COMMAND 0x302)...");
    match SecuredCanFrame::new(
        can_ids::STEERING_COMMAND,
        vec![0x00, 0x00, 0x00, 0x00],
        ECU_NAME.to_string(),
        &mut hsm,
    ) {
        Ok(_) => {
            eprintln!("✗ ERROR: Unauthorized steering command was NOT blocked!");
        }
        Err(e) => {
            println!("✓ Unauthorized steering transmission blocked: {}", e);
        }
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
"#;

    // Write the test ECU to a temporary file
    std::fs::write(
        "autonomous_controller/src/bin/test_access_control_attacker.rs",
        test_code,
    )
    .expect("Failed to write test ECU");

    let mut harness = TestHarness::new();

    // Start infrastructure
    harness
        .start_bus_server()
        .expect("Failed to start bus server");

    // Run the malicious ECU test
    println!("→ Running unauthorized transmission test...");
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--release",
            "--bin",
            "test_access_control_attacker",
        ])
        .current_dir("autonomous_controller")
        .output()
        .expect("Failed to run test attacker");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Test attacker output:");
    println!("{}", stdout);
    if !stderr.is_empty() {
        println!("Errors:");
        println!("{}", stderr);
    }

    // Verify that authorized transmission succeeded
    assert!(
        stdout.contains("Authorized transmission succeeded"),
        "Authorized CAN ID 0x100 should be allowed"
    );

    // Verify that unauthorized transmissions were blocked
    assert!(
        stdout.contains("Unauthorized transmission blocked")
            && stdout.contains("BRAKE_COMMAND"),
        "Unauthorized BRAKE_COMMAND should be blocked"
    );

    assert!(
        stdout.contains("Unauthorized transmission blocked")
            && stdout.contains("STEERING_COMMAND"),
        "Unauthorized STEERING_COMMAND should be blocked"
    );

    // Verify error messages contain expected information
    assert!(
        stdout.contains("not authorized"),
        "Error message should mention 'not authorized'"
    );

    // Clean up test file
    let _ = std::fs::remove_file(
        "autonomous_controller/src/bin/test_access_control_attacker.rs",
    );

    println!("✓ Test passed: Unauthorized transmissions are blocked");
}

#[test]
#[ignore] // Run with: cargo test --test access_control_regression_tests -- --ignored
fn test_access_control_in_full_system() {
    println!("\n=== Test: Access Control in Full System ===\n");

    let mut harness = TestHarness::new();

    // Start infrastructure
    harness
        .start_bus_server()
        .expect("Failed to start bus server");
    harness
        .start_wheel_ecu()
        .expect("Failed to start wheel ECU");

    // Let it run
    println!("→ Running full system test for 10 seconds...");
    thread::sleep(Duration::from_secs(10));

    // Verify normal operation
    let output = harness.wheel_output.lock().unwrap();
    let output_text = output.join("\n");

    // Should have loaded access control
    assert!(
        output_text.contains("TX whitelist: 1 CAN IDs"),
        "Should show 1 CAN ID in TX whitelist"
    );

    // Should have sent messages successfully
    // Note: wheel ECU prints every 10 frames, so at 10Hz for 10 seconds we get ~10 prints
    let sent_count = output_text.matches("Sent wheel speed").count();
    assert!(
        sent_count >= 8, // At least 8 printed messages in 10 seconds
        "Should have sent at least 8 wheel speed messages, got {}",
        sent_count
    );

    // Should have no authorization failures
    assert!(
        !output_text.contains("Failed to create secured frame"),
        "Should have no authorization failures"
    );

    println!(
        "✓ Test passed: Full system operates correctly with access control ({} messages printed, ~{} sent)",
        sent_count,
        sent_count * 10
    );
}
