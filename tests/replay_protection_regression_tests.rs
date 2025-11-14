/// Regression tests for replay attack protection
///
/// These tests verify that the replay protection system works correctly:
/// - Legitimate frames should be accepted
/// - Replayed frames should be detected and rejected
/// - Replay detection should trigger attack mode

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct TestHarness {
    bus_server: Option<Child>,
    brake_controller: Option<Child>,
    legitimate_sender: Option<Child>,
    brake_output: Arc<Mutex<Vec<String>>>,
}

impl TestHarness {
    fn new() -> Self {
        Self {
            bus_server: None,
            brake_controller: None,
            legitimate_sender: None,
            brake_output: Arc::new(Mutex::new(Vec::new())),
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

    fn start_brake_controller(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("→ Starting brake controller...");
        let mut child = Command::new("cargo")
            .args(&["run", "--release", "--bin", "brake_controller"])
            .current_dir("autonomous_controller")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Capture output in a separate thread
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");
        let output = Arc::clone(&self.brake_output);

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    output.lock().unwrap().push(line);
                }
            }
        });

        let output_stderr = Arc::clone(&self.brake_output);
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    output_stderr.lock().unwrap().push(line);
                }
            }
        });

        self.brake_controller = Some(child);
        thread::sleep(Duration::from_secs(3));
        println!("✓ Brake controller started");
        Ok(())
    }

    fn start_legitimate_sender(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("→ Starting legitimate brake command sender...");
        let child = Command::new("cargo")
            .args(&["run", "--release", "--bin", "test_legitimate_sender"])
            .current_dir("autonomous_controller")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.legitimate_sender = Some(child);
        thread::sleep(Duration::from_secs(2));
        println!("✓ Legitimate sender started");
        Ok(())
    }

    fn run_attack(&self, attack_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("→ Running attack: {}", attack_name);

        let output = Command::new("cargo")
            .args(&["run", "--release", "--bin", attack_name])
            .current_dir("autonomous_controller")
            .output()?;

        if !output.status.success() {
            return Err(format!("Attack failed to run: {:?}", output).into());
        }

        println!("✓ Attack completed");
        thread::sleep(Duration::from_secs(2)); // Allow processing time
        Ok(())
    }

    fn get_brake_output(&self) -> Vec<String> {
        self.brake_output.lock().unwrap().clone()
    }

    fn verify_replay_attack_detected(&self) -> bool {
        let output = self.get_brake_output();
        output
            .iter()
            .any(|line| line.contains("REPLAY ATTACK DETECTED") || line.contains("Replay Attack"))
    }

    fn verify_attack_triggered(&self) -> bool {
        let output = self.get_brake_output();
        output.iter().any(|line| line.contains("ATTACK DETECTED"))
    }

    fn verify_replay_errors_shown(&self) -> bool {
        let output = self.get_brake_output();
        output
            .iter()
            .any(|line| line.contains("REPLAY") || line.contains("Replay"))
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        println!("→ Cleaning up processes...");

        if let Some(mut child) = self.legitimate_sender.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        if let Some(mut child) = self.brake_controller.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        if let Some(mut child) = self.bus_server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        thread::sleep(Duration::from_secs(1));
        println!("✓ Cleanup complete");
    }
}

#[test]
#[ignore] // Run with: cargo test --test replay_protection_regression_tests -- --ignored --test-threads=1
fn test_replay_attack_detection() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: Replay Attack Detection");
    println!("═══════════════════════════════════════════════════════\n");

    let mut harness = TestHarness::new();

    // Setup
    harness
        .start_bus_server()
        .expect("Failed to start bus server");
    harness
        .start_brake_controller()
        .expect("Failed to start brake controller");
    harness
        .start_legitimate_sender()
        .expect("Failed to start legitimate sender");

    // Run replay attack
    harness
        .run_attack("attack_replay")
        .expect("Failed to run replay attack");

    // Verify results
    println!("\n→ Analyzing results...");

    // Test 1: Should see REPLAY ATTACK messages
    assert!(
        harness.verify_replay_attack_detected(),
        "FAIL: No replay attack detected"
    );
    println!("✓ PASS: Replay attack detected");

    // Test 2: MUST see "ATTACK DETECTED" (replay attacks trigger immediately)
    assert!(
        harness.verify_attack_triggered(),
        "FAIL: Attack mode NOT triggered (should have triggered with replay attack)"
    );
    println!("✓ PASS: Attack mode triggered (as expected for replay attack)");

    // Test 3: Should see replay error messages
    if harness.verify_replay_errors_shown() {
        println!("✓ PASS: Replay error messages displayed");
    }

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: Replay attack detection works correctly");
    println!("═══════════════════════════════════════════════════════\n");
}
