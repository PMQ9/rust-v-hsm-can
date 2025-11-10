/// Regression tests for injection attacks
///
/// These tests verify that the attack detection system works correctly:
/// - Short cycle attacks (2 frames/cycle) should NOT trigger detection
/// - Burst attacks (4 frames/cycle) SHOULD trigger detection
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

    fn verify_mac_errors_detected(&self) -> bool {
        let output = self.get_brake_output();
        output.iter().any(|line| line.contains("MAC MISMATCH"))
    }

    fn verify_attack_triggered(&self) -> bool {
        let output = self.get_brake_output();
        output.iter().any(|line| line.contains("ATTACK DETECTED"))
    }

    fn verify_warnings_shown(&self) -> bool {
        let output = self.get_brake_output();
        output.iter().any(|line| line.contains("WARNING"))
    }

    fn verify_recovery(&self) -> bool {
        let output = self.get_brake_output();
        output.iter().any(|line| line.contains("RECOVERED"))
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
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_short_cycle_injection_does_not_trigger_detection() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: Short Cycle Injection Attack");
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

    // Run attack
    harness
        .run_attack("attack_injection_short_cycles")
        .expect("Failed to run short cycle attack");

    // Verify results
    println!("\n→ Analyzing results...");

    // Test 1: Should see MAC MISMATCH messages
    assert!(
        harness.verify_mac_errors_detected(),
        "FAIL: No MAC errors detected"
    );
    println!("✓ PASS: MAC errors detected");

    // Test 2: Should NOT see "ATTACK DETECTED" (threshold not exceeded)
    assert!(
        !harness.verify_attack_triggered(),
        "FAIL: Attack mode triggered (should NOT happen for short cycles)"
    );
    println!("✓ PASS: Attack mode NOT triggered (as expected)");

    // Test 3: May see warnings or recovery
    if harness.verify_warnings_shown() {
        println!("✓ PASS: Warning messages displayed");
    }
    if harness.verify_recovery() {
        println!("✓ PASS: Recovery detected between attack cycles");
    }

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: Short cycle attack behaved as expected");
    println!("═══════════════════════════════════════════════════════\n");
}

#[test]
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_burst_injection_triggers_detection() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: Burst Injection Attack");
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

    // Run attack
    harness
        .run_attack("attack_injection_burst")
        .expect("Failed to run burst attack");

    // Verify results
    println!("\n→ Analyzing results...");

    // Test 1: Should see MAC MISMATCH messages
    assert!(
        harness.verify_mac_errors_detected(),
        "FAIL: No MAC errors detected"
    );
    println!("✓ PASS: MAC errors detected");

    // Test 2: MUST see "ATTACK DETECTED" (threshold exceeded)
    assert!(
        harness.verify_attack_triggered(),
        "FAIL: Attack mode NOT triggered (should have triggered with burst attack)"
    );
    println!("✓ PASS: Attack mode triggered (as expected for burst attack)");

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: Burst attack triggered detection");
    println!("═══════════════════════════════════════════════════════\n");
}
