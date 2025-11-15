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

#[test]
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_crc_error_threshold_boundary() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: CRC Error Threshold Boundaries");
    println!("  Testing exact CRC_ERROR_THRESHOLD = 5");
    println!("═══════════════════════════════════════════════════════\n");

    use autonomous_vehicle_sim::error_handling::{AttackDetector, DetectorState};
    use autonomous_vehicle_sim::hsm::VerifyError;

    let mut detector = AttackDetector::new();

    // Test 1: 4 consecutive CRC errors (below threshold) -> Warning
    println!("→ Testing 4 CRC errors (below threshold)...");
    for i in 1..=4 {
        detector.on_verification_error(&VerifyError::CrcMismatch);
        println!("  CRC error {}/5", i);
    }
    assert_eq!(
        detector.state(),
        DetectorState::Warning,
        "4 CRC errors should trigger Warning state"
    );
    println!("✓ PASS: 4 CRC errors = Warning state");

    // Test 2: 5th consecutive CRC error (at threshold) -> UnderAttack
    println!("\n→ Testing 5th CRC error (at threshold)...");
    detector.on_verification_error(&VerifyError::CrcMismatch);
    assert_eq!(
        detector.state(),
        DetectorState::UnderAttack,
        "5 CRC errors (at threshold) should trigger UnderAttack"
    );
    println!("✓ PASS: 5 CRC errors = UnderAttack state");

    // Test 3: Reset and verify 6 errors also trigger
    println!("\n→ Testing 6 CRC errors (above threshold)...");
    detector.reset();
    for i in 1..=6 {
        detector.on_verification_error(&VerifyError::CrcMismatch);
    }
    assert_eq!(
        detector.state(),
        DetectorState::UnderAttack,
        "6 CRC errors should trigger UnderAttack"
    );
    println!("✓ PASS: 6 CRC errors = UnderAttack state");

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: CRC threshold boundaries work correctly");
    println!("═══════════════════════════════════════════════════════\n");
}

#[test]
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_mac_error_threshold_boundary() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: MAC Error Threshold Boundaries");
    println!("  Testing exact MAC_ERROR_THRESHOLD = 3");
    println!("═══════════════════════════════════════════════════════\n");

    use autonomous_vehicle_sim::error_handling::{AttackDetector, DetectorState};
    use autonomous_vehicle_sim::hsm::{MacFailureReason, VerifyError};

    let mut detector = AttackDetector::new();

    // Test 1: 1 MAC error (at warning threshold) -> Warning
    println!("→ Testing 1 MAC error (at warning threshold)...");
    detector.on_verification_error(&VerifyError::MacMismatch(MacFailureReason::CryptoFailure));
    assert_eq!(
        detector.state(),
        DetectorState::Warning,
        "1 MAC error should trigger Warning state (threshold/2 = 1)"
    );
    println!("✓ PASS: 1 MAC error = Warning state");

    // Test 2: 2 consecutive MAC errors (below attack threshold) -> Still Warning
    println!("\n→ Testing 2 MAC errors (below attack threshold)...");
    detector.on_verification_error(&VerifyError::MacMismatch(MacFailureReason::CryptoFailure));
    assert_eq!(
        detector.state(),
        DetectorState::Warning,
        "2 MAC errors should still be Warning"
    );
    println!("✓ PASS: 2 MAC errors = Warning state");

    // Test 3: 3rd consecutive MAC error (at threshold) -> UnderAttack
    println!("\n→ Testing 3rd MAC error (at threshold)...");
    detector.on_verification_error(&VerifyError::MacMismatch(MacFailureReason::CryptoFailure));
    assert_eq!(
        detector.state(),
        DetectorState::UnderAttack,
        "3 MAC errors (at threshold) should trigger UnderAttack"
    );
    println!("✓ PASS: 3 MAC errors = UnderAttack state");

    // Test 4: Reset and verify 4 errors also trigger
    println!("\n→ Testing 4 MAC errors (above threshold)...");
    detector.reset();
    for i in 1..=4 {
        detector.on_verification_error(&VerifyError::MacMismatch(MacFailureReason::CryptoFailure));
    }
    assert_eq!(
        detector.state(),
        DetectorState::UnderAttack,
        "4 MAC errors should trigger UnderAttack"
    );
    println!("✓ PASS: 4 MAC errors = UnderAttack state");

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: MAC threshold boundaries work correctly");
    println!("═══════════════════════════════════════════════════════\n");
}

#[test]
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_unsecured_frame_immediate_trigger() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: Unsecured Frame Immediate Trigger");
    println!("  Testing UNSECURED_FRAME_THRESHOLD = 1");
    println!("═══════════════════════════════════════════════════════\n");

    use autonomous_vehicle_sim::error_handling::{AttackDetector, DetectorState};
    use autonomous_vehicle_sim::hsm::VerifyError;

    let mut detector = AttackDetector::new();

    // Test: Single unsecured frame should immediately trigger UnderAttack
    println!("→ Testing single unsecured frame...");
    detector.on_verification_error(&VerifyError::UnsecuredFrame);

    assert_eq!(
        detector.state(),
        DetectorState::UnderAttack,
        "Single unsecured frame should immediately trigger UnderAttack (threshold=1)"
    );
    println!("✓ PASS: Unsecured frame immediately triggered UnderAttack");

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: Unsecured frame triggers immediately");
    println!("═══════════════════════════════════════════════════════\n");
}

#[test]
#[ignore] // Run with: cargo test --test attack_regression_tests -- --ignored --test-threads=1
fn test_warning_state_threshold_boundaries() {
    println!("\n═══════════════════════════════════════════════════════");
    println!("  Regression Test: Warning State Threshold Boundaries");
    println!("  Warning threshold = attack_threshold / 2");
    println!("═══════════════════════════════════════════════════════\n");

    use autonomous_vehicle_sim::error_handling::{AttackDetector, DetectorState};
    use autonomous_vehicle_sim::hsm::VerifyError;

    // Test 1: CRC warning threshold (5/2 = 2)
    println!("→ Testing CRC warning threshold (2 errors)...");
    let mut detector = AttackDetector::new();

    // 1 error: should stay Normal
    detector.on_verification_error(&VerifyError::CrcMismatch);
    assert_eq!(
        detector.state(),
        DetectorState::Normal,
        "1 CRC error should keep Normal state"
    );
    println!("  1 CRC error = Normal");

    // 2 errors: should trigger Warning
    detector.on_verification_error(&VerifyError::CrcMismatch);
    assert_eq!(
        detector.state(),
        DetectorState::Warning,
        "2 CRC errors should trigger Warning (threshold/2)"
    );
    println!("✓ PASS: 2 CRC errors = Warning state");

    // Test 2: MAC warning threshold (3/2 = 1)
    println!("\n→ Testing MAC warning threshold (1 error)...");
    detector.reset();

    use autonomous_vehicle_sim::hsm::MacFailureReason;
    detector.on_verification_error(&VerifyError::MacMismatch(MacFailureReason::CryptoFailure));
    assert_eq!(
        detector.state(),
        DetectorState::Warning,
        "1 MAC error should trigger Warning (threshold/2 rounded = 1)"
    );
    println!("✓ PASS: 1 MAC error = Warning state");

    println!("\n═══════════════════════════════════════════════════════");
    println!("  ✓ Test PASSED: Warning thresholds work correctly");
    println!("═══════════════════════════════════════════════════════\n");
}
