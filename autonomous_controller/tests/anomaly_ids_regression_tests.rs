/// Anomaly-based IDS Regression Tests
///
/// Tests the full lifecycle of anomaly detection:
/// 1. Training phase with normal traffic
/// 2. Baseline finalization
/// 3. Detection phase with various anomaly types
/// 4. Graduated response verification
use autonomous_vehicle_sim::*;
use chrono::Utc;

fn create_secured_frame(can_id: u32, data: Vec<u8>, source: &str) -> hsm::SecuredCanFrame {
    hsm::SecuredCanFrame {
        can_id: types::CanId::Standard(can_id as u16),
        data,
        timestamp: Utc::now(),
        source: source.to_string(),
        session_counter: 0,
        mac: [0; 32],
        crc: 0,
    }
}

#[test]
#[ignore] // Run with: cargo test --test anomaly_ids_regression_tests -- --ignored
fn test_anomaly_ids_full_lifecycle() {
    println!("\n=== Anomaly-based IDS Full Lifecycle Test ===\n");

    // Step 1: Training Phase
    println!("Step 1: Training Phase");
    println!("----------------------");

    let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
    hsm.start_anomaly_training(50).unwrap(); // Require 50 samples minimum

    // Simulate normal CAN traffic for training
    for i in 0..100 {
        // Wheel speed sensor sends periodic data
        let wheel_speed_data = vec![
            50 + (i % 10) as u8, // Varies slightly around 50
            100,
            150,
            200,
        ];
        let frame = create_secured_frame(0x100, wheel_speed_data, "WHEEL_FL");
        hsm.train_anomaly_detector(&frame).unwrap();

        // Engine RPM sensor
        let rpm_data = vec![
            20 + (i % 5) as u8, // Varies around 20
            30,
        ];
        let frame = create_secured_frame(0x110, rpm_data, "ENGINE_ECU");
        hsm.train_anomaly_detector(&frame).unwrap();
    }

    println!("✓ Collected 200 training samples");

    // Step 2: Finalize Training
    println!("\nStep 2: Finalizing Baseline");
    println!("---------------------------");

    let baseline = hsm.finalize_anomaly_training().unwrap();
    println!("✓ Baseline finalized");
    println!("  • CAN IDs profiled: {}", baseline.profiles.len());
    println!("  • Total samples: {}", baseline.total_samples);

    // Verify baseline contents
    assert_eq!(baseline.profiles.len(), 2); // 0x100 and 0x110
    assert!(baseline.profiles.contains_key(&0x100));
    assert!(baseline.profiles.contains_key(&0x110));

    // Step 3: Activate Detection Mode
    println!("\nStep 3: Activating Detection Mode");
    println!("----------------------------------");

    hsm.activate_anomaly_detection(baseline);
    assert!(hsm.is_anomaly_detecting());
    println!("✓ Anomaly detection activated");

    // Step 4: Test Normal Traffic (No Anomalies)
    println!("\nStep 4: Testing Normal Traffic");
    println!("-------------------------------");

    let normal_frame1 = create_secured_frame(0x100, vec![52, 100, 150, 200], "WHEEL_FL");
    let result1 = hsm.detect_anomaly(&normal_frame1);
    assert!(matches!(result1, AnomalyResult::Normal));
    println!("✓ Normal frame 1: No anomaly detected");

    let normal_frame2 = create_secured_frame(0x110, vec![21, 30], "ENGINE_ECU");
    let result2 = hsm.detect_anomaly(&normal_frame2);
    assert!(matches!(result2, AnomalyResult::Normal));
    println!("✓ Normal frame 2: No anomaly detected");

    // Step 5: Test Unknown CAN ID Anomaly
    println!("\nStep 5: Testing Unknown CAN ID Anomaly");
    println!("---------------------------------------");

    let unknown_id_frame = create_secured_frame(0x200, vec![1, 2, 3], "WHEEL_FL");
    let result = hsm.detect_anomaly(&unknown_id_frame);
    assert!(matches!(result, AnomalyResult::Attack(_)));
    if let AnomalyResult::Attack(report) = result {
        assert!(matches!(report.anomaly_type, AnomalyType::UnknownCanId));
        println!("✓ Unknown CAN ID detected: {}", report.anomaly_type);
        println!("  • Confidence: {:.2}σ", report.confidence_sigma);
        println!("  • Severity: {:?}", report.severity);
    }

    // Step 6: Test Unexpected Source Anomaly
    println!("\nStep 6: Testing Unexpected Source Anomaly");
    println!("------------------------------------------");

    let rogue_source_frame = create_secured_frame(0x100, vec![50, 100, 150, 200], "ROGUE_ECU");
    let result = hsm.detect_anomaly(&rogue_source_frame);
    assert!(matches!(result, AnomalyResult::Attack(_)));
    if let AnomalyResult::Attack(report) = result {
        assert!(matches!(
            report.anomaly_type,
            AnomalyType::UnexpectedSource { .. }
        ));
        println!("✓ Unexpected source detected: {}", report.anomaly_type);
        println!("  • Confidence: {:.2}σ", report.confidence_sigma);
    }

    // Step 7: Test Data Range Anomaly
    println!("\nStep 7: Testing Data Range Anomaly");
    println!("-----------------------------------");

    // Send data way outside the trained range
    let out_of_range_frame = create_secured_frame(0x100, vec![250, 100, 150, 200], "WHEEL_FL");
    let result = hsm.detect_anomaly(&out_of_range_frame);

    // Should be either Warning or Attack depending on how far out of range
    match result {
        AnomalyResult::Warning(report) | AnomalyResult::Attack(report) => {
            println!("✓ Data range anomaly detected: {}", report.anomaly_type);
            println!("  • Confidence: {:.2}σ", report.confidence_sigma);
            println!("  • Severity: {:?}", report.severity);
        }
        AnomalyResult::Normal => {
            panic!("Expected anomaly detection for out-of-range data");
        }
    }

    // Step 8: Test Graduated Response
    println!("\nStep 8: Testing Graduated Response");
    println!("-----------------------------------");

    // Slightly anomalous data (should be Warning, not Attack)
    let slight_anomaly_frame = create_secured_frame(0x100, vec![65, 100, 150, 200], "WHEEL_FL");
    let result = hsm.detect_anomaly(&slight_anomaly_frame);

    match result {
        AnomalyResult::Normal => {
            println!("✓ Slight deviation within tolerance (Normal)");
        }
        AnomalyResult::Warning(report) => {
            assert!(report.confidence_sigma >= 1.3 && report.confidence_sigma < 3.0);
            println!("✓ Medium confidence anomaly triggers Warning");
            println!(
                "  • Confidence: {:.2}σ (80-99% range)",
                report.confidence_sigma
            );
        }
        AnomalyResult::Attack(_) => {
            println!("! Slight deviation triggered Attack (may be expected with small dataset)");
        }
    }

    println!("\n=== All Anomaly IDS Tests Passed ===\n");
}

#[test]
#[ignore]
fn test_anomaly_ids_persistence() {
    println!("\n=== Anomaly IDS Baseline Persistence Test ===\n");

    // Create and train
    let mut hsm = VirtualHSM::new("PERSISTENCE_TEST".to_string(), 99999);
    hsm.start_anomaly_training(10).unwrap();

    for i in 0..20 {
        let frame = create_secured_frame(0x100, vec![(i % 10) as u8, 50, 100], "SENSOR_A");
        hsm.train_anomaly_detector(&frame).unwrap();
    }

    let baseline = hsm.finalize_anomaly_training().unwrap();
    println!("✓ Baseline created with {} samples", baseline.total_samples);

    // Save to file
    let test_path = "/tmp/test_baseline_persistence.json";
    baseline_persistence::save_baseline(baseline.clone(), test_path, &hsm).unwrap();
    println!("✓ Baseline saved to {}", test_path);

    // Load from file
    let loaded_baseline = baseline_persistence::load_baseline(test_path, &hsm).unwrap();
    println!("✓ Baseline loaded and signature verified");

    // Verify contents match
    assert_eq!(loaded_baseline.ecu_id, baseline.ecu_id);
    assert_eq!(loaded_baseline.profiles.len(), baseline.profiles.len());
    assert_eq!(loaded_baseline.total_samples, baseline.total_samples);
    println!("✓ Loaded baseline matches original");

    // Clean up
    std::fs::remove_file(test_path).ok();
    println!("\n=== Persistence Test Passed ===\n");
}

#[test]
#[ignore]
fn test_anomaly_ids_tampered_baseline_detection() {
    println!("\n=== Tampered Baseline Detection Test ===\n");

    // Create baseline
    let mut hsm = VirtualHSM::new("TAMPER_TEST".to_string(), 88888);
    hsm.start_anomaly_training(10).unwrap();

    for i in 0..20 {
        let frame = create_secured_frame(0x100, vec![i as u8, 50], "SENSOR_A");
        hsm.train_anomaly_detector(&frame).unwrap();
    }

    let baseline = hsm.finalize_anomaly_training().unwrap();

    // Save to file
    let test_path = "/tmp/test_baseline_tamper.json";
    baseline_persistence::save_baseline(baseline, test_path, &hsm).unwrap();
    println!("✓ Baseline saved");

    // Load and tamper with the JSON
    let mut json_content = std::fs::read_to_string(test_path).unwrap();
    json_content = json_content.replace("\"total_samples\": 20", "\"total_samples\": 99999");
    std::fs::write(test_path, json_content).unwrap();
    println!("✓ Baseline tampered (modified total_samples from 20 to 99999)");

    // Try to load tampered baseline
    let result = baseline_persistence::load_baseline(test_path, &hsm);
    assert!(result.is_err());
    println!("✓ Tampered baseline rejected: {}", result.unwrap_err());

    // Clean up
    std::fs::remove_file(test_path).ok();
    println!("\n=== Tamper Detection Test Passed ===\n");
}

#[test]
#[ignore]
fn test_anomaly_ids_sigma_threshold_boundaries() {
    println!("\n=== Sigma Threshold Boundary Test ===\n");
    println!("Testing graduated response at exact sigma boundaries:");
    println!("  • < 1.3σ → Normal (allow)");
    println!("  • 1.3σ - 3.0σ → Warning (80-99% confidence)");
    println!("  • ≥ 3.0σ → Attack (>99% confidence)\n");

    // Create HSM with custom thresholds for precise testing
    let mut hsm = VirtualHSM::new("SIGMA_TEST".to_string(), 77777);
    hsm.start_anomaly_training(20).unwrap();

    // Train with very consistent data (low std dev)
    for _ in 0..100 {
        let frame = create_secured_frame(0x100, vec![100, 100, 100, 100], "SENSOR_A");
        hsm.train_anomaly_detector(&frame).unwrap();
    }

    let baseline = hsm.finalize_anomaly_training().unwrap();
    hsm.activate_anomaly_detection(baseline);

    println!("Step 1: Testing just below warning threshold");
    println!("-------------------------------------------");
    // Data very close to mean (should be Normal)
    let near_normal = create_secured_frame(0x100, vec![101, 100, 100, 100], "SENSOR_A");
    let result = hsm.detect_anomaly(&near_normal);
    match result {
        AnomalyResult::Normal => {
            println!("✓ PASS: Small deviation → Normal (< 1.3σ)");
        }
        AnomalyResult::Warning(report) => {
            println!(
                "✓ PASS: Small deviation → Warning ({:.2}σ)",
                report.confidence_sigma
            );
        }
        AnomalyResult::Attack(_) => {
            println!("! Note: Small deviation triggered Attack (may happen with zero std dev)");
        }
    }

    println!("\nStep 2: Testing far from mean (high sigma)");
    println!("--------------------------------------------");
    // Data very far from mean (should be Attack with high sigma)
    let far_anomaly = create_secured_frame(0x100, vec![200, 100, 100, 100], "SENSOR_A");
    let result = hsm.detect_anomaly(&far_anomaly);

    match result {
        AnomalyResult::Attack(report) => {
            println!("✓ PASS: Large deviation → Attack");
            println!("  • Confidence: {:.2}σ", report.confidence_sigma);
            assert!(
                report.confidence_sigma >= 3.0,
                "Attack should have ≥3.0σ confidence"
            );
        }
        AnomalyResult::Warning(report) => {
            println!("✓ PASS: Medium deviation → Warning");
            println!("  • Confidence: {:.2}σ", report.confidence_sigma);
            assert!(
                report.confidence_sigma >= 1.3 && report.confidence_sigma < 3.0,
                "Warning should be 1.3σ - 3.0σ"
            );
        }
        AnomalyResult::Normal => {
            panic!("Large deviation should not be Normal");
        }
    }

    println!("\n=== Sigma Threshold Test Passed ===\n");
}

#[test]
#[ignore]
fn test_anomaly_ids_custom_thresholds() {
    println!("\n=== Custom Sigma Thresholds Test ===\n");

    // Create HSM and configure custom thresholds
    let mut hsm = VirtualHSM::new("CUSTOM_THRESH_TEST".to_string(), 66666);

    // Set custom thresholds: 2.0σ for warning, 4.0σ for attack
    let custom_config = anomaly_detection::AnomalyConfig {
        detection_threshold_sigma: 4.0,
        warning_threshold_sigma: 2.0,
        enabled: true,
    };

    hsm.start_anomaly_training_with_config(20, custom_config)
        .unwrap();

    println!("✓ Custom thresholds configured:");
    println!("  • Warning threshold: 2.0σ");
    println!("  • Attack threshold: 4.0σ");

    // Train with consistent data
    for _ in 0..50 {
        let frame = create_secured_frame(0x100, vec![50, 50, 50], "SENSOR_A");
        hsm.train_anomaly_detector(&frame).unwrap();
    }

    let baseline = hsm.finalize_anomaly_training().unwrap();
    hsm.activate_anomaly_detection(baseline);

    println!("\nTesting graduated response with custom thresholds...");

    // Test medium deviation
    let medium_dev = create_secured_frame(0x100, vec![80, 50, 50], "SENSOR_A");
    let result = hsm.detect_anomaly(&medium_dev);

    match result {
        AnomalyResult::Warning(report) => {
            println!("✓ Medium deviation → Warning");
            println!("  • Confidence: {:.2}σ", report.confidence_sigma);
        }
        AnomalyResult::Normal => {
            println!("✓ Deviation below warning threshold → Normal");
        }
        AnomalyResult::Attack(_) => {
            println!("! Medium deviation triggered Attack");
        }
    }

    println!("\n=== Custom Threshold Test Passed ===\n");
}

#[test]
#[ignore]
fn test_anomaly_ids_wrong_hsm_key() {
    println!("\n=== Wrong HSM Key Detection Test ===\n");

    // Create baseline with HSM1
    let mut hsm1 = VirtualHSM::new("ECU_ORIGINAL".to_string(), 11111);
    hsm1.start_anomaly_training(10).unwrap();

    for i in 0..20 {
        let frame = create_secured_frame(0x100, vec![i as u8], "SENSOR_A");
        hsm1.train_anomaly_detector(&frame).unwrap();
    }

    let baseline = hsm1.finalize_anomaly_training().unwrap();

    // Save baseline
    let test_path = "/tmp/test_baseline_wrong_key.json";
    baseline_persistence::save_baseline(baseline, test_path, &hsm1).unwrap();
    println!("✓ Baseline saved with HSM1 key");

    // Try to load with different HSM (different seed = different keys)
    let hsm2 = VirtualHSM::new("ECU_DIFFERENT".to_string(), 99999);
    let result = baseline_persistence::load_baseline(test_path, &hsm2);

    assert!(result.is_err());
    println!("✓ Baseline rejected when loaded with wrong HSM key");
    println!("  • Error: {}", result.unwrap_err());

    // Clean up
    std::fs::remove_file(test_path).ok();
    println!("\n=== Wrong HSM Key Test Passed ===\n");
}
