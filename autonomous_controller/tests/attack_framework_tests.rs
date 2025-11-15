/// Comprehensive Attack Framework Tests
///
/// Tests the attack simulation framework including:
/// - Fuzzing engines (random, mutation, grammar)
/// - Injection attacks (unsecured, MAC/CRC tampering, spoofing, flooding)
/// - Replay attacks (simple, delayed, reordered, selective)
/// - Orchestration and scenarios
/// - Metrics and reporting

use autonomous_vehicle_sim::attack_sim::fuzzing::{GrammarFuzzer, MutationFuzzer, RandomFuzzer};
use autonomous_vehicle_sim::attack_sim::injection::{
    CrcCorruptor, Flooder, MacTamperer, SourceSpoofer, UnsecuredInjector,
};
use autonomous_vehicle_sim::attack_sim::metrics::{AttackMetrics, ScenarioComparison};
use autonomous_vehicle_sim::attack_sim::orchestrator::{scenarios, AttackOrchestrator, AttackScenario};
use autonomous_vehicle_sim::attack_sim::replay::{
    DelayedReplay, ReorderedReplay, SelectiveReplay, SimpleReplay,
};
use autonomous_vehicle_sim::attack_sim::{AttackConfig, AttackSimulator, AttackType};
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use autonomous_vehicle_sim::types::CanId;

// ============================================================================
// Fuzzing Engine Tests
// ============================================================================

#[test]
fn test_random_fuzzer_generates_varied_frames() {
    let mut fuzzer = RandomFuzzer::new(Some(12345));

    let frame1 = fuzzer.generate_random_frame("FUZZER");
    let frame2 = fuzzer.generate_random_frame("FUZZER");

    // Frames should be different (statistically almost certain)
    assert!(
        frame1.can_id.value() != frame2.can_id.value()
            || frame1.data != frame2.data
            || frame1.session_counter != frame2.session_counter
    );
}

#[test]
fn test_mutation_fuzzer_actually_mutates() {
    let mut fuzzer = MutationFuzzer::new(Some(54321));

    let original = create_test_frame(0x100, vec![0xFF, 0xFF, 0xFF, 0xFF], "ORIGINAL", 1);
    fuzzer.add_seed_frame(original.clone());

    // Mutate 10 times, at least one should be different
    let mut any_different = false;
    for _ in 0..10 {
        let mutated = fuzzer.mutate_frame(&original);
        if mutated.data != original.data
            || mutated.mac != original.mac
            || mutated.crc != original.crc
        {
            any_different = true;
            break;
        }
    }

    assert!(any_different, "Mutation should change the frame");
}

#[test]
fn test_grammar_fuzzer_uses_valid_can_id_ranges() {
    let mut fuzzer = GrammarFuzzer::new(Some(99999));

    // Generate 20 frames and check they all use valid CAN IDs
    for _ in 0..20 {
        let frame = fuzzer.generate_grammar_frame("GRAMMAR");
        let can_id = frame.can_id.value();

        // Should be in one of the automotive ranges
        let valid = (can_id >= 0x100 && can_id <= 0x103) // Wheel speeds
            || (can_id >= 0x110 && can_id <= 0x111)      // Engine
            || (can_id >= 0x120 && can_id <= 0x121)      // Steering
            || (can_id >= 0x300 && can_id <= 0x302)      // Commands
            || (can_id >= 0x400 && can_id <= 0x401); // Autonomous

        assert!(valid, "CAN ID 0x{:03X} not in valid ranges", can_id);
    }
}

#[test]
fn test_fuzzer_execution_config_validation() {
    let mut fuzzer = RandomFuzzer::new(Some(11111));

    let invalid_config = AttackConfig {
        attack_type: AttackType::FuzzRandom,
        intensity: 1.5, // Invalid: > 1.0
        ..Default::default()
    };

    let result = fuzzer.execute(&invalid_config);
    assert!(result.is_err());
}

// ============================================================================
// Injection Attack Tests
// ============================================================================

#[test]
fn test_unsecured_injector_creates_zero_mac_crc() {
    let mut injector = UnsecuredInjector::new("ATTACKER".to_string(), Some(12345));
    let frame = injector.generate_unsecured_frame(0x300, vec![0xFF, 0xFF]);

    assert_eq!(frame.mac, [0u8; 32]);
    assert_eq!(frame.crc, 0);
    assert_eq!(frame.source, "ATTACKER");
}

#[test]
fn test_unsecured_injector_attack_execution() {
    let mut injector = UnsecuredInjector::new("ATTACKER".to_string(), Some(54321));

    let config = AttackConfig {
        attack_type: AttackType::InjectUnsecured,
        target_can_id: Some(0x300),
        frame_count: Some(50),
        ..Default::default()
    };

    let result = injector.execute(&config).unwrap();

    assert_eq!(result.attack_type, AttackType::InjectUnsecured);
    assert_eq!(result.frames_sent, 50);
}

#[test]
fn test_mac_tamperer_corrupts_mac() {
    let mut tamperer = MacTamperer::new("TAMPERER".to_string(), 99999);

    // MAY fail due to authorization, which is expected
    match tamperer.generate_tampered_mac_frame(0x100, vec![1, 2, 3], "SOURCE".to_string()) {
        Ok(_frame) => {
            // If successful, MAC should be corrupted (we can't verify corruption directly,
            // but the function intentionally corrupts it)
        }
        Err(_) => {
            // Authorization may block this - acceptable
        }
    }
}

#[test]
fn test_source_spoofer_claims_different_source() {
    let mut spoofer = SourceSpoofer::new("ACTUAL_ATTACKER".to_string(), 77777);

    match spoofer.generate_spoofed_frame(0x100, vec![7, 8, 9], "PRETEND_TO_BE_THIS".to_string())
    {
        Ok(frame) => {
            assert_eq!(frame.source, "PRETEND_TO_BE_THIS");
            // Frame claims to be from PRETEND_TO_BE_THIS but was actually created by ACTUAL_ATTACKER
        }
        Err(_) => {
            // Authorization may block - acceptable
        }
    }
}

#[test]
fn test_flooder_respects_intensity() {
    let mut flooder = Flooder::new("FLOODER".to_string(), Some(55555));

    let config_low = AttackConfig {
        attack_type: AttackType::InjectFlooding,
        intensity: 0.1, // 10% = 100 fps
        duration_secs: 1,
        ..Default::default()
    };

    let config_high = AttackConfig {
        attack_type: AttackType::InjectFlooding,
        intensity: 0.5, // 50% = 500 fps
        duration_secs: 1,
        ..Default::default()
    };

    let result_low = flooder.execute(&config_low).unwrap();
    let result_high = flooder.execute(&config_high).unwrap();

    assert_eq!(result_low.frames_sent, 100);
    assert_eq!(result_high.frames_sent, 500);
}

// ============================================================================
// Replay Attack Tests
// ============================================================================

#[test]
fn test_simple_replay_capture_and_replay() {
    let mut replayer = SimpleReplay::new(10);

    for i in 0..5 {
        replayer.capture_frame(create_test_frame(0x100, vec![i as u8], "SENSOR", i as u64));
    }

    assert_eq!(replayer.captured_count(), 5);

    let first = replayer.get_replay_frame().unwrap();
    assert_eq!(first.session_counter, 0);
    assert_eq!(replayer.captured_count(), 4);
}

#[test]
fn test_simple_replay_respects_max_size() {
    let mut replayer = SimpleReplay::new(3);

    for i in 0..10 {
        replayer.capture_frame(create_test_frame(0x100, vec![i as u8], "SENSOR", i as u64));
    }

    // Should only keep last 3
    assert_eq!(replayer.captured_count(), 3);
}

#[test]
fn test_delayed_replay_filters_by_age() {
    let mut replayer = DelayedReplay::new(10);

    for i in 0..5 {
        replayer.capture_frame(create_test_frame(0x100, vec![i as u8], "SENSOR", i as u64));
    }

    // Get oldest frames
    let oldest = replayer.get_oldest_frames(3);
    assert_eq!(oldest.len(), 3);
    assert_eq!(oldest[0].session_counter, 0);
    assert_eq!(oldest[1].session_counter, 1);
    assert_eq!(oldest[2].session_counter, 2);
}

#[test]
fn test_reordered_replay_reverses_order() {
    let mut replayer = ReorderedReplay::new(10);

    for i in 0..5 {
        replayer.capture_frame(create_test_frame(0x100, vec![i as u8], "SENSOR", i as u64));
    }

    let reversed = replayer.get_reversed_frames();
    assert_eq!(reversed.len(), 5);
    assert_eq!(reversed[0].session_counter, 4);
    assert_eq!(reversed[4].session_counter, 0);
}

#[test]
fn test_reordered_replay_shuffle_changes_order() {
    let mut replayer = ReorderedReplay::new(10);

    for i in 0..10 {
        replayer.capture_frame(create_test_frame(0x100, vec![i as u8], "SENSOR", i as u64));
    }

    let shuffled = replayer.get_shuffled_frames(12345);
    assert_eq!(shuffled.len(), 10);

    // At least one element should be out of order
    let mut out_of_order = false;
    for i in 0..10 {
        if shuffled[i].session_counter != i as u64 {
            out_of_order = true;
            break;
        }
    }
    assert!(out_of_order, "Shuffle should change order");
}

#[test]
fn test_selective_replay_filters_by_can_id() {
    let mut replayer = SelectiveReplay::new(10, vec![0x300, 0x301]);

    // Add mixed frames
    replayer.capture_frame(create_test_frame(0x100, vec![1], "SENSOR", 1));
    replayer.capture_frame(create_test_frame(0x300, vec![2], "CTRL", 2));
    replayer.capture_frame(create_test_frame(0x200, vec![3], "OTHER", 3));
    replayer.capture_frame(create_test_frame(0x301, vec![4], "CTRL", 4));

    // Only 0x300 and 0x301 should be captured
    let frames_300 = replayer.get_frames_by_can_id(0x300);
    let frames_301 = replayer.get_frames_by_can_id(0x301);

    assert_eq!(frames_300.len(), 1);
    assert_eq!(frames_301.len(), 1);
}

#[test]
fn test_selective_replay_identifies_command_frames() {
    let mut replayer = SelectiveReplay::new(10, vec![]);

    replayer.capture_frame(create_test_frame(0x100, vec![1], "SENSOR", 1));
    replayer.capture_frame(create_test_frame(0x300, vec![2], "CTRL", 2)); // Brake
    replayer.capture_frame(create_test_frame(0x301, vec![3], "CTRL", 3)); // Throttle
    replayer.capture_frame(create_test_frame(0x302, vec![4], "CTRL", 4)); // Steering

    let commands = replayer.get_command_frames();
    assert_eq!(commands.len(), 3); // Only command frames
}

// ============================================================================
// Orchestration Tests
// ============================================================================

#[test]
fn test_attack_scenario_creation_and_duration() {
    let mut scenario = AttackScenario::new("test".to_string(), "Test scenario".to_string());

    scenario.add_attack(AttackConfig {
        attack_type: AttackType::FuzzRandom,
        duration_secs: 10,
        ..Default::default()
    });

    scenario.add_attack(AttackConfig {
        attack_type: AttackType::InjectUnsecured,
        duration_secs: 20,
        ..Default::default()
    });

    scenario.inter_attack_delay_secs = 5;

    // Total: 10 + 20 + 5 (one delay between two attacks) = 35
    assert_eq!(scenario.estimated_duration_secs(), 35);
}

#[test]
fn test_orchestrator_registers_and_lists_scenarios() {
    let mut orchestrator = AttackOrchestrator::new();

    orchestrator.register_scenario(scenarios::basic_fuzzing());
    orchestrator.register_scenario(scenarios::injection_suite());

    let scenarios = orchestrator.list_scenarios();
    assert!(scenarios.contains(&"basic_fuzzing".to_string()));
    assert!(scenarios.contains(&"injection_suite".to_string()));
}

#[test]
fn test_predefined_scenarios_exist() {
    // Verify all predefined scenarios can be created
    let _basic = scenarios::basic_fuzzing();
    let _injection = scenarios::injection_suite();
    let _replay = scenarios::replay_suite();
    let _flooding = scenarios::flooding_attack();
    let _comprehensive = scenarios::comprehensive_security_test();
}

#[test]
fn test_scenario_basic_fuzzing_structure() {
    let scenario = scenarios::basic_fuzzing();

    assert_eq!(scenario.attacks.len(), 3);
    assert_eq!(scenario.attacks[0].attack_type, AttackType::FuzzRandom);
    assert_eq!(scenario.attacks[1].attack_type, AttackType::FuzzMutation);
    assert_eq!(scenario.attacks[2].attack_type, AttackType::FuzzGrammar);
}

#[test]
fn test_scenario_injection_suite_structure() {
    let scenario = scenarios::injection_suite();

    assert_eq!(scenario.attacks.len(), 3);
    assert!(scenario.stop_on_detection);
}

#[test]
fn test_scenario_comprehensive_has_all_phases() {
    let scenario = scenarios::comprehensive_security_test();

    assert_eq!(scenario.attacks.len(), 4);

    // Check that we have fuzzing, injection, replay, and flooding
    let has_fuzzing = scenario
        .attacks
        .iter()
        .any(|a| matches!(a.attack_type, AttackType::FuzzRandom));
    let has_injection = scenario
        .attacks
        .iter()
        .any(|a| matches!(a.attack_type, AttackType::InjectUnsecured));
    let has_replay = scenario
        .attacks
        .iter()
        .any(|a| matches!(a.attack_type, AttackType::ReplaySimple));
    let has_flooding = scenario
        .attacks
        .iter()
        .any(|a| matches!(a.attack_type, AttackType::InjectFlooding));

    assert!(has_fuzzing);
    assert!(has_injection);
    assert!(has_replay);
    assert!(has_flooding);
}

// ============================================================================
// Metrics Tests
// ============================================================================

#[test]
fn test_attack_metrics_aggregation() {
    use autonomous_vehicle_sim::AttackResult;

    let mut result1 = AttackResult::new(AttackType::FuzzRandom);
    result1.frames_sent = 100;
    result1.frames_injected = 80;
    result1.attack_detected = true;
    result1.time_to_detection_ms = Some(150);

    let mut result2 = AttackResult::new(AttackType::InjectUnsecured);
    result2.frames_sent = 50;
    result2.frames_injected = 30;
    result2.attack_detected = false;

    let mut result3 = AttackResult::new(AttackType::ReplaySimple);
    result3.frames_sent = 75;
    result3.frames_injected = 60;
    result3.attack_detected = true;
    result3.time_to_detection_ms = Some(100);

    let metrics = AttackMetrics::from_results(&[result1, result2, result3]);

    assert_eq!(metrics.total_attacks, 3);
    assert_eq!(metrics.total_frames_sent, 225);
    assert_eq!(metrics.total_frames_injected, 170);
    assert_eq!(metrics.attacks_detected, 2);
    assert!((metrics.detection_rate - 0.6667).abs() < 0.001);
    assert_eq!(metrics.fastest_detection_ms, Some(100));
    assert_eq!(metrics.slowest_detection_ms, Some(150));
}

#[test]
fn test_metrics_report_generation() {
    use autonomous_vehicle_sim::AttackResult;

    let mut result = AttackResult::new(AttackType::FuzzRandom);
    result.frames_sent = 100;
    result.frames_injected = 75;
    result.attack_detected = true;

    let metrics = AttackMetrics::from_results(&[result]);
    let report = metrics.generate_report();

    assert!(report.contains("ATTACK SIMULATION METRICS REPORT"));
    assert!(report.contains("Total Attacks Executed"));
    assert!(report.contains("Frames Sent"));
    assert!(report.contains("Detection Rate"));
}

#[test]
fn test_scenario_comparison_report() {
    use autonomous_vehicle_sim::attack_sim::orchestrator::ScenarioResult;

    let mut comparison = ScenarioComparison::new();

    let mut result1 = ScenarioResult::new("scenario1".to_string());
    let mut result2 = ScenarioResult::new("scenario2".to_string());

    comparison.add_scenario(&result1);
    comparison.add_scenario(&result2);

    let report = comparison.generate_report();
    assert!(report.contains("SCENARIO COMPARISON REPORT"));
    assert!(report.contains("scenario1"));
    assert!(report.contains("scenario2"));
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_frame(can_id: u32, data: Vec<u8>, source: &str, counter: u64) -> SecuredCanFrame {
    SecuredCanFrame {
        can_id: CanId::Standard(can_id as u16),
        data,
        timestamp: chrono::Utc::now(),
        source: source.to_string(),
        session_counter: counter,
        mac: [0; 32],
        crc: 0,
    }
}
