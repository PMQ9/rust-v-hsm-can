/// Attack Framework Demonstration
///
/// Shows how to use the comprehensive attack simulation framework
/// with fuzzing, injection, replay attacks, and metrics collection
use autonomous_vehicle_sim::attack_sim::fuzzing::{GrammarFuzzer, MutationFuzzer, RandomFuzzer};
use autonomous_vehicle_sim::attack_sim::injection::{
    CrcCorruptor, Flooder, MacTamperer, SourceSpoofer, UnsecuredInjector,
};
use autonomous_vehicle_sim::attack_sim::metrics::{AttackMetrics, ScenarioComparison};
use autonomous_vehicle_sim::attack_sim::orchestrator::{AttackOrchestrator, scenarios};
use autonomous_vehicle_sim::attack_sim::replay::{
    DelayedReplay, ReorderedReplay, SelectiveReplay, SimpleReplay,
};
use autonomous_vehicle_sim::attack_sim::{AttackConfig, AttackSimulator, AttackType};
use autonomous_vehicle_sim::hsm::{SecuredCanFrame, VirtualHSM};
use autonomous_vehicle_sim::types::CanId;
use chrono::Utc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   ATTACK SIMULATION FRAMEWORK - COMPREHENSIVE DEMO           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Demo 1: Fuzzing Engines
    demo_fuzzing_engines()?;

    // Demo 2: Injection Attacks
    demo_injection_attacks()?;

    // Demo 3: Replay Attacks
    demo_replay_attacks()?;

    // Demo 4: Attack Orchestration
    demo_attack_orchestration()?;

    // Demo 5: Metrics and Reporting
    demo_metrics_and_reporting()?;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║   DEMO COMPLETE - Attack Framework Ready for Use             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}

fn demo_fuzzing_engines() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  DEMO 1: Fuzzing Engines");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Random Fuzzing
    println!("1. Random Fuzzing");
    println!("   Generates completely random CAN frames\n");

    let mut random_fuzzer = RandomFuzzer::new(Some(12345));
    let random_frame = random_fuzzer.generate_random_frame("FUZZER");
    println!("   Generated random frame:");
    println!("     CAN ID: 0x{:03X}", random_frame.can_id.value());
    println!("     Data length: {} bytes", random_frame.data.len());
    println!("     Source: {}\n", random_frame.source);

    let config = AttackConfig {
        attack_type: AttackType::FuzzRandom,
        frame_count: Some(100),
        ..Default::default()
    };

    let result = random_fuzzer.execute(&config)?;
    println!(
        "   Executed attack: {} frames generated\n",
        result.frames_sent
    );

    // Mutation Fuzzing
    println!("2. Mutation-based Fuzzing");
    println!("   Mutates existing valid frames\n");

    let mut mutation_fuzzer = MutationFuzzer::new(Some(54321));

    // Add seed frames
    let mut hsm = VirtualHSM::new("SEED_ECU".to_string(), 99999);
    let seed_frame = SecuredCanFrame::new(
        CanId::Standard(0x100),
        vec![50, 100, 150, 200],
        "SEED_ECU".to_string(),
        &mut hsm,
    )?;

    mutation_fuzzer.add_seed_frame(seed_frame.clone());
    let mutated = mutation_fuzzer.mutate_frame(&seed_frame);

    println!("   Original data: {:?}", seed_frame.data);
    println!("   Mutated data:  {:?}\n", mutated.data);

    // Grammar-based Fuzzing
    println!("3. Grammar-based Fuzzing");
    println!("   Protocol-aware fuzzing using valid CAN ID ranges\n");

    let mut grammar_fuzzer = GrammarFuzzer::new(Some(11111));
    let grammar_frame = grammar_fuzzer.generate_grammar_frame("GRAMMAR_FUZZER");
    println!(
        "   Generated frame with valid CAN ID: 0x{:03X}",
        grammar_frame.can_id.value()
    );
    println!("   Data: {:?}\n", grammar_frame.data);

    println!("✓ Fuzzing engines demonstration complete\n");
    Ok(())
}

fn demo_injection_attacks() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  DEMO 2: Injection Attacks");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Unsecured Frame Injection
    println!("1. Unsecured Frame Injection");
    println!("   Injects frames without valid MAC/CRC\n");

    let mut unsecured = UnsecuredInjector::new("ATTACKER".to_string(), Some(11111));
    let unsecured_frame = unsecured.generate_unsecured_frame(0x300, vec![0xFF, 0xFF]);
    println!("   MAC: {:?} (all zeros)", &unsecured_frame.mac[..4]);
    println!("   CRC: {} (zero)\n", unsecured_frame.crc);

    // MAC Tampering
    println!("2. MAC Tampering");
    println!("   Creates frames with corrupted MACs\n");

    let mut mac_tamperer = MacTamperer::new("TAMPERER".to_string(), 22222);
    match mac_tamperer.generate_tampered_mac_frame(0x100, vec![1, 2, 3], "SOURCE".to_string()) {
        Ok(_) => println!("   Successfully generated tampered MAC frame\n"),
        Err(e) => println!("   Frame generation blocked: {}\n", e),
    }

    // CRC Corruption
    println!("3. CRC Corruption");
    println!("   Creates frames with invalid CRCs\n");

    let mut crc_corruptor = CrcCorruptor::new("CORRUPTOR".to_string(), 33333);
    match crc_corruptor.generate_corrupted_crc_frame(0x100, vec![4, 5, 6], "SOURCE".to_string()) {
        Ok(_) => println!("   Successfully generated corrupted CRC frame\n"),
        Err(e) => println!("   Frame generation blocked: {}\n", e),
    }

    // Source Spoofing
    println!("4. Source Spoofing");
    println!("   Claims to be from a different ECU\n");

    let mut spoofer = SourceSpoofer::new("SPOOFER".to_string(), 44444);
    match spoofer.generate_spoofed_frame(0x100, vec![7, 8, 9], "WHEEL_FL".to_string()) {
        Ok(frame) => {
            println!("   Frame claims to be from: {}", frame.source);
            println!("   (But was created by attacker)\n");
        }
        Err(e) => println!("   Spoofing blocked: {}\n", e),
    }

    // Flooding Attack
    println!("5. Flooding Attack (DoS)");
    println!("   High-rate message injection\n");

    let mut flooder = Flooder::new("FLOODER".to_string(), Some(55555));
    let config = AttackConfig {
        attack_type: AttackType::InjectFlooding,
        target_can_id: Some(0x300),
        duration_secs: 1,
        intensity: 0.5, // 500 frames/second
        ..Default::default()
    };

    let result = flooder.execute(&config)?;
    println!(
        "   Flooding attack: {} frames in {} ms",
        result.frames_sent,
        result.duration_ms()
    );
    println!(
        "   Rate: {:.0} frames/second\n",
        result.metrics.get("flooding_rate_fps").unwrap()
    );

    println!("✓ Injection attacks demonstration complete\n");
    Ok(())
}

fn demo_replay_attacks() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  DEMO 3: Replay Attacks");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Create some test frames to capture
    let test_frames = create_test_frames(10);

    // Simple Replay
    println!("1. Simple Replay");
    println!("   Immediately replays captured frames\n");

    let mut simple_replay = SimpleReplay::new(100);
    for frame in &test_frames[..5] {
        simple_replay.capture_frame(frame.clone());
    }

    println!("   Captured {} frames", simple_replay.captured_count());

    let config = AttackConfig {
        attack_type: AttackType::ReplaySimple,
        frame_count: Some(3),
        ..Default::default()
    };

    let result = simple_replay.execute(&config)?;
    println!("   Replayed {} frames\n", result.frames_sent);

    // Delayed Replay
    println!("2. Delayed Replay");
    println!("   Replays old frames outside replay window\n");

    let mut delayed_replay = DelayedReplay::new(100);
    for frame in &test_frames {
        delayed_replay.capture_frame(frame.clone());
    }

    let old_frames = delayed_replay.get_oldest_frames(3);
    println!(
        "   Retrieved {} oldest frames for replay\n",
        old_frames.len()
    );

    // Reordered Replay
    println!("3. Reordered Replay");
    println!("   Changes the order of captured frames\n");

    let mut reordered_replay = ReorderedReplay::new(100);
    for frame in &test_frames {
        reordered_replay.capture_frame(frame.clone());
    }

    let reversed = reordered_replay.get_reversed_frames();
    println!("   Original order: counters 0-9");
    println!(
        "   Reversed order: counters {}-{}",
        reversed.first().unwrap().session_counter,
        reversed.last().unwrap().session_counter
    );

    let shuffled = reordered_replay.get_shuffled_frames(12345);
    print!("   Shuffled order: counters ");
    for frame in &shuffled[..5] {
        print!("{} ", frame.session_counter);
    }
    println!("...\n");

    // Selective Replay
    println!("4. Selective Replay");
    println!("   Targets specific high-value frames\n");

    let mut selective_replay = SelectiveReplay::new(100, vec![0x300, 0x301, 0x302]);

    // Add command frames
    for i in 0..5 {
        let mut hsm = VirtualHSM::new("CTRL".to_string(), 88888 + i);
        let frame = SecuredCanFrame::new(
            CanId::Standard(0x300), // Brake command
            vec![i as u8, 50],
            "CTRL".to_string(),
            &mut hsm,
        )?;
        selective_replay.capture_frame(frame);
    }

    let commands = selective_replay.get_command_frames();
    println!(
        "   Captured {} command frames (brake, throttle, steering)",
        commands.len()
    );
    println!("   Ready for selective replay\n");

    println!("✓ Replay attacks demonstration complete\n");
    Ok(())
}

fn demo_attack_orchestration() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  DEMO 4: Attack Orchestration");
    println!("═══════════════════════════════════════════════════════════════\n");

    let mut orchestrator = AttackOrchestrator::new();

    // Register predefined scenarios
    orchestrator.register_scenario(scenarios::basic_fuzzing());
    orchestrator.register_scenario(scenarios::injection_suite());
    orchestrator.register_scenario(scenarios::replay_suite());
    orchestrator.register_scenario(scenarios::flooding_attack());
    orchestrator.register_scenario(scenarios::comprehensive_security_test());

    println!("Registered scenarios:");
    for (idx, name) in orchestrator.list_scenarios().iter().enumerate() {
        println!("  {}. {}", idx + 1, name);
    }
    println!();

    // Execute a scenario (dry run)
    println!("Executing 'basic_fuzzing' scenario (dry run)...\n");
    let result = orchestrator.execute_scenario_dry_run("basic_fuzzing")?;

    println!("Scenario Result:");
    println!("  Status: {:?}", result.status);
    println!("  Attacks executed: {}", result.attack_results.len());
    println!("  Duration: {} ms", result.duration_ms());
    println!();

    println!("✓ Attack orchestration demonstration complete\n");
    Ok(())
}

fn demo_metrics_and_reporting() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  DEMO 5: Metrics and Reporting");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Execute multiple attacks and collect metrics
    let mut orchestrator = AttackOrchestrator::new();
    orchestrator.register_scenario(scenarios::basic_fuzzing());
    orchestrator.register_scenario(scenarios::injection_suite());

    let result1 = orchestrator.execute_scenario_dry_run("basic_fuzzing")?;
    let result2 = orchestrator.execute_scenario_dry_run("injection_suite")?;

    // Generate attack metrics report
    let metrics1 = AttackMetrics::from_results(&result1.attack_results);
    println!("{}", metrics1.generate_report());

    // Generate scenario comparison
    let mut comparison = ScenarioComparison::new();
    comparison.add_scenario(&result1);
    comparison.add_scenario(&result2);

    println!("{}", comparison.generate_report());

    println!("✓ Metrics and reporting demonstration complete\n");
    Ok(())
}

fn create_test_frames(count: u64) -> Vec<SecuredCanFrame> {
    let mut frames = Vec::new();
    for i in 0..count {
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 77777 + i);
        match SecuredCanFrame::new(
            CanId::Standard(0x100),
            vec![i as u8, 50, 100, 150],
            "TEST_ECU".to_string(),
            &mut hsm,
        ) {
            Ok(frame) => frames.push(frame),
            Err(_) => {}
        }
    }
    frames
}
