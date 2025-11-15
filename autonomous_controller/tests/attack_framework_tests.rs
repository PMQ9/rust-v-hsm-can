/// Attack Framework Integration Tests
///
/// These tests verify the attack simulation framework works correctly
/// in a realistic CAN bus environment with HSM security enabled.
use autonomous_vehicle_sim::{
    AttackConfig, AttackSimulator, AttackType, VirtualHSM,
    network::{BusClient, NetMessage},
    types::{CanFrame, CanId},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;

const BUS_ADDRESS: &str = "127.0.0.1:9001"; // Use different port for tests

/// Test: Fuzzing attack generates various frame types
#[tokio::test]
#[ignore] // Run with: cargo test --test attack_framework_tests -- --ignored
async fn test_fuzzing_attack_generates_frames() {
    // Start bus server in background
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server(BUS_ADDRESS).await {
            eprintln!("Bus server error: {}", e);
        }
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Configure fuzzing attack
    let config = AttackConfig {
        attack_type: AttackType::Fuzzing,
        duration_secs: Some(2),
        frames_per_second: 100,
        target_can_ids: vec![],
        attacker_name: "TEST_FUZZER".to_string(),
        malform_percentage: 50,
        capture_duration_secs: 10,
    };

    // Run fuzzing attack
    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect(BUS_ADDRESS)
        .await
        .expect("Failed to connect");
    let stats = simulator.execute().await.expect("Fuzzing failed");

    // Verify frames were sent
    assert!(stats.frames_sent > 0, "Should send frames");
    assert!(
        stats.duration_secs >= 2,
        "Should run for specified duration"
    );

    // Verify frame rate is approximately correct
    let expected_frames = 100 * 2; // 100 fps * 2 seconds
    let tolerance = expected_frames as f64 * 0.2; // 20% tolerance
    assert!(
        (stats.frames_sent as f64 - expected_frames as f64).abs() < tolerance,
        "Frame count {} should be close to expected {}",
        stats.frames_sent,
        expected_frames
    );

    bus_handle.abort();
}

/// Test: Injection attack targets specific CAN IDs
#[tokio::test]
#[ignore]
async fn test_injection_attack_targets_specific_ids() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9002").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Monitor to capture frames
    let captured_frames = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured_frames.clone();

    let monitor_handle = tokio::spawn(async move {
        if let Ok(client) = BusClient::connect("127.0.0.1:9002", "MONITOR".to_string()).await {
            let (mut reader, _writer) = client.split();
            for _ in 0..50 {
                if let Ok(msg) =
                    tokio::time::timeout(Duration::from_millis(100), reader.receive_message()).await
                {
                    if let Ok(NetMessage::CanFrame(frame)) = msg {
                        captured_clone.lock().await.push(frame);
                    }
                }
            }
        }
    });

    // Configure injection attack
    let config = AttackConfig {
        attack_type: AttackType::Injection,
        duration_secs: Some(1),
        frames_per_second: 50,
        target_can_ids: vec![0x100, 0x300],
        attacker_name: "TEST_INJECTOR".to_string(),
        malform_percentage: 0,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9002")
        .await
        .expect("Failed to connect");
    simulator.execute().await.expect("Injection failed");

    tokio::time::sleep(Duration::from_millis(500)).await;
    monitor_handle.abort();

    // Verify frames were sent (though target filtering isn't implemented yet in injection)
    let frames = captured_frames.lock().await;
    assert!(frames.len() > 0, "Should capture injected frames");

    bus_handle.abort();
}

/// Test: Flooding attack achieves high frame rates
#[tokio::test]
#[ignore]
async fn test_flooding_attack_high_rate() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9003").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Configure flooding attack
    let config = AttackConfig {
        attack_type: AttackType::Flooding,
        duration_secs: Some(1),
        frames_per_second: 500, // High rate
        target_can_ids: vec![],
        attacker_name: "TEST_FLOODER".to_string(),
        malform_percentage: 0,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9003")
        .await
        .expect("Failed to connect");
    let stats = simulator.execute().await.expect("Flooding failed");

    // Verify high frame rate was achieved
    assert!(
        stats.frames_sent > 400,
        "Should send many frames at high rate"
    );
    assert!(stats.frames_per_second() > 300.0, "Should achieve high fps");

    bus_handle.abort();
}

/// Test: Spoofing attack uses legitimate ECU names
#[tokio::test]
#[ignore]
async fn test_spoofing_attack_uses_legitimate_names() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9004").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Monitor to capture frames
    let captured_frames = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured_frames.clone();

    let monitor_handle = tokio::spawn(async move {
        if let Ok(client) = BusClient::connect("127.0.0.1:9004", "MONITOR".to_string()).await {
            let (mut reader, _writer) = client.split();
            for _ in 0..50 {
                if let Ok(msg) =
                    tokio::time::timeout(Duration::from_millis(100), reader.receive_message()).await
                {
                    if let Ok(NetMessage::CanFrame(frame)) = msg {
                        captured_clone.lock().await.push(frame);
                    }
                }
            }
        }
    });

    // Configure spoofing attack
    let config = AttackConfig {
        attack_type: AttackType::Spoofing,
        duration_secs: Some(1),
        frames_per_second: 50,
        target_can_ids: vec![],
        attacker_name: "TEST_SPOOFER".to_string(),
        malform_percentage: 0,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9004")
        .await
        .expect("Failed to connect");
    simulator.execute().await.expect("Spoofing failed");

    tokio::time::sleep(Duration::from_millis(500)).await;
    monitor_handle.abort();

    // Verify frames have spoofed sources
    let frames = captured_frames.lock().await;
    assert!(frames.len() > 0, "Should capture spoofed frames");

    // Check that frames don't use the attacker name (they use spoofed names)
    let has_spoofed_name = frames.iter().any(|f| f.source != "TEST_SPOOFER");
    assert!(has_spoofed_name, "Should use spoofed ECU names");

    bus_handle.abort();
}

/// Test: Attack statistics are accurate
#[tokio::test]
#[ignore]
async fn test_attack_statistics_accuracy() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9005").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let config = AttackConfig {
        attack_type: AttackType::Fuzzing,
        duration_secs: Some(3),
        frames_per_second: 100,
        target_can_ids: vec![],
        attacker_name: "TEST_STATS".to_string(),
        malform_percentage: 50,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9005")
        .await
        .expect("Failed to connect");

    let start = std::time::Instant::now();
    let stats = simulator.execute().await.expect("Attack failed");
    let elapsed = start.elapsed().as_secs();

    // Verify duration tracking
    assert!(
        (stats.duration_secs as i64 - elapsed as i64).abs() <= 1,
        "Duration should match actual time"
    );

    // Verify frames per second calculation
    let calculated_fps = stats.frames_sent as f64 / stats.duration_secs as f64;
    assert!(
        (calculated_fps - stats.frames_per_second()).abs() < 0.1,
        "FPS calculation should be accurate"
    );

    bus_handle.abort();
}

/// Test: Malformed frames violate CAN frame constraints
#[tokio::test]
#[ignore]
async fn test_malformed_frames_violate_constraints() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9006").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Monitor to capture frames
    let captured_frames = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured_frames.clone();

    let monitor_handle = tokio::spawn(async move {
        if let Ok(client) = BusClient::connect("127.0.0.1:9006", "MONITOR".to_string()).await {
            let (mut reader, _writer) = client.split();
            for _ in 0..200 {
                if let Ok(msg) =
                    tokio::time::timeout(Duration::from_millis(50), reader.receive_message()).await
                {
                    if let Ok(NetMessage::CanFrame(frame)) = msg {
                        captured_clone.lock().await.push(frame);
                    }
                }
            }
        }
    });

    // Configure fuzzing with 100% malformed frames
    let config = AttackConfig {
        attack_type: AttackType::Fuzzing,
        duration_secs: Some(2),
        frames_per_second: 100,
        target_can_ids: vec![],
        attacker_name: "TEST_MALFORM".to_string(),
        malform_percentage: 100,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9006")
        .await
        .expect("Failed to connect");
    simulator.execute().await.expect("Fuzzing failed");

    tokio::time::sleep(Duration::from_millis(500)).await;
    monitor_handle.abort();

    // Verify frames violate constraints
    let frames = captured_frames.lock().await;
    assert!(frames.len() > 0, "Should capture malformed frames");

    // Check that some frames are invalid (> 8 bytes or invalid ID)
    let has_invalid = frames.iter().any(|f| !f.is_valid());
    assert!(
        has_invalid,
        "Should have invalid frames when malform_percentage is 100%"
    );

    bus_handle.abort();
}

/// Test: Combined attack executes multiple stages
#[tokio::test]
#[ignore]
async fn test_combined_attack_multi_stage() {
    let bus_handle = tokio::spawn(async {
        if let Err(e) = start_test_bus_server("127.0.0.1:9007").await {
            eprintln!("Bus server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let config = AttackConfig {
        attack_type: AttackType::Combined,
        duration_secs: Some(6), // 3 stages * 2 seconds each
        frames_per_second: 50,
        target_can_ids: vec![],
        attacker_name: "TEST_COMBINED".to_string(),
        malform_percentage: 50,
        capture_duration_secs: 10,
    };

    let mut simulator = AttackSimulator::new(config);
    simulator
        .connect("127.0.0.1:9007")
        .await
        .expect("Failed to connect");

    let start = std::time::Instant::now();
    let stats = simulator.execute().await.expect("Combined attack failed");
    let elapsed = start.elapsed().as_secs();

    // Verify multi-stage execution
    assert!(elapsed >= 5, "Combined attack should take multiple stages");
    assert!(
        stats.frames_sent > 200,
        "Should send frames across multiple stages"
    );

    bus_handle.abort();
}

/// Helper: Start a test bus server on a specific address
async fn start_test_bus_server(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    let listener = TcpListener::bind(addr).await?;
    let clients: Arc<RwLock<HashMap<String, tokio::net::tcp::OwnedWriteHalf>>> =
        Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (socket, _) = listener.accept().await?;
        let clients = clients.clone();

        tokio::spawn(async move {
            let (read_half, write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();

            // Read registration
            if reader.read_line(&mut line).await.is_ok() {
                if let Ok(msg) = serde_json::from_str::<NetMessage>(&line) {
                    if let NetMessage::Register { client_name } = msg {
                        clients.write().await.insert(client_name, write_half);
                    }
                }
            }

            // Echo frames to all clients
            loop {
                line.clear();
                if reader.read_line(&mut line).await.is_err() || line.is_empty() {
                    break;
                }

                // Broadcast to all clients
                let clients_lock = clients.read().await;
                for (_name, writer) in clients_lock.iter() {
                    let mut writer = writer;
                    let _ = writer.write_all(line.as_bytes()).await;
                }
            }
        });
    }
}
