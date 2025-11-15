use autonomous_vehicle_sim::{
    can_bus::VirtualCanBus,
    ecu::Ecu,
    types::{ArmVariant, CanFrame, CanId, EcuConfig},
};

#[tokio::test]
async fn test_basic_can_communication() {
    // Create virtual CAN bus
    let bus = VirtualCanBus::new(100);

    // Create test ECU
    let config = EcuConfig {
        name: "TEST_ECU".to_string(),
        arm_variant: ArmVariant::CortexM4,
        bus_address: "tcp://localhost:5555".to_string(),
    };
    let ecu = Ecu::new(config, bus.clone());

    // Create a test frame
    let test_frame = CanFrame::new(
        CanId::Standard(0x123),
        vec![0x01, 0x02, 0x03],
        "TEST_ECU".to_string(),
    );

    // Subscribe to bus
    let mut rx = bus.subscribe();

    // Send frame
    ecu.send_frame(test_frame.id, test_frame.data.clone())
        .await
        .unwrap();

    // Receive frame
    let received = rx.recv().await.unwrap();

    // Verify frame contents
    assert_eq!(received.id, test_frame.id);
    assert_eq!(received.data, test_frame.data);
    assert_eq!(received.source, "TEST_ECU");
}

#[tokio::test]
async fn test_multiple_ecu_communication() {
    let bus = VirtualCanBus::new(100);

    // Create two ECUs
    let config1 = EcuConfig {
        name: "ECU1".to_string(),
        arm_variant: ArmVariant::CortexM4,
        bus_address: "tcp://localhost:5555".to_string(),
    };
    let config2 = EcuConfig {
        name: "ECU2".to_string(),
        arm_variant: ArmVariant::CortexM4,
        bus_address: "tcp://localhost:5555".to_string(),
    };

    let ecu1 = Ecu::new(config1, bus.clone());
    let _ecu2 = Ecu::new(config2, bus.clone()); // Keep ECU2 alive for the test duration

    // Subscribe both ECUs to the bus
    let mut rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();

    // Test message from ECU1
    let frame1 = CanFrame::new(CanId::Standard(0x100), vec![0xFF], "ECU1".to_string());

    ecu1.send_frame(frame1.id, frame1.data.clone())
        .await
        .unwrap();

    // Both ECUs should receive the message
    let received1 = rx1.recv().await.unwrap();
    let received2 = rx2.recv().await.unwrap();

    assert_eq!(received1.id, frame1.id);
    assert_eq!(received2.id, frame1.id);
    assert_eq!(received1.source, "ECU1");
    assert_eq!(received2.source, "ECU1");
}

#[tokio::test]
async fn test_bus_capacity() {
    let bus = VirtualCanBus::new(2); // Small capacity to test overflow behavior
    let mut rx = bus.subscribe();

    // Send some messages
    let frame1 = CanFrame::new(CanId::Standard(0x123), vec![0x01], "TEST".to_string());
    bus.send(frame1.clone()).await.unwrap();

    let frame2 = CanFrame::new(CanId::Standard(0x124), vec![0x02], "TEST".to_string());
    bus.send(frame2.clone()).await.unwrap();

    // Verify we can receive them
    let received1 = rx.recv().await.unwrap();
    let received2 = rx.recv().await.unwrap();

    assert_eq!(received1.id, frame1.id);
    assert_eq!(received2.id, frame2.id);
}

// ========================================================================
// NEW FAILURE SCENARIO TESTS
// ========================================================================

#[tokio::test]
async fn test_invalid_frame_too_long() {
    // Test that invalid frames are rejected
    let bus = VirtualCanBus::new(10);

    // Frame with data exceeding 8 bytes
    let invalid_frame = CanFrame::new(
        CanId::Standard(0x100),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9], // 9 bytes - invalid!
        "TEST_ECU".to_string(),
    );

    let result = bus.send(invalid_frame).await;
    assert!(
        result.is_err(),
        "Invalid frame (>8 bytes) should be rejected"
    );
    assert!(result.unwrap_err().contains("data length must be <= 8"));
}

#[tokio::test]
async fn test_concurrent_multi_ecu_stress() {
    // Test concurrent communication from many ECUs
    let bus = VirtualCanBus::new(1000);
    let num_ecus = 50;

    // Create multiple ECUs
    let mut ecus = Vec::new();
    for i in 0..num_ecus {
        let config = EcuConfig {
            name: format!("ECU{}", i),
            arm_variant: ArmVariant::CortexM4,
            bus_address: "tcp://localhost:5555".to_string(),
        };
        ecus.push(Ecu::new(config, bus.clone()));
    }

    // Subscribe to count messages
    let mut rx = bus.subscribe();

    // Each ECU sends 10 messages concurrently
    let mut handles = Vec::new();
    for (i, ecu) in ecus.into_iter().enumerate() {
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                let can_id = CanId::Standard(((0x100 + i as u32) % 0x7FF) as u16);
                let data = vec![j as u8];
                ecu.send_frame(can_id, data).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all sends to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify we received all 500 messages (50 ECUs * 10 messages)
    let mut count = 0;
    for _ in 0..(num_ecus * 10) {
        if rx.recv().await.is_ok() {
            count += 1;
        } else {
            break;
        }
    }

    assert_eq!(
        count,
        num_ecus * 10,
        "Should receive all messages from concurrent ECUs"
    );
}

#[tokio::test]
async fn test_bus_behavior_with_receiver_disconnect() {
    // Test that bus continues working when receivers disconnect
    let bus = VirtualCanBus::new(10);

    let rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();

    // Send first message
    let frame1 = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST".to_string());
    bus.send(frame1.clone()).await.unwrap();

    // Drop rx1 (simulating disconnect)
    drop(rx1);

    // Send second message
    let frame2 = CanFrame::new(CanId::Standard(0x101), vec![0x02], "TEST".to_string());
    bus.send(frame2.clone()).await.unwrap();

    // rx2 should still receive both messages
    let received1 = rx2.recv().await.unwrap();
    let received2 = rx2.recv().await.unwrap();

    assert_eq!(received1.id, frame1.id);
    assert_eq!(received2.id, frame2.id);
}

#[tokio::test]
async fn test_minimal_capacity_bus() {
    // Test edge case: bus with minimal capacity (1 message buffer)
    let bus = VirtualCanBus::new(1);

    // Subscriber must exist before send
    let mut rx = bus.subscribe();

    // Spawn sender in separate task
    let bus_clone = bus.clone();
    let send_handle = tokio::spawn(async move {
        let frame = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST".to_string());
        bus_clone.send(frame).await.unwrap();
    });

    // Receive immediately
    let received = rx.recv().await.unwrap();
    assert_eq!(received.id, CanId::Standard(0x100));

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_rapid_subscribe_unsubscribe() {
    // Test rapid subscription/unsubscription cycles
    let bus = VirtualCanBus::new(10);

    for _ in 0..100 {
        let _rx = bus.subscribe();
        // Immediately drop (unsubscribe)
    }

    // Bus should still work normally
    let mut rx = bus.subscribe();
    let frame = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST".to_string());
    bus.send(frame.clone()).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.id, frame.id);
}

#[tokio::test]
async fn test_empty_data_frame() {
    // Test sending frames with zero-length data
    let bus = VirtualCanBus::new(10);
    let mut rx = bus.subscribe();

    let empty_frame = CanFrame::new(CanId::Standard(0x100), vec![], "TEST_ECU".to_string());

    bus.send(empty_frame.clone()).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.id, empty_frame.id);
    assert_eq!(received.data.len(), 0);
}

#[tokio::test]
async fn test_extended_can_id() {
    // Test 29-bit extended CAN IDs
    let bus = VirtualCanBus::new(10);
    let mut rx = bus.subscribe();

    let extended_id = 0x1FFFFFFF; // Maximum 29-bit ID
    let frame = CanFrame::new(CanId::Extended(extended_id), vec![0xAB], "TEST".to_string());

    bus.send(frame.clone()).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.id, CanId::Extended(extended_id));
}

#[tokio::test]
async fn test_many_subscribers_stress() {
    // Test with many simultaneous subscribers
    let bus = VirtualCanBus::new(100);
    let num_subscribers = 100;

    // Create many subscribers
    let mut subscribers = Vec::new();
    for _ in 0..num_subscribers {
        subscribers.push(bus.subscribe());
    }

    // Send a message
    let frame = CanFrame::new(CanId::Standard(0x100), vec![0xFF], "TEST".to_string());
    bus.send(frame.clone()).await.unwrap();

    // All subscribers should receive it
    for rx in subscribers.iter_mut() {
        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, frame.id);
    }
}

#[tokio::test]
async fn test_mixed_valid_invalid_frames() {
    // Test mixing valid and invalid frames
    let bus = VirtualCanBus::new(10);
    let mut rx = bus.subscribe();

    // Valid frame
    let valid1 = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST".to_string());
    bus.send(valid1.clone()).await.unwrap();

    // Invalid frame (too long)
    let invalid = CanFrame::new(
        CanId::Standard(0x101),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        "TEST".to_string(),
    );
    let result = bus.send(invalid).await;
    assert!(result.is_err());

    // Another valid frame
    let valid2 = CanFrame::new(CanId::Standard(0x102), vec![0x02], "TEST".to_string());
    bus.send(valid2.clone()).await.unwrap();

    // Should only receive the two valid frames
    let received1 = rx.recv().await.unwrap();
    let received2 = rx.recv().await.unwrap();

    assert_eq!(received1.id, valid1.id);
    assert_eq!(received2.id, valid2.id);
}

#[tokio::test]
async fn test_interleaved_send_receive() {
    // Test interleaved sending and receiving
    let bus = VirtualCanBus::new(10);
    let mut rx = bus.subscribe();

    for i in 0..10 {
        // Send
        let frame = CanFrame::new(
            CanId::Standard(0x100 + i),
            vec![i as u8],
            "TEST".to_string(),
        );
        bus.send(frame.clone()).await.unwrap();

        // Immediately receive
        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, frame.id);
        assert_eq!(received.data[0], i as u8);
    }
}
