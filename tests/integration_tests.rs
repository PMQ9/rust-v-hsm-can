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
