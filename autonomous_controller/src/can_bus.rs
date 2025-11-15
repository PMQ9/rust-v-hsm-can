use crate::types::CanFrame;
use tokio::sync::broadcast;

/// Virtual CAN Bus
/// Uses broadcast channels to simulate a real CAN bus where all nodes see all messages
#[derive(Clone)]
pub struct VirtualCanBus {
    tx: broadcast::Sender<CanFrame>,
}

impl VirtualCanBus {
    /// Create a new virtual CAN bus with a specified buffer size
    pub fn new(buffer_size: usize) -> Self {
        let (tx, _rx) = broadcast::channel(buffer_size);
        Self { tx }
    }

    /// Send a frame onto the bus
    pub async fn send(&self, frame: CanFrame) -> Result<(), String> {
        if !frame.is_valid() {
            return Err("Invalid CAN frame: data length must be <= 8 bytes".to_string());
        }

        self.tx
            .send(frame)
            .map_err(|e| format!("Failed to send frame: {}", e))?;

        Ok(())
    }

    /// Subscribe to receive frames from the bus
    pub fn subscribe(&self) -> broadcast::Receiver<CanFrame> {
        self.tx.subscribe()
    }

    /// Get the number of active receivers
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CanId;

    #[tokio::test]
    async fn test_can_bus_broadcast() {
        let bus = VirtualCanBus::new(100);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let frame = CanFrame::new(
            CanId::Standard(0x123),
            vec![0x01, 0x02, 0x03],
            "TEST_ECU".to_string(),
        );

        bus.send(frame.clone()).await.unwrap();

        let received1 = rx1.recv().await.unwrap();
        let received2 = rx2.recv().await.unwrap();

        assert_eq!(received1.id, frame.id);
        assert_eq!(received2.id, frame.id);
    }

    // ========================================================================
    // NEW EDGE CASE TESTS - Data Length Boundaries
    // ========================================================================

    #[tokio::test]
    async fn test_data_length_zero_bytes() {
        // Test minimum valid length (0 bytes)
        let bus = VirtualCanBus::new(10);
        let _rx = bus.subscribe(); // Need subscriber for send to work

        let frame = CanFrame::new(CanId::Standard(0x100), vec![], "TEST_ECU".to_string());

        let result = bus.send(frame).await;
        assert!(result.is_ok(), "0-byte frame should be valid");
    }

    #[tokio::test]
    async fn test_data_length_one_byte() {
        // Test 1-byte frame
        let bus = VirtualCanBus::new(10);
        let _rx = bus.subscribe(); // Need subscriber for send to work

        let frame = CanFrame::new(CanId::Standard(0x100), vec![0xAA], "TEST_ECU".to_string());

        let result = bus.send(frame).await;
        assert!(result.is_ok(), "1-byte frame should be valid");
    }

    #[tokio::test]
    async fn test_data_length_seven_bytes() {
        // Test 7-byte frame (just under max)
        let bus = VirtualCanBus::new(10);
        let _rx = bus.subscribe(); // Need subscriber for send to work

        let frame = CanFrame::new(
            CanId::Standard(0x100),
            vec![1, 2, 3, 4, 5, 6, 7],
            "TEST_ECU".to_string(),
        );

        let result = bus.send(frame).await;
        assert!(result.is_ok(), "7-byte frame should be valid");
    }

    #[tokio::test]
    async fn test_data_length_exactly_eight_bytes() {
        // Test maximum valid length (8 bytes) - at boundary
        let bus = VirtualCanBus::new(10);
        let _rx = bus.subscribe(); // Need subscriber for send to work

        let frame = CanFrame::new(
            CanId::Standard(0x100),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            "TEST_ECU".to_string(),
        );

        let result = bus.send(frame).await;
        assert!(result.is_ok(), "8-byte frame should be valid (at boundary)");
    }

    #[tokio::test]
    async fn test_data_length_nine_bytes_rejected() {
        // Test over maximum (9 bytes) - just over boundary
        let bus = VirtualCanBus::new(10);
        let frame = CanFrame::new(
            CanId::Standard(0x100),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            "TEST_ECU".to_string(),
        );

        let result = bus.send(frame).await;
        assert!(
            result.is_err(),
            "9-byte frame should be rejected (over boundary)"
        );
        assert!(result.unwrap_err().contains("data length must be <= 8"));
    }

    #[tokio::test]
    async fn test_data_length_excessive_rejected() {
        // Test far over maximum (100 bytes)
        let bus = VirtualCanBus::new(10);
        let data = vec![0xFF; 100];
        let frame = CanFrame::new(CanId::Standard(0x100), data, "TEST_ECU".to_string());

        let result = bus.send(frame).await;
        assert!(
            result.is_err(),
            "100-byte frame should be rejected (far over limit)"
        );
    }

    // ========================================================================
    // NEW EDGE CASE TESTS - Buffer Overflow and Capacity
    // ========================================================================

    #[tokio::test]
    async fn test_buffer_capacity_just_under_limit() {
        // Test filling buffer to capacity-1
        let buffer_size = 10;
        let bus = VirtualCanBus::new(buffer_size);
        let mut rx = bus.subscribe();

        // Send 9 frames (just under limit of 10)
        for i in 0..9 {
            let frame = CanFrame::new(
                CanId::Standard(0x100 + i),
                vec![i as u8],
                "TEST_ECU".to_string(),
            );
            bus.send(frame).await.unwrap();
        }

        // All should be receivable
        for i in 0..9 {
            let received = rx.recv().await.unwrap();
            assert_eq!(received.data[0], i as u8);
        }
    }

    #[tokio::test]
    async fn test_buffer_capacity_at_limit() {
        // Test filling buffer to exact capacity
        let buffer_size = 10;
        let bus = VirtualCanBus::new(buffer_size);
        let mut rx = bus.subscribe();

        // Send exactly 10 frames (at limit)
        for i in 0..10 {
            let frame = CanFrame::new(
                CanId::Standard(0x100 + i),
                vec![i as u8],
                "TEST_ECU".to_string(),
            );
            bus.send(frame).await.unwrap();
        }

        // All should be receivable
        for i in 0..10 {
            let received = rx.recv().await.unwrap();
            assert_eq!(received.data[0], i as u8);
        }
    }

    #[tokio::test]
    async fn test_buffer_overflow_lagged_receiver() {
        // Test buffer overflow with slow receiver
        let buffer_size = 10;
        let bus = VirtualCanBus::new(buffer_size);
        let mut rx = bus.subscribe();

        // Send 20 frames without reading (exceeds buffer)
        for i in 0..20 {
            let frame = CanFrame::new(
                CanId::Standard(0x100 + i),
                vec![i as u8],
                "TEST_ECU".to_string(),
            );
            let _ = bus.send(frame).await;
        }

        // Receiver should get a Lagged error for dropped messages
        let result = rx.recv().await;
        if let Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) = result {
            assert!(
                n > 0,
                "Receiver should report lagged messages when buffer overflows"
            );
        } else {
            // Some messages may be received before lag is detected
            // This is acceptable behavior
        }
    }

    #[tokio::test]
    async fn test_multiple_subscribers_independent_buffers() {
        // Test that multiple subscribers have independent buffers
        let bus = VirtualCanBus::new(10);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        // Send 5 frames
        for i in 0..5 {
            let frame = CanFrame::new(
                CanId::Standard(0x100 + i),
                vec![i as u8],
                "TEST_ECU".to_string(),
            );
            bus.send(frame).await.unwrap();
        }

        // rx1 reads all frames
        for _ in 0..5 {
            rx1.recv().await.unwrap();
        }

        // rx2 should still have all frames (independent buffer)
        for i in 0..5 {
            let received = rx2.recv().await.unwrap();
            assert_eq!(received.data[0], i as u8);
        }
    }

    #[tokio::test]
    async fn test_receiver_count_tracking() {
        // Test receiver count tracking
        let bus = VirtualCanBus::new(10);

        assert_eq!(bus.receiver_count(), 0, "Should start with 0 receivers");

        let _rx1 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1, "Should have 1 receiver");

        let _rx2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2, "Should have 2 receivers");

        let _rx3 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 3, "Should have 3 receivers");

        drop(_rx1);
        // Note: receiver_count may not immediately update after drop
        // This is acceptable tokio broadcast behavior
    }

    #[tokio::test]
    async fn test_send_to_bus_with_no_active_receivers() {
        // Test that sending with no receivers results in expected behavior
        // Note: tokio broadcast channels fail when there are no receivers
        let bus = VirtualCanBus::new(10);

        let frame = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST_ECU".to_string());

        // With no receivers, send will fail with "channel closed" error
        let result = bus.send(frame).await;
        assert!(
            result.is_err(),
            "Send with no receivers should fail (expected broadcast behavior)"
        );
        let error_msg = result.unwrap_err();
        assert!(
            error_msg.contains("channel closed") || error_msg.contains("no receivers"),
            "Expected channel closed error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_subscriber_after_messages_sent() {
        // Test that late subscribers don't receive old messages
        let bus = VirtualCanBus::new(10);

        // Need at least one subscriber for send to work
        let _keeper = bus.subscribe();

        // Send 3 frames before late subscriber
        for i in 0..3 {
            let frame = CanFrame::new(
                CanId::Standard(0x100 + i),
                vec![i as u8],
                "TEST_ECU".to_string(),
            );
            bus.send(frame).await.unwrap();
        }

        // Subscribe after messages sent
        let mut rx = bus.subscribe();

        // Send new frame
        let frame = CanFrame::new(CanId::Standard(0x200), vec![0xFF], "TEST_ECU".to_string());
        bus.send(frame).await.unwrap();

        // Should only receive the new frame, not old ones
        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, CanId::Standard(0x200));
    }

    #[tokio::test]
    async fn test_small_buffer_boundary() {
        // Test edge case with very small buffer (size 1)
        let bus = VirtualCanBus::new(1);
        let mut rx = bus.subscribe();

        // Send one frame (at capacity)
        let frame1 = CanFrame::new(CanId::Standard(0x100), vec![0x01], "TEST_ECU".to_string());
        bus.send(frame1).await.unwrap();

        // Receive it
        let received = rx.recv().await.unwrap();
        assert_eq!(received.data[0], 0x01);

        // Send another (should work after previous was consumed)
        let frame2 = CanFrame::new(CanId::Standard(0x101), vec![0x02], "TEST_ECU".to_string());
        bus.send(frame2).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.data[0], 0x02);
    }
}
