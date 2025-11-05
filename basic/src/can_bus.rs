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
}
