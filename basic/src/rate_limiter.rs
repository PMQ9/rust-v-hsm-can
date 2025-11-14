use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Token bucket rate limiter for per-ECU DoS prevention
///
/// Uses token bucket algorithm:
/// - Each ECU has a bucket with tokens
/// - Tokens refill at a constant rate
/// - Each message consumes one token
/// - Messages are dropped when bucket is empty
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: u32,
    refill_rate: u32, // tokens per second
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_tokens` - Maximum burst size (bucket capacity)
    /// * `refill_rate` - Sustained rate in messages per second
    ///
    /// # Example
    /// ```
    /// // Allow bursts of 100 messages, sustained rate of 50 msg/sec
    /// let limiter = RateLimiter::new(100, 50);
    /// ```
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens,
            refill_rate,
        }
    }

    /// Create a rate limiter with automotive CAN defaults
    ///
    /// Default limits:
    /// - Burst: 200 messages (allows sensor bursts)
    /// - Sustained: 100 messages/second (typical automotive CAN rate)
    pub fn with_automotive_defaults() -> Self {
        Self::new(200, 100)
    }

    /// Check if a message from the given ECU should be allowed
    ///
    /// Returns true if message is allowed, false if it should be throttled
    pub async fn allow_message(&self, ecu_name: &str) -> bool {
        let mut buckets = self.buckets.lock().await;

        // Get or create bucket for this ECU
        let bucket = buckets
            .entry(ecu_name.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.max_tokens as f64,
                last_refill: Instant::now(),
            });

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate as f64;

        bucket.tokens = (bucket.tokens + new_tokens).min(self.max_tokens as f64);
        bucket.last_refill = now;

        // Check if we have tokens available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current token count for an ECU (for monitoring/debugging)
    pub async fn get_tokens(&self, ecu_name: &str) -> Option<f64> {
        let buckets = self.buckets.lock().await;
        buckets.get(ecu_name).map(|b| b.tokens)
    }

    /// Reset an ECU's token bucket (e.g., after reconnection)
    pub async fn reset_ecu(&self, ecu_name: &str) {
        let mut buckets = self.buckets.lock().await;
        buckets.remove(ecu_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_burst_allowed() {
        let limiter = RateLimiter::new(10, 5);

        // Should allow 10 messages immediately (burst)
        for i in 0..10 {
            assert!(
                limiter.allow_message("TEST_ECU").await,
                "Message {} should be allowed in burst",
                i
            );
        }

        // 11th message should be throttled
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "Message after burst should be throttled"
        );
    }

    #[tokio::test]
    async fn test_refill_over_time() {
        let limiter = RateLimiter::new(5, 10); // 10 tokens/sec = 1 token per 100ms

        // Drain bucket
        for _ in 0..5 {
            assert!(limiter.allow_message("TEST_ECU").await);
        }

        // Should be empty
        assert!(!limiter.allow_message("TEST_ECU").await);

        // Wait for refill (200ms = ~2 tokens at 10 tokens/sec)
        sleep(Duration::from_millis(200)).await;

        // Should have refilled ~2 tokens
        assert!(limiter.allow_message("TEST_ECU").await);
        assert!(limiter.allow_message("TEST_ECU").await);
        assert!(!limiter.allow_message("TEST_ECU").await);
    }

    #[tokio::test]
    async fn test_per_ecu_isolation() {
        let limiter = RateLimiter::new(5, 10);

        // Drain ECU1's bucket
        for _ in 0..5 {
            assert!(limiter.allow_message("ECU1").await);
        }
        assert!(!limiter.allow_message("ECU1").await);

        // ECU2 should have full bucket
        for i in 0..5 {
            assert!(
                limiter.allow_message("ECU2").await,
                "ECU2 message {} should be allowed",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_automotive_defaults() {
        let limiter = RateLimiter::with_automotive_defaults();

        // Should allow burst of 200
        for i in 0..200 {
            assert!(
                limiter.allow_message("SENSOR_ECU").await,
                "Message {} should be allowed",
                i
            );
        }

        // 201st should be throttled
        assert!(!limiter.allow_message("SENSOR_ECU").await);
    }

    #[tokio::test]
    async fn test_reset_ecu() {
        let limiter = RateLimiter::new(5, 10);

        // Drain bucket
        for _ in 0..5 {
            assert!(limiter.allow_message("TEST_ECU").await);
        }
        assert!(!limiter.allow_message("TEST_ECU").await);

        // Reset
        limiter.reset_ecu("TEST_ECU").await;

        // Should have full bucket again
        for i in 0..5 {
            assert!(
                limiter.allow_message("TEST_ECU").await,
                "After reset, message {} should be allowed",
                i
            );
        }
    }
}
