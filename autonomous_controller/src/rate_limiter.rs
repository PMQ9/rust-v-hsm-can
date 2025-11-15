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

    // ========================================================================
    // Edge Case and Boundary Tests
    // ========================================================================

    #[tokio::test]
    async fn test_partial_token_rejection() {
        let limiter = RateLimiter::new(5, 10);

        // Drain bucket completely
        for _ in 0..5 {
            assert!(limiter.allow_message("TEST_ECU").await);
        }

        // Wait for partial refill (50ms = ~0.5 tokens at 10 tokens/sec)
        sleep(Duration::from_millis(50)).await;

        // Should still be rejected (need at least 1.0 token)
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "Partial token (0.5) should not allow message"
        );

        // Wait another 50ms (total 100ms = 1.0 token)
        sleep(Duration::from_millis(50)).await;

        // Should now be accepted
        assert!(
            limiter.allow_message("TEST_ECU").await,
            "Full token (1.0) should allow message"
        );
    }

    #[tokio::test]
    async fn test_token_bucket_max_capacity() {
        let limiter = RateLimiter::new(10, 100);

        // Wait long enough to refill beyond capacity (500ms >> bucket size)
        sleep(Duration::from_millis(500)).await;

        // Should only allow max_tokens messages (10), not more
        for i in 0..10 {
            assert!(
                limiter.allow_message("TEST_ECU").await,
                "Message {} should be allowed (within max capacity)",
                i
            );
        }

        // 11th message should be throttled (bucket capped at max_tokens)
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "Message beyond max_tokens should be throttled"
        );
    }

    #[tokio::test]
    async fn test_exact_refill_timing() {
        // 10 tokens/sec = 1 token per 100ms
        let limiter = RateLimiter::new(1, 10);

        // Drain the single token
        assert!(limiter.allow_message("TEST_ECU").await);

        // Wait exactly 100ms (should refill exactly 1 token)
        sleep(Duration::from_millis(100)).await;

        // Should allow exactly one message
        assert!(
            limiter.allow_message("TEST_ECU").await,
            "Should allow message after exact refill time"
        );

        // Immediate second message should be throttled
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "Second message without refill should be throttled"
        );
    }

    #[tokio::test]
    async fn test_zero_initial_tokens() {
        // Start with empty bucket (max_tokens=0)
        let limiter = RateLimiter::new(0, 10);

        // Should immediately throttle (no burst capacity)
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "Should throttle with zero max_tokens"
        );
    }

    #[tokio::test]
    async fn test_very_high_refill_rate() {
        // 1000 tokens/sec = very permissive
        let limiter = RateLimiter::new(100, 1000);

        // Send burst of 100 messages
        for i in 0..100 {
            assert!(
                limiter.allow_message("TEST_ECU").await,
                "Message {} should be allowed in burst",
                i
            );
        }

        // 101st should be throttled
        assert!(!limiter.allow_message("TEST_ECU").await);

        // Wait tiny amount (10ms = ~10 tokens at 1000/sec)
        sleep(Duration::from_millis(10)).await;

        // Should allow ~10 more messages
        for i in 0..10 {
            assert!(
                limiter.allow_message("TEST_ECU").await,
                "Message {} should be allowed after fast refill",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_sustained_rate_at_limit() {
        // 10 msg/sec sustained rate
        let limiter = RateLimiter::new(2, 10);

        // Send messages at exactly the refill rate (100ms intervals)
        for i in 0..20 {
            // First 2 use burst capacity
            if i < 2 {
                assert!(
                    limiter.allow_message("TEST_ECU").await,
                    "Burst message {} should be allowed",
                    i
                );
            } else {
                // Wait for refill
                sleep(Duration::from_millis(100)).await;
                assert!(
                    limiter.allow_message("TEST_ECU").await,
                    "Sustained message {} should be allowed",
                    i
                );
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_ecus_do_not_share_buckets() {
        let limiter = RateLimiter::new(5, 10);

        // ECU1 drains its bucket
        for _ in 0..5 {
            assert!(limiter.allow_message("ECU1").await);
        }
        assert!(!limiter.allow_message("ECU1").await);

        // ECU2 should have full bucket (independent)
        for i in 0..5 {
            assert!(
                limiter.allow_message("ECU2").await,
                "ECU2 message {} should be allowed (independent bucket)",
                i
            );
        }
        assert!(!limiter.allow_message("ECU2").await);

        // ECU3 should also have full bucket
        for i in 0..5 {
            assert!(
                limiter.allow_message("ECU3").await,
                "ECU3 message {} should be allowed (independent bucket)",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_fractional_refill_accumulation() {
        // 1 token/sec (slow refill)
        let limiter = RateLimiter::new(2, 1);

        // Drain bucket
        assert!(limiter.allow_message("TEST_ECU").await);
        assert!(limiter.allow_message("TEST_ECU").await);
        assert!(!limiter.allow_message("TEST_ECU").await);

        // Wait 500ms (0.5 tokens)
        sleep(Duration::from_millis(500)).await;
        assert!(
            !limiter.allow_message("TEST_ECU").await,
            "0.5 tokens not enough"
        );

        // Wait another 500ms (total 1.0 token)
        sleep(Duration::from_millis(500)).await;
        assert!(
            limiter.allow_message("TEST_ECU").await,
            "1.0 token should allow message"
        );
    }
}
