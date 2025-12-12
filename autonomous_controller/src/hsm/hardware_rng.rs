use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::fs::File;
use std::io::Read;

/// Configuration for hardware RNG
#[derive(Debug, Clone)]
pub struct HardwareRngConfig {
    /// Enable hardware RNG device access
    pub enable_hwrng: bool,

    /// Path to hardware RNG device (default: /dev/hwrng)
    pub hwrng_path: String,

    /// Buffer size for batched reads (default: 4096 bytes)
    pub buffer_size: usize,

    /// Refill threshold - refill buffer when bytes remaining < threshold
    pub refill_threshold: usize,

    /// Allow fallback to OsRng if hardware RNG unavailable
    pub fallback_to_osrng: bool,

    /// Deterministic seed for testing (None for hardware/OS RNG)
    pub deterministic_seed: Option<u64>,
}

impl Default for HardwareRngConfig {
    fn default() -> Self {
        Self {
            enable_hwrng: cfg!(target_os = "linux"),
            hwrng_path: "/dev/hwrng".to_string(),
            buffer_size: 4096,
            refill_threshold: 256,
            fallback_to_osrng: true,
            deterministic_seed: None,
        }
    }
}

impl HardwareRngConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            enable_hwrng: std::env::var("VHSM_ENABLE_HWRNG")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(cfg!(target_os = "linux")),

            hwrng_path: std::env::var("VHSM_HWRNG_PATH")
                .unwrap_or_else(|_| "/dev/hwrng".to_string()),

            buffer_size: std::env::var("VHSM_RNG_BUFFER_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4096),

            refill_threshold: 256,
            fallback_to_osrng: true,
            deterministic_seed: None,
        }
    }
}

/// Random number generator source
enum RngSource {
    /// Hardware RNG device (e.g., /dev/hwrng on Raspberry Pi 4)
    HardwareDevice(File),

    /// OS-provided CSPRNG (e.g., /dev/urandom via getrandom)
    OsRng,

    /// Deterministic RNG for testing
    Deterministic,
}

impl RngSource {
    /// Get human-readable name of RNG source
    fn name(&self) -> &str {
        match self {
            RngSource::HardwareDevice(_) => "HardwareDevice",
            RngSource::OsRng => "OsRng",
            RngSource::Deterministic => "Deterministic",
        }
    }
}

/// Hardware-based random number generator with buffering and fallback
///
/// Provides direct access to hardware RNG (/dev/hwrng on Raspberry Pi 4)
/// with automatic fallback to OsRng and support for deterministic testing.
///
/// # Features
/// - Direct /dev/hwrng access for true hardware randomness
/// - Buffered reading (4 KB default) for performance
/// - Graceful fallback chain: Hardware -> OsRng -> Deterministic
/// - Thread-safe via internal buffer management
/// - Implements RngCore trait for compatibility with rand ecosystem
///
/// # Example
/// ```
/// use crate::hsm::hardware_rng::HardwareRng;
/// use rand::RngCore;
///
/// // Auto-detect hardware RNG (uses /dev/hwrng if available on Linux)
/// let mut rng = HardwareRng::new();
/// let random_value = rng.next_u64();
///
/// // Deterministic RNG for testing
/// let mut test_rng = HardwareRng::new_deterministic(12345);
/// ```
pub struct HardwareRng {
    /// RNG source (hardware device, OsRng, or deterministic)
    source: RngSource,

    /// Buffer for batched reads from hardware device
    buffer: Vec<u8>,

    /// Current position in buffer
    position: usize,

    /// Deterministic RNG (only Some when using Deterministic source)
    deterministic_rng: Option<StdRng>,

    /// Configuration
    config: HardwareRngConfig,
}

impl HardwareRng {
    /// Create new hardware RNG with default configuration
    ///
    /// Auto-detects hardware RNG on Linux systems. Falls back to OsRng
    /// if hardware RNG is unavailable.
    pub fn new() -> Self {
        Self::with_config(HardwareRngConfig::from_env())
    }

    /// Create new deterministic RNG for testing
    ///
    /// # Arguments
    /// * `seed` - Seed value for reproducible random number generation
    pub fn new_deterministic(seed: u64) -> Self {
        let mut config = HardwareRngConfig::default();
        config.deterministic_seed = Some(seed);
        Self::with_config(config)
    }

    /// Create new hardware RNG with custom configuration
    pub fn with_config(config: HardwareRngConfig) -> Self {
        let source = if let Some(_seed) = config.deterministic_seed {
            // Testing mode: deterministic
            RngSource::Deterministic
        } else if config.enable_hwrng && cfg!(target_os = "linux") {
            // Try hardware device
            match File::open(&config.hwrng_path) {
                Ok(file) => {
                    eprintln!("INFO: Using hardware RNG at {}", config.hwrng_path);
                    RngSource::HardwareDevice(file)
                }
                Err(e) => {
                    eprintln!("WARNING: Cannot open {}: {}", config.hwrng_path, e);

                    // Suggest solutions for common errors
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        eprintln!(
                            "HINT: Add user to 'hwrng' group or check /etc/udev/rules.d/90-hwrng.rules"
                        );
                        eprintln!("      sudo usermod -a -G hwrng $USER");
                    }

                    if config.fallback_to_osrng {
                        eprintln!("INFO: Falling back to OsRng");
                        RngSource::OsRng
                    } else {
                        panic!("Hardware RNG required but unavailable: {}", e);
                    }
                }
            }
        } else if config.fallback_to_osrng {
            // Non-Linux or hwrng disabled
            RngSource::OsRng
        } else {
            panic!("No RNG source configured");
        };

        let deterministic_rng = if let Some(seed) = config.deterministic_seed {
            Some(StdRng::seed_from_u64(seed))
        } else {
            None
        };

        let buffer = vec![0u8; config.buffer_size];

        let mut rng = Self {
            source,
            buffer,
            position: 0,
            deterministic_rng,
            config,
        };

        // Pre-fill buffer on initialization
        rng.refill_buffer();

        rng
    }

    /// Get the name of the current RNG source
    pub fn source_name(&self) -> &str {
        self.source.name()
    }

    /// Refill internal buffer from RNG source
    fn refill_buffer(&mut self) {
        match &mut self.source {
            RngSource::HardwareDevice(file) => {
                // Read from hardware device
                self.buffer.resize(self.config.buffer_size, 0);

                if let Err(e) = file.read_exact(&mut self.buffer) {
                    eprintln!(
                        "ERROR: Failed to read from {}: {}",
                        self.config.hwrng_path, e
                    );
                    eprintln!("INFO: Permanently switching to OsRng fallback");

                    // Permanent fallback to OsRng
                    self.source = RngSource::OsRng;
                    self.refill_buffer(); // Retry with OsRng
                    return;
                }

                self.position = 0;
            }

            RngSource::OsRng => {
                // Use OsRng to fill buffer
                rand::rngs::OsRng.fill_bytes(&mut self.buffer);
                self.position = 0;
            }

            RngSource::Deterministic => {
                // Use deterministic RNG
                if let Some(ref mut rng) = self.deterministic_rng {
                    rng.fill_bytes(&mut self.buffer);
                    self.position = 0;
                }
            }
        }
    }

    /// Fill destination buffer with random bytes
    ///
    /// Automatically refills internal buffer when needed.
    fn fill_bytes_internal(&mut self, dest: &mut [u8]) {
        let mut offset = 0;

        while offset < dest.len() {
            // Check if we need to refill
            let remaining = self.buffer.len() - self.position;

            if remaining == 0
                || (remaining < self.config.refill_threshold
                    && dest.len() - offset >= self.config.refill_threshold)
            {
                self.refill_buffer();
            }

            // Copy from buffer to destination
            let available = self.buffer.len() - self.position;
            let to_copy = std::cmp::min(available, dest.len() - offset);

            dest[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.position..self.position + to_copy]);

            self.position += to_copy;
            offset += to_copy;
        }
    }
}

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes_internal(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes_internal(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes_internal(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes_internal(dest);
        Ok(())
    }
}

impl Clone for HardwareRng {
    fn clone(&self) -> Self {
        // For cloning, we need to recreate the RNG with the same configuration
        // File handles cannot be cloned, so we reopen the device
        match &self.source {
            RngSource::Deterministic => {
                // Reconstruct from deterministic seed
                if let Some(seed) = self.config.deterministic_seed {
                    HardwareRng::new_deterministic(seed)
                } else {
                    // Shouldn't happen, but fallback to OsRng
                    let mut config = self.config.clone();
                    config.enable_hwrng = false;
                    HardwareRng::with_config(config)
                }
            }
            _ => {
                // For hardware device or OsRng, recreate with same config
                HardwareRng::with_config(self.config.clone())
            }
        }
    }
}

impl Default for HardwareRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_reproducibility() {
        let mut rng1 = HardwareRng::new_deterministic(12345);
        let mut rng2 = HardwareRng::new_deterministic(12345);

        // Same seed should produce same sequence
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_deterministic_different_seeds() {
        let mut rng1 = HardwareRng::new_deterministic(12345);
        let mut rng2 = HardwareRng::new_deterministic(54321);

        // Different seeds should produce different sequences
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_fallback_chain() {
        // Invalid path should fallback to OsRng
        let config = HardwareRngConfig {
            enable_hwrng: true,
            hwrng_path: "/dev/nonexistent_hwrng_device".to_string(),
            fallback_to_osrng: true,
            ..Default::default()
        };

        let rng = HardwareRng::with_config(config);
        assert_eq!(rng.source_name(), "OsRng");
    }

    #[test]
    fn test_buffer_refill() {
        let mut rng = HardwareRng::new_deterministic(999);

        // Read 2x buffer size to force refill
        let mut buf = vec![0u8; 8192];
        rng.fill_bytes(&mut buf);

        // Should succeed without panic
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_fill_bytes_small() {
        let mut rng = HardwareRng::new_deterministic(777);
        let mut buf = [0u8; 16];

        rng.fill_bytes(&mut buf);

        // Statistically, at least one byte should be non-zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_fill_bytes_large() {
        let mut rng = HardwareRng::new_deterministic(888);
        let mut buf = vec![0u8; 16384]; // 4x buffer size

        rng.fill_bytes(&mut buf);

        // Should handle large buffers correctly
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_next_u32() {
        let mut rng = HardwareRng::new_deterministic(123);

        let val1 = rng.next_u32();
        let val2 = rng.next_u32();

        // Should generate different values (with high probability)
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_config_from_env() {
        // Test default configuration
        let config = HardwareRngConfig::from_env();

        assert_eq!(config.hwrng_path, "/dev/hwrng");
        assert_eq!(config.buffer_size, 4096);
        assert_eq!(config.refill_threshold, 256);
        assert!(config.fallback_to_osrng);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_hwrng_access_if_available() {
        // Only runs if /dev/hwrng is accessible
        if std::fs::File::open("/dev/hwrng").is_ok() {
            let mut rng = HardwareRng::new();

            // Should successfully initialize with hardware RNG
            assert_eq!(rng.source_name(), "HardwareDevice");

            // Should generate random bytes
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            assert!(buf.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn test_osrng_fallback() {
        let mut config = HardwareRngConfig::default();
        config.enable_hwrng = false; // Disable hardware RNG

        let mut rng = HardwareRng::with_config(config);

        assert_eq!(rng.source_name(), "OsRng");

        // Should still generate random bytes
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
