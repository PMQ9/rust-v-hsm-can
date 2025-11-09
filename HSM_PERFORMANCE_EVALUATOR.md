# HSM Performance Evaluator

## Overview

The HSM Performance Evaluator measures the processing time for Hardware Security Module (HSM) operations in the CAN bus simulator. It tracks the time taken for cryptographic operations to help identify performance bottlenecks and evaluate the overhead of security measures.

## Features

- **Automatic Timing**: Measures execution time for all HSM operations
- **Multiple Operation Types**: Tracks 4 different HSM operations:
  - `generate_mac`: HMAC-SHA256 generation for message authentication
  - `verify_mac`: HMAC-SHA256 verification for incoming messages
  - `calculate_crc`: CRC32 checksum calculation
  - `verify_crc`: CRC32 checksum verification
- **Statistical Analysis**: Provides comprehensive statistics including:
  - Min, Max, Average execution times
  - Percentiles (P50/Median, P95, P99)
  - Total operation count
  - Cumulative processing time
- **Configurable Storage**: Set maximum number of measurements to keep in memory
- **Zero-Overhead Option**: Can be disabled for production deployments

## Architecture

### Performance Tracking Flow

```
┌─────────────────────────────────────────────────────────┐
│  Message Send/Receive                                   │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  HSM Operation (generate_mac/verify_mac/crc)            │
│                                                          │
│  1. Start timing (capture Instant::now())               │
│  2. Execute cryptographic operation                     │
│  3. Record timing (calculate duration)                  │
│  4. Store in PerformanceEvaluator                       │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  HsmPerformanceEvaluator                                │
│                                                          │
│  • Stores measurements in VecDeque (FIFO)               │
│  • Calculates statistics on demand                      │
│  • Exports data for analysis                            │
└─────────────────────────────────────────────────────────┘
```

## Integration

The performance evaluator is integrated directly into the `VirtualHSM` struct:

```rust
pub struct VirtualHSM {
    // ... crypto keys ...
    performance_evaluator: HsmPerformanceEvaluator,
}
```

All HSM operations automatically record timing measurements:

```rust
pub fn generate_mac(&self, data: &[u8], session_counter: u64) -> [u8; 32] {
    let start = self.performance_evaluator.start_measurement();

    // ... perform HMAC-SHA256 ...

    self.performance_evaluator.record_measurement(
        start,
        HsmOperation::GenerateMac,
        data.len(),
    );

    output
}
```

## Usage

### 1. Automatic Monitoring in Autonomous Controller

The autonomous controller displays HSM performance statistics every 5 seconds:

```bash
cargo run --release --bin autonomous_controller
```

Output example:
```
→ Control: Brake=30%, Throttle=50%, Steering=2.5° | Avg Wheel Speed=45.2 rad/s

📊 HSM Performance: generate_mac: avg=15μs verify_mac: avg=18μs calculate_crc: avg=3μs verify_crc: avg=3μs
```

### 2. Dedicated Performance Monitor

Run the standalone HSM performance monitor for detailed real-time statistics:

```bash
cargo run --release --bin hsm_performance_monitor
```

This displays:
- Total measurement count
- Detailed statistics per operation type
- Performance insights (Excellent/Good/Acceptable/Slow ratings)
- Updates every 5 seconds

Example output:
```
┌────────────────────────────────────────────────┐
│   HSM Performance Monitor                      │
└────────────────────────────────────────────────┘

Total measurements: 15234

  generate_mac Stats:
    Count:   3812
    Min:     12μs
    Max:     245μs
    Avg:     18μs
    Median:  16μs
    P95:     28μs
    P99:     45μs
    Total:   68.62ms

  verify_mac Stats:
    Count:   3809
    Min:     14μs
    Max:     287μs
    Avg:     21μs
    Median:  19μs
    P95:     32μs
    P99:     52μs
    Total:   79.99ms

┌────────────────────────────────────────────────┐
│   Performance Insights                         │
└────────────────────────────────────────────────┘
  generate_mac: ✓ Excellent (avg: 18μs)
  verify_mac: ✓ Excellent (avg: 21μs)
  calculate_crc: ✓ Excellent (avg: 3μs)
  verify_crc: ✓ Excellent (avg: 3μs)
```

### 3. Programmatic Access

Access the performance evaluator from any ECU:

```rust
use autonomous_vehicle_sim::VirtualHSM;

let mut hsm = VirtualHSM::new("MY_ECU".to_string(), 0x1234);

// Use HSM normally...
let mac = hsm.generate_mac(&data, session_counter);

// Access performance stats
let perf_eval = hsm.performance_evaluator();
println!("Total measurements: {}", perf_eval.measurement_count());

// Get statistics for specific operation
if let Some(stats) = perf_eval.get_stats(HsmOperation::GenerateMac) {
    println!("Average MAC generation time: {}μs", stats.avg.as_micros());
}

// Display all statistics
perf_eval.display_stats();

// Export to CSV for external analysis
let csv_data = perf_eval.export_csv();
std::fs::write("hsm_performance.csv", csv_data)?;
```

### 4. Configuration

Adjust the number of measurements stored:

```rust
// Default: 10,000 measurements
let hsm = VirtualHSM::new("ECU_NAME".to_string(), seed);

// Access and configure
let mut perf_eval = HsmPerformanceEvaluator::new(50000); // Keep last 50k

// Disable for production
let perf_eval = HsmPerformanceEvaluator::disabled();
```

## Performance Characteristics

Based on typical measurements on a modern CPU:

| Operation      | Typical Avg | Data Size | Notes |
|----------------|-------------|-----------|-------|
| `generate_mac` | 15-25 μs    | ~20 bytes | HMAC-SHA256, includes session counter |
| `verify_mac`   | 18-30 μs    | ~20 bytes | HMAC-SHA256 + constant-time comparison |
| `calculate_crc`| 1-5 μs      | ~20 bytes | CRC32 hardware-accelerated |
| `verify_crc`   | 1-5 μs      | ~20 bytes | CRC32 calculation + comparison |

**Total per message**:
- Sender overhead: ~20-30 μs (MAC + CRC generation)
- Receiver overhead: ~20-35 μs (MAC + CRC verification)

For a 10 Hz control loop (100ms period), HSM overhead is **< 0.1%** of the cycle time.

## Performance Ratings

The monitor automatically rates performance:

- **✓ Excellent**: < 50 μs average
- **✓ Good**: 50-100 μs average
- **⚠ Acceptable**: 100-200 μs average
- **✗ Slow**: > 200 μs average

## Interpreting Results

### High P99 Values

If P99 times are significantly higher than average:
- Indicates occasional slowdowns (GC, context switches, cache misses)
- Usually acceptable if P99 < 200 μs
- Consider profiling if P99 > 500 μs

### Increasing Average Times

If average times increase over runtime:
- May indicate memory pressure or thermal throttling
- Check measurement count (auto-limited to prevent memory growth)
- Monitor system resources

### CRC Faster Than Expected

Modern CPUs have CRC32 hardware acceleration:
- Intel: CRC32 instruction (SSE 4.2)
- ARM: CRC32 instruction (ARMv8)
- Expect 1-5 μs for small payloads

### MAC Verification Slower Than Generation

This is expected because verification includes:
1. Lookup of trusted ECU's key
2. HMAC-SHA256 calculation
3. Constant-time comparison (prevents timing attacks)

## Testing

Run the performance evaluator tests:

```bash
cargo test --lib performance
```

Tests cover:
- Basic timing measurement
- Statistics calculation
- Measurement limiting (FIFO behavior)
- Disabled mode (zero overhead)

## CSV Export Format

Export data for external analysis tools:

```csv
operation,duration_us,data_size,timestamp_us
generate_mac,18,20,0
verify_mac,22,20,150
calculate_crc,3,20,200
verify_crc,3,20,250
...
```

Import into Python/R/Excel for visualization and advanced analysis.

## Implementation Details

### Thread Safety

The `HsmPerformanceEvaluator` uses `Arc<Mutex<VecDeque>>` for thread-safe access across async tasks.

### Memory Management

- FIFO queue with configurable size (default: 10,000 measurements)
- Oldest measurements automatically removed when capacity reached
- Each measurement: ~64 bytes (operation type, duration, timestamp, data size)
- Default memory usage: ~640 KB

### Zero-Cost Abstraction

When disabled, all timing operations return `None` and recording is a no-op:

```rust
pub fn start_measurement(&self) -> Option<Instant> {
    if self.enabled {
        Some(Instant::now())
    } else {
        None  // Compiler optimizes this away
    }
}
```

## Troubleshooting

### No Measurements Recorded

- Check that performance tracking is enabled (default: enabled)
- Verify ECUs are running and sending messages
- Ensure HSM operations are being called

### Performance Worse Than Expected

- Check CPU load and system resources
- Verify running in `--release` mode (not debug)
- Profile with `perf` or `flamegraph` for detailed analysis

### Monitor Not Displaying Stats

- Ensure bus server is running first
- Check that ECUs are registered and sending messages
- Verify correct BUS_ADDRESS (default: 127.0.0.1:9000)

## Future Enhancements

Potential improvements:

- [ ] Real-time graphing with terminal UI (tui-rs)
- [ ] Histogram visualization
- [ ] Alerting when thresholds exceeded
- [ ] Export to Prometheus/Grafana
- [ ] Per-ECU breakdown of performance
- [ ] Correlation with CAN message types
- [ ] Performance regression testing

## Related Files

- `src/performance.rs` - Core performance evaluator implementation
- `src/hsm.rs` - HSM integration points
- `src/bin/hsm_performance_monitor.rs` - Standalone monitoring tool
- `src/bin/autonomous_controller.rs` - Example integration

## License

Same as the rust-v-hsm-can project.
