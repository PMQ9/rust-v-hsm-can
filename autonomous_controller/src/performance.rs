/// HSM Performance Evaluator
///
/// Measures the time taken for HSM operations to calculate processing latency.
/// Tracks MAC generation, MAC verification, CRC calculation, and CRC verification times.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Type of HSM operation being measured
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmOperation {
    GenerateMac,
    VerifyMac,
    CalculateCrc,
    VerifyCrc,
}

impl HsmOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            HsmOperation::GenerateMac => "generate_mac",
            HsmOperation::VerifyMac => "verify_mac",
            HsmOperation::CalculateCrc => "calculate_crc",
            HsmOperation::VerifyCrc => "verify_crc",
        }
    }
}

/// Single measurement of an HSM operation
#[derive(Debug, Clone)]
pub struct HsmMeasurement {
    pub operation: HsmOperation,
    pub duration: Duration,
    pub timestamp: Instant,
    pub data_size: usize,
}

/// Statistics for HSM operations
#[derive(Debug, Clone)]
pub struct HsmStats {
    pub operation: HsmOperation,
    pub count: usize,
    pub min: Duration,
    pub max: Duration,
    pub avg: Duration,
    pub total: Duration,
    pub p50: Duration,  // Median
    pub p95: Duration,
    pub p99: Duration,
}

impl HsmStats {
    pub fn format_duration(d: &Duration) -> String {
        let micros = d.as_micros();
        if micros < 1000 {
            format!("{}μs", micros)
        } else {
            format!("{:.2}ms", d.as_secs_f64() * 1000.0)
        }
    }

    pub fn display(&self) {
        println!("  {} Stats:", self.operation.as_str());
        println!("    Count:   {}", self.count);
        println!("    Min:     {}", Self::format_duration(&self.min));
        println!("    Max:     {}", Self::format_duration(&self.max));
        println!("    Avg:     {}", Self::format_duration(&self.avg));
        println!("    Median:  {}", Self::format_duration(&self.p50));
        println!("    P95:     {}", Self::format_duration(&self.p95));
        println!("    P99:     {}", Self::format_duration(&self.p99));
        println!("    Total:   {}", Self::format_duration(&self.total));
    }
}

/// HSM Performance Evaluator
///
/// Tracks timing measurements for all HSM operations and provides statistics.
/// Thread-safe for use across multiple ECUs.
#[derive(Clone)]
pub struct HsmPerformanceEvaluator {
    measurements: Arc<Mutex<VecDeque<HsmMeasurement>>>,
    max_measurements: usize,
    enabled: bool,
}

impl HsmPerformanceEvaluator {
    /// Create a new performance evaluator
    ///
    /// # Arguments
    /// * `max_measurements` - Maximum number of measurements to keep in memory (FIFO)
    pub fn new(max_measurements: usize) -> Self {
        Self {
            measurements: Arc::new(Mutex::new(VecDeque::with_capacity(max_measurements))),
            max_measurements,
            enabled: true,
        }
    }

    /// Create a disabled evaluator (no overhead)
    pub fn disabled() -> Self {
        Self {
            measurements: Arc::new(Mutex::new(VecDeque::new())),
            max_measurements: 0,
            enabled: false,
        }
    }

    /// Enable performance tracking
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable performance tracking
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if tracking is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start timing an operation
    pub fn start_measurement(&self) -> Option<Instant> {
        if self.enabled {
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Complete timing measurement and record it
    pub fn record_measurement(
        &self,
        start_time: Option<Instant>,
        operation: HsmOperation,
        data_size: usize,
    ) {
        if !self.enabled {
            return;
        }

        if let Some(start) = start_time {
            let duration = start.elapsed();
            let measurement = HsmMeasurement {
                operation,
                duration,
                timestamp: start,
                data_size,
            };

            if let Ok(mut measurements) = self.measurements.lock() {
                // Add new measurement
                measurements.push_back(measurement);

                // Remove oldest if over capacity
                if measurements.len() > self.max_measurements {
                    measurements.pop_front();
                }
            }
        }
    }

    /// Get statistics for a specific operation
    pub fn get_stats(&self, operation: HsmOperation) -> Option<HsmStats> {
        let measurements = self.measurements.lock().ok()?;

        let mut durations: Vec<Duration> = measurements
            .iter()
            .filter(|m| m.operation == operation)
            .map(|m| m.duration)
            .collect();

        if durations.is_empty() {
            return None;
        }

        durations.sort();

        let count = durations.len();
        let min = durations[0];
        let max = durations[count - 1];
        let total: Duration = durations.iter().sum();
        let avg = total / count as u32;

        let p50_idx = (count as f64 * 0.50) as usize;
        let p95_idx = (count as f64 * 0.95) as usize;
        let p99_idx = (count as f64 * 0.99) as usize;

        Some(HsmStats {
            operation,
            count,
            min,
            max,
            avg,
            total,
            p50: durations[p50_idx.min(count - 1)],
            p95: durations[p95_idx.min(count - 1)],
            p99: durations[p99_idx.min(count - 1)],
        })
    }

    /// Get all statistics grouped by operation
    pub fn get_all_stats(&self) -> Vec<HsmStats> {
        use HsmOperation::*;
        vec![GenerateMac, VerifyMac, CalculateCrc, VerifyCrc]
            .into_iter()
            .filter_map(|op| self.get_stats(op))
            .collect()
    }

    /// Display all statistics
    pub fn display_stats(&self) {
        println!("\n┌─────────────────────────────────────────┐");
        println!("│   HSM Performance Statistics            │");
        println!("└─────────────────────────────────────────┘");

        let stats = self.get_all_stats();

        if stats.is_empty() {
            println!("  No measurements recorded yet.");
        } else {
            for stat in stats {
                stat.display();
                println!();
            }
        }
    }

    /// Get total number of measurements
    pub fn measurement_count(&self) -> usize {
        self.measurements.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Clear all measurements
    pub fn clear(&self) {
        if let Ok(mut measurements) = self.measurements.lock() {
            measurements.clear();
        }
    }

    /// Get summary string for display
    pub fn get_summary(&self) -> String {
        let stats = self.get_all_stats();
        if stats.is_empty() {
            return "No HSM measurements".to_string();
        }

        let mut summary = String::new();
        for stat in stats {
            summary.push_str(&format!(
                "{}: avg={} ",
                stat.operation.as_str(),
                HsmStats::format_duration(&stat.avg)
            ));
        }
        summary
    }

    /// Export measurements to CSV format
    pub fn export_csv(&self) -> String {
        let measurements = match self.measurements.lock() {
            Ok(m) => m,
            Err(_) => return String::new(),
        };

        let mut csv = String::from("operation,duration_us,data_size,timestamp_us\n");

        for m in measurements.iter() {
            csv.push_str(&format!(
                "{},{},{},{}\n",
                m.operation.as_str(),
                m.duration.as_micros(),
                m.data_size,
                m.timestamp.elapsed().as_micros()
            ));
        }

        csv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_performance_evaluator_basic() {
        let evaluator = HsmPerformanceEvaluator::new(100);

        // Simulate some operations
        let start = evaluator.start_measurement();
        thread::sleep(Duration::from_micros(10));
        evaluator.record_measurement(start, HsmOperation::GenerateMac, 64);

        let start = evaluator.start_measurement();
        thread::sleep(Duration::from_micros(20));
        evaluator.record_measurement(start, HsmOperation::VerifyMac, 64);

        assert_eq!(evaluator.measurement_count(), 2);

        let stats = evaluator.get_stats(HsmOperation::GenerateMac);
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.count, 1);
        assert!(stats.avg.as_micros() >= 10);
    }

    #[test]
    fn test_disabled_evaluator() {
        let evaluator = HsmPerformanceEvaluator::disabled();

        let start = evaluator.start_measurement();
        assert!(start.is_none());

        evaluator.record_measurement(start, HsmOperation::GenerateMac, 64);
        assert_eq!(evaluator.measurement_count(), 0);
    }

    #[test]
    fn test_max_measurements_limit() {
        let evaluator = HsmPerformanceEvaluator::new(5);

        // Add 10 measurements
        for _ in 0..10 {
            let start = evaluator.start_measurement();
            evaluator.record_measurement(start, HsmOperation::GenerateMac, 64);
        }

        // Should only keep 5
        assert_eq!(evaluator.measurement_count(), 5);
    }

    #[test]
    fn test_statistics_calculation() {
        let evaluator = HsmPerformanceEvaluator::new(100);

        // Add known durations
        for micros in [10, 20, 30, 40, 50] {
            let measurements = Arc::clone(&evaluator.measurements);
            let mut lock = measurements.lock().unwrap();
            lock.push_back(HsmMeasurement {
                operation: HsmOperation::GenerateMac,
                duration: Duration::from_micros(micros),
                timestamp: Instant::now(),
                data_size: 64,
            });
        }

        let stats = evaluator.get_stats(HsmOperation::GenerateMac).unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min.as_micros(), 10);
        assert_eq!(stats.max.as_micros(), 50);
        assert_eq!(stats.avg.as_micros(), 30);
    }
}
