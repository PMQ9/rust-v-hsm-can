use colored::*;
use serde::{Deserialize, Serialize};

/// Performance metrics for HSM operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    /// Total MAC generation operations
    pub mac_gen_count: u64,
    /// Total time spent generating MACs (microseconds)
    pub mac_gen_time_us: u64,

    /// Total MAC verification operations
    pub mac_verify_count: u64,
    /// Total time spent verifying MACs (microseconds)
    pub mac_verify_time_us: u64,

    /// Total CRC calculation operations
    pub crc_calc_count: u64,
    /// Total time spent calculating CRCs (microseconds)
    pub crc_calc_time_us: u64,

    /// Total CRC verification operations
    pub crc_verify_count: u64,
    /// Total time spent verifying CRCs (microseconds)
    pub crc_verify_time_us: u64,

    /// Total frame creation operations
    pub frame_create_count: u64,
    /// Total time spent creating secured frames (microseconds)
    pub frame_create_time_us: u64,

    /// Total frame verification operations
    pub frame_verify_count: u64,
    /// Total time spent verifying secured frames (microseconds)
    pub frame_verify_time_us: u64,

    /// End-to-end latency samples (microseconds)
    pub e2e_latency_samples: Vec<u64>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Print performance statistics
    pub fn print_stats(&self, ecu_name: &str) {
        println!(
            "\n{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );
        println!(
            "{} HSM Performance Statistics for {}",
            "ℹ".bright_blue(),
            ecu_name.bright_white().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );

        if self.mac_gen_count > 0 {
            let avg_mac_gen = self.mac_gen_time_us as f64 / self.mac_gen_count as f64;
            println!(
                "MAC Generation:    {} ops, avg {:.2} μs/op",
                self.mac_gen_count, avg_mac_gen
            );
        }

        if self.mac_verify_count > 0 {
            let avg_mac_verify = self.mac_verify_time_us as f64 / self.mac_verify_count as f64;
            println!(
                "MAC Verification:  {} ops, avg {:.2} μs/op",
                self.mac_verify_count, avg_mac_verify
            );
        }

        if self.crc_calc_count > 0 {
            let avg_crc_calc = self.crc_calc_time_us as f64 / self.crc_calc_count as f64;
            println!(
                "CRC Calculation:   {} ops, avg {:.2} μs/op",
                self.crc_calc_count, avg_crc_calc
            );
        }

        if self.crc_verify_count > 0 {
            let avg_crc_verify = self.crc_verify_time_us as f64 / self.crc_verify_count as f64;
            println!(
                "CRC Verification:  {} ops, avg {:.2} μs/op",
                self.crc_verify_count, avg_crc_verify
            );
        }

        if self.frame_create_count > 0 {
            let avg_frame_create =
                self.frame_create_time_us as f64 / self.frame_create_count as f64;
            println!(
                "Frame Creation:    {} ops, avg {:.2} μs/op",
                self.frame_create_count, avg_frame_create
            );
        }

        if self.frame_verify_count > 0 {
            let avg_frame_verify =
                self.frame_verify_time_us as f64 / self.frame_verify_count as f64;
            println!(
                "Frame Verification: {} ops, avg {:.2} μs/op",
                self.frame_verify_count, avg_frame_verify
            );
        }

        if !self.e2e_latency_samples.is_empty() {
            let avg_e2e = self.e2e_latency_samples.iter().sum::<u64>() as f64
                / self.e2e_latency_samples.len() as f64;
            let min_e2e = *self.e2e_latency_samples.iter().min().unwrap_or(&0);
            let max_e2e = *self.e2e_latency_samples.iter().max().unwrap_or(&0);
            println!(
                "\nEnd-to-End Latency: {} samples",
                self.e2e_latency_samples.len()
            );
            println!("  Average: {:.2} μs ({:.3} ms)", avg_e2e, avg_e2e / 1000.0);
            println!(
                "  Min:     {} μs ({:.3} ms)",
                min_e2e,
                min_e2e as f64 / 1000.0
            );
            println!(
                "  Max:     {} μs ({:.3} ms)",
                max_e2e,
                max_e2e as f64 / 1000.0
            );
        }

        println!(
            "{}",
            "═══════════════════════════════════════════════════════".bright_blue()
        );
    }
}

/// Simplified performance snapshot for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub ecu_name: String,
    pub mac_gen_count: u64,
    pub mac_gen_avg_us: f64,
    pub mac_verify_count: u64,
    pub mac_verify_avg_us: f64,
    pub crc_calc_count: u64,
    pub crc_calc_avg_us: f64,
    pub crc_verify_count: u64,
    pub crc_verify_avg_us: f64,
    pub frame_create_count: u64,
    pub frame_create_avg_us: f64,
    pub frame_verify_count: u64,
    pub frame_verify_avg_us: f64,
    pub e2e_latency_avg_us: f64,
    pub e2e_latency_min_us: u64,
    pub e2e_latency_max_us: u64,
    pub e2e_sample_count: u64,
}
