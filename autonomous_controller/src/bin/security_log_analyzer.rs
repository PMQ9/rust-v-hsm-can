/// Security Log Analyzer Tool
///
/// Verifies the integrity of security audit logs and provides analysis of security events.
use autonomous_vehicle_sim::security_log::{SecurityEvent, SecurityLogEntry, verify_log_file};
use colored::*;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

fn main() {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "         SECURITY LOG ANALYZER                        "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!();

    // Get log file path from command line
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!(
            "{} Usage: {} <log_file_path>",
            "ERROR:".red().bold(),
            args[0]
        );
        println!();
        println!("Examples:");
        println!("  {} security_logs/AUTONOMOUS_CTRL_*.jsonl", args[0]);
        println!("  {} security_logs/BRAKE_CTRL_*.jsonl", args[0]);
        std::process::exit(1);
    }

    let log_path = PathBuf::from(&args[1]);

    if !log_path.exists() {
        println!(
            "{} Log file not found: {}",
            "ERROR:".red().bold(),
            log_path.display()
        );
        std::process::exit(1);
    }

    println!("{} Analyzing log file: {}", "→".cyan(), log_path.display());
    println!();

    // Verify log integrity
    println!("{}", "INTEGRITY VERIFICATION".yellow().bold());
    println!(
        "{}",
        "─────────────────────────────────────────────────────".bright_black()
    );

    match verify_log_file(log_path.clone()) {
        Ok(result) => {
            println!("{} Total log entries: {}", "→".cyan(), result.total_entries);

            if result.verified {
                println!(
                    "{} {}",
                    "✓".green().bold(),
                    "Log integrity verified".green()
                );
                println!("   • All entry hashes are valid");
                println!("   • Chain integrity maintained");
                println!("   • No tampering detected");
            } else {
                println!(
                    "{} {}",
                    "✗".red().bold(),
                    "Log integrity FAILED".red().bold()
                );
                println!();
                println!("{} Issues detected:", "⚠".yellow());
                for issue in &result.issues {
                    println!("   • {}", issue.red());
                }
                println!();
                println!(
                    "{} {}",
                    "⚠".yellow(),
                    "This log may have been tampered with!".red().bold()
                );
            }
        }
        Err(e) => {
            println!("{} Verification error: {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    }

    println!();

    // Parse and analyze log entries
    println!("{}", "SECURITY EVENT ANALYSIS".yellow().bold());
    println!(
        "{}",
        "─────────────────────────────────────────────────────".bright_black()
    );

    match analyze_log_events(&log_path) {
        Ok(analysis) => {
            println!(
                "{} ECU: {}",
                "→".cyan(),
                analysis.ecu_name.bright_white().bold()
            );
            println!(
                "{} Time range: {} to {}",
                "→".cyan(),
                analysis.start_time.format("%Y-%m-%d %H:%M:%S"),
                analysis.end_time.format("%Y-%m-%d %H:%M:%S")
            );
            println!("{} Total events: {}", "→".cyan(), analysis.total_events);
            println!();

            println!("{}", "Event Type Breakdown:".bright_white());
            for (event_type, count) in &analysis.event_counts {
                println!("   • {}: {}", event_type, count);
            }
            println!();

            if analysis.attack_count > 0 {
                println!("{}", "ATTACKS DETECTED".red().bold());
                println!(
                    "   • Total attacks: {}",
                    analysis.attack_count.to_string().red().bold()
                );
                for attack in &analysis.attacks {
                    println!("   • {}", attack);
                }
                println!();
            }

            if analysis.verification_failures > 0 {
                println!("{}", "Verification Failures:".yellow());
                println!("   • Total failures: {}", analysis.verification_failures);
                println!("   • CRC failures: {}", analysis.crc_failures);
                println!("   • MAC failures: {}", analysis.mac_failures);
                println!("   • Unsecured frames: {}", analysis.unsecured_frames);
                println!();
            }

            if analysis.state_changes > 0 {
                println!("{}", "Security State Changes:".yellow());
                println!("   • Total state changes: {}", analysis.state_changes);
                for (i, change) in analysis.state_change_list.iter().enumerate() {
                    println!("   {}: {}", i + 1, change);
                }
                println!();
            }

            println!("{}", "Summary:".bright_white().bold());
            if analysis.attack_count > 0 {
                println!(
                    "   {} {}",
                    "⚠".red(),
                    format!(
                        "This ECU detected {} attack(s) during the logged period",
                        analysis.attack_count
                    )
                    .red()
                    .bold()
                );
            } else if analysis.verification_failures > 0 {
                println!(
                    "   {} {}",
                    "⚠".yellow(),
                    "Verification failures detected but no attacks triggered".yellow()
                );
            } else {
                println!(
                    "   {} {}",
                    "✓".green(),
                    "No security issues detected".green()
                );
            }
        }
        Err(e) => {
            println!("{} Analysis error: {}", "ERROR:".red().bold(), e);
        }
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════".cyan()
    );
    println!();
}

#[derive(Debug)]
struct LogAnalysis {
    ecu_name: String,
    start_time: chrono::DateTime<chrono::Utc>,
    end_time: chrono::DateTime<chrono::Utc>,
    total_events: usize,
    event_counts: HashMap<String, usize>,
    attack_count: usize,
    attacks: Vec<String>,
    verification_failures: usize,
    crc_failures: usize,
    mac_failures: usize,
    unsecured_frames: usize,
    state_changes: usize,
    state_change_list: Vec<String>,
}

fn analyze_log_events(log_path: &PathBuf) -> Result<LogAnalysis, String> {
    let file = File::open(log_path).map_err(|e| format!("Failed to open log: {}", e))?;
    let reader = BufReader::new(file);

    let mut entries: Vec<SecurityLogEntry> = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Line {} read error: {}", line_num + 1, e))?;
        let entry: SecurityLogEntry = serde_json::from_str(&line)
            .map_err(|e| format!("Line {} parse error: {}", line_num + 1, e))?;
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err("No entries found in log".to_string());
    }

    let ecu_name = entries[0].ecu_id.clone();
    let start_time = entries[0].timestamp;
    let end_time = entries.last().unwrap().timestamp;

    let mut event_counts: HashMap<String, usize> = HashMap::new();
    let mut attack_count = 0;
    let mut attacks = Vec::new();
    let mut verification_failures = 0;
    let mut crc_failures = 0;
    let mut mac_failures = 0;
    let mut unsecured_frames = 0;
    let mut state_changes = 0;
    let mut state_change_list = Vec::new();

    for entry in &entries {
        // Count event types
        let event_type = match &entry.event {
            SecurityEvent::SystemStartup { .. } => "SystemStartup",
            SecurityEvent::VerificationFailure { .. } => "VerificationFailure",
            SecurityEvent::VerificationSuccess { .. } => "VerificationSuccess",
            SecurityEvent::StateChange { .. } => "StateChange",
            SecurityEvent::AttackDetected { .. } => "AttackDetected",
            SecurityEvent::FrameRejected { .. } => "FrameRejected",
            SecurityEvent::FailSafeActivated { .. } => "FailSafeActivated",
            SecurityEvent::SecurityReset { .. } => "SecurityReset",
            SecurityEvent::KeyRegistration { .. } => "KeyRegistration",
            SecurityEvent::StatisticsSnapshot { .. } => "StatisticsSnapshot",
            SecurityEvent::UnauthorizedTransmit { .. } => "UnauthorizedTransmit",
            SecurityEvent::UnauthorizedReceive { .. } => "UnauthorizedReceive",
            SecurityEvent::AccessControlLoaded { .. } => "AccessControlLoaded",
        };

        *event_counts.entry(event_type.to_string()).or_insert(0) += 1;

        // Analyze specific events
        match &entry.event {
            SecurityEvent::VerificationFailure { error_type, .. } => {
                verification_failures += 1;
                match error_type.as_str() {
                    "CRC_MISMATCH" => crc_failures += 1,
                    "MAC_MISMATCH" => mac_failures += 1,
                    "UNSECURED_FRAME" => unsecured_frames += 1,
                    _ => {}
                }
            }
            SecurityEvent::AttackDetected { attack_type, .. } => {
                attack_count += 1;
                attacks.push(format!(
                    "{} - Attack type: {}",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    attack_type
                ));
            }
            SecurityEvent::StateChange {
                from_state,
                to_state,
                trigger,
            } => {
                state_changes += 1;
                state_change_list.push(format!("{} -> {} ({})", from_state, to_state, trigger));
            }
            _ => {}
        }
    }

    Ok(LogAnalysis {
        ecu_name,
        start_time,
        end_time,
        total_events: entries.len(),
        event_counts,
        attack_count,
        attacks,
        verification_failures,
        crc_failures,
        mac_failures,
        unsecured_frames,
        state_changes,
        state_change_list,
    })
}
