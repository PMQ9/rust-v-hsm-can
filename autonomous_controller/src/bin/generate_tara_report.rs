/// TARA Report Generation Tool
///
/// Generates ISO 21434 Threat Analysis and Risk Assessment documentation
/// for the V-HSM CAN Bus Security System.
use autonomous_vehicle_sim::TaraGenerator;
use chrono::Utc;
use colored::*;

fn main() {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bright_magenta()
            .bold()
    );
    println!(
        "{}",
        "         ISO 21434 TARA REPORT GENERATOR                   "
            .bright_magenta()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bright_magenta()
            .bold()
    );
    println!();

    // Create TARA generator
    let mut generator = TaraGenerator::new(
        "V-HSM CAN Bus Security System".to_string(),
        "1.0.0".to_string(),
        "Security Engineering Team".to_string(),
        "Automotive Security Research Lab".to_string(),
    );

    println!("{} Generating automotive threat scenarios...", "→".cyan());
    generator.generate_automotive_threats();

    println!("{} Analyzing threats and calculating risks...", "→".cyan());
    let analysis = generator.generate_analysis();

    println!("{} Generating TARA report...", "→".cyan());
    let report = generator.export_report();

    // Print summary
    println!();
    println!("{}", "TARA SUMMARY".bright_white().bold());
    println!(
        "{}",
        "─────────────────────────────────────────".bright_white()
    );
    println!(
        "Total Threats: {}",
        analysis.risk_summary.total_threats.to_string().yellow()
    );
    println!(
        "High/Critical Risk: {}",
        analysis
            .risk_summary
            .high_risk_count
            .to_string()
            .red()
            .bold()
    );
    println!(
        "Medium Risk: {}",
        analysis.risk_summary.medium_risk_count.to_string().yellow()
    );
    println!(
        "Low Risk: {}",
        analysis.risk_summary.low_risk_count.to_string().green()
    );
    println!();

    // Save to file
    let filename = format!("tara_report_{}.txt", Utc::now().format("%Y%m%d_%H%M%S"));
    if let Err(e) = std::fs::write(&filename, &report) {
        eprintln!("{} Failed to save TARA report: {}", "✗".red(), e);
        std::process::exit(1);
    }

    println!(
        "{} TARA report saved to: {}",
        "✓".green(),
        filename.bright_white().bold()
    );
    println!();
}
