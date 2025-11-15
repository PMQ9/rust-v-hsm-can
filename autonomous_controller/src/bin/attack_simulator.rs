/// Attack Simulator CLI
///
/// Unified command-line interface for running various CAN bus attack simulations.
/// This tool is designed for security research, penetration testing, and educational purposes.
///
/// SECURITY RESEARCH ONLY: Use only on authorized test systems.
use autonomous_vehicle_sim::{AttackConfig, AttackSimulator, AttackType};
use colored::*;
use std::process;

const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let attack_type_str = &args[1];

    // Parse attack type
    let attack_type = match attack_type_str.to_lowercase().as_str() {
        "injection" | "inject" => AttackType::Injection,
        "replay" => AttackType::Replay,
        "flooding" | "flood" | "dos" => AttackType::Flooding,
        "spoofing" | "spoof" => AttackType::Spoofing,
        "fuzzing" | "fuzz" => AttackType::Fuzzing,
        "combined" | "multi" => AttackType::Combined,
        _ => {
            eprintln!("{} Unknown attack type: {}", "✗".red(), attack_type_str);
            print_usage();
            process::exit(1);
        }
    };

    // Parse optional parameters
    let mut config = AttackConfig {
        attack_type,
        attacker_name: format!("ATTACKER_{}", attack_type_str.to_uppercase()),
        ..Default::default()
    };

    // Parse additional arguments
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--duration" | "-d" => {
                if i + 1 < args.len() {
                    config.duration_secs = Some(args[i + 1].parse().unwrap_or(60));
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --duration", "✗".red());
                    process::exit(1);
                }
            }
            "--rate" | "-r" => {
                if i + 1 < args.len() {
                    config.frames_per_second = args[i + 1].parse().unwrap_or(100);
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --rate", "✗".red());
                    process::exit(1);
                }
            }
            "--malform" | "-m" => {
                if i + 1 < args.len() {
                    config.malform_percentage = args[i + 1].parse().unwrap_or(50);
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --malform", "✗".red());
                    process::exit(1);
                }
            }
            "--target" | "-t" => {
                if i + 1 < args.len() {
                    if let Ok(can_id) =
                        u32::from_str_radix(args[i + 1].trim_start_matches("0x"), 16)
                    {
                        config.target_can_ids.push(can_id);
                    }
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --target", "✗".red());
                    process::exit(1);
                }
            }
            "--capture" | "-c" => {
                if i + 1 < args.len() {
                    config.capture_duration_secs = args[i + 1].parse().unwrap_or(10);
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --capture", "✗".red());
                    process::exit(1);
                }
            }
            "--name" | "-n" => {
                if i + 1 < args.len() {
                    config.attacker_name = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("{} Missing value for --name", "✗".red());
                    process::exit(1);
                }
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                eprintln!("{} Unknown option: {}", "✗".red(), args[i]);
                print_usage();
                process::exit(1);
            }
        }
    }

    print_banner(&config);

    // Create and connect simulator
    let mut simulator = AttackSimulator::new(config.clone());

    println!("{} Connecting to CAN bus at {}...", "→".cyan(), BUS_ADDRESS);
    match simulator.connect(BUS_ADDRESS).await {
        Ok(_) => println!(
            "{} Connected as {}",
            "✓".green().bold(),
            config.attacker_name.bright_yellow()
        ),
        Err(e) => {
            eprintln!("{} Failed to connect: {}", "✗".red(), e);
            process::exit(1);
        }
    }

    println!();
    println!("{}", "Starting attack simulation...".red().bold());
    print_attack_details(&config);
    println!();

    // Execute attack
    match simulator.execute().await {
        Ok(stats) => {
            println!();
            println!("{}", "═══════════════════════════════════════".green());
            println!(
                "{}",
                "   Attack Simulation Completed        ".green().bold()
            );
            println!("{}", "═══════════════════════════════════════".green());
            println!();
            println!(
                "  Frames sent:       {}",
                stats.frames_sent.to_string().bright_white()
            );
            println!(
                "  Frames captured:   {}",
                stats.frames_captured.to_string().bright_white()
            );
            println!(
                "  Errors:            {}",
                stats.errors_encountered.to_string().bright_white()
            );
            println!(
                "  Duration:          {} seconds",
                stats.duration_secs.to_string().bright_white()
            );
            println!(
                "  Avg rate:          {:.2} frames/sec",
                stats.frames_per_second().to_string().bright_white()
            );
            println!();
        }
        Err(e) => {
            eprintln!();
            eprintln!("{} Attack simulation failed: {}", "✗".red(), e);
            process::exit(1);
        }
    }

    Ok(())
}

fn print_banner(config: &AttackConfig) {
    println!();
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!("{}", "    CAN Bus Attack Simulator v1.0      ".red().bold());
    println!("{}", "═══════════════════════════════════════".red().bold());
    println!();
    println!("{}", "⚠️  WARNING: Security Research Tool".yellow());
    println!("{}", "⚠️  Only use on authorized test systems".yellow());
    println!("{}", "⚠️  Unauthorized use may be illegal".yellow());
    println!();
    println!(
        "Attack Type: {}",
        format!("{:?}", config.attack_type).bright_red().bold()
    );
    println!();
}

fn print_attack_details(config: &AttackConfig) {
    println!("{}", "Attack Configuration:".bright_white().bold());
    println!(
        "  {} Duration:        {} seconds",
        "→".cyan(),
        config
            .duration_secs
            .map(|d| d.to_string())
            .unwrap_or_else(|| "infinite".to_string())
            .bright_white()
    );
    println!(
        "  {} Rate:           {} frames/sec",
        "→".cyan(),
        config.frames_per_second.to_string().bright_white()
    );

    if !config.target_can_ids.is_empty() {
        print!("  {} Target IDs:     ", "→".cyan());
        for (i, id) in config.target_can_ids.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", format!("0x{:03X}", id).bright_white());
        }
        println!();
    } else {
        println!("  {} Target IDs:     All", "→".cyan());
    }

    match config.attack_type {
        AttackType::Fuzzing => {
            println!(
                "  {} Malform rate:   {}%",
                "→".cyan(),
                config.malform_percentage.to_string().bright_white()
            );
        }
        AttackType::Replay => {
            println!(
                "  {} Capture time:   {} seconds",
                "→".cyan(),
                config.capture_duration_secs.to_string().bright_white()
            );
        }
        _ => {}
    }
}

fn print_usage() {
    println!();
    println!("{}", "CAN Bus Attack Simulator".bold());
    println!();
    println!("USAGE:");
    println!("    {} <ATTACK_TYPE> [OPTIONS]", "attack_simulator".green());
    println!();
    println!("ATTACK TYPES:");
    println!(
        "    {}         Inject malicious CAN frames with fake sensor data",
        "injection".yellow()
    );
    println!(
        "    {}            Capture and replay legitimate frames",
        "replay".yellow()
    );
    println!(
        "    {}          Flood the bus with high-priority frames (DoS)",
        "flooding".yellow()
    );
    println!(
        "    {}          Spoof legitimate ECU identities",
        "spoofing".yellow()
    );
    println!(
        "    {}           Send random/malformed frames (fuzzing)",
        "fuzzing".yellow()
    );
    println!(
        "    {}          Combined multi-stage attack",
        "combined".yellow()
    );
    println!();
    println!("OPTIONS:");
    println!(
        "    {} <SECS>       Duration in seconds (default: 60)",
        "-d, --duration".green()
    );
    println!(
        "    {} <NUM>          Frames per second (default: 100)",
        "-r, --rate".green()
    );
    println!(
        "    {} <PERCENT>    Malformed frame percentage for fuzzing (default: 50)",
        "-m, --malform".green()
    );
    println!(
        "    {} <ID>        Target CAN ID in hex (can specify multiple)",
        "-t, --target".green()
    );
    println!(
        "    {} <SECS>      Capture duration for replay attack (default: 10)",
        "-c, --capture".green()
    );
    println!(
        "    {} <NAME>        Custom attacker name (default: ATTACKER_*)",
        "-n, --name".green()
    );
    println!(
        "    {}              Show this help message",
        "-h, --help".green()
    );
    println!();
    println!("EXAMPLES:");
    println!("    # Run fuzzing attack for 30 seconds at 200 fps with 75% malformed frames");
    println!(
        "    {} {} -d 30 -r 200 -m 75",
        "attack_simulator".green(),
        "fuzzing".yellow()
    );
    println!();
    println!("    # Run injection attack targeting brake command CAN ID");
    println!(
        "    {} {} -t 0x300 -d 60",
        "attack_simulator".green(),
        "injection".yellow()
    );
    println!();
    println!("    # Run replay attack with 15 second capture");
    println!(
        "    {} {} -c 15 -d 120",
        "attack_simulator".green(),
        "replay".yellow()
    );
    println!();
    println!("    # Run combined multi-stage attack");
    println!(
        "    {} {} -d 90",
        "attack_simulator".green(),
        "combined".yellow()
    );
    println!();
}
