use colored::*;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "       AUTONOMOUS VEHICLE SIMULATION - LAUNCHER               "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    if perf_mode {
        println!("{} Performance evaluation mode enabled", "ℹ".bright_blue());
        println!(
            "{} All ECUs will track HSM performance metrics",
            "→".bright_blue()
        );
    }
    println!();

    // Cleanup: Kill any old simulation processes first
    println!("{} Cleaning up old processes...", "→".yellow());
    let cleanup = Command::new("pkill")
        .args(&[
            "-f",
            "target/debug/(bus_server|autonomous_controller|wheel|engine|steering|brake|monitor)",
        ])
        .output();

    match cleanup {
        Ok(_) => {
            println!("{} Old processes cleaned up", "✓".green());
            thread::sleep(Duration::from_millis(500)); // Wait for processes to die
        }
        Err(_) => {
            println!(
                "{} No old processes found (or pkill unavailable)",
                "→".bright_black()
            );
        }
    }
    println!();

    let mut processes: Vec<Child> = Vec::new();

    // Start bus server first
    println!("{} Starting CAN bus server...", "→".green());
    let mut bus_cmd = Command::new("cargo");
    bus_cmd.args(&["run", "--bin", "bus_server"]);
    if perf_mode {
        bus_cmd.args(&["--", "--perf"]);
    }
    match bus_cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Ok(child) => {
            processes.push(child);
            println!("{} Bus server started", "✓".green().bold());
        }
        Err(e) => {
            eprintln!("{} Failed to start bus server: {}", "✗".red().bold(), e);
            return;
        }
    }

    // Wait for bus server to be ready
    println!("{} Waiting for bus server to be ready...", "→".yellow());
    thread::sleep(Duration::from_secs(2));

    // Start all sensor ECUs
    println!("\n{} Starting sensor ECUs...", "→".green());
    let sensors = vec![
        "wheel_fl",
        "wheel_fr",
        "wheel_rl",
        "wheel_rr",
        "engine_ecu",
        "steering_sensor",
    ];

    for sensor in &sensors {
        let mut sensor_cmd = Command::new("cargo");
        sensor_cmd.args(&["run", "--bin", sensor]);
        if perf_mode {
            sensor_cmd.args(&["--", "--perf"]);
        }
        match sensor_cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => {
                processes.push(child);
                println!("  {} {} started", "✓".green(), sensor);
            }
            Err(e) => {
                eprintln!("  {} Failed to start {}: {}", "✗".red(), sensor, e);
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    // Start autonomous controller
    println!("\n{} Starting autonomous controller...", "→".green());
    let mut controller_cmd = Command::new("cargo");
    controller_cmd.args(&["run", "--bin", "autonomous_controller"]);
    if perf_mode {
        controller_cmd.args(&["--", "--perf"]);
        println!("{} Performance tracking enabled", "→".bright_blue());
    }

    // Suppress controller stdout (monitor will display performance stats in perf mode)
    match controller_cmd
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()) // Allow stderr to pass through for attack warnings
        .spawn()
    {
        Ok(child) => {
            processes.push(child);
            println!("{} Autonomous controller started", "✓".green().bold());
        }
        Err(e) => {
            eprintln!(
                "{} Failed to start autonomous controller: {}",
                "✗".red().bold(),
                e
            );
        }
    }
    thread::sleep(Duration::from_millis(500));

    // Start actuator ECUs
    println!("\n{} Starting actuator ECUs...", "→".green());
    let actuators = vec!["brake_controller", "steering_controller"];

    for actuator in &actuators {
        let mut actuator_cmd = Command::new("cargo");
        actuator_cmd.args(&["run", "--bin", actuator]);
        if perf_mode {
            actuator_cmd.args(&["--", "--perf"]);
        }
        match actuator_cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => {
                processes.push(child);
                println!("  {} {} started", "✓".green(), actuator);
            }
            Err(e) => {
                eprintln!("  {} Failed to start {}: {}", "✗".red(), actuator, e);
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    // Give ECUs time to connect and start sending data
    println!(
        "\n{} Waiting for ECUs to connect and start transmitting...",
        "→".yellow()
    );
    thread::sleep(Duration::from_secs(3));

    // Start monitor (displays dashboard + performance stats if in perf mode)
    if perf_mode {
        println!();
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════"
                .bright_blue()
                .bold()
        );
        println!("{} PERFORMANCE MODE ENABLED", "→".bright_blue().bold());
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════"
                .bright_blue()
                .bold()
        );
        println!(
            "{} Performance stats will be shown in monitor dashboard",
            "ℹ".bright_blue()
        );
        println!(
            "{} Statistics update every 10 seconds (100 iterations)",
            "ℹ".bright_blue()
        );
        println!("{} Press 'q' in monitor to exit", "ℹ".bright_blue());
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════"
                .bright_blue()
                .bold()
        );
        println!();
    }

    println!("{} Starting monitor (dashboard)...", "→".green());

    let mut monitor_process = match Command::new("cargo")
        .args(&["run", "--bin", "monitor"])
        .spawn()
    {
        Ok(child) => {
            println!(
                "{} Monitor started - displaying dashboard...\n",
                "✓".green().bold()
            );
            thread::sleep(Duration::from_millis(500));
            child
        }
        Err(e) => {
            eprintln!("{} Failed to start monitor: {}", "✗".red().bold(), e);
            // Kill all background processes
            for mut process in processes {
                let _ = process.kill();
            }
            return;
        }
    };

    // Wait for monitor to exit (user presses 'q')
    let _ = monitor_process.wait();

    // Cleanup: kill all child processes
    for mut process in processes {
        let _ = process.kill();
        let _ = process.wait();
    }
}
