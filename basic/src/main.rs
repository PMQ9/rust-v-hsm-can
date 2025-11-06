use colored::*;
use std::env;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use vhsm_can::can_bus::VirtualCanBus;
use vhsm_can::ecu::Ecu;
use vhsm_can::types::{ArmVariant, CanId, EcuConfig};

const LAUNCH_MODE_ENV: &str = "VHSM_LAUNCH_MODE";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in a specific launch mode
    if let Ok(mode) = env::var(LAUNCH_MODE_ENV) {
        match mode.as_str() {
            "bus_server" => run_bus_server().await?,
            "input_ecu" => run_input_ecu().await?,
            "output_ecu" => run_output_ecu().await?,
            "monitor" => run_monitor().await?,
            _ => {}
        }
        return Ok(());
    }

    // Main launcher mode
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "     Virtual CAN Bus with ARM-based ECU Emulators             "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!();
    println!("{} Initializing virtual CAN bus...", "→".green());

    // Detect available terminal emulator
    let terminal = detect_terminal();
    println!(
        "{} Detected terminal: {}",
        "→".green(),
        terminal.bright_white()
    );

    println!("{} Launching components...", "→".green());
    println!();

    // Get the current executable path
    let exe_path = env::current_exe()?;
    let cargo_bin = "cargo";

    // Launch bus server in background
    println!("  {} Starting CAN bus server...", "1.".yellow());
    let _bus_server = spawn_component_background(&exe_path, "bus_server")?;
    thread::sleep(Duration::from_millis(500));

    // Launch monitor
    println!("  {} Launching Monitor terminal...", "2.".yellow());
    spawn_terminal(&terminal, &exe_path, "monitor")?;
    thread::sleep(Duration::from_millis(300));

    // Launch input ECU
    println!("  {} Launching Input ECU terminal...", "3.".yellow());
    spawn_terminal(&terminal, &exe_path, "input_ecu")?;
    thread::sleep(Duration::from_millis(300));

    // Launch output ECU
    println!("  {} Launching Output ECU terminal...", "4.".yellow());
    spawn_terminal(&terminal, &exe_path, "output_ecu")?;

    println!();
    println!("{}", "✓ All components launched!".green().bold());
    println!();
    println!("Three terminal windows should now be open:");
    println!("  • {}", "CAN Bus Monitor".cyan());
    println!("  • {}", "Input ECU".green());
    println!("  • {}", "Output ECU".blue());
    println!();
    println!("Press 'q' in any window to quit that component.");
    println!();
    println!("The bus server will run until you stop it (Ctrl+C).");

    // Keep the bus server running
    run_bus_server().await?;

    Ok(())
}

async fn run_bus_server() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;

    println!("CAN Bus Server starting on 127.0.0.1:9000...");

    let bus = VirtualCanBus::new(1000);
    let listener = TcpListener::bind("127.0.0.1:9000").await?;

    println!("Bus server ready. Waiting for connections...");

    // For now, just keep the bus alive
    // In a full implementation, this would handle network connections
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn run_input_ecu() -> Result<(), Box<dyn std::error::Error>> {
    // This will be handled by the bin/input_ecu.rs
    Ok(())
}

async fn run_output_ecu() -> Result<(), Box<dyn std::error::Error>> {
    // This will be handled by the bin/output_ecu.rs
    Ok(())
}

async fn run_monitor() -> Result<(), Box<dyn std::error::Error>> {
    // This will be handled by the bin/monitor.rs
    Ok(())
}

fn detect_terminal() -> String {
    // Try to detect the terminal emulator
    if let Ok(term) = env::var("TERM_PROGRAM") {
        return term;
    }

    // Check for common terminal emulators
    let terminals = vec![
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "xterm",
        "alacritty",
        "kitty",
        "terminator",
    ];

    for term in terminals {
        if Command::new("which")
            .arg(term)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return term.to_string();
        }
    }

    "xterm".to_string() // fallback
}

fn spawn_terminal(
    terminal: &str,
    exe_path: &std::path::Path,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let exe_dir = exe_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or("Could not determine project directory")?;

    let title = match mode {
        "monitor" => "CAN Bus Monitor",
        "input_ecu" => "Input ECU",
        "output_ecu" => "Output ECU",
        _ => "VHSM Component",
    };

    // Build the command to run in the new terminal
    let run_cmd = format!(
        "cd '{}' && VHSM_LAUNCH_MODE={} cargo run --bin {} 2>/dev/null || cargo run --bin {}",
        exe_dir.display(),
        mode,
        mode,
        mode
    );

    match terminal {
        "gnome-terminal" => {
            Command::new("gnome-terminal")
                .arg("--title")
                .arg(title)
                .arg("--")
                .arg("bash")
                .arg("-c")
                .arg(&run_cmd)
                .spawn()?;
        }
        "konsole" => {
            Command::new("konsole")
                .arg("--title")
                .arg(title)
                .arg("-e")
                .arg("bash")
                .arg("-c")
                .arg(&run_cmd)
                .spawn()?;
        }
        "xfce4-terminal" => {
            Command::new("xfce4-terminal")
                .arg("--title")
                .arg(title)
                .arg("-e")
                .arg(format!("bash -c '{}'", run_cmd))
                .spawn()?;
        }
        "alacritty" => {
            Command::new("alacritty")
                .arg("-t")
                .arg(title)
                .arg("-e")
                .arg("bash")
                .arg("-c")
                .arg(&run_cmd)
                .spawn()?;
        }
        "kitty" => {
            Command::new("kitty")
                .arg("--title")
                .arg(title)
                .arg("bash")
                .arg("-c")
                .arg(&run_cmd)
                .spawn()?;
        }
        _ => {
            // Fallback to xterm
            Command::new("xterm")
                .arg("-title")
                .arg(title)
                .arg("-e")
                .arg("bash")
                .arg("-c")
                .arg(&run_cmd)
                .spawn()?;
        }
    }

    Ok(())
}

fn spawn_component_background(
    exe_path: &std::path::Path,
    mode: &str,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = Command::new(exe_path);
    cmd.env(LAUNCH_MODE_ENV, mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    Ok(cmd.spawn()?)
}
