use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::time::Duration;
use vhsm_can::types::{ArmVariant, CanFrame, CanId, EcuConfig};

const ECU_NAME: &str = "OUTPUT_ECU";
const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::Clear(ClearType::All))?;

    let config = EcuConfig {
        name: ECU_NAME.to_string(),
        bus_address: BUS_ADDRESS.to_string(),
        arm_variant: ArmVariant::CortexM7,
    };

    draw_ui(&mut stdout, &config)?;

    let mut received_count = 0u64;
    let mut last_received: Vec<String> = Vec::new();

    // TODO: Connect to bus when integrated
    loop {
        // Check for user input (q to quit)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Simulate receiving frames (will be replaced with actual bus connection)
        // For now, just keep the UI alive
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Cleanup
    terminal::disable_raw_mode()?;
    execute!(stdout, terminal::Clear(ClearType::All))?;
    execute!(stdout, cursor::MoveTo(0, 0))?;
    println!("Output ECU stopped.");

    Ok(())
}

fn draw_ui(stdout: &mut io::Stdout, config: &EcuConfig) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 0))?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".blue().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "                          OUTPUT ECU                                          ".blue().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".blue().bold()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "ECU Name".bright_white().bold(),
        config.name.blue()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "Processor".bright_white().bold(),
        config.arm_variant.as_str().blue()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "Bus Addr".bright_white().bold(),
        config.bus_address.blue()
    )?;
    writeln!(stdout, "\r")?;
    writeln!(
        stdout,
        "\r{}",
        "───────────────────────────────────────────────────────────────────────────────".bright_black()
    )?;
    writeln!(stdout, "\r{}", "RECEIVED FRAMES:".cyan().bold())?;
    writeln!(
        stdout,
        "\r{}",
        "(Listening for CAN frames...)".bright_black()
    )?;
    writeln!(stdout, "\r")?;
    stdout.flush()?;
    Ok(())
}

fn update_received_area(stdout: &mut io::Stdout, received: &[String]) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 10))?;
    execute!(stdout, terminal::Clear(ClearType::FromCursorDown))?;

    for msg in received {
        writeln!(stdout, "\r{}", msg.bright_cyan())?;
    }

    stdout.flush()?;
    Ok(())
}

fn format_received_frame(frame: &CanFrame, count: u64) -> String {
    let id_str = match frame.id {
        CanId::Standard(id) => format!("{:03X}", id),
        CanId::Extended(id) => format!("{:08X}", id),
    };

    let data_str = frame
        .data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "[{}] #{:05} │ ID: {} │ Data: [{}] │ From: {}",
        frame.timestamp.format("%H:%M:%S"),
        count,
        id_str,
        data_str,
        frame.source
    )
}
