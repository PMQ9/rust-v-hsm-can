use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::time::Duration;
use tokio::sync::mpsc;
use vhsm_can::network::{BusClient, NetMessage};
use vhsm_can::types::{ArmVariant, CanFrame, CanId, EcuConfig};

const ECU_NAME: &str = "OUTPUT_ECU";
const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    // Connect to bus server
    writeln!(stdout, "\r\nConnecting to CAN bus at {}...\r", BUS_ADDRESS)?;
    stdout.flush()?;

    let client = match BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            terminal::disable_raw_mode()?;
            eprintln!("\r\n{}Failed to connect: {}{}", "✗ ".red(), e, "".clear());
            eprintln!("\r\nStart the bus server with: cargo run --bin bus_server");
            return Ok(());
        }
    };

    writeln!(stdout, "\r{}Connected to CAN bus!{}\r", "✓ ".green(), "".clear())?;
    stdout.flush()?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    execute!(stdout, terminal::Clear(ClearType::All))?;
    draw_ui(&mut stdout, &config)?;

    // Split the client
    let (mut reader, _writer) = client.split();

    let mut received_count = 0u64;
    let mut last_received: Vec<String> = Vec::new();

    // Create a channel to receive frames from the network task
    let (frame_tx, mut frame_rx) = mpsc::channel::<CanFrame>(100);

    // Spawn network reader task
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::CanFrame(frame)) => {
                    if frame_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    loop {
        // Check for user input (q to quit)
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Try to receive frames
        match frame_rx.try_recv() {
            Ok(frame) => {
                received_count += 1;
                let frame_str = format_received_frame(&frame, received_count);
                last_received.push(frame_str);

                // Keep only last 15 frames
                if last_received.len() > 15 {
                    last_received.remove(0);
                }

                update_received_area(&mut stdout, &last_received)?;
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => {
                break;
            }
        }
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
        writeln!(stdout, "\r{}", msg)?;
    }

    stdout.flush()?;
    Ok(())
}

fn format_received_frame(frame: &CanFrame, count: u64) -> String {
    let id_str = match frame.id {
        CanId::Standard(id) => format!("{:03X}", id).yellow(),
        CanId::Extended(id) => format!("{:08X}", id).magenta(),
    };

    let data_str = frame
        .data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    let time_str = frame.timestamp.format("%H:%M:%S%.3f").to_string().bright_black();

    format!(
        "[{}] {} │ ID: {} │ DLC: {} │ Data: [{}] │ From: {}",
        time_str,
        format!("#{:04}", count).blue().bold(),
        id_str,
        format!("{}", frame.data.len()).green(),
        data_str.bright_white(),
        frame.source.bright_cyan()
    )
}
