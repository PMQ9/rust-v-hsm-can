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
use vhsm_can::types::{CanFrame, CanId};

const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::Clear(ClearType::All))?;

    // Draw header
    draw_header(&mut stdout)?;

    let mut frame_count = 0u64;
    let mut last_frames: Vec<String> = Vec::new();

    // Connect to the CAN bus server
    writeln!(stdout, "\r\nConnecting to CAN bus at {}...", BUS_ADDRESS)?;
    stdout.flush()?;

    // Wait for server to be available
    let mut connected = false;
    for attempt in 1..=10 {
        match tokio::time::timeout(
            Duration::from_millis(500),
            BusClient::connect(BUS_ADDRESS, "MONITOR".to_string())
        ).await {
            Ok(Ok(_client)) => {
                connected = true;
                break;
            }
            _ => {
                if attempt < 10 {
                    writeln!(stdout, "\r\nRetrying connection ({}/10)...", attempt)?;
                    stdout.flush()?;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    if !connected {
        terminal::disable_raw_mode()?;
        eprintln!("\r\n{}Failed to connect to bus server. Is it running?{}", "✗ ".red(), "".clear());
        eprintln!("\r\nStart the bus server with: cargo run --bin bus_server");
        return Ok(());
    }

    // Reconnect to get the client
    let client = BusClient::connect(BUS_ADDRESS, "MONITOR".to_string()).await?;
    writeln!(stdout, "\r\n{}Connected to CAN bus!{}", "✓ ".green(), "".clear())?;
    stdout.flush()?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    execute!(stdout, terminal::Clear(ClearType::All))?;
    draw_header(&mut stdout)?;

    // Split the client into reader and writer
    let (mut reader, _writer) = client.split();

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
                frame_count += 1;
                let frame_str = format_frame(&frame, frame_count);
                last_frames.push(frame_str.clone());

                // Keep only last 20 frames
                if last_frames.len() > 20 {
                    last_frames.remove(0);
                }

                // Redraw
                execute!(stdout, cursor::MoveTo(0, 3))?;
                execute!(stdout, terminal::Clear(ClearType::FromCursorDown))?;

                for frame_line in &last_frames {
                    writeln!(stdout, "\r{}", frame_line)?;
                }

                stdout.flush()?;
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No frame available
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
    println!("Monitor stopped.");

    Ok(())
}

fn draw_header(stdout: &mut io::Stdout) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 0))?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".cyan().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "                         CAN BUS MONITOR                                      ".cyan().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".cyan().bold()
    )?;
    writeln!(stdout, "\r")?;
    stdout.flush()?;
    Ok(())
}

fn format_frame(frame: &CanFrame, count: u64) -> String {
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
        "[{}] {} │ ID: {} │ DLC: {} │ Data: [{}] │ Src: {}",
        time_str,
        format!("#{:05}", count).blue().bold(),
        id_str,
        format!("{}", frame.data.len()).green(),
        data_str.bright_white(),
        frame.source.bright_cyan()
    )
}
