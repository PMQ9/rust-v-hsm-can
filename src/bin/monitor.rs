use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::net::TcpStream;
use std::time::Duration;
use vhsm_can::types::{CanFrame, CanId};

const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::Clear(ClearType::All))?;

    // Draw header
    draw_header(&mut stdout)?;

    let mut frame_count = 0u64;
    let mut last_frames: Vec<String> = Vec::new();

    // Connect to the CAN bus server
    println!("\r\nConnecting to CAN bus at {}...", BUS_ADDRESS);

    match connect_to_bus().await {
        Ok(mut rx) => {
            println!("\r\n{}Connected to CAN bus!{}\r", "✓ ".green(), "".clear());
            std::thread::sleep(Duration::from_millis(500));

            execute!(stdout, terminal::Clear(ClearType::All))?;
            draw_header(&mut stdout)?;

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
                match rx.try_recv() {
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
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                        // No frame available
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        eprintln!("\r\nError receiving frame: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("\r\n{}Failed to connect: {}{}\r", "✗ ".red(), e, "".clear());
            std::thread::sleep(Duration::from_secs(2));
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

// Helper function to connect to the bus
async fn connect_to_bus() -> Result<tokio::sync::broadcast::Receiver<CanFrame>, Box<dyn std::error::Error>> {
    // Wait for bus server to be available
    for _ in 0..10 {
        if TcpStream::connect_timeout(
            &BUS_ADDRESS.parse()?,
            Duration::from_millis(100)
        ).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Create a channel to receive frames
    let (tx, rx) = tokio::sync::broadcast::channel(1000);

    // In a real implementation, this would connect to the network bus
    // For now, we'll use the shared bus from the main process
    // This is a simplified version - we'll improve this in the integration

    Ok(rx)
}
