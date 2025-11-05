use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use vhsm_can::network::BusWriter;
use vhsm_can::types::{ArmVariant, CanFrame, CanId, EcuConfig};

const ECU_NAME: &str = "INPUT_ECU";
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
        arm_variant: ArmVariant::CortexM4,
    };

    draw_ui(&mut stdout, &config)?;

    // Connect to bus server
    writeln!(stdout, "\r\n\nConnecting to CAN bus at {}...\r", BUS_ADDRESS)?;
    stdout.flush()?;

    let client = match vhsm_can::network::BusClient::connect(BUS_ADDRESS, ECU_NAME.to_string()).await {
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

    // Split client
    let (_reader, writer) = client.split();
    let writer = Arc::new(Mutex::new(writer));

    let mut input_buffer = String::new();
    let mut last_sent: Vec<String> = Vec::new();

    loop {
        // Poll for keyboard events
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char(c) => {
                        input_buffer.push(c);
                        update_input_area(&mut stdout, &input_buffer)?;
                    }
                    KeyCode::Backspace => {
                        input_buffer.pop();
                        update_input_area(&mut stdout, &input_buffer)?;
                    }
                    KeyCode::Enter => {
                        if !input_buffer.is_empty() {
                            // Parse and send frame
                            if let Some((id, data)) = process_input(&input_buffer) {
                                let frame = CanFrame::new(id, data, ECU_NAME.to_string());

                                // Send to bus
                                let mut w = writer.lock().await;
                                match w.send_frame(frame.clone()).await {
                                    Ok(_) => {
                                        let log_entry = format!(
                                            "[{}] Sent frame: ID={}, Data=[{}]",
                                            chrono::Utc::now().format("%H:%M:%S"),
                                            match frame.id {
                                                CanId::Standard(id) => format!("{:03X}", id),
                                                CanId::Extended(id) => format!("{:08X}", id),
                                            },
                                            frame.data
                                                .iter()
                                                .map(|b| format!("{:02X}", b))
                                                .collect::<Vec<_>>()
                                                .join(" ")
                                        );
                                        last_sent.push(log_entry);
                                    }
                                    Err(e) => {
                                        let error = format!(
                                            "[{}] Error sending: {}",
                                            chrono::Utc::now().format("%H:%M:%S"),
                                            e
                                        );
                                        last_sent.push(error);
                                    }
                                }

                                if last_sent.len() > 10 {
                                    last_sent.remove(0);
                                }

                                update_sent_area(&mut stdout, &last_sent)?;
                            } else {
                                let error = format!(
                                    "[{}] Invalid format. Use: <ID> <byte1> <byte2> ... (hex)",
                                    chrono::Utc::now().format("%H:%M:%S")
                                );
                                last_sent.push(error);
                                if last_sent.len() > 10 {
                                    last_sent.remove(0);
                                }
                                update_sent_area(&mut stdout, &last_sent)?;
                            }

                            input_buffer.clear();
                            update_input_area(&mut stdout, &input_buffer)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    terminal::disable_raw_mode()?;
    execute!(stdout, terminal::Clear(ClearType::All))?;
    execute!(stdout, cursor::MoveTo(0, 0))?;
    println!("Input ECU stopped.");

    Ok(())
}

fn draw_ui(stdout: &mut io::Stdout, config: &EcuConfig) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 0))?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".green().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "                           INPUT ECU                                          ".green().bold()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "═══════════════════════════════════════════════════════════════════════════════".green().bold()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "ECU Name".bright_white().bold(),
        config.name.green()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "Processor".bright_white().bold(),
        config.arm_variant.as_str().green()
    )?;
    writeln!(
        stdout,
        "\r{}: {}",
        "Bus Addr".bright_white().bold(),
        config.bus_address.green()
    )?;
    writeln!(stdout, "\r")?;
    writeln!(
        stdout,
        "\r{}",
        "───────────────────────────────────────────────────────────────────────────────".bright_black()
    )?;
    writeln!(stdout, "\r{}", "SEND FRAME:".yellow().bold())?;
    writeln!(
        stdout,
        "\r{}",
        "Format: <CAN_ID> <byte1> <byte2> ... (all in hex)".bright_black()
    )?;
    writeln!(
        stdout,
        "\r{}",
        "Example: 123 01 02 03 04".bright_black()
    )?;
    writeln!(stdout, "\r")?;
    writeln!(stdout, "\r> ")?;
    writeln!(stdout, "\r")?;
    writeln!(
        stdout,
        "\r{}",
        "───────────────────────────────────────────────────────────────────────────────".bright_black()
    )?;
    writeln!(stdout, "\r{}", "SENT FRAMES:".cyan().bold())?;
    writeln!(stdout, "\r")?;
    stdout.flush()?;
    Ok(())
}

fn update_input_area(stdout: &mut io::Stdout, input: &str) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 12))?;
    execute!(stdout, terminal::Clear(ClearType::CurrentLine))?;
    write!(stdout, "\r> {}", input.bright_white())?;
    stdout.flush()?;
    Ok(())
}

fn update_sent_area(stdout: &mut io::Stdout, sent: &[String]) -> io::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 16))?;
    execute!(stdout, terminal::Clear(ClearType::FromCursorDown))?;

    for msg in sent {
        writeln!(stdout, "\r{}", msg.bright_green())?;
    }

    stdout.flush()?;
    Ok(())
}

// Parse input format: "123 01 02 03" -> (CanId::Standard(0x123), vec![0x01, 0x02, 0x03])
fn process_input(input: &str) -> Option<(CanId, Vec<u8>)> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Parse ID - if it's longer than 3 hex digits, treat as extended
    let id_str = parts[0];
    let id = if id_str.len() <= 3 {
        let id_val = u16::from_str_radix(id_str, 16).ok()?;
        if id_val > 0x7FF {
            return None; // Invalid standard ID
        }
        CanId::Standard(id_val)
    } else {
        let id_val = u32::from_str_radix(id_str, 16).ok()?;
        if id_val > 0x1FFFFFFF {
            return None; // Invalid extended ID
        }
        CanId::Extended(id_val)
    };

    let mut data = Vec::new();
    for part in &parts[1..] {
        let byte = u8::from_str_radix(part, 16).ok()?;
        data.push(byte);
    }

    if data.len() > 8 {
        return None; // CAN frames can't have more than 8 bytes
    }

    Some((id, data))
}
