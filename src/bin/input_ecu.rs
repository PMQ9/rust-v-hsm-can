use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::time::Duration;
use vhsm_can::types::{ArmVariant, CanId, EcuConfig};

const ECU_NAME: &str = "INPUT_ECU";
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
        arm_variant: ArmVariant::CortexM4,
    };

    draw_ui(&mut stdout, &config)?;

    let mut input_buffer = String::new();
    let mut sent_count = 0u64;
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
                            if let Some(msg) = process_input(&input_buffer) {
                                sent_count += 1;
                                let log_entry = format!(
                                    "[{}] Sent frame: ID={:03X}, Data=[{}]",
                                    chrono::Utc::now().format("%H:%M:%S"),
                                    msg.0,
                                    msg.1
                                        .iter()
                                        .map(|b| format!("{:02X}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                );
                                last_sent.push(log_entry);

                                if last_sent.len() > 10 {
                                    last_sent.remove(0);
                                }

                                update_sent_area(&mut stdout, &last_sent)?;

                                // TODO: Actually send to bus when integrated
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

// Parse input format: "123 01 02 03" -> (0x123, vec![0x01, 0x02, 0x03])
fn process_input(input: &str) -> Option<(u16, Vec<u8>)> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let id = u16::from_str_radix(parts[0], 16).ok()?;

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
