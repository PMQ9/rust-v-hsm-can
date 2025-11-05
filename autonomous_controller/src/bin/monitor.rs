use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;
use tokio::sync::mpsc;
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{CanFrame, CanId, can_ids, encoding};

const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[derive(Clone)]
struct LatestFrame {
    frame: CanFrame,
    decoded: String,
}

struct Dashboard {
    sensors: HashMap<CanId, LatestFrame>,
    controller_tx: HashMap<CanId, LatestFrame>,
    controller_rx: HashMap<CanId, LatestFrame>,
    actuators: HashMap<CanId, LatestFrame>,
    frame_count: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup terminal
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;
    execute!(stdout, cursor::Hide)?;

    let mut dashboard = Dashboard::new();

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
    dashboard.draw(&mut stdout)?;

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

    let mut last_draw = std::time::Instant::now();
    let draw_interval = Duration::from_millis(100); // Update display 10 times per second

    loop {
        // Check for user input (q to quit)
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Process all available frames
        let mut frames_processed = 0;
        while let Ok(frame) = frame_rx.try_recv() {
            dashboard.update_frame(frame);
            frames_processed += 1;
        }

        // Only redraw if we processed frames AND enough time has passed
        if frames_processed > 0 && last_draw.elapsed() >= draw_interval {
            dashboard.draw(&mut stdout)?;
            last_draw = std::time::Instant::now();
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Cleanup
    execute!(stdout, cursor::Show)?;
    terminal::disable_raw_mode()?;
    execute!(stdout, LeaveAlternateScreen)?;
    println!("Monitor stopped.");

    Ok(())
}

impl Dashboard {
    fn new() -> Self {
        Self {
            sensors: HashMap::new(),
            controller_tx: HashMap::new(),
            controller_rx: HashMap::new(),
            actuators: HashMap::new(),
            frame_count: 0,
        }
    }

    fn update_frame(&mut self, frame: CanFrame) {
        self.frame_count += 1;
        let decoded = decode_message(&frame);
        let latest = LatestFrame {
            frame: frame.clone(),
            decoded,
        };

        // Categorize frame based on CAN ID and source
        match frame.id {
            // Sensor messages (TX only)
            id if id == can_ids::WHEEL_SPEED_FL ||
                  id == can_ids::WHEEL_SPEED_FR ||
                  id == can_ids::WHEEL_SPEED_RL ||
                  id == can_ids::WHEEL_SPEED_RR ||
                  id == can_ids::ENGINE_RPM ||
                  id == can_ids::ENGINE_THROTTLE ||
                  id == can_ids::STEERING_ANGLE ||
                  id == can_ids::STEERING_TORQUE => {
                self.sensors.insert(frame.id, latest.clone());
            },
            // Controller commands (TX from controller)
            id if id == can_ids::BRAKE_COMMAND ||
                  id == can_ids::THROTTLE_COMMAND ||
                  id == can_ids::STEERING_COMMAND => {
                if frame.source == "AUTONOMOUS_CTRL" {
                    self.controller_tx.insert(frame.id, latest.clone());
                }
                // Also track in actuators (RX for actuators)
                self.actuators.insert(frame.id, latest.clone());
            },
            _ => {}
        }

        // Track sensor messages received by controller
        if frame.source != "AUTONOMOUS_CTRL" {
            let sensor_ids = vec![
                can_ids::WHEEL_SPEED_FL,
                can_ids::WHEEL_SPEED_FR,
                can_ids::WHEEL_SPEED_RL,
                can_ids::WHEEL_SPEED_RR,
                can_ids::ENGINE_RPM,
                can_ids::ENGINE_THROTTLE,
                can_ids::STEERING_ANGLE,
                can_ids::STEERING_TORQUE,
            ];
            if sensor_ids.contains(&frame.id) {
                self.controller_rx.insert(frame.id, latest.clone());
            }
        }
    }

    fn draw(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        // Move to top-left and clear everything
        execute!(
            stdout,
            cursor::MoveTo(0, 0),
            terminal::Clear(ClearType::All),
            cursor::Hide
        )?;

        // Header
        writeln!(stdout, "\r{}", "═══════════════════════════════════════════════════════════════════════════════".cyan().bold())?;
        writeln!(stdout, "\r{}", "               AUTONOMOUS VEHICLE CAN BUS MONITOR                             ".cyan().bold())?;
        writeln!(stdout, "\r{}", "═══════════════════════════════════════════════════════════════════════════════".cyan().bold())?;
        writeln!(stdout, "\r")?;
        writeln!(stdout, "\r{} Total frames: {} | Press 'q' to quit\r", "ℹ".blue(), self.frame_count)?;
        writeln!(stdout, "\r")?;

        // SENSORS Section
        writeln!(stdout, "\r{}", "SENSORS (Sending):".green().bold())?;
        self.draw_sensor_line(stdout, can_ids::WHEEL_SPEED_FL, "WHEEL_FL")?;
        self.draw_sensor_line(stdout, can_ids::WHEEL_SPEED_FR, "WHEEL_FR")?;
        self.draw_sensor_line(stdout, can_ids::WHEEL_SPEED_RL, "WHEEL_RL")?;
        self.draw_sensor_line(stdout, can_ids::WHEEL_SPEED_RR, "WHEEL_RR")?;
        self.draw_sensor_line(stdout, can_ids::ENGINE_RPM, "ENGINE_ECU")?;
        self.draw_sensor_line(stdout, can_ids::STEERING_ANGLE, "STEER_SENSOR")?;
        writeln!(stdout, "\r")?;

        // CONTROLLER Section
        writeln!(stdout, "\r{}", "CONTROLLER (Autonomous):".bright_blue().bold())?;
        writeln!(stdout, "\r{}", "  → Commands Sent:".bright_blue())?;
        self.draw_controller_tx_line(stdout, can_ids::BRAKE_COMMAND, "Brake Cmd")?;
        self.draw_controller_tx_line(stdout, can_ids::THROTTLE_COMMAND, "Throttle Cmd")?;
        self.draw_controller_tx_line(stdout, can_ids::STEERING_COMMAND, "Steering Cmd")?;
        writeln!(stdout, "\r{}", "  ← Sensor Data Received (sample):".bright_blue())?;
        self.draw_controller_rx_line(stdout, can_ids::WHEEL_SPEED_FL, "Wheel FL")?;
        self.draw_controller_rx_line(stdout, can_ids::ENGINE_RPM, "Engine RPM")?;
        writeln!(stdout, "\r")?;

        // ACTUATORS Section
        writeln!(stdout, "\r{}", "ACTUATORS (Receiving):".red().bold())?;
        self.draw_actuator_line(stdout, can_ids::BRAKE_COMMAND, "BRAKE_CTRL")?;
        self.draw_actuator_line(stdout, can_ids::STEERING_COMMAND, "STEER_CTRL")?;

        execute!(stdout, cursor::Show)?;
        stdout.flush()?;
        Ok(())
    }

    fn draw_sensor_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.sensors.get(&id) {
            let time_str = latest.frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.frame.id);
            writeln!(
                stdout,
                "\r  {} {} → ID: {} | {} | {}",
                format!("[{:12}]", name).green(),
                "→".cyan(),
                id_str,
                latest.decoded,
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r  {} {} ID: --- | {} | ---",
                format!("[{:12}]", name).bright_black(),
                "→".bright_black(),
                "Waiting for data...".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_controller_tx_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.controller_tx.get(&id) {
            let time_str = latest.frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.frame.id);
            writeln!(
                stdout,
                "\r    {} {} ID: {} | {} | {}",
                format!("[{:14}]", name).bright_blue(),
                "→".cyan(),
                id_str,
                latest.decoded,
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r    {} {} ID: --- | {} | ---",
                format!("[{:14}]", name).bright_black(),
                "→".bright_black(),
                "No data sent yet".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_controller_rx_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.controller_rx.get(&id) {
            let time_str = latest.frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.frame.id);
            writeln!(
                stdout,
                "\r    {} {} ID: {} | {} | {}",
                format!("[{:14}]", name).bright_blue(),
                "←".cyan(),
                id_str,
                latest.decoded,
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r    {} {} ID: --- | {} | ---",
                format!("[{:14}]", name).bright_black(),
                "←".bright_black(),
                "No data received yet".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_actuator_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.actuators.get(&id) {
            let time_str = latest.frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.frame.id);
            writeln!(
                stdout,
                "\r  {} {} ID: {} | {} | {}",
                format!("[{:12}]", name).red(),
                "←".cyan(),
                id_str,
                latest.decoded,
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r  {} {} ID: --- | {} | ---",
                format!("[{:12}]", name).bright_black(),
                "←".bright_black(),
                "Waiting for data...".bright_black()
            )?;
        }
        Ok(())
    }
}

fn format_can_id(id: CanId) -> ColoredString {
    match id {
        CanId::Standard(id) => format!("0x{:03X}", id).yellow(),
        CanId::Extended(id) => format!("0x{:08X}", id).magenta(),
    }
}

fn decode_message(frame: &CanFrame) -> String {
    match frame.id {
        id if id == can_ids::WHEEL_SPEED_FL => {
            let speed = encoding::decode_wheel_speed(&frame.data);
            format!("Speed: {:.2} rad/s", speed)
        },
        id if id == can_ids::WHEEL_SPEED_FR => {
            let speed = encoding::decode_wheel_speed(&frame.data);
            format!("Speed: {:.2} rad/s", speed)
        },
        id if id == can_ids::WHEEL_SPEED_RL => {
            let speed = encoding::decode_wheel_speed(&frame.data);
            format!("Speed: {:.2} rad/s", speed)
        },
        id if id == can_ids::WHEEL_SPEED_RR => {
            let speed = encoding::decode_wheel_speed(&frame.data);
            format!("Speed: {:.2} rad/s", speed)
        },
        id if id == can_ids::ENGINE_RPM => {
            if frame.data.len() >= 2 {
                let rpm = encoding::decode_rpm(&frame.data);
                let throttle = if frame.data.len() > 2 {
                    encoding::decode_throttle(frame.data[2])
                } else {
                    0.0
                };
                format!("RPM: {:.0} | Throttle: {:.0}%", rpm, throttle)
            } else {
                "Invalid data".to_string()
            }
        },
        id if id == can_ids::ENGINE_THROTTLE => {
            if !frame.data.is_empty() {
                let throttle = encoding::decode_throttle(frame.data[0]);
                format!("Throttle: {:.0}%", throttle)
            } else {
                "Invalid data".to_string()
            }
        },
        id if id == can_ids::STEERING_ANGLE => {
            let angle = encoding::decode_steering_angle(&frame.data);
            format!("Angle: {:.1}°", angle)
        },
        id if id == can_ids::STEERING_TORQUE => {
            let torque = encoding::decode_steering_torque(&frame.data);
            format!("Torque: {:.2} Nm", torque)
        },
        id if id == can_ids::BRAKE_COMMAND => {
            if !frame.data.is_empty() {
                let pressure = encoding::decode_brake_pressure(frame.data[0]);
                format!("Pressure: {:.0}%", pressure)
            } else {
                "Invalid data".to_string()
            }
        },
        id if id == can_ids::THROTTLE_COMMAND => {
            if !frame.data.is_empty() {
                let throttle = encoding::decode_throttle(frame.data[0]);
                format!("Position: {:.0}%", throttle)
            } else {
                "Invalid data".to_string()
            }
        },
        id if id == can_ids::STEERING_COMMAND => {
            let angle = encoding::decode_steering_angle(&frame.data);
            format!("Angle: {:.1}°", angle)
        },
        _ => "Unknown".to_string()
    }
}
