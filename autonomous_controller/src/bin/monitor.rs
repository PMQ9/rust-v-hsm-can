use autonomous_vehicle_sim::hsm::{PerformanceSnapshot, SecuredCanFrame};
use autonomous_vehicle_sim::network::{BusClient, NetMessage};
use autonomous_vehicle_sim::types::{CanId, can_ids, encoding};
use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::time::Duration;
use tokio::sync::mpsc;

const BUS_ADDRESS: &str = "127.0.0.1:9000";

#[derive(Clone)]
struct LatestFrame {
    secured_frame: SecuredCanFrame,
    decoded: String,
}

struct Dashboard {
    sensors: HashMap<CanId, LatestFrame>,
    controller_tx: HashMap<CanId, LatestFrame>,
    controller_rx: HashMap<CanId, LatestFrame>,
    actuators: HashMap<CanId, LatestFrame>,
    frame_count: u64,
    unsecured_frame_count: u64,
    recent_attackers: Vec<String>, // Track sources of unsecured frames
    controller_emergency_shutdown: bool, // Controller in emergency shutdown mode
    performance_stats: HashMap<String, PerformanceSnapshot>, // Performance stats by ECU name

    // Enhanced security metrics
    secured_frame_count: u64,
    frames_per_ecu: HashMap<String, u64>,
    unsecured_frames_per_ecu: HashMap<String, u64>,
    unique_can_ids: HashSet<u32>,
    threat_level: ThreatLevel,
    attack_start_time: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreatLevel {
    Secure,   // No attacks detected
    Low,      // 1-5 unsecured frames
    Medium,   // 6-20 unsecured frames
    High,     // 21-50 unsecured frames
    Critical, // >50 unsecured frames
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup terminal - try to enable features but don't fail if unsupported
    let mut stdout = io::stdout();
    let use_alternate_screen = execute!(stdout, EnterAlternateScreen).is_ok();
    let use_raw_mode = terminal::enable_raw_mode().is_ok();
    let _ = execute!(stdout, cursor::Hide); // Hide cursor if possible

    let mut dashboard = Dashboard::new();

    // Connect to the CAN bus server
    writeln!(stdout, "\r\nConnecting to CAN bus at {}...", BUS_ADDRESS)?;
    stdout.flush()?;

    // Wait for server to be available
    let mut connected = false;
    for attempt in 1..=10 {
        match tokio::time::timeout(
            Duration::from_millis(500),
            BusClient::connect(BUS_ADDRESS, "MONITOR".to_string()),
        )
        .await
        {
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
        eprintln!(
            "\r\n{}Failed to connect to bus server. Is it running?{}",
            "✗ ".red(),
            "".clear()
        );
        eprintln!("\r\nStart the bus server with: cargo run --bin bus_server");
        return Ok(());
    }

    // Reconnect to get the client
    let client = BusClient::connect(BUS_ADDRESS, "MONITOR".to_string()).await?;
    writeln!(
        stdout,
        "\r\n{}Connected to CAN bus!{}",
        "✓ ".green(),
        "".clear()
    )?;
    stdout.flush()?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let _ = execute!(stdout, terminal::Clear(ClearType::All)); // Clear if possible
    dashboard.draw(&mut stdout)?;

    // Split the client into reader and writer
    let (mut reader, _writer) = client.split();

    // Create channels to receive frames and performance stats from the network task
    // Use larger capacity to handle bursts from multiple ECUs (9 ECUs @ 10Hz = ~100 fps)
    let (frame_tx, mut frame_rx) = mpsc::channel::<SecuredCanFrame>(1000);
    let (perf_tx, mut perf_rx) = mpsc::channel::<PerformanceSnapshot>(100);

    // Spawn network reader task (monitoring all secured frames and performance stats)
    tokio::spawn(async move {
        loop {
            match reader.receive_message().await {
                Ok(NetMessage::SecuredCanFrame(secured_frame)) => {
                    // Monitor receives all frames without verification
                    // (it's a passive observer, not a security participant)
                    if frame_tx.send(secured_frame).await.is_err() {
                        break;
                    }
                }
                Ok(NetMessage::PerformanceStats(stats)) => {
                    // Receive performance statistics from ECUs
                    if perf_tx.send(stats).await.is_err() {
                        break;
                    }
                }
                Ok(NetMessage::CanFrame(_)) => {
                    // Legacy unencrypted frames (ignore in secure mode)
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let mut last_draw = std::time::Instant::now();
    let draw_interval = Duration::from_millis(100); // Update display 10 times per second

    loop {
        // Check for user input (q to quit) - only if raw mode is available
        if use_raw_mode
            && let Ok(true) = event::poll(Duration::from_millis(10))
            && let Ok(Event::Key(key_event)) = event::read()
            && key_event.code == KeyCode::Char('q')
        {
            break;
        }

        // Process all available frames
        let mut frames_processed = 0;
        while let Ok(frame) = frame_rx.try_recv() {
            dashboard.update_frame(frame);
            frames_processed += 1;
        }

        // Process all available performance stats
        let mut stats_processed = 0;
        while let Ok(stats) = perf_rx.try_recv() {
            dashboard.update_performance_stats(stats);
            stats_processed += 1;
        }

        // Only redraw if we processed frames/stats AND enough time has passed
        if (frames_processed > 0 || stats_processed > 0) && last_draw.elapsed() >= draw_interval {
            dashboard.draw(&mut stdout)?;
            last_draw = std::time::Instant::now();
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Cleanup - only if features were enabled
    let _ = execute!(stdout, cursor::Show);
    if use_raw_mode {
        let _ = terminal::disable_raw_mode();
    }
    if use_alternate_screen {
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
    println!("\nMonitor stopped.");

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
            unsecured_frame_count: 0,
            recent_attackers: Vec::new(),
            controller_emergency_shutdown: false,
            performance_stats: HashMap::new(),
            secured_frame_count: 0,
            frames_per_ecu: HashMap::new(),
            unsecured_frames_per_ecu: HashMap::new(),
            unique_can_ids: HashSet::new(),
            threat_level: ThreatLevel::Secure,
            attack_start_time: None,
        }
    }

    fn update_frame(&mut self, secured_frame: SecuredCanFrame) {
        self.frame_count += 1;

        // Track frames per ECU
        *self
            .frames_per_ecu
            .entry(secured_frame.source.clone())
            .or_insert(0) += 1;

        // Track unique CAN IDs
        match secured_frame.can_id {
            CanId::Standard(id) => {
                self.unique_can_ids.insert(id as u32);
            }
            CanId::Extended(id) => {
                self.unique_can_ids.insert(id);
            }
        }

        // Check if this is an unsecured frame (MAC=0 and CRC=0)
        if secured_frame.mac == [0u8; 32] && secured_frame.crc == 0 {
            self.unsecured_frame_count += 1;
            *self
                .unsecured_frames_per_ecu
                .entry(secured_frame.source.clone())
                .or_insert(0) += 1;

            // Track attack start time
            if self.attack_start_time.is_none() {
                self.attack_start_time = Some(std::time::Instant::now());
            }

            // Track unique attackers (keep last 5)
            if !self.recent_attackers.contains(&secured_frame.source) {
                self.recent_attackers.push(secured_frame.source.clone());
                if self.recent_attackers.len() > 5 {
                    self.recent_attackers.remove(0);
                }
            }
        } else {
            // Secured frame
            self.secured_frame_count += 1;
        }

        // Update threat level
        self.threat_level = match self.unsecured_frame_count {
            0 => ThreatLevel::Secure,
            1..=5 => ThreatLevel::Low,
            6..=20 => ThreatLevel::Medium,
            21..=50 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        };

        let decoded = decode_secured_message(&secured_frame);
        let latest = LatestFrame {
            secured_frame: secured_frame.clone(),
            decoded,
        };

        // Check for emergency shutdown status from controller
        if secured_frame.can_id == can_ids::AUTO_STATUS
            && !secured_frame.data.is_empty()
            && secured_frame.data[0] == 0xFF
        {
            // 0xFF = Emergency Shutdown
            self.controller_emergency_shutdown = true;
        }

        // Categorize frame based on CAN ID and source
        match secured_frame.can_id {
            // Sensor messages (TX only)
            id if id == can_ids::WHEEL_SPEED_FL
                || id == can_ids::WHEEL_SPEED_FR
                || id == can_ids::WHEEL_SPEED_RL
                || id == can_ids::WHEEL_SPEED_RR
                || id == can_ids::ENGINE_RPM
                || id == can_ids::ENGINE_THROTTLE
                || id == can_ids::STEERING_ANGLE
                || id == can_ids::STEERING_TORQUE =>
            {
                self.sensors.insert(secured_frame.can_id, latest.clone());
            }
            // Controller commands (TX from controller)
            id if id == can_ids::BRAKE_COMMAND
                || id == can_ids::THROTTLE_COMMAND
                || id == can_ids::STEERING_COMMAND =>
            {
                if secured_frame.source == "AUTONOMOUS_CONTROLLER" {
                    self.controller_tx
                        .insert(secured_frame.can_id, latest.clone());
                }
                // Also track in actuators (RX for actuators)
                self.actuators.insert(secured_frame.can_id, latest.clone());
            }
            _ => {}
        }

        // Track sensor messages received by controller
        if secured_frame.source != "AUTONOMOUS_CONTROLLER" {
            let sensor_ids = [
                can_ids::WHEEL_SPEED_FL,
                can_ids::WHEEL_SPEED_FR,
                can_ids::WHEEL_SPEED_RL,
                can_ids::WHEEL_SPEED_RR,
                can_ids::ENGINE_RPM,
                can_ids::ENGINE_THROTTLE,
                can_ids::STEERING_ANGLE,
                can_ids::STEERING_TORQUE,
            ];
            if sensor_ids.contains(&secured_frame.can_id) {
                self.controller_rx
                    .insert(secured_frame.can_id, latest.clone());
            }
        }
    }

    fn update_performance_stats(&mut self, stats: PerformanceSnapshot) {
        // Update or insert the performance stats for this ECU
        self.performance_stats.insert(stats.ecu_name.clone(), stats);
    }

    fn draw(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        // Move to top-left and clear everything - ignore failures for terminal compatibility
        let _ = execute!(
            stdout,
            cursor::MoveTo(0, 0),
            terminal::Clear(ClearType::All),
            cursor::Hide
        );

        // Header
        writeln!(
            stdout,
            "\r{}",
            "═══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        )?;
        writeln!(
            stdout,
            "\r{}",
            "          AUTONOMOUS VEHICLE CAN BUS MONITOR                   "
                .cyan()
                .bold()
        )?;
        writeln!(
            stdout,
            "\r{}",
            "═══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        )?;
        writeln!(stdout, "\r")?;
        // Display security status with attack warnings
        if self.unsecured_frame_count > 0 {
            writeln!(
                stdout,
                "\r{} Total frames: {} | {} {} | Press 'q' to quit\r",
                "ℹ".blue(),
                self.frame_count,
                "⚠".red().bold(),
                format!(
                    "ATTACK DETECTED: {} unsecured frames",
                    self.unsecured_frame_count
                )
                .red()
                .bold()
            )?;
            if !self.recent_attackers.is_empty() {
                writeln!(
                    stdout,
                    "\r{} {}\r",
                    " Attack Source:".red().bold(),
                    self.recent_attackers.join(", ").red()
                )?;
            }
        } else {
            writeln!(
                stdout,
                "\r{} Total frames: {} | {} Security: ENABLED | Press 'q' to quit\r",
                "ℹ".blue(),
                self.frame_count,
                "✓".green().bold()
            )?;
        }

        // Display emergency shutdown warning if controller is stopped
        if self.controller_emergency_shutdown {
            writeln!(stdout, "\r")?;
            writeln!(
                stdout,
                "\r{}",
                "═══════════════════════════════════════════════════════════════════════════════"
                    .red()
                    .bold()
            )?;
            writeln!(
                stdout,
                "\r{}  {}\r",
                " ".repeat(15),
                "⚠ AUTONOMOUS CONTROLLER DEACTIVATED ⚠".red().bold()
            )?;
            writeln!(
                stdout,
                "\r{}",
                "═══════════════════════════════════════════════════════════════════════════════"
                    .red()
                    .bold()
            )?;
            writeln!(
                stdout,
                "\r{} Attack detected - Controller STOPPED for safety | {} to resume\r",
                " ".repeat(10),
                "RESTART REQUIRED".yellow().bold()
            )?;
            writeln!(
                stdout,
                "\r{}",
                "═══════════════════════════════════════════════════════════════════════════════"
                    .red()
                    .bold()
            )?;
        }
        // writeln!(stdout, "\r{} All frames include MAC (HMAC-SHA256) and CRC32 verification\r", "⚡".yellow())?;
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
        writeln!(
            stdout,
            "\r{}",
            "CONTROLLER (Autonomous):".bright_blue().bold()
        )?;
        writeln!(stdout, "\r{}", "  → Commands Sent:".bright_blue())?;
        self.draw_controller_tx_line(stdout, can_ids::BRAKE_COMMAND, "Brake Cmd")?;
        self.draw_controller_tx_line(stdout, can_ids::THROTTLE_COMMAND, "Throttle Cmd")?;
        self.draw_controller_tx_line(stdout, can_ids::STEERING_COMMAND, "Steering Cmd")?;
        writeln!(
            stdout,
            "\r{}",
            "  ← Sensor Data Received (sample):".bright_blue()
        )?;
        self.draw_controller_rx_line(stdout, can_ids::WHEEL_SPEED_FL, "Wheel FL")?;
        self.draw_controller_rx_line(stdout, can_ids::ENGINE_RPM, "Engine RPM")?;
        writeln!(stdout, "\r")?;

        // ACTUATORS Section
        writeln!(stdout, "\r{}", "ACTUATORS (Receiving):".red().bold())?;
        self.draw_actuator_line(stdout, can_ids::BRAKE_COMMAND, "BRAKE_CTRL")?;
        self.draw_actuator_line(stdout, can_ids::STEERING_COMMAND, "STEER_CTRL")?;

        // SECURITY METRICS Section
        writeln!(stdout, "\r")?;
        writeln!(stdout, "\r{}", "SECURITY METRICS:".magenta().bold())?;
        self.draw_security_metrics(stdout)?;

        // PERFORMANCE Section (if any stats available)
        if !self.performance_stats.is_empty() {
            writeln!(stdout, "\r")?;
            writeln!(stdout, "\r{}", "PERFORMANCE (HSM Metrics):".yellow().bold())?;
            self.draw_performance_stats(stdout)?;
        }

        let _ = execute!(stdout, cursor::Show); // Show cursor if possible
        stdout.flush()?;
        Ok(())
    }

    fn draw_sensor_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.sensors.get(&id) {
            let time_str = latest.secured_frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.secured_frame.can_id);
            let raw_data = format_raw_data(&latest.secured_frame.data);
            let crc_str = format!("CRC:{:08X}", latest.secured_frame.crc);
            let mac_str = format!("MAC:{}...", hex_encode(&latest.secured_frame.mac[..4]));
            writeln!(
                stdout,
                "\r  {:18} {} ID: {:6} | Data: {:29} | {:32} | {} {} | {}",
                format!("[{}]", name).green(),
                "→".cyan(),
                id_str,
                raw_data.bright_black(),
                latest.decoded,
                crc_str.yellow(),
                mac_str.magenta(),
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r  {:18} {} ID: {:6} | Data: {:29} | {:32} | ---",
                format!("[{}]", name).bright_black(),
                "→".bright_black(),
                "---",
                "---",
                "Waiting for data...".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_controller_tx_line(
        &self,
        stdout: &mut io::Stdout,
        id: CanId,
        name: &str,
    ) -> io::Result<()> {
        if let Some(latest) = self.controller_tx.get(&id) {
            let time_str = latest.secured_frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.secured_frame.can_id);
            let raw_data = format_raw_data(&latest.secured_frame.data);
            let crc_str = format!("CRC:{:08X}", latest.secured_frame.crc);
            let mac_str = format!("MAC:{}...", hex_encode(&latest.secured_frame.mac[..4]));
            writeln!(
                stdout,
                "\r    {:16} {} ID: {:6} | Data: {:29} | {:32} | {} {} | {}",
                format!("[{}]", name).bright_blue(),
                "→".cyan(),
                id_str,
                raw_data.bright_black(),
                latest.decoded,
                crc_str.yellow(),
                mac_str.magenta(),
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r    {:16} {} ID: {:6} | Data: {:29} | {:32} | ---",
                format!("[{}]", name).bright_black(),
                "→".bright_black(),
                "---",
                "---",
                "No data sent yet".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_controller_rx_line(
        &self,
        stdout: &mut io::Stdout,
        id: CanId,
        name: &str,
    ) -> io::Result<()> {
        if let Some(latest) = self.controller_rx.get(&id) {
            let time_str = latest.secured_frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.secured_frame.can_id);
            let raw_data = format_raw_data(&latest.secured_frame.data);
            let crc_str = format!("CRC:{:08X}", latest.secured_frame.crc);
            writeln!(
                stdout,
                "\r    {:16} {} ID: {:6} | Data: {:29} | {:32} | {} | {}",
                format!("[{}]", name).bright_blue(),
                "←".cyan(),
                id_str,
                raw_data.bright_black(),
                latest.decoded,
                crc_str.yellow(),
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r    {:16} {} ID: {:6} | Data: {:29} | {:32} | ---",
                format!("[{}]", name).bright_black(),
                "←".bright_black(),
                "---",
                "---",
                "No data received yet".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_actuator_line(&self, stdout: &mut io::Stdout, id: CanId, name: &str) -> io::Result<()> {
        if let Some(latest) = self.actuators.get(&id) {
            let time_str = latest.secured_frame.timestamp.format("%H:%M:%S%.3f");
            let id_str = format_can_id(latest.secured_frame.can_id);
            let raw_data = format_raw_data(&latest.secured_frame.data);
            let crc_str = format!("CRC:{:08X}", latest.secured_frame.crc);
            let mac_str = format!("MAC:{}...", hex_encode(&latest.secured_frame.mac[..4]));
            writeln!(
                stdout,
                "\r  {:18} {} ID: {:6} | Data: {:29} | {:32} | {} {} | {}",
                format!("[{}]", name).red(),
                "←".cyan(),
                id_str,
                raw_data.bright_black(),
                latest.decoded,
                crc_str.yellow(),
                mac_str.magenta(),
                time_str.to_string().bright_black()
            )?;
        } else {
            writeln!(
                stdout,
                "\r  {:18} {} ID: {:6} | Data: {:29} | {:32} | ---",
                format!("[{}]", name).bright_black(),
                "←".bright_black(),
                "---",
                "---",
                "Waiting for data...".bright_black()
            )?;
        }
        Ok(())
    }

    fn draw_performance_stats(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        // Sort ECUs by name for consistent display
        let mut ecus: Vec<_> = self.performance_stats.keys().collect();
        ecus.sort();

        // Draw table header
        writeln!(
            stdout,
            "\r  {:20} {:11} {:11} {:10} {:13} {:30}",
            "ECU Name".bright_yellow().bold(),
            "MAC Gen".bright_yellow().bold(),
            "MAC Verify".bright_yellow().bold(),
            "CRC Calc".bright_yellow().bold(),
            "Frame Create".bright_yellow().bold(),
            "E2E Latency (avg/min/max)".bright_yellow().bold()
        )?;
        writeln!(stdout, "\r  {}", "─".repeat(110).bright_black())?;

        // Draw table rows
        for ecu_name in ecus {
            if let Some(stats) = self.performance_stats.get(ecu_name) {
                // Format each metric with 1 decimal place, or "-" if no data
                let mac_gen = if stats.mac_gen_count > 0 {
                    format!("{:.1} μs", stats.mac_gen_avg_us)
                } else {
                    "-".to_string()
                };

                let mac_verify = if stats.mac_verify_count > 0 {
                    format!("{:.1} μs", stats.mac_verify_avg_us)
                } else {
                    "-".to_string()
                };

                let crc_calc = if stats.crc_calc_count > 0 {
                    format!("{:.1} μs", stats.crc_calc_avg_us)
                } else {
                    "-".to_string()
                };

                let frame_create = if stats.frame_create_count > 0 {
                    format!("{:.1} μs", stats.frame_create_avg_us)
                } else {
                    "-".to_string()
                };

                let e2e_latency = if stats.e2e_sample_count > 0 {
                    format!(
                        "{:.1}/{:.1}/{:.1} ms",
                        stats.e2e_latency_avg_us / 1000.0,
                        stats.e2e_latency_min_us as f64 / 1000.0,
                        stats.e2e_latency_max_us as f64 / 1000.0
                    )
                } else {
                    "-".to_string()
                };

                writeln!(
                    stdout,
                    "\r  {:20} {:11} {:11} {:10} {:13} {:30}",
                    ecu_name.cyan(),
                    mac_gen,
                    mac_verify,
                    crc_calc,
                    frame_create,
                    e2e_latency
                )?;
            }
        }
        Ok(())
    }

    fn draw_security_metrics(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        // Overall security status
        let security_rate = if self.frame_count > 0 {
            (self.secured_frame_count as f64 / self.frame_count as f64) * 100.0
        } else {
            100.0
        };

        let (threat_color, threat_label) = match self.threat_level {
            ThreatLevel::Secure => ("green".to_string(), "SECURE"),
            ThreatLevel::Low => ("yellow".to_string(), "LOW THREAT"),
            ThreatLevel::Medium => ("bright_yellow".to_string(), "MEDIUM THREAT"),
            ThreatLevel::High => ("red".to_string(), "HIGH THREAT"),
            ThreatLevel::Critical => ("bright_red".to_string(), "CRITICAL THREAT"),
        };

        writeln!(
            stdout,
            "\r  {} Threat Level: {} | Security Rate: {:.1}% | Unique CAN IDs: {}",
            "ℹ".magenta(),
            threat_label.to_string().color(threat_color.as_str()).bold(),
            security_rate,
            self.unique_can_ids.len()
        )?;

        writeln!(
            stdout,
            "\r  {} Secured Frames: {} | Unsecured Frames: {} | Total: {}",
            "▶".green(),
            self.secured_frame_count.to_string().green(),
            self.unsecured_frame_count.to_string().red(),
            self.frame_count
        )?;

        // Attack duration if under attack
        if let Some(start_time) = self.attack_start_time {
            let duration = start_time.elapsed().as_secs();
            writeln!(
                stdout,
                "\r  {} Attack Duration: {} seconds",
                "⚠".red().bold(),
                duration.to_string().red()
            )?;
        }

        // Per-ECU security statistics (if we have any unsecured frames)
        if !self.unsecured_frames_per_ecu.is_empty() {
            writeln!(stdout, "\r")?;
            writeln!(stdout, "\r  {}", "Per-ECU Attack Statistics:".red().bold())?;
            writeln!(
                stdout,
                "\r    {:20} {:12} {:15} {:15}",
                "ECU Name".bright_magenta(),
                "Total Frames".bright_magenta(),
                "Unsecured".bright_magenta(),
                "Attack Rate %".bright_magenta()
            )?;
            writeln!(stdout, "\r    {}", "─".repeat(70).bright_black())?;

            // Sort ECUs by unsecured frame count (descending)
            let mut ecu_attacks: Vec<_> = self.unsecured_frames_per_ecu.iter().collect();
            ecu_attacks.sort_by(|a, b| b.1.cmp(a.1));

            for (ecu_name, &unsecured_count) in ecu_attacks {
                let total = self.frames_per_ecu.get(ecu_name).unwrap_or(&0);
                let attack_rate = if *total > 0 {
                    (unsecured_count as f64 / *total as f64) * 100.0
                } else {
                    0.0
                };

                let rate_color = if attack_rate > 50.0 {
                    "red"
                } else if attack_rate > 20.0 {
                    "yellow"
                } else {
                    "white"
                };

                writeln!(
                    stdout,
                    "\r    {:20} {:12} {:15} {:15}",
                    ecu_name.red(),
                    total,
                    unsecured_count.to_string().red(),
                    format!("{:.1}%", attack_rate).color(rate_color)
                )?;
            }
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

fn decode_secured_message(secured_frame: &SecuredCanFrame) -> String {
    match secured_frame.can_id {
        id if id == can_ids::WHEEL_SPEED_FL => {
            let speed = encoding::decode_wheel_speed(&secured_frame.data);
            format!("Speed: {:.2} rad/s", speed)
        }
        id if id == can_ids::WHEEL_SPEED_FR => {
            let speed = encoding::decode_wheel_speed(&secured_frame.data);
            format!("Speed: {:.2} rad/s", speed)
        }
        id if id == can_ids::WHEEL_SPEED_RL => {
            let speed = encoding::decode_wheel_speed(&secured_frame.data);
            format!("Speed: {:.2} rad/s", speed)
        }
        id if id == can_ids::WHEEL_SPEED_RR => {
            let speed = encoding::decode_wheel_speed(&secured_frame.data);
            format!("Speed: {:.2} rad/s", speed)
        }
        id if id == can_ids::ENGINE_RPM => {
            if secured_frame.data.len() >= 2 {
                let rpm = encoding::decode_rpm(&secured_frame.data);
                let throttle = if secured_frame.data.len() > 2 {
                    encoding::decode_throttle(secured_frame.data[2])
                } else {
                    0.0
                };
                format!("RPM: {:.0} | Throttle: {:.0}%", rpm, throttle)
            } else {
                "Invalid data".to_string()
            }
        }
        id if id == can_ids::ENGINE_THROTTLE => {
            if !secured_frame.data.is_empty() {
                let throttle = encoding::decode_throttle(secured_frame.data[0]);
                format!("Throttle: {:.0}%", throttle)
            } else {
                "Invalid data".to_string()
            }
        }
        id if id == can_ids::STEERING_ANGLE => {
            let angle = encoding::decode_steering_angle(&secured_frame.data);
            format!("Angle: {:.1}°", angle)
        }
        id if id == can_ids::STEERING_TORQUE => {
            let torque = encoding::decode_steering_torque(&secured_frame.data);
            format!("Torque: {:.2} Nm", torque)
        }
        id if id == can_ids::BRAKE_COMMAND => {
            if !secured_frame.data.is_empty() {
                let pressure = encoding::decode_brake_pressure(secured_frame.data[0]);
                format!("Pressure: {:.0}%", pressure)
            } else {
                "Invalid data".to_string()
            }
        }
        id if id == can_ids::THROTTLE_COMMAND => {
            if !secured_frame.data.is_empty() {
                let throttle = encoding::decode_throttle(secured_frame.data[0]);
                format!("Position: {:.0}%", throttle)
            } else {
                "Invalid data".to_string()
            }
        }
        id if id == can_ids::STEERING_COMMAND => {
            let angle = encoding::decode_steering_angle(&secured_frame.data);
            format!("Angle: {:.1}°", angle)
        }
        _ => "Unknown".to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn format_raw_data(data: &[u8]) -> String {
    // Format as 4 blocks of 2 bytes each (standard CAN 8-byte frame visualization)
    let mut bytes = [0u8; 8];
    bytes[..data.len()].copy_from_slice(data);

    let blocks: Vec<String> = (0..4)
        .map(|i| {
            if i * 2 < data.len() {
                format!(
                    "{:02X} {:02X}",
                    bytes[i * 2],
                    if i * 2 + 1 < data.len() {
                        bytes[i * 2 + 1]
                    } else {
                        0
                    }
                )
            } else {
                "-- --".to_string()
            }
        })
        .collect();

    blocks.join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_secured_frame(source: &str, can_id: u16, is_secured: bool) -> SecuredCanFrame {
        SecuredCanFrame {
            can_id: CanId::Standard(can_id),
            data: vec![0x01, 0x02, 0x03, 0x04],
            mac: if is_secured { [0xFF; 32] } else { [0x00; 32] },
            crc: if is_secured { 0x12345678 } else { 0 },
            session_counter: 1,
            key_version: 0,
            timestamp: Utc::now(),
            source: source.to_string(),
        }
    }

    #[test]
    fn test_dashboard_creation() {
        let dashboard = Dashboard::new();
        assert_eq!(dashboard.frame_count, 0);
        assert_eq!(dashboard.unsecured_frame_count, 0);
        assert_eq!(dashboard.threat_level, ThreatLevel::Secure);
    }

    #[test]
    fn test_secured_frame_tracking() {
        let mut dashboard = Dashboard::new();
        let frame = create_test_secured_frame("ECU1", 0x100, true);

        dashboard.update_frame(frame);

        assert_eq!(dashboard.frame_count, 1);
        assert_eq!(dashboard.secured_frame_count, 1);
        assert_eq!(dashboard.unsecured_frame_count, 0);
        assert_eq!(dashboard.threat_level, ThreatLevel::Secure);
    }

    #[test]
    fn test_unsecured_frame_tracking() {
        let mut dashboard = Dashboard::new();
        let frame = create_test_secured_frame("ATTACKER", 0x100, false);

        dashboard.update_frame(frame);

        assert_eq!(dashboard.frame_count, 1);
        assert_eq!(dashboard.secured_frame_count, 0);
        assert_eq!(dashboard.unsecured_frame_count, 1);
        assert_eq!(dashboard.threat_level, ThreatLevel::Low);
        assert!(dashboard.attack_start_time.is_some());
        assert_eq!(dashboard.recent_attackers, vec!["ATTACKER"]);
    }

    #[test]
    fn test_threat_level_transitions() {
        let mut dashboard = Dashboard::new();

        // Secure
        assert_eq!(dashboard.threat_level, ThreatLevel::Secure);

        // Low threat (1-5 unsecured)
        for _ in 0..3 {
            dashboard.update_frame(create_test_secured_frame("ATTACKER", 0x100, false));
        }
        assert_eq!(dashboard.threat_level, ThreatLevel::Low);

        // Medium threat (6-20 unsecured)
        for _ in 0..5 {
            dashboard.update_frame(create_test_secured_frame("ATTACKER", 0x100, false));
        }
        assert_eq!(dashboard.threat_level, ThreatLevel::Medium);

        // High threat (21-50 unsecured)
        for _ in 0..15 {
            dashboard.update_frame(create_test_secured_frame("ATTACKER", 0x100, false));
        }
        assert_eq!(dashboard.threat_level, ThreatLevel::High);

        // Critical threat (>50 unsecured)
        for _ in 0..35 {
            dashboard.update_frame(create_test_secured_frame("ATTACKER", 0x100, false));
        }
        assert_eq!(dashboard.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_per_ecu_statistics() {
        let mut dashboard = Dashboard::new();

        // ECU1: 10 secured frames
        for _ in 0..10 {
            dashboard.update_frame(create_test_secured_frame("ECU1", 0x100, true));
        }

        // ECU2: 5 secured, 5 unsecured
        for _ in 0..5 {
            dashboard.update_frame(create_test_secured_frame("ECU2", 0x200, true));
        }
        for _ in 0..5 {
            dashboard.update_frame(create_test_secured_frame("ECU2", 0x200, false));
        }

        assert_eq!(*dashboard.frames_per_ecu.get("ECU1").unwrap(), 10);
        assert_eq!(*dashboard.frames_per_ecu.get("ECU2").unwrap(), 10);
        assert_eq!(dashboard.unsecured_frames_per_ecu.get("ECU1"), None);
        assert_eq!(*dashboard.unsecured_frames_per_ecu.get("ECU2").unwrap(), 5);
    }

    #[test]
    fn test_unique_can_id_tracking() {
        let mut dashboard = Dashboard::new();

        dashboard.update_frame(create_test_secured_frame("ECU1", 0x100, true));
        dashboard.update_frame(create_test_secured_frame("ECU1", 0x100, true));
        dashboard.update_frame(create_test_secured_frame("ECU2", 0x200, true));
        dashboard.update_frame(create_test_secured_frame("ECU3", 0x300, true));

        assert_eq!(dashboard.unique_can_ids.len(), 3);
        assert!(dashboard.unique_can_ids.contains(&0x100));
        assert!(dashboard.unique_can_ids.contains(&0x200));
        assert!(dashboard.unique_can_ids.contains(&0x300));
    }

    #[test]
    fn test_multiple_attackers_tracking() {
        let mut dashboard = Dashboard::new();

        dashboard.update_frame(create_test_secured_frame("ATTACKER1", 0x100, false));
        dashboard.update_frame(create_test_secured_frame("ATTACKER2", 0x200, false));
        dashboard.update_frame(create_test_secured_frame("ATTACKER3", 0x300, false));

        assert_eq!(dashboard.recent_attackers.len(), 3);
        assert!(
            dashboard
                .recent_attackers
                .contains(&"ATTACKER1".to_string())
        );
        assert!(
            dashboard
                .recent_attackers
                .contains(&"ATTACKER2".to_string())
        );
        assert!(
            dashboard
                .recent_attackers
                .contains(&"ATTACKER3".to_string())
        );
    }

    #[test]
    fn test_attacker_list_max_size() {
        let mut dashboard = Dashboard::new();

        // Add 7 attackers (more than the max of 5)
        for i in 0..7 {
            dashboard.update_frame(create_test_secured_frame(
                &format!("ATTACKER{}", i),
                0x100,
                false,
            ));
        }

        // Should only keep last 5
        assert_eq!(dashboard.recent_attackers.len(), 5);
        // Should have ATTACKER2-ATTACKER6
        assert!(
            !dashboard
                .recent_attackers
                .contains(&"ATTACKER0".to_string())
        );
        assert!(
            !dashboard
                .recent_attackers
                .contains(&"ATTACKER1".to_string())
        );
        assert!(
            dashboard
                .recent_attackers
                .contains(&"ATTACKER6".to_string())
        );
    }

    #[test]
    fn test_security_rate_calculation() {
        let mut dashboard = Dashboard::new();

        // Add 70 secured frames and 30 unsecured frames
        for _ in 0..70 {
            dashboard.update_frame(create_test_secured_frame("ECU1", 0x100, true));
        }
        for _ in 0..30 {
            dashboard.update_frame(create_test_secured_frame("ATTACKER", 0x200, false));
        }

        assert_eq!(dashboard.frame_count, 100);
        assert_eq!(dashboard.secured_frame_count, 70);
        assert_eq!(dashboard.unsecured_frame_count, 30);

        // Security rate should be 70%
        let security_rate =
            (dashboard.secured_frame_count as f64 / dashboard.frame_count as f64) * 100.0;
        assert!((security_rate - 70.0).abs() < 0.1);
    }
}
