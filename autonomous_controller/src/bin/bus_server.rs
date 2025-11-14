use autonomous_vehicle_sim::hsm::SecuredCanFrame;
use autonomous_vehicle_sim::network::NetMessage;
use autonomous_vehicle_sim::rate_limiter::RateLimiter;
use colored::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const BUFFER_SIZE: usize = 10000; // Increased for 9 ECUs @ 10Hz (~100 fps) = ~100 seconds of buffering

type ClientMap = Arc<Mutex<HashMap<String, tokio::net::tcp::OwnedWriteHalf>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .magenta()
            .bold()
    );
    println!(
        "{}",
        "         AUTONOMOUS VEHICLE CAN BUS SERVER                    "
            .magenta()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .magenta()
            .bold()
    );
    println!();
    println!(
        "{} Starting bus server on {}...",
        "→".green(),
        BUS_ADDRESS.bright_white()
    );

    // Create broadcast channel for all network messages (frames + performance stats)
    let (tx, _rx) = broadcast::channel::<NetMessage>(BUFFER_SIZE);
    let tx = Arc::new(tx);

    // Create client map
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    // Create rate limiter with automotive defaults (200 burst, 100 msg/sec sustained)
    let rate_limiter = RateLimiter::with_automotive_defaults();
    println!(
        "{} Rate limiting enabled: 200 msg burst, 100 msg/sec sustained per ECU",
        "ℹ".bright_blue()
    );

    let listener = TcpListener::bind(BUS_ADDRESS).await?;
    println!(
        "{} Bus server ready! Waiting for ECU connections...",
        "✓".green().bold()
    );
    println!();

    let mut client_count = 0u32;

    loop {
        let (socket, addr) = listener.accept().await?;
        client_count += 1;

        println!(
            "{} New connection from {} (Total clients: {})",
            "→".cyan(),
            addr.to_string().bright_white(),
            client_count.to_string().bright_cyan()
        );

        let tx = Arc::clone(&tx);
        let clients = Arc::clone(&clients);
        let rate_limiter = rate_limiter.clone();

        // Spawn a task to handle this client
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, tx, clients, rate_limiter).await {
                eprintln!("{} Client error: {}", "✗".red(), e);
            }
        });
    }
}

async fn handle_client(
    socket: TcpStream,
    tx: Arc<broadcast::Sender<NetMessage>>,
    clients: ClientMap,
    rate_limiter: RateLimiter,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = socket.peer_addr()?;
    let (read_half, write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);

    // Wait for client registration
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let msg: NetMessage = serde_json::from_str(&line)?;
    let client_name = match msg {
        NetMessage::Register { client_name } => {
            println!(
                "  {} {} registered from {}",
                "✓".green(),
                client_name.bright_cyan().bold(),
                peer_addr.to_string().bright_black()
            );
            client_name
        }
        _ => {
            return Err("First message must be Register".into());
        }
    };

    // Store client name for tracking
    {
        let mut clients_lock = clients.lock().await;
        clients_lock.insert(client_name.clone(), write_half);
    }

    // Subscribe to CAN frames
    let mut rx = tx.subscribe();

    // Remove writer from map and give ownership to forwarding task
    // This prevents mutex contention during I/O operations
    let mut writer = {
        let mut clients_lock = clients.lock().await;
        clients_lock.remove(&client_name).unwrap()
    };

    // Spawn a task to forward all network messages to this client
    let client_name_clone = client_name.clone();
    tokio::spawn(async move {
        loop {
            // Handle broadcast receive with lag recovery
            let msg = match rx.recv().await {
                Ok(message) => message,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    eprintln!(
                        "{} Client {} lagged, skipped {} messages (recovering...)",
                        "⚠".yellow(),
                        client_name_clone.bright_cyan(),
                        skipped
                    );
                    // Continue receiving after lag instead of dying
                    continue;
                }
                Err(_) => {
                    // Channel closed, exit task
                    break;
                }
            };

            // Write directly to this client's writer (NO MUTEX!)
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(_) => continue,
            };

            if writer.write_all(json.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    // Read messages from the client
    let mut frame_count = 0;
    let mut throttled_count = 0;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;

        if n == 0 {
            // Connection closed
            break;
        }

        let msg: NetMessage = serde_json::from_str(&line)?;

        match msg {
            NetMessage::SecuredCanFrame(secured_frame) => {
                // Rate limiting check
                if !rate_limiter.allow_message(&client_name).await {
                    throttled_count += 1;
                    eprintln!(
                        "{} Frame from {} THROTTLED (rate limit exceeded, {} total throttled)",
                        "⚠".yellow().bold(),
                        client_name.bright_cyan(),
                        throttled_count
                    );
                    continue; // Drop the frame
                }

                frame_count += 1;
                println!(
                    "  {} Frame #{:04} from {} - ID: 0x{:03X} (secured)",
                    "→".yellow(),
                    frame_count,
                    client_name.bright_cyan(),
                    secured_frame.can_id.value()
                );

                // Broadcast to all clients
                if let Err(e) = tx.send(NetMessage::SecuredCanFrame(secured_frame)) {
                    eprintln!("{} Failed to broadcast frame: {}", "✗".red(), e);
                }
            }
            NetMessage::CanFrame(frame) => {
                // Handle legacy unencrypted frames (for backwards compatibility)

                // Rate limiting check
                if !rate_limiter.allow_message(&client_name).await {
                    throttled_count += 1;
                    eprintln!(
                        "{} Frame from {} THROTTLED (rate limit exceeded, {} total throttled)",
                        "⚠".yellow().bold(),
                        client_name.bright_cyan(),
                        throttled_count
                    );
                    continue; // Drop the frame
                }

                frame_count += 1;
                println!(
                    "  {} Frame #{:04} from {} - ID: 0x{:03X} (unsecured/legacy)",
                    "→".yellow(),
                    frame_count,
                    client_name.bright_cyan(),
                    frame.id.value()
                );

                // Wrap in a secured frame structure and broadcast
                // Note: This is a legacy compatibility path
                let secured_frame = SecuredCanFrame {
                    can_id: frame.id,
                    data: frame.data,
                    source: frame.source,
                    timestamp: frame.timestamp,
                    mac: [0u8; 32], // No MAC for legacy frames
                    crc: 0,         // No CRC for legacy frames
                    session_counter: 0,
                };

                if let Err(e) = tx.send(NetMessage::SecuredCanFrame(secured_frame)) {
                    eprintln!("{} Failed to broadcast frame: {}", "✗".red(), e);
                }
            }
            NetMessage::PerformanceStats(stats) => {
                // Broadcast performance statistics to all clients (especially monitor)
                println!(
                    "  {} Performance stats from {}",
                    "ℹ".bright_blue(),
                    client_name.bright_cyan()
                );

                if let Err(e) = tx.send(NetMessage::PerformanceStats(stats)) {
                    eprintln!("{} Failed to broadcast performance stats: {}", "✗".red(), e);
                }
            }
            _ => {
                // Ignore other message types (Register, Ack, Error)
            }
        }
    }

    // Client already removed from map (writer was moved to forwarding task)

    if throttled_count > 0 {
        println!(
            "{} {} disconnected (sent {} frames, {} throttled)",
            "→".bright_black(),
            client_name.bright_black(),
            frame_count,
            throttled_count
        );
    } else {
        println!(
            "{} {} disconnected (sent {} frames)",
            "→".bright_black(),
            client_name.bright_black(),
            frame_count
        );
    }

    Ok(())
}
