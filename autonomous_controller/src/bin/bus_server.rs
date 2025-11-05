use colored::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use autonomous_vehicle_sim::network::NetMessage;
use autonomous_vehicle_sim::types::CanFrame;

const BUS_ADDRESS: &str = "127.0.0.1:9000";
const BUFFER_SIZE: usize = 1000;

type ClientMap = Arc<Mutex<HashMap<String, tokio::net::tcp::OwnedWriteHalf>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
    println!("{}", "         AUTONOMOUS VEHICLE CAN BUS SERVER                    ".magenta().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
    println!();
    println!("{} Starting bus server on {}...", "→".green(), BUS_ADDRESS.bright_white());

    // Create broadcast channel for CAN frames
    let (tx, _rx) = broadcast::channel::<CanFrame>(BUFFER_SIZE);
    let tx = Arc::new(tx);

    // Create client map
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind(BUS_ADDRESS).await?;
    println!("{} Bus server ready! Waiting for ECU connections...", "✓".green().bold());
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

        // Spawn a task to handle this client
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, tx, clients).await {
                eprintln!("{} Client error: {}", "✗".red(), e);
            }
        });
    }
}

async fn handle_client(
    socket: TcpStream,
    tx: Arc<broadcast::Sender<CanFrame>>,
    clients: ClientMap,
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

    // Store the write half for this client
    {
        let mut clients_lock = clients.lock().await;
        clients_lock.insert(client_name.clone(), write_half);
    }

    // Subscribe to CAN frames
    let mut rx = tx.subscribe();

    // Spawn a task to forward CAN frames to this client
    let client_name_clone = client_name.clone();
    let clients_clone = Arc::clone(&clients);
    tokio::spawn(async move {
        while let Ok(frame) = rx.recv().await {
            // Get the write half for this client
            let mut clients_lock = clients_clone.lock().await;
            if let Some(writer) = clients_lock.get_mut(&client_name_clone) {
                let msg = NetMessage::CanFrame(frame);
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
        }
    });

    // Read messages from the client
    let mut frame_count = 0;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;

        if n == 0 {
            // Connection closed
            break;
        }

        let msg: NetMessage = serde_json::from_str(&line)?;

        match msg {
            NetMessage::CanFrame(frame) => {
                frame_count += 1;
                println!(
                    "  {} Frame #{:04} from {} - ID: 0x{:03X}",
                    "→".yellow(),
                    frame_count,
                    client_name.bright_cyan(),
                    frame.id.value()
                );

                // Broadcast to all clients
                if let Err(e) = tx.send(frame) {
                    eprintln!("{} Failed to broadcast frame: {}", "✗".red(), e);
                }
            }
            _ => {
                // Ignore other message types for now
            }
        }
    }

    // Remove client from map
    {
        let mut clients_lock = clients.lock().await;
        clients_lock.remove(&client_name);
    }

    println!(
        "{} {} disconnected (sent {} frames)",
        "→".bright_black(),
        client_name.bright_black(),
        frame_count
    );

    Ok(())
}
