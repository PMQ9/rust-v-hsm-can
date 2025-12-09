// HSM Service Binary - Standalone cryptographic service for Core 3
// Handles all MAC generation, verification, and security operations for ECUs

use autonomous_vehicle_sim::hsm_service::HsmServiceServer;
use colored::*;
use std::process;

const DEFAULT_SOCKET_PATH: &str = "/tmp/vsm_hsm_service.sock";

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let perf_mode = args.contains(&"--perf".to_string());

    // Get socket path from args or use default
    let socket_path = args
        .iter()
        .position(|arg| arg == "--socket")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_SOCKET_PATH);

    // Create HSM service server
    let mut server = HsmServiceServer::new(socket_path.to_string(), perf_mode);

    // Setup Ctrl+C handler for clean shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{} Shutting down HSM Service...", "→".yellow());
        process::exit(0);
    });

    // Run HSM service (blocks until shutdown)
    if let Err(e) = server.run().await {
        eprintln!("{} HSM Service error: {}", "✗".red().bold(), e);
        process::exit(1);
    }
}
