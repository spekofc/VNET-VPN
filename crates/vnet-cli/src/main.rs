//! vnet-cli — Command-line interface for vnet

use clap::{Parser, Subcommand};
use anyhow::Result;
use tracing_subscriber::EnvFilter;
use vnet_ipc::{IpcClient, ClientConfig};

#[derive(Parser)]
#[command(name = "vnet", version = "0.1.0", author = "dj", long_about = "vnet - Cross-platform virtual private network")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a network
    Connect {
        /// Network name or ID
        network: String,
        /// Password (optional, will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Virtual IP address
        #[arg(long, default_value = "10.0.0.1")]
        virtual_ip: std::net::Ipv4Addr,
    },
    /// Disconnect from current network
    Disconnect,
    /// Show connection status
    Status,
    /// List connected peers
    Peers,
    /// Show network info
    Info {
        /// Network name or ID
        network: String,
    },
    /// Create a new network
    Create {
        /// Network name
        name: String,
        /// Password
        #[arg(short, long)]
        password: String,
    },
    /// Join an existing network
    Join {
        /// Network name or ID
        network: String,
        /// Password
        #[arg(short, long)]
        password: String,
    },
    /// Leave current network
    Leave,
    /// Show version
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut client = IpcClient::new(ClientConfig::default());
    client.connect().await?;

    match cli.command {
        Commands::Connect { network, password, virtual_ip } => {
            println!("Connecting to network: {}", network);
            
            // Create session
            let params = serde_json::json!({
                "name": network,
                "password": password,
                "virtual_ip": virtual_ip.to_string(),
            });
            let result = client.call("session.create", params).await?;
            println!("Session created: {}", result);
            
            // Initialize
            let result = client.call("session.initialize", serde_json::json!({})).await?;
            println!("Session initialized: {}", result);
            
            // Connect
            let result = client.call("session.connect", serde_json::json!({})).await?;
            println!("Session connected: {}", result);
        }
        Commands::Disconnect => {
            println!("Disconnecting...");
            let result = client.call("session.disconnect", serde_json::json!({})).await?;
            println!("Disconnected: {}", result);
        }
        Commands::Status => {
            let result = client.call("session.state", serde_json::json!({})).await?;
            println!("Status: {}", result);
        }
        Commands::Peers => {
            let result = client.call("peer.list", serde_json::json!({})).await?;
            println!("Peers: {}", result);
        }
        Commands::Info { network } => {
            println!("Network info for: {}", network);
            // TODO: Implement network info
        }
        Commands::Create { name, password } => {
            println!("Creating network: {}", name);
            let params = serde_json::json!({
                "name": name,
                "password": password,
            });
            let result = client.call("session.create", params).await?;
            println!("Network created: {}", result);
        }
        Commands::Join { network, password } => {
            println!("Joining network: {}", network);
            let params = serde_json::json!({
                "name": network,
                "password": Some(password),
            });
            let result = client.call("session.create", params).await?;
            println!("Joined network: {}", result);
            
            let result = client.call("session.initialize", serde_json::json!({})).await?;
            println!("Initialized: {}", result);
            
            let result = client.call("session.connect", serde_json::json!({})).await?;
            println!("Connected: {}", result);
        }
        Commands::Leave => {
            println!("Leaving network...");
            let result = client.call("session.disconnect", serde_json::json!({})).await?;
            println!("Left network: {}", result);
        }
        Commands::Version => {
            println!("vnet {}", env!("CARGO_PKG_VERSION"));
        }
    }

    client.disconnect().await?;
    Ok(())
}