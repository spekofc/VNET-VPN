//! vnet-gui — Native GUI entry point

use vnet_gui::{GuiApp, GuiConfig};

#[tokio::main]
async fn main() -> vnet_gui::GuiResult<()> {
    let config = GuiConfig::default();
    let app = GuiApp::new(config);
    
    // Run the GUI (this blocks until window closes)
    app.run().await
}