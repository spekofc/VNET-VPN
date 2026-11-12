//! vnet-gui — Native GUI for vnet (egui + wgpu)

#![warn(missing_docs, clippy::all)]

pub mod app;
pub mod windows;
pub mod widgets;

pub use app::{GuiApp, GuiConfig, GuiError, GuiResult};
pub use windows::WindowManager;
pub use widgets::{WidgetRegistry, Widget, GuiEvent};