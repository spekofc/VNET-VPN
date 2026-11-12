//! vnet-tui — Terminal UI for vnet

#![warn(missing_docs, clippy::all)]

pub mod app;
pub mod ui;
pub mod events;

pub use app::{App, TuiConfig, TuiError, TuiResult};
pub use events::{Event, EventHandler};