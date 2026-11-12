//! TUI events

use crate::app::{TuiError, TuiResult};
use crossterm::event::Event as CrosstermEvent;
use tokio::sync::mpsc;
use std::time::Duration;

/// TUI event handler
pub struct EventHandler {
    sender: mpsc::Sender<Event>,
    receiver: mpsc::Receiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(100);
        Self { sender, receiver }
    }

    pub async fn start(&self) -> TuiResult<()> {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(event) = crossterm::event::read() {
                    if sender.send(Event::Crossterm(event)).await.is_err() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        Ok(())
    }

    pub async fn next_event(&mut self) -> TuiResult<Option<Event>> {
        Ok(self.receiver.recv().await)
    }
}

/// TUI event
#[derive(Debug, Clone)]
pub enum Event {
    Crossterm(CrosstermEvent),
    Tick,
    Resize(u16, u16),
    Custom(String),
}

impl From<CrosstermEvent> for Event {
    fn from(event: CrosstermEvent) -> Self {
        Event::Crossterm(event)
    }
}