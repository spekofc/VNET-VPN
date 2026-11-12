//! GUI widgets

use crate::GuiResult;

/// Widget system stub
pub struct WidgetRegistry {
    // Stub implementation
}

impl WidgetRegistry {
    pub fn new() -> Self {
        Self {}
    }

    pub fn register_widget(&mut self, _name: &str, _widget: Box<dyn Widget>) -> GuiResult<()> {
        Ok(())
    }

    pub fn get_widget(&self, _name: &str) -> Option<&dyn Widget> {
        None
    }
}

/// Widget trait
pub trait Widget: Send + Sync {
    fn render(&self) -> GuiResult<()>;
    fn handle_event(&mut self, _event: GuiEvent) -> GuiResult<()>;
}

/// GUI event
#[derive(Debug, Clone)]
pub enum GuiEvent {
    Click,
    KeyPress(char),
    Resize(u32, u32),
    Close,
}