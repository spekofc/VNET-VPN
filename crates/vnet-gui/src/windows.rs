//! GUI windows

use crate::GuiResult;

/// Window management stub
pub struct WindowManager {
    // Stub implementation
}

impl WindowManager {
    pub fn new() -> GuiResult<Self> {
        Ok(Self {})
    }

    pub fn create_window(&self, _title: &str, _width: f32, _height: f32) -> GuiResult<u32> {
        // Stub implementation
        Ok(0)
    }

    pub fn show_window(&self, _id: u32) -> GuiResult<()> {
        Ok(())
    }

    pub fn close_window(&self, _id: u32) -> GuiResult<()> {
        Ok(())
    }
}