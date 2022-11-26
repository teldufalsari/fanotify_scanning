use std::time::{self, SystemTime};
use std::path::PathBuf;

/// This structure contains a field that measures how
/// suspicious this process is and stores all file paths
/// that were modified by this process.
#[derive(Debug, Clone)]
pub struct ProcStats {
    pub susness : i32,
    pub paths: Vec<PathBuf>,
    pub last_update_time: time::SystemTime,
}

impl ProcStats {
    /// Creates an empty record with zero fields.
    pub fn new() -> ProcStats {
        ProcStats {
            susness: 0,
            paths: Vec::new(),
            last_update_time: SystemTime::now(),
        }
    }
}
