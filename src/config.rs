use std::str::FromStr;
use std::path::PathBuf;
use std::fs;
use serde::{Serialize, Deserialize};

const PATH_TO_CONFIG: &str = "/etc/daeth/config";

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Struct that hold all application settings
pub struct Config {
    // ~~~~~~~~~~ [Detection] ~~~~~~~~~~ //
    /// Enable allow list checking.
    /// 
    /// If false, allow list is ignored and all suspicious
    /// processes are killed immediately
    pub enable_allowlist: bool,
    /// Path to SQLite3 database file
    /// with allow list
    pub allowlist_path: PathBuf,
    /// Max time a process can be inactive before its stats get removed from
    /// process table.
    pub flush_timeout_sec: u64,
    /// Max value of susness field that processes are allowed to have.
    ///  If this value is exceeded, the process is killed.
    pub critical_susp: i32,
    
    // ~~~~~~~~~~ [Killing] ~~~~~~~~~~ //
    /// When killing a suspicious process, also
    /// kill its parent process
    pub kill_parent: bool,
    /// When killing a suspicious process, also
    /// kill all its descendants recursively
    pub kill_children: bool,
    /// When killing a suspicious process,
    /// kill the entire process group the process
    /// belongs to
    pub kill_proc_group: bool,
    /// *For debug purposes.*
    ///
    /// When killing a suspicious process, send
    /// `SIGTERM` instead of `SIGKILL`, so that accidentally
    /// killed processes could cleanup before exiting
    pub use_sigterm: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            enable_allowlist: true,
            allowlist_path: PathBuf::from_str("/etc/daeth/allowlist.db").unwrap(),
            flush_timeout_sec: 120,
            critical_susp: 5,
            kill_parent: false,
            kill_children: true,
            kill_proc_group: false,
            use_sigterm: false
        }
    }
}

impl Config {
    pub fn load() -> Result<Config, String> {
        let raw_conf = match fs::read_to_string(PATH_TO_CONFIG) {
            Ok(s) => s,
            Err(e) => return Err(e.to_string())
        };
        match serde_json::from_str::<Config>(&raw_conf) {
            Ok(conf) => Ok(conf),
            Err(e) => Err(e.to_string())
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let raw_conf = match serde_json::to_string_pretty(self) {
            Ok(s) => s,
            Err(e) => return Err(e.to_string())
        };
        match fs::write(PATH_TO_CONFIG, raw_conf) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string())
        }
    }
}
