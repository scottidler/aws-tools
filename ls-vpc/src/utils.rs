//! utils.rs
//! ---------------------------------------------------------------------------
//! Helper utilities that don’t fit anywhere else.

use std::{env, fs, path::PathBuf};

/// Return (and create if needed) a platform-appropriate directory for log files.
pub fn get_or_create_log_dir() -> PathBuf {
    let dir = if cfg!(target_os = "macos") {
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("Library")
            .join("Logs")
            .join("slam")
    } else if let Ok(x) = env::var("XDG_STATE_HOME") {
        PathBuf::from(x).join("slam")
    } else if let Ok(h) = env::var("HOME") {
        PathBuf::from(h).join(".local").join("state").join("slam")
    } else {
        PathBuf::from("slam_logs")
    };
    fs::create_dir_all(&dir).ok();
    dir
}
