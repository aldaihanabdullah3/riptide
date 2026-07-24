/// Shared utility functions for the C2 server.
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Log a line to stdout and to the given file.
pub fn log_line(path: &PathBuf, line: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let full = format!("{}  {}", ts, line);
    println!("{}", full);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", full);
    }
}
