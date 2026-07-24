# Riptide — Codebase Reference

Quick-orientation notes for the Riptide C2 framework. Refreshed against the tree
as of 2026-07-24. Keep this untracked working notes, not source of truth — the
code is.

## What it is

A small Rust C2 framework for authorized red-team work in closed environments.
Four crates in one cargo workspace:

```
operator ─▶ console (TUI/REPL) ─▶ c2-server (REST + WS) ◀── implant (beacon)
operator ─▶ curl / Python (c2client.py) ─▶ c2-server
```

- **implant** — static musl binary, pull-only beacon. Phones home, polls for
  commands, dispatches to on-demand modules, posts results. Never listens.
- **c2-server** — axum hub. One operator API port (default 10337) for REST + WS.
  Beacon listeners (HTTP/HTTPS) are started/stopped dynamically at runtime.
- **console** — rustyline REPL that talks to the server's REST API (polls, no WS).
- **payload-gen** — thin CLI wrapper around `cargo build -p implant` that bakes
  config in via env vars and emits a musl binary.

Release profile: `opt-level="z"`, `lto=true`, `strip=true`, `panic="abort"`.

## Command protocol

Triple of `module` / `action` / `args` (serde_json::Value), delivered as JSON.

```
operator:  POST /api/v1/sessions/:id/commands  {module, action, args, timeout_secs}
server:    -> PendingCommand (uuid) queued in VecDeque (max 10/beacon)
implant:   POST /beacon (BeaconPayload) -> {"commands":[...], "stay_alive":bool}
implant:   dispatch (module, action) -> result
implant:   POST /result  {implant_id, command_id, status:"completed"|"failed", data}
console:   poll GET /api/v1/sessions/:id/commands/:cid until result present
```

Modules / actions (defaults marked):
| module    | actions                                   |
|-----------|-------------------------------------------|
| shell     | exec                                      |
| recon     | passive, active, arp, gather (default)    |
| creds     | harvest (default)                         |
| persist   | cron (default), systemd, bashrc           |
| privesc   | copyfail (default), pkexec                |
| exfil     | file (default), dir                       |
| file      | read (default), write                     |
| marker    | write (default)                           |
| system    | info (default), sleep, exit               |

## Routes

Operator-facing (api-port):
- `GET /health`
- `GET/DELETE /api/v1/sessions[/:id]`
- `POST /api/v1/sessions/:id/commands`, `GET /api/v1/sessions/:id/commands[/:cid]` (+DELETE)
- `GET/POST /api/v1/sessions/:id/files`
- `GET/POST /api/v1/listeners`, `DELETE /api/v1/listeners/:port`
- `GET /ws/events`

Implant-facing (on dynamic listeners, built by `routes::build_implant_router`):
- `GET/POST /beacon`, `POST /upload`, `POST /result`

Note: `download_file` and `update_config` handlers exist but are NOT registered
on any router (dead-code-allowed).

## State (`c2-server/src/state.rs`)

`AppState` (Arc), all RwLock: `sessions`, `command_queues` (VecDeque, batch-10),
`command_history` (capped 500/session), `event_tx` (broadcast 256, C2Event enum),
`listeners` (port -> ListenerHandle {protocol, oneshot abort}), cert paths, log
paths.

## Implant modules

All statically compiled; dispatch is a single `match (module, action)` in
`implant/src/dispatch.rs::CommandAction::execute`. No dlopen.
- `recon.rs` passive (/proc reads) / active (shell, ping sweep)
- `creds.rs` Firefox/key4.db, ssh keys, /etc/shadow, bash_history, NM wifi
- `copyfail.rs` CVE-2026-31431 AF_ALG page-cache corruption -> root
- `persist.rs` cron @reboot / systemd unit / .bashrc backdoor
- `exfil.rs` shell tar+gzip POST, or in-memory tar+flate2 chunked
- `marker.rs` writes /dev/shm/ras_marker.<ts> when LABELLING_MARKER set
- `payload.rs` hardcoded x86_64 ELF payloads for copyfail injection
- `system` info / sleep / exit handled inline in dispatch + lib.rs loop

Beacon loop in `implant/src/lib.rs::run_beacon_loop`: jitter sleep -> beacon ->
execute commands -> post results -> optional fast-poll (stay_alive, 10s, 5m) ->
sleep current_interval. Exit via `system exit`.

## Build & config

Implant config baked at compile time via `option_env!` in `config.rs`/`marker.rs`,
driven by `payload-gen` setting: `C2_HOST, C2_PORT, BEACON_RATE, BEACON_JITTER,
C2_TLS, PROCESS_NAME, SERVICE_NAME, IMPLANT_PATH, LABELLING_MARKER`.
`implant/build.rs` reruns on C2_HOST/C2_PORT/BEACON_RATE/LABELLING_MARKER change.
`implant_id` = `<hostname>-<first-nonzero-MAC-with-dashes>`.

Build an implant:
```
cargo run -p payload-gen --release -- --protocol https --host c2.example.com \
  --port 443 --beacon-rate 600 --jitter 120 --process-name "[kworker/0:2]"
```
HTTP protocol builds with `--no-default-features` (drops TLS).

Run the server (actual flags, NOT the README's):
```
cargo run -p c2-server --release             # API on :10337, no beacon listeners
cargo run -p c2-server --release -- --api-port 8443
# then start beacon listeners via API/console:
curl -X POST .../api/v1/listeners -d '{"port":8080,"protocol":"http"}'
```
Run the console: `cargo run -p console --release -- --server http://<api-host>:10337`

## Discrepancies / things to know

- **README is stale.** It advertises `--http-port`/`--https-port` and "HTTP on :80,
  HTTPS on :443 at startup". The real CLI is `--api-port` (default 10337) with
  dynamic beacon listeners started via API/console only. README quick-start for
  the server and several port examples are wrong. README also lists endpoints
  generally correctly.
- **main.rs header comment says default api-port 10000; the `#[arg]` default is
  10337.** Code wins (10337). Internal doc drift.
- **`tier_label`/`escalate_via` and several config fields** (`beacon_env_var`,
  `cleanup_staging`, stage/chunk pauses, shell_* toggles) exist in `Config` but
  several are not wired from env in config.rs — verify before relying on them.
- `download_file` / `update_config` handlers are dead (unregistered routes).
- `send_chunk` (implant c2.rs) is dead-code-allowed.

## Current uncommitted working state (HEAD = 9d85b98)

Session 2026-07-24 changes (in addition to the pre-existing cleanup pass still
in the tree):

1. **Operator-presence profiles (`--mode interactive|beacon`)** — compile-time,
   set by payload-gen, baked via `IMPLANT_MODE` env. Default = interactive.
   - `config.rs`: `ImplantMode` enum + `mode` field + `INTERACTIVE_POLL_SECS=1`
     + `mode_label()`. `build.rs` reruns on `IMPLANT_MODE`.
   - `lib.rs::run_beacon_loop`: interactive polls ~1s, no jitter, skips
     stay_alive fast-poll (already faster). Beacon = interval+jitter as before.
   - `payload-gen`: `--mode` flag, validated, printed in banner.
   - `dispatch.rs::cmd_system_info`: now reports `mode`.
   - Purpose: interactive = loud (chatty, easy to detect); beacon = low-and-slow.
     Both coexist so different TUA agent profiles generate distinguishable
     dataset traces. No transport/protocol change — same /beacon+/result.

2. **pkexec escalation fixed** (`dispatch.rs::cmd_privesc_pkexec` + `lib.rs`) —
   now escalates THIS session, not a sibling. Spawns a root re-exec of self
   under the SAME implant_id, returns `reexec:true`, and the unprivileged
   parent exits so only one root process beacons. Server upgrades the existing
   session's uid→0 instead of creating a confusing second session. Mirrors
   copyfail's same-session contract. (GUI prompt needs a human — untested live.)

3. **Sleep hot-loop regression fixed** (`lib.rs`) — restored `secs > 0` floor;
   `system sleep 0` is now a no-op, not a tight-loop hammering the server.

4. **NEW `discovery` module** (`implant/src/discovery.rs` + dispatch arms +
   console mapping) — host enumeration with two tradecraft levels:
   - `procs` (T1057, in-memory /proc), `users` (T1087/T1069, in-memory /etc) — stealth
   - `suid` (T1083, shell find), `services` (T1007/T1053, systemctl+cron) — loud
   - `all` — combined

5. **`persist bashrc` robustness fix** (`dispatch.rs`) — was aborting on the
   first unwritable .bashrc (reported `failed` despite partial success). Now
   best-effort across all writable files, idempotent, reports `written`/`failed`.

Pre-existing tree cleanup (still present): `#[allow(dead_code)]` on several
unused fields/handlers, dropped `port` from `ListenerHandle` + unused imports.

## Memory / prefs for this session

- Never stage or commit without prompting the user first. (saved to memory)
- See TEST_PLAN.md for the full ATT&CK mapping + executed test results.

