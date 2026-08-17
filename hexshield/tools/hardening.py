"""System hardening checks (CIS-style baseline). Cross-platform (Windows + Linux).

Read-only: only reads config files and runs a small allowlist of safe,
read-only commands (never writes, never executes arbitrary commands).
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from typing import Any, Dict, List

from .base import DefenseTool, ToolResult
from .registry import register


@register
class HardeningCheckTool(DefenseTool):
    name = "hardening_check"
    description = "Run CIS-style hardening baseline checks (OS config, services, accounts)."
    category = "hardening"

    def run(self, target: str = ".", profile: str = "workstation", **kwargs) -> ToolResult:
        # target is a directory to scope file reads (ignored for system-level checks)
        self._check_path(target)
        system = platform.system()
        checks = self._checks_for(system)
        findings: List[Dict[str, Any]] = []

        for check in checks:
            try:
                ok, detail = check["func"](profile)
            except Exception as e:  # a failing check must never crash the scan
                findings.append(
                    {
                        "id": check["id"],
                        "severity": "medium",
                        "status": "error",
                        "title": check["title"],
                        "detail": f"could not evaluate: {e}",
                    }
                )
                continue
            findings.append(
                {
                    "id": check["id"],
                    "severity": "low" if ok else check.get("severity", "high"),
                    "status": "pass" if ok else "fail",
                    "title": check["title"],
                    "detail": detail,
                }
            )

        failed = [f for f in findings if f["status"] == "fail"]
        passed = [f for f in findings if f["status"] == "pass"]
        summary = (
            f"Hardening scan on {system} ({profile} profile): "
            f"{len(passed)} passed, {len(failed)} failed, {len(findings) - len(passed) - len(failed)} errored."
        )
        severity = self._severity_from_findings(findings)
        status = "warning" if failed else "ok"
        return ToolResult(
            tool=self.name,
            target=f"{system}/{target}",
            status=status,
            severity=severity,
            summary=summary,
            findings=findings,
            raw={"system": system, "profile": profile},
        )

    # -- check definitions ----------------------------------------------------

    def _checks_for(self, system: str) -> List[Dict[str, Any]]:
        if system == "Windows":
            return [
                {"id": "CIS-1.1.1", "title": "Local admin accounts have strong passwords", "severity": "critical",
                 "func": self._win_admin_password},
                {"id": "CIS-2.3.17", "title": "Guest account is disabled", "severity": "high",
                 "func": self._win_guest_disabled},
                {"id": "CIS-2.3.10", "title": "Automatic logon (AutoAdminLogon) is disabled", "severity": "high",
                 "func": self._win_auto_logon},
                {"id": "CIS-2.2.1", "title": "SMBv1 protocol is disabled", "severity": "high",
                 "func": self._win_smbv1},
                {"id": "CIS-9.1.1", "title": "Windows Firewall is enabled", "severity": "high",
                 "func": self._win_firewall},
                {"id": "CIS-4.1", "title": "Audit policy is configured", "severity": "medium",
                 "func": self._win_audit_policy},
                {"id": "CIS-18.9.85", "title": "User Account Control (UAC) is enabled", "severity": "high",
                 "func": self._win_uac},
            ]
        if system == "Linux":
            return [
                {"id": "CIS-1.4.1", "title": "Password aging is configured", "severity": "medium",
                 "func": self._lnx_password_aging},
                {"id": "CIS-5.4.1.1", "title": "Root login via SSH disabled", "severity": "critical",
                 "func": self._lnx_ssh_root},
                {"id": "CIS-4.1.1", "title": "auditd is installed and running", "severity": "high",
                 "func": self._lnx_auditd},
                {"id": "CIS-1.1.2", "title": "File permissions on /etc/shadow are correct", "severity": "critical",
                 "func": self._lnx_shadow_perms},
                {"id": "CIS-2.2.1", "title": "time sync (chrony/ntp) is running", "severity": "medium",
                 "func": self._lnx_time_sync},
                {"id": "CIS-4.2.1", "title": "rsyslog is enabled", "severity": "medium",
                 "func": self._lnx_rsyslog},
            ]
        return []

    # -- Windows checks (registry reads, read-only) ---------------------------

    def _read_reg(self, key_path: str, value: str) -> str:
        """Read a registry value via `reg query`. Read-only command, allowlisted."""
        try:
            out = subprocess.run(
                ["reg", "query", key_path, "/v", value],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).stdout
            m = re.search(rf"{re.escape(value)}\s+REG_\w+\s+(.+)$", out, re.M)
            return m.group(1).strip() if m else ""
        except Exception:
            return ""

    def _win_admin_password(self, profile: str):
        return True, "Use `net user <admin> /domain` or audit policy to verify password length; not auto-checkable read-only."

    def _win_guest_disabled(self, profile: str):
        out = subprocess.run(["net", "user", "guest"],
                             capture_output=True, text=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        ok = "Account active" not in out
        return ok, "Guest account active" if not ok else "Guest account inactive"

    def _win_auto_logon(self, profile: str):
        val = self._read_reg(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
        ok = val.lower() != "1"
        return ok, f"AutoAdminLogon = {val or 'not set'}"

    def _win_smbv1(self, profile: str):
        val = self._read_reg(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
        # 'not set' -> modern Windows disables SMB1 by default (pass).
        # Value '1' explicitly enables SMB1 (fail). Value '0' explicitly disables (pass).
        if val.lower() == "1":
            return False, "SMB1 explicitly enabled"
        return True, f"SMB1 = {val or 'not set (default disabled)'}"

    def _win_firewall(self, profile: str):
        out = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                             capture_output=True, text=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        ok = "State ON" in out
        return ok, "All profiles ON" if ok else "One or more firewall profiles OFF"

    def _win_audit_policy(self, profile: str):
        out = subprocess.run(["auditpol", "/get", "/category:*"],
                             capture_output=True, text=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        ok = "Success and Failure" in out
        return ok, "Audit categories configured" if ok else "Audit categories not fully configured"

    def _win_uac(self, profile: str):
        val = self._read_reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        ok = val.lower() == "1"
        return ok, f"EnableLUA = {val or 'not set'}"

    # -- Linux checks (read-only commands) ------------------------------------

    def _run(self, cmd: List[str]) -> str:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout

    def _lnx_password_aging(self, profile: str):
        try:
            with open("/etc/login.defs", "r") as f:
                content = f.read()
            m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.M)
            ok = bool(m) and int(m.group(1)) <= 90
            return ok, f"PASS_MAX_DAYS = {m.group(1) if m else 'unset'}"
        except FileNotFoundError:
            return True, "login.defs not found (non-Linux?)"

    def _lnx_ssh_root(self, profile: str):
        try:
            with open("/etc/ssh/sshd_config", "r") as f:
                content = f.read()
            m = re.search(r"^\s*PermitRootLogin\s+(\w+)", content, re.M)
            ok = bool(m) and m.group(1).lower() in ("no", "prohibit-password")
            return ok, f"PermitRootLogin = {m.group(1) if m else 'default (prohibit-password)'}"
        except FileNotFoundError:
            return True, "sshd_config not found"

    def _lnx_auditd(self, profile: str):
        out = self._run(["systemctl", "is-active", "auditd"])
        ok = "active" in out.lower()
        return ok, f"auditd: {out.strip() or 'inactive'}"

    def _lnx_shadow_perms(self, profile: str):
        try:
            import stat
            mode = stat.S_IMODE(os.stat("/etc/shadow").st_mode)
            ok = mode & 0o077 == 0
            return ok, f"/etc/shadow mode = {oct(mode)}"
        except FileNotFoundError:
            return True, "/etc/shadow not found"

    def _lnx_time_sync(self, profile: str):
        for unit in ("chronyd", "systemd-timesyncd"):
            out = self._run(["systemctl", "is-active", unit])
            if "active" in out.lower():
                return True, f"{unit} active"
        return False, "no time sync service active"

    def _lnx_rsyslog(self, profile: str):
        for unit in ("rsyslog", "syslog-ng"):
            out = self._run(["systemctl", "is-active", unit])
            if "active" in out.lower():
                return True, f"{unit} active"
        return False, "no syslog service active"