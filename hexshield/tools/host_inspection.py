"""Host inspection tools: exposure and persistence checks.

Read-only, bounded host inspection. Uses a tiny allowlist of harmless system
queries and local file reads to answer two common blue-team questions:

1. What is this host listening on, and is anything exposed that should worry me?
2. What persistence points are configured, and which ones deserve review?
"""

from __future__ import annotations

import csv
import io
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from .base import DefenseTool, ToolResult
from .registry import register

_RISKY_PORTS = {
    21: ("FTP", "medium"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    25: ("SMTP", "low"),
    53: ("DNS", "low"),
    80: ("HTTP", "low"),
    135: ("RPC", "high"),
    139: ("NetBIOS", "high"),
    1433: ("MSSQL", "high"),
    1521: ("Oracle DB", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    445: ("SMB", "critical"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    5985: ("WinRM HTTP", "high"),
    5986: ("WinRM HTTPS", "medium"),
    6379: ("Redis", "critical"),
    8080: ("Alt HTTP", "medium"),
    9200: ("Elasticsearch", "critical"),
}

_SUSPICIOUS_PATH_RE = re.compile(
    r"(\\temp\\|\\appdata\\|/tmp/|/var/tmp/|powershell(?:\.exe)?|cmd\.exe|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?)",
    re.I,
)


def _subprocess_text(cmd: List[str]) -> str:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ).stdout


@register
class ExposureCheckTool(DefenseTool):
    name = "exposure_check"
    description = "Inspect listening services and flag risky or broadly exposed ports."
    category = "hardening"

    def run(self, target: str = ".", **kwargs) -> ToolResult:
        self._check_path(target)
        system = platform.system()
        findings: List[Dict[str, str]] = []

        listeners = self._get_listeners(system)
        for row in listeners:
            port = row["port"]
            port_meta = _RISKY_PORTS.get(port)
            bind = row["bind"]
            broad = bind in {"0.0.0.0", "::", "*", "[::]"}

            if port_meta and broad:
                service_name, severity = port_meta
                findings.append(
                    {
                        "severity": severity,
                        "type": "open_service",
                        "detail": (
                            f"{service_name} listening on {bind}:{port}"
                            + (f" (proc={row['process']})" if row.get("process") else "")
                        ),
                    }
                )
            elif port in {80, 443, 22} and broad:
                findings.append(
                    {
                        "severity": "low",
                        "type": "broad_bind",
                        "detail": f"Common service listening on all interfaces: {bind}:{port}",
                    }
                )

        summary = (
            f"Exposure check on {system}: found {len(listeners)} listening socket(s), "
            f"{len(findings)} finding(s)."
        )
        return ToolResult(
            tool=self.name,
            target=system,
            status="warning" if findings else "ok",
            severity=self._severity_from_findings(findings) if findings else "info",
            summary=summary,
            findings=findings,
            raw={"listeners": listeners[:200]},
        )

    def _get_listeners(self, system: str) -> List[Dict[str, str]]:
        if system == "Windows":
            return self._win_listeners()
        if system == "Linux":
            return self._linux_listeners()
        return []

    def _win_listeners(self) -> List[Dict[str, str]]:
        out = _subprocess_text(["netstat", "-ano"])
        listeners: List[Dict[str, str]] = []
        pids = set()
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith(("TCP", "UDP")):
                continue
            parts = re.split(r"\s+", line)
            if len(parts) < 4:
                continue
            proto = parts[0]
            local = parts[1]
            state = parts[3] if proto == "TCP" and len(parts) >= 5 else "LISTENING"
            pid = parts[-1]
            if proto == "TCP" and state != "LISTENING":
                continue
            bind, port = self._split_host_port(local)
            if port is None:
                continue
            listeners.append({"proto": proto, "bind": bind, "port": port, "pid": pid})
            pids.add(pid)

        pid_to_proc = self._win_pid_map(pids)
        for row in listeners:
            row["process"] = pid_to_proc.get(row["pid"], "")
        return listeners

    def _win_pid_map(self, pids: set[str]) -> Dict[str, str]:
        if not pids:
            return {}
        out = _subprocess_text(["tasklist", "/fo", "csv", "/nh"])
        mapping: Dict[str, str] = {}
        reader = csv.reader(io.StringIO(out))
        for row in reader:
            if len(row) < 2:
                continue
            image, pid = row[0], row[1]
            if pid in pids:
                mapping[pid] = image
        return mapping

    def _linux_listeners(self) -> List[Dict[str, str]]:
        out = _subprocess_text(["ss", "-lntup"])
        listeners: List[Dict[str, str]] = []
        for line in out.splitlines():
            if not line or line.startswith(("Netid", "udp", "tcp")) is False:
                continue
            parts = re.split(r"\s+", line, maxsplit=6)
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            proc = parts[6] if len(parts) > 6 else ""
            bind, port = self._split_host_port(local)
            if port is None:
                continue
            listeners.append({"proto": proto, "bind": bind, "port": port, "process": proc})
        return listeners

    @staticmethod
    def _split_host_port(local: str) -> Tuple[str, int | None]:
        local = local.strip()
        if local.startswith("[") and "]:" in local:
            host, port = local.rsplit("]:", 1)
            host = host[1:]
        else:
            if ":" not in local:
                return local, None
            host, port = local.rsplit(":", 1)
        try:
            return host or "*", int(port)
        except ValueError:
            return host or "*", None


@register
class PersistenceCheckTool(DefenseTool):
    name = "persistence_check"
    description = "Inspect common autorun and persistence points for suspicious entries."
    category = "hardening"

    def run(self, target: str = ".", **kwargs) -> ToolResult:
        self._check_path(target)
        system = platform.system()
        findings: List[Dict[str, str]] = []
        entries = self._collect_entries(system)

        for entry in entries:
            detail = entry["detail"]
            title = entry["location"]
            if _SUSPICIOUS_PATH_RE.search(detail):
                findings.append(
                    {
                        "severity": "high",
                        "type": "suspicious_persistence",
                        "detail": f"{title}: {detail}",
                    }
                )
            elif entry["kind"] == "scheduled_task" and ("temp" in detail.lower() or "appdata" in detail.lower()):
                findings.append(
                    {
                        "severity": "high",
                        "type": "scheduled_task_temp_exec",
                        "detail": f"{title}: {detail}",
                    }
                )
            elif entry["kind"] in {"run_key", "startup_item", "cron", "autostart"}:
                findings.append(
                    {
                        "severity": "low",
                        "type": "persistence_present",
                        "detail": f"{title}: {detail}",
                    }
                )

        summary = (
            f"Persistence audit on {system}: inspected {len(entries)} entry/entries, "
            f"{len(findings)} finding(s)."
        )
        return ToolResult(
            tool=self.name,
            target=system,
            status="warning" if findings else "ok",
            severity=self._severity_from_findings(findings) if findings else "info",
            summary=summary,
            findings=findings,
            raw={"entries": entries[:300]},
        )

    def _collect_entries(self, system: str) -> List[Dict[str, str]]:
        if system == "Windows":
            return self._win_entries()
        if system == "Linux":
            return self._linux_entries()
        return []

    def _win_entries(self) -> List[Dict[str, str]]:
        entries: List[Dict[str, str]] = []
        run_keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        ]
        for key in run_keys:
            out = _subprocess_text(["reg", "query", key])
            for line in out.splitlines():
                if "REG_" not in line:
                    continue
                parts = re.split(r"\s{2,}", line.strip(), maxsplit=2)
                if len(parts) == 3:
                    entries.append(
                        {
                            "kind": "run_key",
                            "location": key,
                            "detail": f"{parts[0]} -> {parts[2]}",
                        }
                    )

        startup_dirs = [
            os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp"),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for folder in startup_dirs:
            if folder and os.path.isdir(folder):
                for item in os.listdir(folder):
                    entries.append(
                        {
                            "kind": "startup_item",
                            "location": folder,
                            "detail": item,
                        }
                    )

        out = _subprocess_text(["schtasks", "/query", "/fo", "csv", "/v"])
        reader = csv.DictReader(io.StringIO(out))
        for row in reader:
            task_name = row.get("TaskName") or row.get("Task Name")
            task_to_run = row.get("Task To Run") or row.get("Actions")
            if not task_name:
                continue
            detail = task_to_run or "(no action text)"
            entries.append(
                {
                    "kind": "scheduled_task",
                    "location": task_name,
                    "detail": detail,
                }
            )
        return entries

    def _linux_entries(self) -> List[Dict[str, str]]:
        entries: List[Dict[str, str]] = []
        cron_paths = ["/etc/crontab", "/etc/rc.local"]
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]

        for path in cron_paths:
            if os.path.isfile(path):
                for line in self._read_non_comment_lines(path):
                    entries.append({"kind": "cron", "location": path, "detail": line})

        for folder in cron_dirs:
            if os.path.isdir(folder):
                for item in sorted(os.listdir(folder)):
                    full = os.path.join(folder, item)
                    if os.path.isfile(full):
                        entries.append({"kind": "cron", "location": folder, "detail": item})

        autostart = os.path.join(Path.home(), ".config", "autostart")
        if os.path.isdir(autostart):
            for item in sorted(os.listdir(autostart)):
                full = os.path.join(autostart, item)
                if os.path.isfile(full):
                    for line in self._read_non_comment_lines(full):
                        if line.startswith(("Exec=", "TryExec=")):
                            entries.append({"kind": "autostart", "location": full, "detail": line})

        try:
            out = _subprocess_text(["crontab", "-l"])
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append({"kind": "cron", "location": "user crontab", "detail": line})
        except Exception:
            pass
        return entries

    @staticmethod
    def _read_non_comment_lines(path: str) -> List[str]:
        lines: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        lines.append(line)
        except Exception:
            return []
        return lines
