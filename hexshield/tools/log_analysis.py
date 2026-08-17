"""Log analysis tool: parse common log formats, extract events, detect anomalies.

Read-only. Supports plain-text logs (Apache/Nginx, syslog, generic key=value,
JSONL). Does bounded line-count sampling for large files.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List

from .base import DefenseTool, ToolResult
from .registry import register

_SUSPICIOUS_PATTERNS = {
    "auth failure": re.compile(r"(failed password|authentication failure|invalid user)", re.I),
    "brute force": re.compile(r"(too many (bad|failed)|max retries|login attempt)", re.I),
    "sqli attempt": re.compile(r"(union select|'\s*or\s*1=1|--\s*;|information_schema|or\s+\d+\s*=\s*\d+|sleep\s*\(\s*\d+\)|benchmark\s*\()", re.I),
    "xss attempt": re.compile(r"(<script|alert\(|onerror=|javascript:|onload=|<img[^>]*on)", re.I),
    "path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|c:\\\\windows|/etc/shadow)", re.I),
    "command injection": re.compile(r"(\|\s*(cat|nc|bash|sh|wget|curl)\b|;\s*(id|whoami|rm|cat)\b|\$\()", re.I),
    "known cve keyword": re.compile(r"(log4shell|log4j|cve-\d{4}-\d+)", re.I),
    "suspicious ip": re.compile(r"\b(0\.0\.0\.0|255\.255\.255\.255)\b"),
    "exfil": re.compile(r"(base64|powershell -enc|curl.*\?data=|ftp.*\bput\b)", re.I),
}

_COMMON_STATUS = {"200", "201", "204", "301", "302", "400", "401", "403", "404", "500", "502", "503"}

# Tie-break priority: which pattern is most actionable when multiple match.
_PATTERN_PRIORITY = {
    "command injection": 5,
    "sqli attempt": 4,
    "xss attempt": 3,
    "exfil": 3,
    "path traversal": 2,
    "auth failure": 1,
    "brute force": 1,
    "known cve keyword": 1,
    "suspicious ip": 1,
}


def _normalize(line: str) -> str:
    """Return line with URL-encoding and common unicode escapes decoded,
    so obfuscated payloads still match patterns. Never fails."""
    decoded = line
    try:
        decoded = urllib.parse.unquote(line)
    except Exception:
        pass
    # unicode escape sequences like \u0027 (single quote)
    try:
        decoded = decoded.encode("utf-8", errors="replace").decode("unicode_escape", errors="replace")
    except Exception:
        pass
    return decoded


@register
class LogAnalysisTool(DefenseTool):
    name = "parse_logs"
    description = "Parse a log file, summarize events, and flag suspicious patterns."
    category = "log_analysis"

    def run(self, target: str, max_lines: int = 5000, **kwargs) -> ToolResult:
        path = self._check_path(target)
        if os.path.isdir(path):
            raise IsADirectoryError(f"expected a log file, got directory: {path}")

        total_lines = 0
        events: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        severity_counter = Counter()

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                total_lines += 1
                if lineno > max_lines:
                    break
                best_name = None
                best_sev = -1
                best_prio = -1
                decoded = _normalize(line)
                for name, pat in _SUSPICIOUS_PATTERNS.items():
                    if pat.search(line) or pat.search(decoded):
                        sev = _sev_rank(self._severity_for(name, line))
                        prio = _PATTERN_PRIORITY.get(name, 0)
                        # prefer highest severity; on tie, most actionable pattern
                        if (sev, prio) > (best_sev, best_prio):
                            best_sev = sev
                            best_prio = prio
                            best_name = name
                if best_name is not None:
                    sev = self._severity_for(best_name, line)
                    severity_counter[sev] += 1
                    events.append(
                        {
                            "line": lineno,
                            "pattern": best_name,
                            "severity": sev,
                            "sample": line.strip()[:220],
                        }
                    )

        # Aggregate suspicious hits
        for ev in events[:200]:
            findings.append(
                {
                    "severity": ev["severity"],
                    "type": ev["pattern"],
                    "detail": f"line {ev['line']}: {ev['sample']}",
                }
            )

        skipped = max(0, total_lines - min(total_lines, max_lines))
        summary = (
            f"Parsed {min(total_lines, max_lines)} of {total_lines} lines "
            f"({'skipped ' + str(skipped) + ' beyond limit' if skipped else 'complete'}). "
            f"{len(events)} suspicious events flagged "
            f"({dict(severity_counter) or 'none'})."
        )

        severity = self._severity_from_findings(findings)
        status = "warning" if severity in ("high", "critical") else "ok"
        return ToolResult(
            tool=self.name,
            target=path,
            status=status,
            severity=severity,
            summary=summary,
            findings=findings,
            raw={"total_lines": total_lines, "parsed_lines": min(total_lines, max_lines), "events": events},
        )

    @staticmethod
    def _severity_for(pattern: str, line: str) -> str:
        if pattern in ("brute force", "exfil", "command injection"):
            return "high"
        if pattern in ("sqli attempt", "path traversal", "known cve keyword"):
            return "high"
        if pattern == "auth failure":
            return "medium"
        return "low"


@register
class AlertTriageTool(DefenseTool):
    name = "triage_alert"
    description = "Classify a security alert by severity, likely TTP, and suggested first response."
    category = "log_analysis"

    def run(self, target: str, **kwargs) -> ToolResult:
        # target here is the alert text itself
        if not target or len(target.strip()) < 4:
            raise ValueError("triage_alert requires alert text as target")
        text = target
        severity = "info"
        ttp_hints: List[str] = []
        findings: List[Dict[str, Any]] = []

        rules = [
            (re.compile(r"(ransomware|encrypt|lockbit|conti|vssadmin|shadowcopy|\.encrypted|readme\.txt)", re.I), "critical", "Ransomware / destructive"),
            (re.compile(r"(kerberoast|golden ticket|mimikatz|lsass|hashdump|ntlm|sekurlsa)", re.I), "critical", "Credential theft"),
            (re.compile(r"(powershell -enc|cmd\.exe /c|wmic process|schtasks /create|reg add|powershell\.exe)", re.I), "high", "Living-off-the-land execution"),
            (re.compile(r"(cobalt|beacon|meterpreter|metasploit|nc .* -e|bash -i|reverse shell)", re.I), "critical", "C2 / reverse shell"),
            (re.compile(r"(phish|spoof|sender.*(paypal|bank|microsoft)|attachment.*\.(scr|hta|iso)|invoice.*\.scr)", re.I), "high", "Phishing / spoofing"),
            (re.compile(r"(sql injection|union select|id=\d|' or 1=1)", re.I), "high", "SQL injection"),
            (re.compile(r"(xss|<script|onerror=)", re.I), "medium", "Cross-site scripting"),
            (re.compile(r"(privilege escalation|whoami /priv|getsystem|token duplication)", re.I), "high", "Privilege escalation"),
            (re.compile(r"(exfil|ftp .*put|base64|data exfiltration|raw.githubusercontent|exfiltrat)", re.I), "high", "Exfiltration"),
        ]

        for pat, sev, ttp in rules:
            if pat.search(text):
                severity = sev if _sev_rank(sev) > _sev_rank(severity) else severity
                if ttp not in ttp_hints:
                    ttp_hints.append(ttp)
                findings.append({"severity": sev, "type": "ttp_match", "detail": ttp})

        # kill-chain escalation: 3+ distinct high/critical TTPs together is critical
        high_critical = [t for t in ttp_hints if t not in ("Cross-site scripting",)]
        if len(high_critical) >= 3 and _sev_rank(severity) < _sev_rank("critical"):
            severity = "critical"
            findings.append({
                "severity": "critical",
                "type": "kill_chain",
                "detail": f"Multi-stage pattern with {len(high_critical)} high/critical TTPs: {', '.join(high_critical)}",
            })

        suggested = self._first_response(severity, ttp_hints)
        status = "warning" if _sev_rank(severity) >= _sev_rank("high") else "ok"
        return ToolResult(
            tool=self.name,
            target=text[:120],
            status=status,
            severity=severity,
            summary=(
                f"Alert classified as {severity.upper()} with {len(ttp_hints)} TTP hint(s): "
                f"{', '.join(ttp_hints) or 'none identified'}. First response: {suggested}"
            ),
            findings=findings,
            raw={"ttp_hints": ttp_hints, "first_response": suggested},
        )

    @staticmethod
    def _first_response(severity: str, ttp_hints: List[str]) -> str:
        if _sev_rank(severity) >= _sev_rank("critical"):
            return "Isolate the host immediately, preserve volatile evidence (RAM, connections), snapshot the disk, engage IR on-call."
        if _sev_rank(severity) >= _sev_rank("high"):
            return "Correlate related logs, contain the affected accounts/hosts, snapshot evidence, escalate per IR plan."
        if ttp_hints:
            return "Open a low-priority ticket; confirm whether the event is expected/scheduled before acting."
        return "Log for monitoring; set a watch on the source for recurrence."


def _sev_rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)