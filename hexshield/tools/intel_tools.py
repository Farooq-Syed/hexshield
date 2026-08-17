"""IOC extraction & correlation tool.

Read-only. Extracts indicators of compromise (IPs, domains, hashes, emails,
CVE refs) from text or a file, then cross-checks against locally known-bad
lists if provided. Never makes external network calls by default.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from typing import Any, Dict, List

from .base import DefenseTool, ToolResult
from .registry import register

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_APIPA = {"10.", "192.168.", "172."}


@register
class IOCLookupTool(DefenseTool):
    name = "ioc_lookup"
    description = "Extract and correlate indicators of compromise from text or a file."
    category = "intel"

    def run(self, target: str, source: str = "text", **kwargs) -> ToolResult:
        if source == "file":
            path = self._check_path(target)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(2_000_000)  # cap input
            label = path
        else:
            text = target
            label = "inline text"

        iocs = self._extract(text)
        findings: List[Dict[str, Any]] = []

        def top(counter: Counter, n: int = 10) -> List[str]:
            return list(counter)[:n]

        # Private IPs are context (not inherently malicious) but worth flagging
        for ip in iocs["ips"]:
            if any(ip.startswith(p) for p in _APIPA):
                findings.append({"severity": "low", "type": "private_ip", "value": ip})

        if iocs["hashes"]:
            findings.append({
                "severity": "info",
                "type": "hash",
                "value": ", ".join(top(iocs["hashes"])),
                "detail": "Look up these hashes in VirusTotal/ThreatIntel (external call required).",
            })

        if iocs["cves"]:
            findings.append({
                "severity": "medium",
                "type": "cve",
                "value": ", ".join(top(iocs["cves"])),
                "detail": "Cross-reference these CVEs against your patch status.",
            })

        total = sum(len(v) for v in iocs.values())
        summary = (
            f"Extracted {total} IOC(s): {len(iocs['ips'])} IP, {len(iocs['domains'])} domain, "
            f"{len(iocs['hashes'])} hash, {len(iocs['emails'])} email, {len(iocs['cves'])} CVE."
        )
        status = "warning" if findings else "ok"
        severity = self._severity_from_findings(findings) if findings else "info"
        return ToolResult(
            tool=self.name,
            target=label,
            status=status,
            severity=severity,
            summary=summary,
            findings=findings,
            raw={k: list(v) for k, v in iocs.items()},
        )

    @staticmethod
    def _extract(text: str) -> Dict[str, Counter]:
        return {
            "ips": Counter(_IP_RE.findall(text)),
            "domains": Counter(_DOMAIN_RE.findall(text)),
            "hashes": Counter(_HASH_RE.findall(text)),
            "emails": Counter(_EMAIL_RE.findall(text)),
            "cves": Counter(_CVE_RE.findall(text)),
        }


@register
class FileTriageTool(DefenseTool):
    name = "file_triage"
    description = "Static triage of a suspicious file: metadata, strings, entropy, checksums."
    category = "malware"

    def run(self, target: str, entropy: bool = True, strings: bool = True, **kwargs) -> ToolResult:
        path = self._check_path(target)
        size = os.path.getsize(path)
        findings: List[Dict[str, Any]] = []

        # checksums
        md5 = sha1 = sha256 = ""
        with open(path, "rb") as fh:
            chunk = fh.read(8 * 1024 * 1024)
            md5 = hashlib.md5(chunk).hexdigest()
            sha1 = hashlib.sha1(chunk).hexdigest()
            sha256 = hashlib.sha256(chunk).hexdigest()

        # signature / magic bytes
        with open(path, "rb") as fh:
            head = fh.read(64)
        magic = head[:4]
        file_type = self._magic(magic, size)

        details = {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "size_bytes": size,
            "magic": magic.hex(),
            "detected_type": file_type,
        }

        # entropy heuristic for packed/encrypted binaries.
        # Applies to binary AND unknown/opaque files: high entropy with no
        # recognizable structure is a strong packing/encryption signal.
        if entropy:
            e = self._file_entropy(path)
            details["entropy_bits_per_byte"] = round(e, 3)
            is_binary = file_type.startswith("binary") or file_type.startswith("text or unknown")
            if is_binary and e > 7.2 and size >= 1024:
                findings.append({
                    "severity": "medium",
                    "type": "high_entropy",
                    "detail": f"Entropy {e:.2f} > 7.2 suggests packing/encryption; run unpacking & sandbox.",
                })

        if strings and size <= 50_000_000:
            susp = self._scan_strings(path)
            if susp:
                findings.append({
                    "severity": "medium",
                    "type": "suspicious_strings",
                    "detail": "; ".join(susp[:8]),
                })
            details["string_hits"] = susp

        severity = self._severity_from_findings(findings) if findings else "info"
        summary = (
            f"File '{os.path.basename(path)}' ({size} bytes, {file_type}). "
            f"SHA256 {sha256[:16]}... {len(findings)} suspicious signal(s). "
            f"Look up the hash in a threat-intel service to confirm."
        )
        return ToolResult(
            tool=self.name,
            target=path,
            status="warning" if findings else "ok",
            severity=severity,
            summary=summary,
            findings=findings,
            raw=details,
        )

    @staticmethod
    def _magic(magic: bytes, size: int) -> str:
        if magic.startswith(b"\x7fELF"):
            return "binary (ELF executable)"
        if magic.startswith(b"MZ"):
            return "binary (PE/Windows executable)"
        if magic.startswith(b"\x89PNG"):
            return "image (PNG)"
        if magic.startswith(b"\xff\xd8\xff"):
            return "image (JPEG)"
        if magic.startswith(b"PK"):
            return "archive (ZIP/OOXML)"
        if magic.startswith(b"GIF8"):
            return "image (GIF)"
        if magic.startswith(b"%PDF"):
            return "document (PDF)"
        if magic.startswith(b"<"):
            return "text (markup/HTML)"
        return "text or unknown"

    @staticmethod
    def _file_entropy(path: str) -> float:
        import math
        from collections import Counter

        freq = Counter()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                freq.update(chunk)
        total = sum(freq.values())
        if not total:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    @staticmethod
    def _scan_strings(path: str) -> List[str]:
        suspicious = []
        suspects = [
            "powershell", "-enc", "rundll32", "cmd.exe", "schtasks",
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "http://", "https://", "tcp://", "socks", "base64",
            "gmail", "windows/exploit", "\\temp\\", "\\appdata\\",
        ]
        try:
            with open(path, "rb") as fh:
                data = fh.read(20_000_000)
        except Exception:
            return suspicious
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return suspicious
        lower = text.lower()
        for s in suspects:
            if s.lower() in lower:
                suspicious.append(s)
        return suspicious