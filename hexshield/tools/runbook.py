"""Incident response runbook tool: maps an incident type to a guided playbook."""

from __future__ import annotations

from typing import Any, Dict, List

from .base import DefenseTool, ToolResult
from .registry import register

_RUNBOOKS = {
    "ransomware": {
        "severity": "critical",
        "phases": [
            "Isolate: disconnect host from network + cloud sync; preserve RAM & disk image.",
            "Identify: determine ransomware family via extension/note/entropy; collect samples.",
            "Contain: kill persistence (schtasks/services), rotate shared credentials.",
            "Eradicate: wipe/reimage affected hosts; remove staging paths.",
            "Recover: restore from clean offline backups; verify no re-encryption.",
            "Post: preserve evidence, report to authorities if required by policy.",
        ],
    },
    "phishing": {
        "severity": "high",
        "phases": [
            "Capture: save full email headers + attachment (do not execute).",
            "Triage: check for macros/links; hash attachments; check sender vs. SPF/DKIM.",
            "Contain: block sender domain + URL at gateway; quarantine all recipients' mailboxes.",
            "Investigate: determine if credentials were entered; force password reset if so.",
            "Remediate: enable MFA, train users, purge malicious messages.",
        ],
    },
    "credential_theft": {
        "severity": "critical",
        "phases": [
            "Preserve: capture evidence of where the credential was used/stored.",
            "Contain: revoke/reset affected credentials; kill active sessions (Azure AD revoke, taskkill).",
            "Hunt: search for lateral movement with the stolen credential (event 4624/4625).",
            "Eradicate: remove credential-dumping tools and persistence.",
            "Recover: reissue tokens/certs; increase monitoring on affected accounts.",
        ],
    },
    "exfiltration": {
        "severity": "high",
        "phases": [
            "Identify: find the exfil vector (email, cloud share, USB, FTP, HTTP POST).",
            "Contain: block destination domains/IPs at egress; suspend uploader accounts.",
            "Assess: determine data classification and volume of data at risk.",
            "Remediate: revoke access, notify data owners, enable DLP.",
            "Report: document scope for breach-notification obligations.",
        ],
    },
    "ddos": {
        "severity": "medium",
        "phases": [
            "Detect: confirm volumetric vs. app-layer; identify source vectors.",
            "Mitigate: enable rate-limiting/WAF; null-route or use CDN scrubbing.",
            "Stabilize: scale resources; validate legitimate traffic.",
            "Recover: restore full capacity; tune thresholds.",
            "Post: document attack signature for future automated defense.",
        ],
    },
    "insider_threat": {
        "severity": "high",
        "phases": [
            "Collect: gather evidence of unusual access/behavior (eDR, DLP, VPN logs).",
            "Contain: restrict account privileges, disable remote access.",
            "Investigate: interview manager, review data accessed/exfiltrated.",
            "Remediate: terminate/limit access per policy; monitor remaining insiders.",
            "Post: review policy and access-control gaps.",
        ],
    },
    "supply_chain": {
        "severity": "critical",
        "phases": [
            "Identify: confirm the affected dependency/vendor and version.",
            "Contain: block the vulnerable component; find all instances in inventory.",
            "Patch: apply vendor fix/rollback to a clean version.",
            "Validate: verify integrity (hashes) of rebuilt artifacts.",
            "Post: update SBOM and procurement policy.",
        ],
    },
}


@register
class IncidentRunbookTool(DefenseTool):
    name = "incident_runbook"
    description = "Return a guided incident-response playbook for a given incident type."
    category = "incident_response"

    def run(self, target: str, **kwargs) -> ToolResult:
        key = target.strip().lower()
        # fuzzy match
        book = None
        for name, b in _RUNBOOKS.items():
            if key == name or any(token in key for token in name.split("_")):
                book = (name, b)
                break
        if book is None:
            available = ", ".join(sorted(_RUNBOOKS))
            raise ValueError(f"unknown incident type '{key}'. Available: {available}")

        name, b = book
        findings = [
            {"severity": b["severity"], "type": "playbook", "phase": phase}
            for phase in b["phases"]
        ]
        return ToolResult(
            tool=self.name,
            target=name,
            status="warning",
            severity=b["severity"],
            summary=f"Incident-response playbook for '{name}' with {len(b['phases'])} phases.",
            findings=findings,
            raw={"phases": b["phases"], "available_types": sorted(_RUNBOOKS)},
        )

    def list_types(self) -> List[str]:
        return sorted(_RUNBOOKS)