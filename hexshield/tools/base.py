"""Base class for defensive tools and the LLM-assisted runner.

A tool does two things:
  1. `run(...)`  -> structured, deterministic analysis (pure Python / stdlib)
  2. optionally an LLM summary on top of that analysis for readability.

Design rule (differs from HexStrike): tools are READ-ONLY and bounded.
They never execute arbitrary shell commands. All I/O is explicit and
permission-checked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..llm import LLMChain


@dataclass
class ToolResult:
    tool: str
    target: str
    status: str = "ok"  # ok | warning | error
    severity: str = "info"  # info | low | medium | high | critical
    summary: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    llm_analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "severity": self.severity,
            "summary": self.summary,
            "findings": self.findings,
            "llm_analysis": self.llm_analysis,
        }

    def render(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class DefenseTool:
    """Base class for all HexShield defensive tools."""

    name: str = "base"
    description: str = ""
    category: str = "general"
    requires_target: bool = True

    def run(self, target: str, **kwargs) -> ToolResult:
        raise NotImplementedError

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _check_path(path: str) -> str:
        """Validate a path is readable and return its absolute form."""
        import os

        abspath = os.path.abspath(path)
        if not os.path.exists(abspath):
            raise FileNotFoundError(f"path does not exist: {abspath}")
        if os.path.isdir(abspath):
            if not os.access(abspath, os.R_OK):
                raise PermissionError(f"directory not readable: {abspath}")
        elif not os.access(abspath, os.R_OK):
            raise PermissionError(f"file not readable: {abspath}")
        return abspath

    @staticmethod
    def _severity_from_findings(findings: List[Dict[str, Any]]) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        worst = max((order.get(f.get("severity", "info"), 0) for f in findings), default=0)
        return next(k for k, v in order.items() if v == worst)


def _build_system_prompt(tool: DefenseTool) -> str:
    return (
        "You are HexShield, a defensive security analyst assistant. "
        "You are given the raw output of a defensive analysis tool. "
        "Write a concise, actionable analysis of the findings: what is notable, "
        f"the recommended remediation for the '{tool.name}' check, and any caveats. "
        "Do NOT fabricate findings that are not present in the input. "
        "Keep it under 250 words, structured with short sections."
    )


def _sanitize(text: str) -> str:
    """Strip ANSI escape sequences and control chars from LLM output."""
    import re

    ansi = re.compile(r"\x1b\[[0-9;]*m")
    text = ansi.sub("", text)
    text = "".join(ch for ch in text if ch >= " " or ch in "\n\t")
    return text.strip()


def run_tool_with_llm(
    tool: DefenseTool,
    chain: LLMChain,
    target: str,
    heuristic_fallback,
    **kwargs,
) -> ToolResult:
    """Run a tool deterministically, then ask the LLM to summarize findings."""
    result = tool.run(target, **kwargs)
    if chain is not None:
        payload = json.dumps(result.to_dict(), indent=2, default=str)
        user_msg = (
            f"Tool: {tool.name}\nTarget: {target}\n\nRaw analysis:\n{payload}"
        )
        try:
            result.llm_analysis = _sanitize(
                chain.complete(
                    messages=[
                        {"role": "system", "content": _build_system_prompt(tool)},
                        {"role": "user", "content": user_msg},
                    ],
                    heuristic_fallback=heuristic_fallback,
                )
            )
        except Exception as e:  # never let the LLM crash the tool
            result.llm_analysis = f"[LLM unavailable: {e}]"
    return result