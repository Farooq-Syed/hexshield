# Citations & Inspirations

HexShield is the blue-team counterpart to HexStrike. This page records the
projects, standards, and bodies of work that shaped it.

## Primary inspiration

- **HexStrike AI MCP Agents** — `0x4m4/hexstrike-ai` (MIT).
  An MCP server that lets AI agents autonomously run 150+ offensive security
  tools (nmap, nuclei, sqlmap, ghidra, prowler, kube-hunter, ...). HexShield
  inverts its architecture for defense: the same two-part design
  (tool registry + LLM decision layer) but with read-only, permission-checked
  tools and no arbitrary shell execution.
  <https://github.com/0x4m4/hexstrike-ai>

## Protocol & framework

- **Model Context Protocol (MCP)** — Anthropic's open standard for connecting
  LLMs to tools and data. HexStrike and the planned HexShield MCP bridge both
  use it. <https://modelcontextprotocol.io>
- **FastMCP** — the Python MCP server framework used by HexStrike
  (`mcp.server.fastmcp`). <https://github.com/modelcontextprotocol/python-sdk>

## Local inference

- **Ollama** — local model runner; HexShield talks to it over its HTTP API and
  relies on its automatic GPU/CPU offloading. <https://ollama.com>
- **Qwen 3.5 (4B)** and **Qwen 2.5** — small, strong agentic models by Alibaba.
  Used as fast local defaults. <https://qwenlm.github.io>
- **Ornith (9B)** and **robit/ornith:9b** — community GGUF models that fit 8 GB
  VRAM; used as the default local model. <https://ollama.com/library>
- **Llama 3.1/3.2** — Meta's open models; recommended 8B-class alternative.
  <https://llama.meta.com>

## Threat knowledge & standards

- **MITRE ATT&CK** — the tactic/technique framework used for the
  `triage_alert` TTP hints (phishing, living-off-the-land, credential theft,
  exfiltration, etc.). <https://attack.mitre.org>
- **CIS Benchmarks** — hardening baselines used by `hardening_check`
  (e.g. CIS 1.4.1 password aging, 5.4.1.1 SSH root login, Windows audit policy
  and UAC checks). <https://www.cisecurity.org/cis-benchmarks>
- **OWASP** — payload/pattern knowledge for SQLi, XSS, and path traversal
  detection in log analysis. <https://owasp.org>
- **Windows Event IDs** — account logon (4624/4625), Kerberos TGS request
  (4769), domain logon (4768) used in triage and `ask` guidance.
  <https://learn.microsoft.com/windows/security/threat-protection/auditing>

## Threat-intel references (noted, not called by default)

- VirusTotal, AbuseIPDB, and other IOC enrichment services are referenced by
  `ioc_lookup`/`file_triage` output. HexShield deliberately does **not** make
  these calls automatically.

## Design lineage

HexStrike gives an LLM arbitrary system access (it shells out to run tools).
HexShield's core design decision is the opposite and is documented in the
README "Tool safety contract": deterministic, read-only analysis + an LLM that
explains and recommends — because a defensive assistant that can't cause harm
is one you can hand to your whole team.

## AI-use note

AI coding assistance was used during implementation and drafting. The defensive
scope, tool safety model, debugging decisions, and final interpretation were
directed and verified by Farooq Syed.
