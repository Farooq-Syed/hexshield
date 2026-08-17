# Roadmap

HexShield is a v0.1 proof of concept. It is deliberately small, dependency-free,
and safe. The roadmap below is ordered roughly by impact.

## Near term (v0.2)

- **MCP server bridge** — expose the tools as a FastMCP server so Claude Desktop,
  Cursor, or Copilot can drive HexShield directly (mirroring how HexStrike is
  consumed). The tool registry already maps 1:1 to MCP tool definitions.
- **`--watch` live mode** — tail a log file continuously and run `parse_logs` /
  `triage_alert` on rolling windows with dedup and alerting.
- **Windows Event-log decoder** — parse `.evtx` / `wevtutil qe` output into the
  existing log-analysis pipeline (Event IDs → ATT&CK technique hints).
- **Report export** — `--json` already exists; add `--html` and `--pdf` reports
  plus a findings database so triage history accumulates.

## Medium term (v0.3)

- **More defensive tools** (same read-only registry pattern):
  - Cloud posture check (Prowler/ScoutSuite-style, read-only via SDK).
  - YARA rule scanning for file_triage.
  - Slack/email alert ingestion and auto-triage.
  - Credential-stuffing dashboard over failed-logon logs.
- **Web dashboard** — timeline, vulnerability cards, and severity heatmaps
  (roughly the Modern Visual Engine role in HexStrike, but for defense).
- **Plugin marketplace / manifest** — declare tools + their deps in a manifest so
  the community can ship tools without touching core code.

## Later

- **Model-agnostic eval harness** — rerun the LLM-quality suite across many local
  and API models and report accuracy/speed tables (like the one in TESTING.md).
- **CI + Docker** — run `test_rigorous.py` on GitHub Actions per commit; ship a
  Docker image with Ollama for one-command deployment.
- **Federated IOC exchange** — share extracted IOCs between HexShield instances
  (opt-in) for a private, cross-org threat-intel feed.
- **Autonomous IR mode** — given an incident type + evidence bundle, produce a
  full IR timeline and remediation checklist autonomously, with human sign-off
  gates at each destructive step (safety-first, no arbitrary execution).

## Explicit non-goals

- No offensive tooling. No arbitrary command execution (`shell=True`) — by design.
- No silent external calls: IOC enrichment is a deliberate, opt-in action.
- HexShield explains and suggests; a human approves and executes.
