<div align="center">

# 🛡️ HexShield

**Defensive security assistant — the blue-team counterpart to HexStrike.**

Analyzes logs, triages alerts, checks hardening, correlates IOCs, triages
suspicious files, and walks incident response — powered by a **small local LLM**
with an automatic **GPU → CPU → API → rule-based** fallback chain.

Developed with AI coding assistance; the author chose the defensive scope,
tool boundaries, safety constraints, evaluation checks, debugging direction,
and final interpretation of the results.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/tests-94%2F94-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

</div>

---

## Why

[HexStrike](https://github.com/0x4m4/hexstrike-ai) gives an LLM 150+ **offensive**
tools and arbitrary system access. HexShield inverts that for the blue team:
**deterministic, read-only** analysis tools + an LLM that explains findings and
suggests remediation.

The key difference: **there is no `shell=True` anywhere.** Tools only parse
files, read configs, and run a tiny hardcoded allowlist of read-only system
queries. A defensive assistant that cannot cause harm is one you can hand to
your whole team.

```
AI agent / CLI ──▶ HexShield tools (read-only, deterministic)
                          │
                          ▼
                 findings ──▶ local LLM ──▶ actionable analysis
                         (Ollama → API → rule-based)
```

## Quick start

Requires Python 3.10+ (tested 3.12). No install needed:

```bash
git clone https://github.com/Farooq-Syed/hexshield
cd hexshield

python run.py list      # see the 8 tools
python run.py health    # which LLM providers are reachable
```

Run a tool (LLM analysis on top by default):

```bash
# analyze a log file
python run.py run parse_logs /var/log/auth.log

# triage an alert
python run.py run triage_alert "Failed password for root from 10.0.0.5 x5, then schtasks /create"

# check host hardening (Windows or Linux)
python run.py run hardening_check .

# extract IOCs from text or a file
python run.py run ioc_lookup "POST login.php union select... SHA256 abc123..."
python run.py run ioc_lookup report.txt --source file

# triage a suspicious file (static only)
python run.py run file_triage sample.bin

# get an IR playbook
python run.py run incident_runbook ransomware

# open-ended question
python run.py ask "What are the first signs of a kerberoasting attack in Windows event logs?"
```

Deterministic-only (skip the LLM): add `--no-llm`. JSON output: add `--json`.

## The 8 tools

| Tool              | Area              | Mirrors red-team            | Example trigger                |
| ----------------- | ----------------- | --------------------------- | ------------------------------ |
| `parse_logs`      | Log analysis      | (blue core)                 | SSH brute force, URL-encoded SQLi |
| `triage_alert`    | Alert triage      | (blue core)                 | Phishing → LOTL → exfil kill chain |
| `hardening_check` | System hardening  | CIS baseline                | Guest account active, SMBv1    |
| `ioc_lookup`      | Threat intel      | OSINT recon                 | IPs, domains, hashes, CVEs     |
| `file_triage`     | Malware triage    | `strings`/`exiftool`/`binwalk` | Packed binaries, suspicious strings |
| `incident_runbook`| Incident response | (blue core)                 | Ransomware, phishing, DDoS     |
| `exposure_check`  | Host exposure     | Service enumeration         | Broadly bound risky services   |
| `persistence_check` | Persistence audit | Autorun enumeration        | Run keys, tasks, cron, autostart |

Every offensive tool has a read-only defensive counterpart: nmap → "what's
exposed on *my* host", hydra → "test *my* own credentials", mimikatz-signals →
"check for credential exposure in *my* logs."

## How the LLM fallback chain works

`hexshield run ...` tries, in order:

1. **Ollama (local)** — auto GPU if the model fits VRAM, else CPU.
   Default `robit/ornith:9b`. If the configured model isn't pulled, it
   auto-selects the best available one.
2. **API key** — any OpenAI-compatible endpoint (OpenAI, Groq, DeepSeek, local
   vLLM) via `HEXSHIELD_API_KEY` / `HEXSHIELD_API_MODEL` / `HEXSHIELD_API_BASE`.
3. **Rule-based fallback** — full deterministic findings, no language summary.

If no LLM is reachable, HexShield prints setup instructions and lets you
continue without an LLM or exit. See **[docs/CHANGING_MODELS.md](docs/CHANGING_MODELS.md)**
for the complete guide to swapping models (flag, env var, API key, or a new
provider).

## Authorship and AI use

- The project framing, defensive threat model, tool restrictions, and claims are the author's.
- AI assistance was used for coding support and drafting help.
- The author reviewed, edited, tested, and verified the final code and write-up.

## Tool safety contract

- Tools **never** execute arbitrary shell commands; no `shell=True`.
- File access is read-only and permission-checked (`_check_path`).
- The few system commands used (`reg query`, `netsh advfirewall show`,
  `systemctl is-active`, `net user`) are a hardcoded allowlist, read-only.
- No external network calls are made by default (IOC enrichment is flagged,
  never performed silently).

## Adding a tool

Tools self-register via the `@register` decorator. Create
`hexshield/tools/foo.py`:

```python
from .base import DefenseTool, ToolResult
from .registry import register

@register
class FooTool(DefenseTool):
    name = "foo"
    description = "Do a defensive thing."
    category = "analysis"

    def run(self, target: str, **kwargs) -> ToolResult:
        ...  # read-only logic
        return ToolResult(tool=self.name, target=target, findings=[...])
```

Import it in `hexshield/tools/register_all.py` and it appears in `list`/`run`
automatically.

## Documentation

- **[docs/CHANGING_MODELS.md](docs/CHANGING_MODELS.md)** — detailed model-switching guide
- **[docs/TESTING.md](docs/TESTING.md)** — test suites, results, regression history
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — future plans (MCP bridge, dashboard, more tools)
- **[docs/REFERENCES.md](docs/REFERENCES.md)** — citations & inspirations
- **[docs/EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md)** — analyst-study design and current claim boundary

## Testing

Three suites, **94/94 passing** on Windows 11 / Python 3.12 / RTX 4060:

```bash
python -m pytest -q              # CI-friendly wrapper for the core suites
python tests/test_rigorous.py      # fast, deterministic, 46/46
python tests/test_cli_smoke.py     # end-to-end CLI, 28/28
python tests/test_llm_quality.py   # LLM grounding (slow), 20/20
```

The pytest entry point wraps the deterministic regression and CLI smoke suites so
GitHub Actions and reviewers get a standard pass/fail signal. See
**[docs/TESTING.md](docs/TESTING.md)** for detailed results and the model
comparison table.

## Project layout

```
hexshield/
  llm/            # LLMProvider interface, Ollama + OpenAI-compat, fallback chain
  tools/          # DefenseTool base, registry, and built-in tools
  engine/         # (reserved) orchestration glue
  cli/            # command-line interface
run.py            # repo entry point
.env.example      # LLM config reference
```

## Legal & ethical use

HexShield is for **defense**: analyzing logs, configs, and files you are
authorized to inspect, on systems you own or are contracted to protect.
It has no offensive capabilities and cannot execute arbitrary commands. Use it
in accordance with your organization's security policy and applicable law.

## License & inspiration

MIT License. HexShield is the blue-team counterpart to
[HexStrike](https://github.com/0x4m4/hexstrike-ai) (MIT); see
**[docs/REFERENCES.md](docs/REFERENCES.md)** for full citations and inspirations.
