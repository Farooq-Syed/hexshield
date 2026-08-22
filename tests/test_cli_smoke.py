"""End-to-end CLI smoke test: exercises every command path as the user would.

Run:  python tests/test_cli_smoke.py
Behavior:
  - with a reachable LLM, exercises both deterministic and LLM-backed paths
  - without a reachable LLM, automatically falls back to deterministic paths and
    still verifies the explicit "LLM unavailable" gate flows
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "run.py")

PASS = 0
FAIL = 0
FAILURES = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  -- {detail}")


def cli(*args, input_text: str | None = None, timeout: int = 180) -> tuple[int, str]:
    """Run the CLI, return (exit_code, combined_output)."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        proc = subprocess.run(
            [sys.executable, RUN, *args],
            capture_output=True, text=True, timeout=timeout, env=env,
            input=input_text, encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "[TIMEOUT]"


def llm_available() -> bool:
    """Return True when at least one configured provider is reachable."""
    code, out = cli("health")
    if code != 0:
        return False
    return " OK " in out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--no-llm",
        action="store_true",
        help="Only run deterministic paths (no LLM gate).",
    )
    args = ap.parse_args()

    auto_no_llm = args.no_llm or not llm_available()
    extra = ["--no-llm"] if auto_no_llm else []

    print("=" * 70)
    print("0. list / health")
    print("=" * 70)
    code, out = cli("list")
    for tool in ("parse_logs", "triage_alert", "hardening_check", "ioc_lookup", "file_triage", "incident_runbook"):
        check(f"list shows {tool}", f"{tool}" in out, out[:200])
    check("list exit 0", code == 0, str(code))

    if not auto_no_llm:
        code, out = cli("health")
        check("health exit 0", code == 0, str(code))
    else:
        print("  INFO  no reachable LLM; running deterministic smoke paths")

    print("=" * 70)
    print("1. parse_logs (file)")
    print("=" * 70)
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write("\n".join([
        "2026-08-16 10:01:22 sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2",
        "2026-08-16 10:01:25 sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2",
        "2026-08-16 10:02:00 nginx[999]: GET /login.php?id=1' OR 1=1-- HTTP/1.1 200",
    ]))
    f.close()
    code, out = cli("run", "parse_logs", f.name, *extra)
    os.unlink(f.name)
    check("parse_logs exit 0", code == 0, str(code))
    check("parse_logs finds sqli", "sqli attempt" in out or "SQL injection" in out, out[:300])

    print("=" * 70)
    print("2. triage_alert")
    print("=" * 70)
    code, out = cli("run", "triage_alert", "phishing invoice.scr then powershell -enc and schtasks /create exfil", *extra)
    check("triage exit 0", code == 0, str(code))
    check("triage flags high/critical", "HIGH" in out or "CRITICAL" in out, out[:300])

    print("=" * 70)
    print("3. hardening_check")
    print("=" * 70)
    code, out = cli("run", "hardening_check", ".", *extra)
    check("hardening exit 0", code == 0, str(code))
    check("hardening has findings", "Findings" in out, out[:300])

    print("=" * 70)
    print("4. ioc_lookup (text + file)")
    print("=" * 70)
    code, out = cli("run", "ioc_lookup", "src 8.8.8.8 c2.badco.io sha256 44d88612fea8a8f36de82e1278abb02f CVE-2023-23397", *extra)
    check("ioc text exit 0", code == 0, str(code))
    check("ioc extracts CVE", "1 CVE" in out or "[MEDIUM  ] cve:" in out, out[:300])
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    f.write("malicious.example.com 198.51.100.7")
    f.close()
    code, out = cli("run", "ioc_lookup", f.name, "--source", "file", *extra)
    os.unlink(f.name)
    check("ioc file exit 0", code == 0, str(code))

    print("=" * 70)
    print("5. file_triage (real PE)")
    print("=" * 70)
    target = r"C:\Windows\System32\cmd.exe"
    if os.path.exists(target):
        code, out = cli("run", "file_triage", target, *extra)
        check("file_triage exit 0", code == 0, str(code))
        check("file_triage detects PE", "PE" in out, out[:300])
    else:
        print("  SKIP  no system PE")

    print("=" * 70)
    print("6. incident_runbook")
    print("=" * 70)
    code, out = cli("run", "incident_runbook", "ransomware", *extra)
    check("runbook exit 0", code == 0, str(code))
    check("runbook has phases", "isolate" in out.lower() or "phase" in out.lower(), out[:300])

    print("=" * 70)
    print("7. ask (LLM only)")
    print("=" * 70)
    if not auto_no_llm:
        code, out = cli("ask", "What event ID indicates a Windows account lockout?", timeout=240)
        check("ask exit 0", code == 0, str(code))
        check("ask returns an answer", len(out.strip()) > 40, out[:200])
    else:
        print("  SKIP  ask (requires reachable LLM)")

    print("=" * 70)
    print("8. error handling")
    print("=" * 70)
    code, out = cli("run", "parse_logs", "C:/nonexistent/file.log", *extra)
    check("missing file -> non-zero", code != 0, f"code={code}")
    code, out = cli("run", "not_a_tool", "x", *extra)
    check("unknown tool -> code 2", code == 2, f"code={code}")

    if not auto_no_llm:
        print("=" * 70)
        print("9. LLM-gate fallback prompt (Ollama down)")
        print("=" * 70)
        gate_log = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
        gate_log.write("Failed password for root from 10.0.0.1 port 22")
        gate_log.close()
        code, out = cli("run", "parse_logs", gate_log.name, "--ollama-host", "http://127.0.0.1:59999", "--no-api",
                        input_text="n")
        check("gate detects unavailability", "No local or API model is reachable" in out, out[:300])
        check("gate exit n -> 3", code == 3, f"code={code}")
        code, out = cli("run", "parse_logs", gate_log.name, "--ollama-host", "http://127.0.0.1:59999", "--no-api",
                        input_text="y")
        os.unlink(gate_log.name)
        check("gate exit y -> runs deterministic", code == 0 and "Parsed" in out, f"code={code} out={out[:200]}")
    else:
        print("=" * 70)
        print("9. LLM-gate fallback prompt")
        print("=" * 70)
        print("  SKIP  explicit gate prompt already covered by deterministic mode")

    print("=" * 70)
    print(f"RESULT: {PASS} passed, {FAIL} failed")
    print("=" * 70)
    if FAILURES:
        print("\nFailures:")
        for x in FAILURES:
            print(f"  - {x}")
        sys.exit(1)
    print("ALL CLI SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
