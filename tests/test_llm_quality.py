"""LLM quality tests: verify the local model produces accurate, non-hallucinated
analysis across all tools. Requires a working local model (robit/ornith:9b by default).

Run:  python tests/test_llm_quality.py [--model robit/ornith:9b]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hexshield.llm.chain import LLMChain  # noqa: E402
from hexshield.tools.base import run_tool_with_llm  # noqa: E402
from hexshield.tools.registry import ToolRegistry  # noqa: E402
from hexshield.tools.register_all import *  # noqa: F401,F403,E402

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


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="robit/ornith:9b")
    ap.add_argument("--no-llm-ok", action="store_true", help="Allow heuristic fallback to count as pass")
    args = ap.parse_args()

    chain = LLMChain(ollama_model=args.model, enable_api=False)
    diag = chain.ensure_llm()
    if not diag["available"]:
        print(f"[warn] model {args.model} not available: {diag}")
        if args.no_llm_ok:
            print("proceeding in degraded mode")
        else:
            sys.exit(2)
    print(f"[llm] active provider: {diag['active_provider']} model={args.model}")

    heuristic = lambda msgs: "[NO-LLM]"

    # ---- test 1: parse_logs LLM must reflect ACTUAL findings ------------------
    print("=" * 70)
    print("1. parse_logs — LLM must not hallucinate")
    print("=" * 70)
    log = [
        "2026-08-16 10:01:22 sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2",
        "2026-08-16 10:01:25 sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2",
        "2026-08-16 10:02:00 nginx[999]: GET /login.php?id=1' OR 1=1-- HTTP/1.1 200",
    ]
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write("\n".join(log))
    f.close()
    r = run_tool_with_llm(ToolRegistry.get("parse_logs"), chain, f.name, heuristic)
    os.unlink(f.name)
    analysis = strip_ansi(r.llm_analysis).lower()
    check("LLM mentions brute force", "brute" in analysis or "password" in analysis, analysis[:120])
    check("LLM mentions SQL injection", "sql" in analysis or "injection" in analysis, analysis[:120])
    check("LLM mentions the source IP", "203.0.113.10" in analysis, analysis[:120])
    # anti-hallucination: model must NOT claim attack types absent from the input
    for absent in ("ransomware", "xss", "command injection", "exfiltration of data via ftp"):
        check(f"LLM does not invent '{absent}'", absent not in analysis, f"claimed absent finding: {absent}")

    # ---- test 2: triage_alert kill chain --------------------------------------
    print("=" * 70)
    print("2. triage_alert — LLM summarizes a kill chain")
    print("=" * 70)
    alert = (
        "phishing email with invoice.scr; powershell -enc ran; "
        "schtasks /create persistence; outbound to 185.220.101.42; ftp put data"
    )
    r = run_tool_with_llm(ToolRegistry.get("triage_alert"), chain, alert, heuristic)
    a = strip_ansi(r.llm_analysis).lower()
    check("LLM reflects phishing", "phish" in a, a[:120])
    check("LLM reflects persistence/schtasks", "schtask" in a or "persist" in a, a[:120])
    check("LLM reflects exfiltration", "exfil" in a, a[:120])

    # ---- test 3: hardening — LLM must not fabricate specific check results ----
    print("=" * 70)
    print("3. hardening_check — LLM stays grounded in actual findings")
    print("=" * 70)
    r = run_tool_with_llm(ToolRegistry.get("hardening_check"), chain, ".", heuristic)
    a = strip_ansi(r.llm_analysis).lower()
    actual_fail_count = sum(1 for x in r.findings if x["status"] == "fail")
    check("LLM produces analysis", len(a) > 50, a[:80])
    if actual_fail_count == 0:
        print("  (system fully hardened; skipping fail-count grounding check)")
    else:
        check(f"LLM mentions some failures (system has {actual_fail_count} fails)",
              "fail" in a or "issue" in a or "miserable" in a or "concern" in a, a[:150])

    # ---- test 4: ioc_lookup — LLM names the indicators ------------------------
    print("=" * 70)
    print("4. ioc_lookup — LLM reflects extracted IOCs")
    print("=" * 70)
    txt = "src 8.8.8.8 -> evil.example.net, hash 44d88612fea8a8f36de82e1278abb02f, CVE-2023-23397"
    r = run_tool_with_llm(ToolRegistry.get("ioc_lookup"), chain, txt, heuristic)
    a = strip_ansi(r.llm_analysis).lower()
    check("LLM mentions the domain", "evil.example.net" in a, a[:120])
    check("LLM mentions CVE", "cve" in a, a[:120])
    check("LLM mentions hash lookup", "hash" in a or "44d88612" in a, a[:120])

    # ---- test 5: incident_runbook — LLM echoes the playbook --------------------
    print("=" * 70)
    print("5. incident_runbook — LLM expands ransomware runbook")
    print("=" * 70)
    r = run_tool_with_llm(ToolRegistry.get("incident_runbook"), chain, "ransomware", heuristic)
    a = strip_ansi(r.llm_analysis).lower()
    check("LLM mentions isolate", "isolate" in a, a[:120])
    check("LLM mentions backup/recovery", "backup" in a or "recover" in a, a[:120])

    # ---- test 6: ask — open question quality -----------------------------------
    # Small models have generation variance; retry a few times before failing.
    print("=" * 70)
    print("6. ask — open security question")
    print("=" * 70)
    sys_prompt = "You are a defensive security analyst. Be accurate and concise."
    question = "How would you detect a kerberoasting attack in Windows event logs? Be specific about event IDs."
    a = ""
    for attempt in range(3):
        answer = chain.complete(
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": question},
            ],
            heuristic_fallback=lambda m: "[NO-LLM]",
        )
        a = strip_ansi(answer).lower()
        if "4769" in a and "4768" in a:
            break
    check("mentions event 4769", "4769" in a, a[:150])
    check("mentions event 4768", "4768" in a, a[:150])
    check("suggests mitigation", "mitigat" in a or "remediat" in a or "detect" in a, a[:150])

    print("=" * 70)
    print(f"RESULT: {PASS} passed, {FAIL} failed")
    print("=" * 70)
    if FAILURES:
        print("\nFailures:")
        for x in FAILURES:
            print(f"  - {x}")
        sys.exit(1)
    print("ALL LLM TESTS PASSED")


if __name__ == "__main__":
    main()