from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_script(script_name: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / "tests" / script_name)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def test_rigorous_script_passes() -> None:
    result = run_script("test_rigorous.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL TESTS PASSED" in result.stdout


def test_cli_smoke_script_passes() -> None:
    result = run_script("test_cli_smoke.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL CLI SMOKE TESTS PASSED" in result.stdout
