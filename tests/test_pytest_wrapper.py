from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_script(script_name: str, *extra: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / "tests" / script_name), *extra],
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
    # Run deterministic-only so the pytest signal is stable regardless of whether
    # a local LLM is reachable (LLM paths are covered by test_llm_quality.py).
    result = run_script("test_cli_smoke.py", "--no-llm")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL CLI SMOKE TESTS PASSED" in result.stdout
