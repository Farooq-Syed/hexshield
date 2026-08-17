# Testing

HexShield ships with three test suites. They are dependency-free (stdlib only)
and run with the repo as the working directory.

## Suites

| Suite                    | What it covers                                     | Runtime        |
| ------------------------ | -------------------------------------------------- | -------------- |
| `tests/test_rigorous.py` | Adversarial/edge-case analysis of every tool       | seconds        |
| `tests/test_cli_smoke.py`| End-to-end CLI: every command path as the user types it | ~1–2 min (LLM) |
| `tests/test_llm_quality.py` | LLM grounding: no hallucination, correct content | ~3–8 min (LLM) |

The two LLM suites require a reachable local model (default `robit/ornith:9b`).
Run them with `--no-llm`? — no; use `--model <name>` to pick the model, or set
`HEXSHIELD_OLLAMA_MODEL`.

## Run

```bash
# fast, deterministic
python tests/test_rigorous.py

# end-to-end CLI (uses default local model)
python tests/test_cli_smoke.py

# LLM quality/grounding (slow)
python tests/test_llm_quality.py --model robit/ornith:9b
python tests/test_llm_quality.py --model qwen3.5:4b

# deterministic CLI paths only
python tests/test_cli_smoke.py --no-llm
```

## Recorded results

Verified on Windows 11, Python 3.12.10, NVIDIA RTX 4060 (8 GB), Ollama with
`robit/ornith:9b` and `qwen3.5:4b`.

| Suite                | Result | Notes                                        |
| -------------------- | ------ | -------------------------------------------- |
| `test_rigorous.py`   | 46/46  | Stable across repeated runs                  |
| `test_llm_quality.py`| 20/20  | With `robit/ornith:9b` (retries on variance) |
| `test_cli_smoke.py`  | 28/28  | Includes LLM-gate fallback prompt paths      |
| **Total**            | **94/94** |                                        |

## Model comparison (LLM quality suite, 3 runs each)

| Model              | Pass rate | Suite time |
| ------------------ | --------- | ---------- |
| `qwen3.5:4b`       | 59/60     | ~41 s      |
| `robit/ornith:9b`  | 58/60     | ~73–142 s  |
| `ornith:latest`    | 58/60     | ~73–142 s  |

(The occasional single failure is generation variance in small models, not a
code bug — the grounding assertions still hold across runs.)

## What the tests caught (regression history)

- **Obfuscated payloads**: URL-encoded SQLi (`%27`), command injection (`%7C`),
  and `..%2f` path traversal were missed; added URL-decode normalization.
- **Multi-match mislabeling**: a `cat | nc` line was tagged "path traversal"
  instead of "command injection"; added severity + actionability tie-break.
- **Kill-chain severity**: 3+ high/critical TTPs together now escalate to
  critical.
- **High-entropy files**: files with no recognizable magic bytes weren't flagged;
  entropy check now applies to unknown/opaque types too.
- **CLI**: `list` crashed (`Namespace` missing `verbose`); LLM-gate "y" path
  failed when the target file was deleted mid-test (test bug, fixed).
- **qwen3/ornith thinking mode**: models emitted into `thinking` and left
  `content` empty; HexShield now sends `think:false` and falls back to the
  `thinking` field.

## Notes

- The LLM quality suite retries the open-question test a few times because small
  models have generation variance.
- The rigorous suite's high-entropy test uses random data; if you ever see a
  single flake there, re-run — entropy of 256 KB of `os.urandom` measures ~7.99
  consistently.
