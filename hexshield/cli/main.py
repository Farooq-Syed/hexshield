"""HexShield CLI — defensive security assistant driven by a local/remote LLM."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional

# Force UTF-8 console output (avoids UnicodeEncodeError from LLM text on cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from ..llm import LLMChain, get_llm_chain
from ..tools import DefenseTool, run_tool_with_llm
from ..tools.registry import ToolRegistry
from ..tools.register_all import *  # noqa: F401,F403  (register tools)


def _print_banner() -> None:
    print(
        "\n"
        "  ██╗  ██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ \n"
        "  ╚██╗██╔╝██╔════╝╚██╗██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗\n"
        "   ╚███╔╝ █████╗   ╚███╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║\n"
        "   ██╔██╗ ██╔══╝   ██╔██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║\n"
        "  ██╔╝ ██╗███████╗██╔╝ ██╗███████║██║  ██║██║███████╗███████╗██████╔╝\n"
        "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ \n"
        "  Defensive security assistant — HexStrike's blue-team counterpart\n"
        "\n"
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hexshield",
        description="Defensive security analysis with an LLM fallback chain.",
    )
    sub = p.add_subparsers(dest="command")

    def _llm_opts(sp) -> None:
        sp.add_argument("--ollama-model", default=None, help="Ollama model (default robit/ornith:9b).")
        sp.add_argument("--ollama-host", default="http://127.0.0.1:11434", help="Ollama host.")
        sp.add_argument("--api-model", default=None, help="API model name (uses HEXSHIELD_API_KEY).")
        sp.add_argument("--api-base", default=None, help="API base URL.")
        sp.add_argument("--no-api", action="store_true", help="Disable the API fallback provider.")
        sp.add_argument("--verbose", action="store_true", help="Verbose logging.")

    # list
    sub.add_parser("list", help="List available defensive tools.")

    # health
    health = sub.add_parser("health", help="Show LLM provider status (Ollama/API).")
    _llm_opts(health)

    # run <tool>
    run = sub.add_parser("run", help="Run a defensive tool against a target.")
    run.add_argument("tool", help="Tool name (see `hexshield list`).")
    run.add_argument("target", help="Target: file path, alert text, incident type, etc.")
    run.add_argument("--max-lines", type=int, default=5000, help="Log lines to parse (parse_logs).")
    run.add_argument("--source", choices=["text", "file"], default="text", help="Input mode (ioc_lookup).")
    run.add_argument("--profile", default="workstation", help="Hardening profile (hardening_check).")
    run.add_argument("--no-llm", action="store_true", help="Skip LLM analysis (deterministic only).")
    run.add_argument("--json", action="store_true", help="Print raw JSON result.")
    _llm_opts(run)

    # ask
    ask = sub.add_parser("ask", help="Ask the LLM an open security question.")
    ask.add_argument("question", help="Your question or prompt.")
    ask.add_argument("--no-llm", action="store_true", help="Force rule-based fallback.")
    _llm_opts(ask)
    return p


def _make_chain(args) -> LLMChain:
    return get_llm_chain(
        ollama_model=args.ollama_model or "robit/ornith:9b",
        ollama_host=args.ollama_host,
        api_model=args.api_model or "",
        api_key="",  # read from env inside provider
        api_base=args.api_base or "",
        enable_api=not args.no_api,
    )


def _heuristic_summary(messages: List[dict]) -> str:
    """Rule-based fallback when no LLM is available."""
    # For tool summaries we already have structured findings; return guidance.
    last = messages[-1].get("content", "") if messages else ""
    return (
        "LLM unavailable; showing deterministic findings above. "
        "Tip: start Ollama (`ollama serve`) or set HEXSHIELD_API_KEY to enable "
        "natural-language analysis. Findings are machine-generated and reliable; "
        "the language summary is optional context."
    )


def _cmd_list(args) -> int:
    by_cat = ToolRegistry.by_category()
    for cat in sorted(by_cat):
        print(f"\n[{cat}]")
        for t in sorted(by_cat[cat], key=lambda x: x.name):
            print(f"  {t.name:<22} {t.description}")
    print(f"\n{len(ToolRegistry.names())} tools registered.")
    return 0


def _cmd_health(args) -> int:
    chain = _make_chain(args)
    for h in chain.health():
        if h.get("available"):
            status = "OK"
        else:
            status = "unavailable"
        print(f"{h.get('provider'):<16} {status:<12} model={h.get('model') or '-'}")
        if h.get("pulled_models"):
            print(f"  Ollama pulled models: {', '.join(h['pulled_models'][:6])}")
    return 0


def _check_llm_available(chain) -> bool:
    """Probe providers; guide the user if none is reachable.

    Returns True if an LLM is usable (proceed), False if the user chose to
    exit, and signals rule-based fallback by returning True after the user
    opts to continue without an LLM.
    """
    diag = chain.ensure_llm()
    available = [d for d in diag["providers"] if d.get("available")]
    if available:
        for d in available:
            print(f"[llm] using {d.get('provider')} model={d.get('model') or '-'}")
        return True

    print("\n[llm] No local or API model is reachable.")
    print()
    for d in diag["providers"]:
        if d.get("provider") == "ollama":
            models = d.get("pulled_models") or []
            if d.get("configured") and models:
                state = f"server up, but '{d.get('model')}' not pulled"
            elif models:
                state = "server up, no model selected"
            else:
                state = "not reachable"
            print(f"  - ollama: {state}")
            if models:
                print(f"      pulled models: {', '.join(models[:6])}")
        else:
            state = "configured, but not reachable" if d.get("configured") else "not configured"
            print(f"  - {d.get('provider')}: {state}")

    print("""
  You can set up an LLM in one of two ways, then re-run:

  1) Local (Ollama) — recommended if you have a GPU (e.g. RTX 4060, 8GB):
       ollama serve                     # start the server (in another terminal)
       ollama pull robit/ornith:9b             # download a small strong model (8B)
     Then run:  python run.py <command>  (defaults to robit/ornith:9b)

  2) API key — any OpenAI-compatible endpoint (OpenAI, Groq, DeepSeek...):
       set HEXSHIELD_API_KEY=sk-...     # your key
       set HEXSHIELD_API_MODEL=gpt-4o-mini
       set HEXSHIELD_API_BASE=https://api.openai.com/v1
     Then run:  python run.py <command>

  Or continue now with rule-based analysis only (no natural-language summary).
""")
    while True:
        choice = input("Continue without an LLM? [y=continue, n=exit]: ").strip().lower()
        if choice in ("y", "yes"):
            print("[llm] continuing with rule-based analysis only")
            return True
        if choice in ("n", "no", "q", "quit"):
            print("[llm] exiting.")
            return False
        print("  please answer y (continue) or n (exit).")


def _cmd_run(args) -> int:
    if not ToolRegistry.has(args.tool):
        print(f"Unknown tool '{args.tool}'. Available: {', '.join(ToolRegistry.names())}")
        return 2

    tool: DefenseTool = ToolRegistry.get(args.tool)

    if args.no_llm:
        chain = None
    else:
        chain = _make_chain(args)
        if not _check_llm_available(chain):
            return 3

    kwargs = {"max_lines": args.max_lines, "source": args.source, "profile": args.profile}

    try:
        result = run_tool_with_llm(
            tool, chain, args.target, heuristic_fallback=_heuristic_summary, **kwargs
        )
    except Exception as e:
        print(f"Error running {args.tool}: {e}")
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    _render(result)
    return 0


def _render(result) -> None:
    sev = result.severity.upper()
    print(f"\n=== {result.tool} :: {result.target} ===")
    print(f"Status: {result.status.upper()}   Severity: {sev}   ({result.summary})")
    if result.findings:
        print("\nFindings:")
        for f in result.findings:
            detail = (
                f.get("detail")
                or f.get("title")
                or f.get("phase")
                or f.get("id")
                or f.get("type")
                or ""
            )
            print(f"  [{f.get('severity','info').upper():<8}] {f.get('type','')}: {detail}")
    if result.llm_analysis:
        print("\n--- LLM Analysis ---")
        print(result.llm_analysis)
    print()


def _cmd_ask(args) -> int:
    if args.no_llm:
        chain = None
    else:
        chain = _make_chain(args)
        if not _check_llm_available(chain):
            return 3
    sys_prompt = (
        "You are HexShield, a defensive security analyst assistant. "
        "Answer the user's security question concisely and accurately. "
        "Focus on detection, hardening, and remediation (blue team). "
        "If the request is for offensive/attacking another system, respond with "
        "authorized-defense framing only and note authorization requirements."
    )
    try:
        answer = chain.complete(
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": args.question},
            ],
            heuristic_fallback=lambda msgs: (
                "LLM unavailable. Re-run with Ollama running (`ollama serve`) "
                "or set HEXSHIELD_API_KEY to get an AI answer."
            ),
        )
    except Exception as e:
        print(f"Error: {e}")
        return 1
    print(answer)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        _print_banner()
        _build_parser().print_help()
        return 0

    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)

    if args.command == "list":
        return _cmd_list(args)
    if args.command == "health":
        return _cmd_health(args)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "ask":
        return _cmd_ask(args)

    _print_banner()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())