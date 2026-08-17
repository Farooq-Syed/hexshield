# Changing the Model

HexShield never talks to a model directly — everything goes through the
`LLMProvider` interface (`hexshield/llm/provider.py`) and the fallback chain
(`hexshield/llm/chain.py`). That means you can swap the model **four different
ways**, from a one-flag override to writing a brand-new backend. No tool code
changes.

The default chain, tried in order:

```
1. Ollama (local)          auto GPU if the model fits VRAM, else CPU
2. OpenAI-compatible API    any /v1/chat/completions endpoint
3. Rule-based heuristic     pure Python summary, no LLM needed
```

At startup (for any LLM-using command) HexShield probes the providers. If none
is reachable it prints setup instructions and lets you continue without an LLM
or exit.

---

## A. Swap the local Ollama model (the common case)

### Option 1 — one-flag override (per command)

```bash
python run.py run parse_logs /var/log/auth.log --ollama-model qwen3.5:4b
python run.py ask "detection rules for kerberoasting" --ollama-model llama3.1:8b
```

### Option 2 — environment variable (persistent)

```bash
# Linux / macOS
export HEXSHIELD_OLLAMA_MODEL=qwen3.5:4b

# Windows (PowerShell)
$env:HEXSHIELD_OLLAMA_MODEL="qwen3.5:4b"
```

### Option 3 — change the code default

The default lives in two places (keep them in sync):

- `hexshield/llm/chain.py:23` — `ollama_model: str = "robit/ornith:9b"`
- `hexshield/llm/ollama_provider.py:21` — `def __init__(self, model: str = "robit/ornith:9b", ...)`

### Pulling a model with Ollama

```bash
ollama serve                 # start the server (in another terminal)
ollama pull qwen3.5:4b       # download a specific model
ollama list                  # see what you have locally
```

### Recommended models by hardware

| Hardware                            | Model                                    | Notes                                    |
| ----------------------------------- | ---------------------------------------- | ---------------------------------------- |
| CPU only / weak GPU                 | `qwen2.5:3b`, `phi3:mini`, `llama3.2:3b` | Fast, lower accuracy                     |
| 8 GB VRAM (e.g. RTX 4060)           | `robit/ornith:9b`, `qwen2.5:7b`, `llama3.1:8b` | Good balance; 9B is slower (~17 s/reply) |
| 8 GB VRAM, want speed               | `qwen3.5:4b`                             | ~1.3 s/reply, very usable accuracy       |
| 16 GB+ VRAM                         | `llama3.3:70b` (q4), `qwen2.5:32b`, `mistral-large` | Best quality if it fits                 |

Ollama decides GPU vs CPU automatically based on the model size and your VRAM.

### Thinking-mode note (qwen3 / ornith models)

Some models (qwen3-family, ornith) emit their answer in a `thinking` field and
leave `content` empty when thinking mode is on. HexShield sends `"think": false`
and, as a fallback, reads the `thinking` field if `content` is empty — so these
models "just work". If a model still returns empty text, `LLMChain.complete()`
treats an empty response as a failure and tries the next provider.

### Auto-select behavior

If the configured Ollama model is not pulled, `OllamaProvider.auto_select()`
picks the best **already-pulled** model, preferring models that fit ~8 GB VRAM
and your preferred families. To disable surprises, just pull the model you want
and it will be selected.

---

## B. Use an API key (no local hardware needed)

Set three environment variables (secrets stay out of the repo; `.env` is
git-ignored):

| Variable              | Example value                                      |
| --------------------- | -------------------------------------------------- |
| `HEXSHIELD_API_KEY`   | `sk-...`                                           |
| `HEXSHIELD_API_MODEL` | `gpt-4o-mini`                                      |
| `HEXSHIELD_API_BASE`  | `https://api.openai.com/v1`                        |

The API provider is OpenAI-compatible, so the same code works with many
services:

| Service   | `HEXSHIELD_API_BASE`                      | `HEXSHIELD_API_MODEL` example            |
| --------- | ----------------------------------------- | ---------------------------------------- |
| OpenAI    | `https://api.openai.com/v1`               | `gpt-4o-mini`, `gpt-4o`                  |
| Groq      | `https://api.groq.com/openai/v1`          | `llama-3.3-70b-versatile`                |
| DeepSeek  | `https://api.deepseek.com/v1`             | `deepseek-chat`                          |
| OpenRouter| `https://openrouter.ai/api/v1`            | `meta-llama/llama-3.3-70b-instruct`      |
| Local vLLM| `http://localhost:8000/v1`                | any served model                         |
| Ollama    | `http://localhost:11434/v1` (compat)      | `qwen3.5:4b`                             |

Example (PowerShell):

```powershell
$env:HEXSHIELD_API_KEY="sk-..."
$env:HEXSHIELD_API_MODEL="gpt-4o-mini"
python run.py run triage_alert "phishing invoice.scr then powershell -enc"
```

If both Ollama and the API are configured, Ollama is tried first; the API is
used when Ollama is unreachable or returns empty content.

---

## C. Control the fallback order / behavior

| Flag                     | Effect                                                        |
| ------------------------ | ------------------------------------------------------------- |
| `--ollama-model NAME`    | Which local model to use.                                     |
| `--ollama-host URL`      | Point at a different Ollama server (default `http://127.0.0.1:11434`). |
| `--api-model NAME`       | API model (overrides `HEXSHIELD_API_MODEL`).                  |
| `--api-base URL`         | API base URL (overrides `HEXSHIELD_API_BASE`).                |
| `--no-api`               | Disable the API fallback entirely (local-only mode).          |
| `--no-llm`               | Skip LLM analysis; deterministic findings only.               |

Ordering logic: providers are probed; reachable providers run first, then the
others. Empty responses count as failures so the chain keeps moving.

---

## D. Add a brand-new provider

The interface is one file: `hexshield/llm/provider.py`. A provider just needs
`name`, `is_available()`, and `chat(...)`.

Example — an Anthropic provider (concept):

```python
# hexshield/llm/anthropic_provider.py
from .provider import LLMError, LLMProvider

class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model="claude-3-5-haiku", api_key=""):
        self.model = model
        self.api_key = api_key

    def is_available(self) -> bool:
        return bool(self.model and self.api_key)

    def chat(self, messages, temperature=0.2, max_tokens=2048, timeout=120) -> str:
        # Build the Anthropic Messages API request with urllib...
        # Return the assistant text.
        return "..."

    def health_details(self):
        return {"provider": self.name, "model": self.model, "available": self.is_available()}
```

Then add it to the chain in `hexshield/llm/chain.py`:

```python
from .anthropic_provider import AnthropicProvider

# inside LLMChain.__init__, after the other providers:
self.providers.append(AnthropicProvider(...))
```

That's it — every tool and the CLI now use it, no other changes required.

---

## Verifying your setup

```bash
python run.py health        # shows provider status + pulled models
python run.py list          # lists all tools
```
