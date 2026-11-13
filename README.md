# Secure Agentic Incident Triage

Multi-agent triage of SIEM alerts, built around privacy, isolation and auditability. One script, no framework glue.

```
alert → local pseudonymization → [proc A: CrewAI triage agent] → [proc B: AutoGen adversarial verifier on every auto-close]
      → deterministic safety floor → auto_close | human_queue | page_human → encrypted store + HMAC-chained audit log
```

## Stack (open source, free)
CrewAI (triage) · AutoGen AgentChat 0.4+ (verifier) · cryptography/Fernet · SQLite · uv.
Model: any OpenAI-compatible endpoint, hosted (OpenRouter `:free` model, e.g. Qwen3) or fully local (below). No Ollama, no Llama.

## Run
```bash
uv sync                                     # creates .venv
export TRIAGE_KEY=$(uv run python triage.py keygen)
uv run python triage.py eval                # mock mode (keyword rules), proves plumbing
export LLM_API_KEY=sk-or-...  LLM_MODEL="<free-model-id>"   # hosted, live
uv run python triage.py eval --n 100
uv run python triage.py verify --head <audit_head from results.json>
```
Fully local (nothing leaves the machine; the guard below refuses anything else):
```bash
uv pip install transformers torch && transformers serve --port 8000   # check `transformers serve --help`; vLLM or mistral.rs also work
export LLM_BASE_URL=http://localhost:8000/v1 LLM_API_KEY=local LLM_MODEL="Qwen/Qwen3-1.7B" LLM_LOCAL_ONLY=1
```
With `LLM_LOCAL_ONLY=1`, eval aborts if the endpoint host is not localhost.

## What is enforced (and where)
| Property | Mechanism | Maps to |
|---|---|---|
| Pseudonymization before any model call (HMAC tokens, correlation kept) | `anonymize()` | GDPR Art. 4(5), 5(1)(c), 25 |
| Encrypted records, vault, audit payloads | Fernet (`enc`) | GDPR Art. 32, DORA Art. 9 |
| Agent isolation | each agent is its own OS process; env scrubbed (**no master key, no DB path**), temp cwd/HOME, no tools, fresh context per call, 180 s timeout then kill + escalate | least privilege |
| Tamper-evident audit | HMAC-keyed chain; `verify --head` detects edits and truncation against an anchored head hash | DORA Art. 17 (incident management/logging) |
| Fail-safe | parse error, timeout, crash → escalate to human | DORA resilience |
| Prompt injection | alert text fenced as untrusted data, schema-validated output, adversarial verifier, deterministic floor (ransomware/C2 indicators can never be downgraded), injected cases in the benchmark | OWASP LLM01 |
| Human oversight | high/critical never auto-actioned | GDPR Art. 22 spirit |
| Retention / erasure | `purge --days N` deletes vault + records; destroying `TRIAGE_KEY` crypto-shreds everything | GDPR Art. 5(1)(e), 17 |

## Evaluation protocol
`eval` reports three systems side by side: `baseline` (keyword rules), `triage_only` (CrewAI agent) and `full` (with verifier + floor). The verifier's value is the gap between the last two, with no extra LLM calls.
- **Time:** median/p95 per alert (sequential, so queueing never inflates it) + total.
- **Quality:** severity/category accuracy with Wilson 95% CI, split easy vs hard (hard = backup jobs that look like exfiltration, credential theft after a click, injected instructions, unapproved scans). **`missed_high_critical` with its 95% upper bound is the headline safety number.**
- **Human workload:** assumption-free alert-count reduction, plus minutes saved as a **lower bound** (escalated alerts get zero speedup). Measure your own `--manual-min`: time yourself triaging 20 alerts by hand with a stopwatch and use the median.
- **Real data:** `--data alerts.jsonl` takes lines `{"raw": "...", "category": "...", "severity": "..."}`. Convert any public labelled set (Splunk attack_data, CICIDS2017, EVTX samples) to that shape.

## Compliance wording
Use "designed around GDPR and DORA principles", never "compliant". Pseudonymized data is still personal data (GDPR Recital 26): a hosted model makes the provider a processor, which needs a DPA, a transfer assessment and a DPIA. Local mode avoids this. Certification is an organizational process; this repo provides the technical controls and evidence.

## Scope notes
Process isolation shares a kernel and user account with the host; for stronger separation run each worker in a container (the worker protocol is stdin/stdout JSON, so this is a wrapper change). Regex pseudonymization catches structured identifiers, not free-text names; add an NER stage (e.g. Presidio) for unstructured sources.
