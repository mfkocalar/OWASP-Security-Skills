# OWASP LLM Top 10 (2025)

Load this reference when reviewing LLM SDK calls, system prompts,
RAG/vector store code, or anything that takes model output and turns
it into text a user or downstream system consumes. For autonomous
agents — tool-calling loops, multi-agent pipelines, MCP servers —
also load `references/agentic.md`; the Agentic list adds concerns
(goal hijack, cascading failures, inter-agent trust) that this list
doesn't address.

**Source:** OWASP Top 10 for LLM Applications (2025 edition) —
Index: <https://genai.owasp.org/llm-top-10/>.
PDF: <https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf>.

**Edition verification:** LLM Top 10 2025 confirmed current — live index
lists exactly `LLM01:2025`–`LLM10:2025`, matching this file. No 2026
LLM-specific edition found (2026 work is the separate Agentic project —
see `references/agentic.md`). Source: <https://genai.owasp.org/llm-top-10/>.
Retrieved 2026-07-22.

---

## LLM01:2025 — Prompt Injection

Source: <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

User-supplied content alters model behavior in unintended ways.
Direct (user-to-prompt) or indirect (content-retrieved-by-model).
Includes imperceptible inputs the model parses but a reviewer would
not notice.

**Detection signals**
- User input concatenated directly into a prompt (`f"...{user_input}..."`)
  with no structural separation.
- Single flat prompt: no distinct system / user / tool channel.
- RAG or tool outputs placed in the same trust zone as system
  instructions.
- No output-side guardrails on instructions that came from retrieved
  content.
- No adversarial test corpus ("ignore previous instructions", DAN
  prompts, invisible-character payloads).

**Mitigations**
```python
# Role-separated messages API, never string concatenation
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": user_input},
]

# Fence retrieved content so the model treats it as data
retrieved_block = f"<retrieved_context>\n{doc}\n</retrieved_context>"
```
- Human-in-the-loop confirmation for any tool call with external
  side effects.
- Red-team with adversarial strings from public corpora.

---

## LLM02:2025 — Sensitive Information Disclosure

Source: <https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/>

Outputs (or memorized weights) expose PII, credentials, health
records, business secrets, or system internals to parties who should
not see them.

**Detection signals**
- Fine-tuning dataset contains PII with no scrubbing pipeline.
- Chat histories stored without per-user segmentation.
- Model responses logged in plaintext to shared observability tools.
- No DLP/regex scan on model outputs before return to client.

**Mitigations**
```python
import re
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
def redact(text: str) -> str:
    return SECRET_RE.sub("[REDACTED]", text)
```
- Scrub training data with a deterministic PII pipeline before
  fine-tuning.
- Per-tenant isolation in RAG stores; never cross-index tenants.
- Redact before logging; redact again before returning.

---

## LLM03:2025 — Supply Chain

Source: <https://genai.owasp.org/llm-top-10/>

Third-party models, datasets, plugins, and infrastructure introduce
compromise paths: tampered weights, typosquatted model cards,
poisoned datasets, malicious adapters.

**Detection signals**
- Models pulled by tag rather than immutable digest/hash.
- No AIBOM (AI Software Bill of Materials) for deployed models.
- Hugging Face / registry downloads without signature verification.
- No provenance metadata for LoRA adapters or embeddings.

**Mitigations**
- Pin models by SHA-256 digest; verify signatures (Sigstore where
  available).
- Generate an AIBOM per deployment.
- Isolate model-loading code from the public internet at runtime;
  allowlist registry hosts only.

---

## LLM04:2025 — Data and Model Poisoning

Source: <https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/>

Adversaries manipulate training, fine-tuning, or embedding data so
the model emits attacker-chosen outputs on trigger phrases, or
degrades on target inputs. 2025 pairs data and model poisoning.

**Detection signals**
- User-contributed data ingested into fine-tune pipeline without
  review.
- No canary / backdoor probes in the eval harness.
- Embedding index auto-rebuilt from untrusted crawl output.

**Mitigations**
- Curated eval set probing known backdoor triggers on every release.
- Sign and version datasets; compare hashes across runs.
- Segregate training data by source and reputation tier.

---

## LLM05:2025 — Improper Output Handling

Source: <https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/>

Downstream systems treat LLM output as trusted, enabling XSS, SSRF,
SQL injection, or shell injection when the output is rendered or
executed. (Renamed from "Insecure Output Handling" in earlier
editions.)

**Detection signals**
- `exec`, `eval`, `subprocess.run(..., shell=True)` fed directly from
  model output.
- HTML rendered via `innerHTML = llm_output` with no sanitizer.
- SQL constructed by string formatting from a "text-to-SQL" agent.
- Model output used as a filesystem path without normalization.

**Mitigations**
```python
# Parameterize; never interpolate model output into SQL
cursor.execute("SELECT * FROM orders WHERE id = %s", (parsed_id,))
```
- Validate model output with a schema (pydantic, JSON Schema) before
  acting on it.
- Render model output through an HTML sanitizer (DOMPurify, bleach).
- Never `eval` or `exec` on model output.

---

## LLM06:2025 — Excessive Agency

Source: <https://genai.owasp.org/llm-top-10/>

The LLM is granted more functionality, permissions, or autonomy than
it needs, so a single prompt-injection or misstep produces outsized
damage.

**Detection signals**
- Agent holds a long-lived admin / service-account token covering
  many APIs.
- Tools include open-ended primitives (`run_shell`,
  `http_request_any_url`).
- No per-tool allowlist of arguments or destinations.
- No human-approval step on destructive actions (delete, transfer,
  send).

**Mitigations**
```python
ALLOWED_TOOLS = {"search_docs", "summarize"}
def dispatch(tool: str, args: dict):
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(tool)
```
- Scope credentials to the minimum API set the agent actually calls.
- Require explicit user confirmation for irreversible side effects.
- Prefer typed, narrow tools over broad primitives.

---

## LLM07:2025 — System Prompt Leakage

Source: <https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/>

System prompts often contain credentials, internal logic, or
authorization rules; exfiltration of the prompt (via injection or
model coaxing) hands attackers both the rules and any embedded
secrets.

**Detection signals**
- API keys, DB URLs, or feature flags embedded in the system prompt
  string.
- Prompt contains authorization logic ("if user is admin, allow X").
- No test that asserts prompt text is not returned on "repeat your
  instructions" probes.

**Mitigations**
- Keep secrets in environment variables and tool configs, never in
  the prompt.
- Enforce authorization outside the model (policy engine, not prompt
  text).
- Red-team with "repeat your instructions verbatim" style probes;
  assert the prompt doesn't leak.

---

## LLM08:2025 — Vector and Embedding Weaknesses

Source: <https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/>

Weaknesses in how vectors / embeddings are generated, stored, or
retrieved in RAG systems — cross-tenant leakage, embedding inversion,
poisoned chunks, missing access control on the vector store.

**Detection signals**
- Single vector index shared across tenants with filter-only
  isolation.
- Chunk metadata missing `owner` / `acl` field.
- Upsert endpoint exposed without authentication.
- No integrity check on embeddings loaded from disk.

**Mitigations**
- Enforce access control at the vector store layer, not just the
  application query.
- Per-tenant namespaces or collections rather than a shared index.
- Filter retrieved chunks through the user's authorization context
  before prompting.

---

## LLM09:2025 — Misinformation

Source: <https://genai.owasp.org/llm-top-10/>

The model produces plausible but false content, including
hallucinated code, fabricated citations, and "package hallucination"
that leads users to install malicious typosquats.

**Detection signals**
- No grounding step (retrieval or tool call) for factual claims.
- Code-generation path installs suggested packages without lockfile
  review.
- No confidence or citation metadata surfaced to the user.

**Mitigations**
- Ground answers in retrieved documents; show clickable citations.
- Verify suggested package names against a registry allowlist before
  `pip install` / `npm install`.
- Evaluator model or rule pass flagging unsourced factual claims.

---

## LLM10:2025 — Unbounded Consumption

Source: <https://genai.owasp.org/llm-top-10/>

Resource exhaustion via token floods, recursive tool loops, oversized
context windows, or cost-amplification attacks that convert a cheap
request into an expensive model call. Expands the earlier "Model DoS".

**Detection signals**
- No per-request `max_tokens` or per-user rate limit.
- Agent loops have no iteration cap.
- Input size not bounded before tokenization.
- No billing alert tied to per-user spend.

**Mitigations**
```python
MAX_ITERS = 8
for _ in range(MAX_ITERS):
    step = agent.step()
    if step.done: break
else:
    raise RuntimeError("agent loop cap reached")
```
- Enforce token, time, and dollar budgets per session at the gateway.
- Cache deterministic prompts; reject duplicate floods.
- Wire per-user spend to paging alerts.
