# OWASP LLM Top 10 (2026)

Load this reference when reviewing LLM SDK calls, system prompts,
RAG/vector store code, or anything that takes model output and turns
it into text a user or downstream system consumes. For autonomous
agents — tool-calling loops, multi-agent pipelines, MCP servers —
also load `references/agentic.md`; the Agentic list adds concerns
(goal hijack, cascading failures, inter-agent trust) that this list
doesn't address.

**Source:** OWASP Top 10 for LLM Applications, 2026 edition, from the
OWASP GenAI Security Project, published 2026-08-04.
Index: <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>.
Canonical per-item text: OWASP's official source repository, pinned to
commit `9253e38ade58e959b531c0c5c9a4842272c9cd0e` —
<https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final>.
OWASP content is licensed `CC BY-SA 4.0`; the entries below paraphrase
it with attribution.

**Edition verification:** The ten codes, titles, and rank order were
confirmed against OWASP's official per-item files and the edition's
2025-to-2026 rank-migration figure in that repository. genai.owasp.org
publishes no per-item 2026 risk pages, and its LLM Top 10 landing page
still listed the 2025 edition on the retrieval date, so each entry's
Source line cites its pinned per-item file instead. Retrieved 2026-10-04.

**Scoring methodology:** The 2026 ranking is the first hybrid one: the
practitioner (community) vote carries about 75% of the weight and
real-incident data about 25%. OWASP collected 7,714 incidents from
public vulnerability databases and an AI-harm database, and classified
the 6,639 that had enough detail to sort (see `LLM00_Preface.md` in the
pinned source directory).

The Detection signals lists in each entry are this skill's code and
configuration readings of OWASP's Common Examples of Risk; OWASP's items
have no detection section of their own.

---

## LLM01:2026 — Prompt Injection

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM01_PromptInjection.md>

Any input that reaches the model can change its behavior in ways the
developer did not intend. That covers direct user messages and indirect
content the model retrieves, and since 2025 the scope is wider: images,
audio and video, tool output, intermediate reasoning, and persistent
agent memory or RAG corpora all count. Indirect injection now includes
trusted surfaces such as MCP servers, where text planted through a
low-privilege channel is read by an agent running with elevated
credentials. Payloads may hide in invisible Unicode, or in encoded and
low-resource-language text that filters never saw. OWASP's position is
that models make no architectural split between instructions and data,
so "no reliable prevention mechanism exists today" and defense has to be
architectural rather than interceptive: assume the instruction boundary
will be bypassed and limit what a bypass can reach. For the
consequences side, see `LLM03:2026`; for what the model leaks, see
`LLM02:2026`; for unsafe handling of what it emits, see `LLM10:2026`.

**Detection signals**
- User input concatenated directly into a prompt (`f"...{user_input}..."`)
  with no structural separation.
- Single flat prompt: no distinct system / user / tool channel.
- RAG or tool outputs placed in the same trust zone as system
  instructions.
- No testing against adaptive attackers who know the deployed defense;
  results from a static attack corpus alone are misleading.
- No stripping, at ingest and at render, of tag-block characters
  U+E0000–U+E007F, variation selectors U+FE00–U+FE0F, or zero-width
  characters U+200B, U+200C, U+200D, U+2060.
- Model output acted on without schema validation in application code,
  or validated only by a second LLM.
- Credentials used, or state-changing decisions made, in the model path
  rather than in application code behind a deterministic policy engine.
- Agent memory writes not treated as privileged operations.
- Unpinned or unsigned MCP servers or tool packages.
- Rendering of Markdown image URLs emitted by the model (an exfiltration
  channel).
- One agent that combines untrusted input, sensitive-data access, and
  external communication — the "lethal trifecta" that the Rule of Two
  capability budget forbids.

**Mitigations**
```python
# Role-separated messages API, never string concatenation
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": user_input},
]

# Fence retrieved content so the model treats it as data.
# NOTE: this structural separation reduces only non-adaptive attacks;
# an attacker who knows the scheme can mimic it. It does not solve injection.
retrieved_block = f"<retrieved_context>\n{doc}\n</retrieved_context>"
```
```python
import re

# Tag block, variation selectors, and zero-width characters that carry
# hidden instructions or exfiltrated bytes. Strip at ingest and at render.
INVISIBLE_RE = re.compile(
    "[\U000E0000-\U000E007F︀-️​-‍⁠]"
)

def strip_invisible(text: str) -> str:
    return INVISIBLE_RE.sub("", text)
```
- Keep human confirmation for any tool call with external side effects,
  and show the reviewer the exact action rendered, not a summary.
- Schema-validate model output in application code, not with a second
  LLM; remember this catches format violations, not semantic
  manipulation.
- Hold credentials and state changes in application code behind a
  deterministic policy engine that re-checks intent and arguments at
  execution time.
- Filter at every modality boundary (text, image, audio), extracting
  text from non-text inputs before filtering.
- Treat agent memory writes as privileged: log the cause, classify for
  instruction-like content, and require approval before it persists.
- Pin, sign, and verify MCP servers and tool packages, and audit tool
  descriptions for hidden instructions (cross-ref `LLM04:2026` and
  `ASI04`).
- Budget capabilities so no single agent holds all three trifecta legs
  (untrusted input, sensitive data, external action).
- Test against adaptive attackers who have read the defense, rather than
  static public corpora, and distrust static-only success claims.

---

## LLM02:2026 — Sensitive Information Disclosure

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM02_SensitiveInformationDisclosure.md>

Confidential, regulated, or proprietary data leaves the system through a
channel nobody authorized. The channel is no longer just the final
answer: tool-call arguments, reasoning traces, retrieved chunks, logs
and telemetry, embeddings, and side channels (response timing, token
length, logprobs, confidence scores, cache hits) are all disclosure
surfaces and deserve the same classification and redaction as the reply
itself. OWASP frames the exposure across four lifecycle phases —
training, inference, pipeline, and observation — and tiers its controls
from foundational to advanced. Two structural causes recur: oversharing
upstream (RAG fed from over-permissioned drives and knowledge bases) and
persistence (data that has shaped weights or embeddings stays
extractable after the source is deleted). Embedding-inversion mechanics
live in `LLM09:2026`.

**Detection signals**
- Fine-tuning dataset contains PII with no scrubbing pipeline.
- Chat histories stored without per-user segmentation.
- Model responses logged in plaintext to shared observability tools.
- No DLP scan or classifier pass on model outputs before they return to
  the client.
- Reasoning traces or tool-call arguments logged verbatim to a shared
  APM project.
- Secrets, credentials, or regulated data embedded in system prompts.
- Logprobs or confidence scores exposed on production endpoints.
- Automatic full-record context appends (for example a "customer 360"
  blob) added to every prompt.
- No per-user or per-session query budget on sensitive endpoints.

**Mitigations**
```python
import re
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
def redact(text: str) -> str:
    return SECRET_RE.sub("[REDACTED]", text)
```
- Treat the regex above as a floor only. OWASP's guidance is to sanitize
  with trained classifiers plus NER, because pattern matching alone
  misses encoded and cross-lingual output.
- Redact before logging and again before returning.
- Authorize before retrieval: apply per-document and per-chunk access
  checks within the index query itself, since filtering after
  generation cannot recall a chunk the model already saw. Isolate
  tenants per index for high-sensitivity workloads.
- Send only task-required fields to external providers, and disable
  automatic context appends unless justified per template.
- Gate logprobs and confidence output; classify and redact reasoning
  traces as first-class output; budget queries per user.
- For regulated or high-target deployments, OWASP adds Tier 2 and 3
  controls (differentially private training, side-channel padding and
  cache partitioning, verifiable erasure across data, embeddings, and
  adapters) that this skill only names.

---

## LLM03:2026 — Excessive Agency

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM03_ExcessiveAgency.md>

The model is given more functionality, permission, or autonomy than the
task needs, so a hallucination, an injection, or a compromised peer
agent can trigger damaging actions. The three root causes are unchanged
from 2025: excessive functionality, excessive permissions, and excessive
autonomy. The 2026 text maps the risk to the agentic items `ASI02`
(tool misuse), `ASI03` (identity and privilege abuse), and `ASI08`
(cascading failures). Scope boundary: sanitizing inputs and outputs is
not a root control here; that belongs to `LLM01:2026` for inputs and
`LLM10:2026` for outputs.

**Detection signals**
- Agent holds a long-lived admin / service-account token covering
  many APIs.
- Tools include open-ended primitives (`run_shell`,
  `http_request_any_url`).
- No per-tool allowlist of arguments or destinations.
- No human-approval step on destructive actions (delete, transfer,
  send).
- Tools run under one generic privileged identity instead of the end
  user's own authorization context (for example an OAuth scope), across
  multi-agent or delegated chains.
- Development or trial tools left registered after a better one
  replaced them.
- Authorization decided by the LLM rather than by a policy decision
  point outside the model.
- No per-tool invocation thresholds or circuit breakers.
- No logging or monitoring of tool use.

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
- Execute tools in the user's context, preserving the original
  authorization scope across chained tool and agent calls.
- Apply complete mediation: validate every downstream request in code or
  at an independent policy decision point, with graduated enforcement
  (audit, warn, block, escalate) so reversible actions auto-approve and
  irreversible ones go to a human.
- Set a circuit breaker per tool that halts or escalates once an
  invocation or cumulative-value threshold is crossed, and monitor tool
  use. These limit damage but do not remove the root causes.

---

## LLM04:2026 — Supply Chain

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM04_SupplyChain.md>

Models, datasets, adapters, conversion pipelines, and serving platforms
can all be tampered with before they reach production. The 2026 text
treats artifact provenance and the conversion, merge, and quantization
workflows as first-class attack surfaces, extends the scope to on-device
models, and adds coding-assistant "slopsquatting": hallucinated package
names that attackers register in advance. A valid signature proves that
an artifact is intact and who published it, not that it is safe. Overlap
with poisoning is covered in `LLM05:2026`; MCP servers and tool
registries belong to `ASI04`, and MITRE ATLAS tracks the technique as
AML.T0010.

**Detection signals**
- Models pulled by mutable tag rather than immutable digest/hash.
- No AIBOM (AI Software Bill of Materials) for deployed models.
- Hugging Face / registry downloads without signature verification.
- No provenance metadata for LoRA adapters or embeddings.
- Identifier-only `Author/ModelName` references that stay open to
  namespace reuse after an account is deleted or transferred.
- `pickle` or `torch.load` on third-party files without
  `weights_only`, or reliance on that flag alone (it has had a bypass
  tracked as CVE-2025-32434).
- Trust in "safe" formats such as ONNX without considering a backdoor in
  the computational graph.
- Conversion and merge services not treated as high-risk promotion
  points; adapters merged without review.
- AI-suggested dependencies installed unverified (see `LLM07:2026`).

**Mitigations**
- Pin models by SHA-256 digest and use immutable references; allowlist
  registry hosts only and isolate model-loading code from the public
  internet at runtime.
- Sign and verify artifacts, for example with OpenSSF Model Signing
  backed by a transparency log. Signing is not a safety guarantee, so
  pair it with SLSA-style release gates and behavioural evaluation of
  third-party models.
- Extend the SBOM to an ML-BOM / AIBOM (CycloneDX ML-BOM, the OWASP
  AIBOM project) covering models, adapters, datasets, and licences.
- Treat scanners and safe-loader flags as defense-in-depth layers, and
  keep loaders and parsers patched.
- Review adapters before merging, and audit collaborative model
  environments and conversion services.
- Verify that any AI-suggested package exists and is the intended one
  before adopting it.

---

## LLM05:2026 — Data and Model Poisoning

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM05_DataModelPoisoning.md>

An adversary, or an unsafe process, corrupts data or model artifacts so
the system carries hidden bias, a backdoor, or an exploitable weakness
while still looking functional. In 2026, poisoning is scoped to anywhere
data is ingested, transformed, retrieved, or reused: pre-training,
fine-tuning (including attacks that erode refusal behaviour), embedding
creation, RAG, continuous-learning loops, and model distribution.
Inference artifacts such as chat templates, tokenizer configs, LoRA/PEFT
adapters, and quantization artifacts now count as poisoning vectors.
OWASP cites low-volume backdoors (about 250 documents were enough
against models from 600M to 13B parameters, per the file's Souly et al.
2025 reference) and sleeper-agent behaviour that survives safety
training (Hubinger et al., 2024). Boundaries: instructions delivered
through retrieved content at runtime belong to `LLM01:2026`, and
attacks on embedding geometry belong to `LLM09:2026`.

**Detection signals**
- User-contributed data ingested into fine-tune pipeline without
  review.
- No canary / backdoor probes in the eval harness.
- Embedding index auto-rebuilt from untrusted crawl output.
- Automated retraining or feedback loops that ingest user signals
  without validation, human oversight, or rate limits.
- Chat-template or tokenizer-config changes merged without review.

**Mitigations**
- Sign and version datasets; compare hashes across runs, and keep data
  under version control (for example DVC) so a poisoned change can be
  rolled back and investigated.
- Segregate training data by source and reputation tier, and use
  curated domain datasets for fine-tuning.
- Run dedicated trigger probing after every alignment cycle. Do not
  assume safety alignment removes a backdoor; treat the curated
  backdoor-trigger eval as a release gate.
- Protect RAG with trust boundaries, filtering of retrieved content, and
  source scoring.
- Treat inference artifacts as security-relevant code: hash, sign, and
  diff them before deployment.

---

## LLM06:2026 — Unbounded Consumption

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM06_UnboundedConsumption.md>

The application allows excessive, uncontrolled inference, so attackers
can degrade availability, run up unsustainable cost (denial of wallet),
or clone the model by querying it. The defining trait is cost
asymmetry: a cheap request, a stolen credential, or a manipulated
workflow buys the attacker expensive computation. The 2026 text widens
the picture to reasoning and extended-thinking models with loose
output budgets; short, benign-looking prompts that force prolonged
reasoning loops past input-size filters; sponge inputs and adversarial
image perturbations tuned to maximize compute; multimodal inputs that
inflate token counts; model extraction and distillation theft, which
exposed logits and log-probabilities accelerate; agent tool fan-out and
sessions whose context keeps growing; and exploitation of inference
servers (vLLM, TensorRT-LLM, SGLang, Triton, Ollama) through unsafe
deserialization, special-token injection, and injected chat templates.
Request-rate limiting alone is no longer enough. Extracting weights
through timing or shared-infrastructure side channels is covered by
`LLM02:2026`.

**Detection signals**
- No per-request `max_tokens` or per-user rate limit.
- Agent loops have no iteration cap.
- Input size not bounded before tokenization.
- No hard spending cap that halts inference; alerts alone are outpaced
  by fast-accumulating workloads.
- Reasoning or extended-thinking budgets left unbounded.
- Logprobs or logits exposed on production endpoints (an extraction
  aid).
- No step, recursion, time, or per-run cost ceilings on agent
  executions, and no state hashing to detect loops.
- No baseline for normal tool-call volume or per-tool token use.
- Unauthenticated inference endpoints, or unsafe deserialization and
  special-token passthrough on model-serving stacks.

**Mitigations**
```python
MAX_ITERS = 8
for _ in range(MAX_ITERS):
    step = agent.step()
    if step.done: break
else:
    raise RuntimeError("agent loop cap reached")
```
- Replace plain request-rate limits with token-aware limits: tokens per
  minute and per day plus estimated cost, using pre-flight token
  estimation to reject oversized requests before inference starts.
- Set non-overridable hard spending caps per key, user, team, and cloud
  account that halt inference when crossed, accounting for the cost
  difference between modalities and tool protocols.
- Add agent circuit breakers: step, recursion-depth, time, and cost
  ceilings per run, with state hashing to spot loops.
- Cache deterministic prompts; reject duplicate floods.
- Monitor tool-call volume against a per-tool baseline, and scan visual
  inputs for adversarial perturbations.
- Keep serving frameworks patched, disable unsafe deserialization,
  restrict special-token passthrough, and require authentication on
  every inference endpoint.

---

## LLM07:2026 — Misinformation

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM07_Misinformation.md>

The 2026 text reframes this item from plausible-but-false text to a
system-level failure: incorrect, incomplete, or unsupported output that
looks credible enough to drive a human decision, an automated workflow,
or an agent action. Model output now triggers tool calls, infers system
state, and passes between agents, so the harm is the false claim that
gets acted on, including overreliance built into agent design,
propagation of bad state from one agent to the next, and fabricated
task completion. Scope boundaries: unsafe execution of generated code
belongs to `LLM10:2026`, and the registration of hallucinated package
names as an attack vector belongs to `LLM04:2026`; injection, poisoning,
and supply-chain root causes are referenced separately.

**Detection signals**
- No grounding step (retrieval or tool call) for factual claims.
- No confidence or citation metadata surfaced to the user.
- Suggested packages installed without review (the control for that
  vector lives under `LLM04:2026`).
- Generation not separated from execution: no claim-check-act step
  between the model's statement and the action.
- Tool-call arguments, preconditions, or current state not validated
  before execution.
- An agent trusting another agent's state claim ("customer verified",
  "backup done") without verifying it.
- No structured outputs with mandatory fields to catch omissions in
  summaries.
- No approval step for high-impact actions.
- No logging of claims, supporting evidence, and outcomes.

**Mitigations**
- Ground answers in authoritative, current retrieved documents; show
  clickable citations.
- Run an evaluator model or rule pass that flags unsourced factual
  claims.
- Separate generation from execution (claim-check-act), and validate
  tool-call arguments, authorization, preconditions, and current state
  before acting.
- Use verification signals beyond model confidence, such as groundedness
  and consistency checks.
- Require approval workflows and runtime checks for high-impact actions.
- Require structured outputs with mandatory fields so omissions fail
  validation.
- Log claims, evidence, and outcomes, and test workflows against
  misleading scenarios.
- Verify suggested package names against a registry allowlist before
  `pip install` / `npm install` (this is the `LLM04:2026` control).

---

## LLM08:2026 — Hidden Context Exposure

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM08_HiddenContextExposure.md>

This item was renamed from System Prompt Leakage in the 2025 edition,
and its scope widened along with the name. It now covers all hidden,
non-user-facing context the application assembles for the model: the
system prompt and developer instructions, retrieved policy text (RAG
knowledge bases, configuration stores, user-profile services), tool and
function schemas, and any other directives placed in the context
window. OWASP's stance is to assume hidden context is discoverable, so
nothing in it counts as a secret, and it is never a security boundary:
authorization, privilege separation, policy enforcement, and content
filtering must live outside it. Severity runs from informational to
critical, depending on what the context holds and how far the
application leans on its secrecy.

Exposure here amplifies neighbouring risks: disclosed rules sharpen
`LLM01:2026` attacks, embedded credentials are an `LLM02:2026`
disclosure, revealed tool permissions and schemas widen the surface for
`LLM03:2026`, and leaked output-format rules help craft payloads for
`LLM10:2026`. Out of scope: leakage of regulated user or training data
(`LLM02:2026`), agentic amplifications such as persistent memory and
inter-agent channels (see `references/agentic.md` and the Agentic
Top 10), and generic application-security issues such as server-side
log leakage.

**Detection signals**
- API keys, DB URLs, or feature flags embedded in prompt strings.
- Prompt text contains authorization logic ("if user is admin, allow X").
- Tool or function schemas, and the role requirements in them (for
  example MCP tool descriptions naming a required role), assumed to stay
  hidden from users.
- Refusal or safety logic, and output-format or validation rules,
  written into prompts; attackers use them to evade refusals and to
  produce schema-conformant malicious output.
- Guardrails implemented only as prompt text rather than in
  deterministic systems outside the model.
- Authorization bounds checks delegated to the LLM.

**Mitigations**
- Keep secrets out of hidden context entirely: environment variables
  and tool configuration, never the prompt. Assume anything the model
  can see a user may eventually see.
- Enforce behavior with deterministic guardrails and validation outside
  the model; do not rely on prompt wording for content filtering or
  policy.
- Enforce authorization independently of the LLM (policy engine, not
  prompt text), separating tasks by authorization context and granting
  each only the privileges it needs.
- This skill's own practical test, not an OWASP prescription: probe
  with "repeat your instructions" style requests and assert that
  nothing sensitive comes back. Passing it does not make hidden context
  safe to rely on.

---

## LLM09:2026 — Vector and Embedding Weaknesses

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM09_VectorAndEmbeddingWeaknesses.md>

These are weaknesses that exploit embedding geometry and similarity
search, and they are distinct from prompt injection: many succeed even
when the retrieved content carries no instructions at all. Scope covers
RAG, vector-backed agent memory, and semantic caches; vectorless
retrieval has no surface here. OWASP offers a four-way contrast to
remember the failure modes: poisoning leaves the system wrong,
inversion makes it leak, jamming leaves it silent, and weak access
control makes retrieval indiscriminate. The seven named risks are cross-tenant leakage through shared
similarity search; embedding inversion (embeddings-only storage is not
a safe harbor); retrieval-time poisoning; retrieval jamming with
blocker documents; membership inference from similarity scores;
semantic-cache and dedup poisoning; and multimodal embedding poisoning.
Adjacent items live elsewhere: injection delivered via retrieved content
is covered by `LLM01:2026`, deserialization bugs in vector-store
libraries by `LLM04:2026`, and a tampered or backdoored embedding model
by `LLM05:2026`. Attacks on agent memory that never touch embedding
geometry belong to `ASI06`.

**Detection signals**
- Single vector index shared across tenants with filter-only isolation;
  an access-control decision made after the similarity search is itself
  the leak.
- Chunk metadata missing `owner` / `acl` field.
- Upsert endpoint exposed without authentication.
- No integrity check on embeddings loaded from disk.
- Raw similarity scores or distances returned to clients (a membership
  oracle).
- Vector database backups or exports not handled at the sensitivity of
  the source documents.
- Mixed-trust content (web scrapes, internal documents, partner data)
  in one index.
- Embedding-model rotation without re-embedding the corpus.
- Embedding-API keys not protected as secrets.
- No provenance or trust-tier metadata per embedding.
- No ingest-time normalization of zero-width characters, white-on-white
  text, or homoglyphs.
- Semantic-cache or dedup similarity thresholds never examined.

**Mitigations**
- Scope tenants inside the index query and validate the scope on the
  server; scope that the client supplies is only a hint, never a
  control.
- Apply chunk-level ACLs, since a mostly-public document can hold one
  confidential paragraph.
- Per-tenant namespaces or collections rather than a shared index, and
  hard isolation by trust tier for mixed-trust content.
- Filter retrieved chunks through the user's authorization context
  inside the query, before anything reaches the prompt.
- Record provenance (source, ingestion time, trust tier, pipeline
  version) for every embedding so a bad batch can be invalidated.
- Clients receive generated answers only, never raw similarity scores or
  distances, and query volume on endpoints usable for membership probing
  is throttled.
- Treat vector backups and embeddings as equivalent to the source
  documents for breach assessment, and delete embeddings when the source
  is deleted.

---

## LLM10:2026 — Improper Output Handling

Source: <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM10_ImproperOutputHandling.md>

Downstream systems treat model output as trusted, so anything an
attacker can steer into that output reaches a sink as if a user had
typed it. Classic consequences are XSS, CSRF, SSRF, SQL injection, and
remote code execution. The 2026 text adds three sink classes: terminals,
log viewers, and IDE panes that interpret control sequences (ANSI
escapes, OSC 52 clipboard writes); client renderers that auto-fetch
resources named in model output (Markdown images, link previews,
iframes), which enables data exfiltration; and insecure generated code
that is deployed without review. Scope boundaries: sanitizing inputs
belongs to `LLM01:2026`, and output that is wrong but safe belongs to
`LLM07:2026`. (Renamed from "Insecure Output Handling" in earlier
editions.)

**Detection signals**
- `exec`, `eval`, `subprocess.run(..., shell=True)` fed directly from
  model output.
- HTML rendered via `innerHTML = llm_output` with no sanitizer.
- SQL constructed by string formatting from a "text-to-SQL" agent.
- Model output used as a filesystem path without normalization.
- Chat UI or IDE that auto-renders Markdown images or link previews
  from model output.
- Control characters (ANSI, BEL, OSC, backspace, carriage return)
  written unneutralized to terminals or logs.
- No Content Security Policy, and no context-specific output encoding
  for HTML, JavaScript, or SQL contexts.
- Model output placed in email templates without escaping.
- Generated code merged or deployed without review or testing.
- No monitoring for unusual model outputs.

**Mitigations**
```python
# Parameterize; never interpolate model output into SQL
cursor.execute("SELECT * FROM orders WHERE id = %s", (parsed_id,))
```
- Treat the model as a zero-trust user: validate its output before it
  reaches backend functions, with a schema (pydantic, JSON Schema).
- Encode output for the context it lands in (HTML, JavaScript, SQL), and
  render it through an HTML sanitizer (DOMPurify, bleach).
- Set a strict Content Security Policy.
- Restrict auto-rendered images and links to an origin allowlist, or
  route them through a server-side proxy that strips query parameters.
- Neutralize control characters before output reaches terminals or
  logs.
- Review generated code before it is deployed.
- Monitor for unusual outputs that may indicate exploitation attempts.
- Never `eval` or `exec` on model output.

---

## Appendix: 2025 → 2026 crosswalk

The table names each 2026 item's predecessor in the superseded 2025
edition by rank and title only. 2025 codes are deliberately never
written as codes here, so none can be copied out of this file. Status
`OWASP-stated` means OWASP's own Preface text or its official
rank-migration figure (Figure 1) names the move; `repo-inferred` means
neither does.

Source (shared, for every row): `2026/final/LLM00_Preface.md` and
`2026/final/report/images/OWASP LLM Top10 2025-2026 Bump Chart.svg` in
the OWASP GenAI-LLM-Top10 repository at commit
`9253e38ade58e959b531c0c5c9a4842272c9cd0e`. Retrieved 2026-10-04.

| 2026 Code | 2026 Title | 2025 Predecessor | Move | Status | Note |
|---|---|---|---|---|---|
| LLM01:2026 | Prompt Injection | 2025 #1: Prompt Injection | unchanged | OWASP-stated | Preface text + Figure 1. |
| LLM02:2026 | Sensitive Information Disclosure | 2025 #2: Sensitive Information Disclosure | unchanged | OWASP-stated | Preface text + Figure 1. |
| LLM03:2026 | Excessive Agency | 2025 #6: Excessive Agency | up 3 | OWASP-stated | Preface text + Figure 1. |
| LLM04:2026 | Supply Chain | 2025 #3: Supply Chain | down 1 | OWASP-stated | Figure 1 only; both published lists place the topic under the same title. |
| LLM05:2026 | Data and Model Poisoning | 2025 #4: Data and Model Poisoning | down 1 | OWASP-stated | Figure 1 only; both published lists place the topic under the same title. |
| LLM06:2026 | Unbounded Consumption | 2025 #10: Unbounded Consumption | up 4 | OWASP-stated | Preface text + Figure 1. |
| LLM07:2026 | Misinformation | 2025 #9: Misinformation | up 2 | OWASP-stated | Figure 1 only; both published lists place the topic under the same title. |
| LLM08:2026 | Hidden Context Exposure | 2025 #7: System Prompt Leakage | down 1, renamed | OWASP-stated | Preface text + Figure 1, renamed and re-scoped; the figure marks the evolution with a dashed red line. |
| LLM09:2026 | Vector and Embedding Weaknesses | 2025 #8: Vector and Embedding Weaknesses | down 1 | OWASP-stated | Figure 1 only; both published lists place the topic under the same title. |
| LLM10:2026 | Improper Output Handling | 2025 #5: Improper Output Handling | down 5 | OWASP-stated | Preface text + Figure 1. |
