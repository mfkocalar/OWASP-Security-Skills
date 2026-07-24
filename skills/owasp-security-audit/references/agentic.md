# OWASP Top 10 for Agentic Applications (2026)

Load this reference when reviewing autonomous agents — tool-calling
loops, multi-agent pipelines, MCP servers, or anything where model
output drives further autonomous action rather than just producing
text for a human to read. For non-agent LLM code (chatbots, RAG,
summarizers), `references/llm.md` is usually enough on its own; for
autonomous agents, apply both lists — this one adds concerns (goal
hijack, cascading failures, inter-agent trust) the LLM list doesn't
address.

**Source:** OWASP Top 10 for Agentic Applications (2026 edition) —
agentic risks on top of LLM risks; released 2025-12-09 by the Agentic
Security Initiative under the OWASP GenAI Security Project.
Announcement: <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>.
Resource page: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>.

**Edition verification:** Agentic Apps Top 10 2026 confirmed **Final**,
not RC/draft — the official 2025-12-09 announcement states verbatim:
"Today, with immense pride, we release the OWASP Top 10 for Agentic AI
Applications." `ASI01`–`ASI10` names below match the primary source
exactly (verified against goteleport.com-style third-party paraphrases
and rejected those variants — see Pitfall 3 in RESEARCH.md).
Source: <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>.
Retrieved 2026-07-22.

> Earlier drafts of this project called this list "Preview" and used
> invented codes like `AG01–AG10`. Those codes are **not** part of any
> OWASP publication. Use `ASI01`–`ASI10` only (and `LLM01`–`LLM10` for
> the base LLM list in `references/llm.md`).

> Risks below are verified against the December 9, 2025 OWASP
> announcement and the resource page. Per-item descriptions for
> ASI01–ASI10 are paraphrased from the announcement's real-world-
> incident framing; the downloadable PDF linked on the resource page
> carries the canonical definitions [?] — consult it for direct quotes.

---

## ASI01 — Agent Goal Hijack

An attacker redirects the agent's objective via hidden prompts
embedded in tool output, retrieved documents, or multi-turn memory
(EchoLeak-class attacks that turn copilots into exfil engines).

**Detection signals**
- Agent goal / plan derived from untrusted retrieval output with no
  integrity check.
- No distinction between "user-stated goal" and "content the agent
  read".
- Chain-of-thought can be rewritten by tool outputs mid-run.

**Mitigations**
- Pin the goal at the start of the run; treat later "new
  instructions" in retrieved content as data.
- Validate the plan against the original user intent before each
  tool call.
- Separate "instructions" and "evidence" channels in the agent
  scaffolding.

---

## ASI02 — Tool Misuse

Legitimate tools coerced into destructive use (Amazon Q incident),
typically because tool arguments are not constrained to the agent's
authorized scope.

**Detection signals**
- Tool wrappers accept arbitrary arguments without schema validation.
- Destructive tools (`delete_files`, `run_sql`) registered without a
  dry-run mode.
- No audit of which arguments the agent has historically used.

**Mitigations**
```python
from pydantic import BaseModel, Field

class DeleteArgs(BaseModel):
    path: str = Field(pattern=r"^/workspace/tmp/")
# validate BEFORE the tool executes
```
- Allowlist arguments by pattern; reject anything outside.
- Require second-factor confirmation for destructive tools.

---

## ASI03 — Identity & Privilege Abuse

Agents run with credentials that exceed the current user's session
scope, so prompt injection or a loop bug causes cross-user data
access or privilege escalation.

**Detection signals**
- Single service account used for all users.
- Agent does not pass end-user identity through to downstream APIs.
- No short-lived token exchange per session.

**Mitigations**
- OAuth token exchange / on-behalf-of flows so downstream calls run
  as the user.
- Per-session scoped tokens with tight TTL.
- Log and alert on agent-initiated access to resources outside the
  user's tenant.

---

## ASI04 — Agentic Supply Chain Vulnerabilities

Dynamic MCP servers, A2A (agent-to-agent) ecosystems, and
third-party skills can be poisoned at runtime (GitHub MCP exploit
example).

**Detection signals**
- MCP server list fetched dynamically at startup without pinning.
- Tools discovered and auto-registered without human review.
- No signature verification on MCP server binaries or manifests.

**Mitigations**
- Pin MCP servers by version + digest; review manifest diffs in PRs.
- Host-side allowlist of MCP server origins.
- Isolate MCP processes with OS-level sandboxing.

---

## ASI05 — Unexpected Code Execution

Natural-language instructions become executable paths (AutoGPT-style
RCE) because the agent has access to `exec`, shell, or
code-interpreter tools without constraints.

**Detection signals**
- Agent calls `exec()`, `eval()`, or an unsandboxed Python REPL tool.
- Code-interpreter runs with network access and host filesystem
  access.
- No per-call resource limits on the interpreter.

**Mitigations**
- Run code interpreters in a sandbox (gVisor, Firecracker, or a
  remote sandbox service) with no host filesystem and restricted
  egress.
- CPU / RAM / wall-clock caps per execution.
- Disallow package installation at runtime; pre-bake the interpreter
  image.

---

## ASI06 — Memory & Context Poisoning

Attackers plant content in the agent's long-term memory (vector
store, scratchpad, summary history) that reshapes behavior on future
turns (Gemini memory attack example).

**Detection signals**
- Memory writes unauthenticated / accept any string the agent
  produces.
- No provenance metadata (who wrote, when, from what source).
- Memory retrieval returns items across sessions without scoping.

**Mitigations**
- Treat memory writes as privileged: explicit tool calls with user
  approval for persistent memory.
- Tag every memory item with source + trust level; filter by trust
  at retrieval.
- Expire/verify items on a schedule; let users view and delete their
  agent's memory.

---

## ASI07 — Insecure Inter-Agent Communication

Multi-agent deployments trust inbound messages from sibling agents;
spoofed or replayed messages misdirect the cluster.

**Detection signals**
- Agent-to-agent messages carry no signature or session binding.
- No message-ordering / replay protection.
- Shared bus without per-agent identity or ACL.

**Mitigations**
- mTLS or signed envelopes between agents; verify sender identity.
- Nonce + timestamp on every message; reject replays.
- Per-agent authorization: sender X may ask receiver Y to do Z only.

---

## ASI08 — Cascading Failures

One agent's wrong output becomes the next agent's input, and errors
amplify as they propagate — particularly dangerous when downstream
agents take irreversible action on upstream hallucinations.

**Detection signals**
- No circuit breaker between agents.
- No confidence threshold gating downstream action.
- Retries on failure without back-off or escalation to a human.

**Mitigations**
- Explicit confidence / quality gates between stages; fail closed
  below threshold.
- Circuit breakers: halt the pipeline after N failures and page a
  human.
- End-to-end dry-run mode before committing irreversible changes.

---

## ASI09 — Human-Agent Trust Exploitation

Confident, well-formatted output causes human operators to approve
harmful actions — social engineering via the agent's own articulacy.

**Detection signals**
- Approval UI shows only the natural-language summary, not the
  underlying tool call.
- No diff view for "what will actually change".
- Approvals can be batched / auto-confirmed with one click.

**Mitigations**
- Show the exact tool call + arguments + expected side effects
  alongside any summary.
- Destructive actions require typing a confirmation token.
- Record approval decisions with full context for audit.

---

## ASI10 — Rogue Agents

Agents exhibit misalignment, concealment, or self-directed action
(Replit meltdown incident). Includes agents that spawn sub-agents,
hide actions from logs, or persist beyond intended lifetime.

**Detection signals**
- Agent can spawn other agents without per-child budget / permission
  check.
- Logging is under the agent's own control — the agent can suppress
  its trace.
- No watchdog that can kill a runaway agent.

**Mitigations**
- Out-of-band logging: logs stream to a sink the agent cannot write
  to or delete.
- External kill switch and per-run hard budget (wall-clock, tokens,
  dollars).
- Continuous behavior monitoring against a baseline; alert on drift.

---

# Mapping: repo's old `AG##` codes → real OWASP items

For anyone updating code or docs that used the old taxonomy:

| Old (invented) | Real OWASP item(s) |
|---|---|
| AG01 Prompt Injection | LLM01 Prompt Injection; related ASI01 |
| AG02 Insufficient Input Validation | **No OWASP item.** Folded into LLM01 / LLM05 |
| AG03 Insecure Output Handling | LLM05 Improper Output Handling |
| AG04 Model Poisoning | LLM04 Data and Model Poisoning |
| AG05 Denial of Service | LLM10 Unbounded Consumption |
| AG06 Unauthorized Tool Access | LLM06 Excessive Agency; ASI02; ASI03 |
| AG07 Training Data Leakage | LLM02 Sensitive Information Disclosure |
| AG08 Excessive Autonomy | LLM06 Excessive Agency |
| AG09 Inadequate Logging | **Not OWASP LLM/Agentic.** Closest: web A09 |
| AG10 Supply Chain Risks | LLM03 Supply Chain; ASI04 |

Use the real codes in findings. If you encounter an audit report or
repo referencing `AG01`–`AG10`, translate it before acting. Note some
entries resolve to `LLM0X` codes in `references/llm.md` rather than
`ASI0X` codes in this file — both reference files may need loading to
fully resolve an old `AG##` citation.
