# RPKIScout Architecture

## Overview

RPKIScout is a BGP routing security intelligence agent deployed entirely on
Cloudflare's edge. There is no origin server. Every component — the React
frontend, the AI agent, the audit pipeline, and the prefix analysis engine —
runs within Cloudflare's network, within 50ms of 95% of the Internet-connected
population.

```
Browser
  │  WebSocket (hibernated between messages)
  ▼
Durable Object: RPKIScoutAgent      ← session state + AI orchestration
  │
  ├── Cloudflare Radar API          ← BGP/RPKI live data
  ├── Workers AI (Llama 3.3 70B)   ← LLM inference, on-network
  ├── Workflow: ASNAuditWorkflow    ← durable 6-step audit pipeline
  └── Service Binding: prefix-trie ← Rust/Wasm prefix trie Worker
```

---

## Decision: Durable Objects for session state (not KV, not D1)

**What we need:** Each user session is a stateful WebSocket connection.
Messages arrive sequentially. The AI agent must read and write its conversation
history on every message. Audit reports must be persisted and visible to
subsequent messages in the same session.

**Why not KV:**
Cloudflare KV is eventually consistent with up to 60 seconds of propagation
lag. A message sent at T=0 might read state written at T=-61s. More critically,
KV has no atomicity — two concurrent writes from parallel WebSocket frames race.
KV is designed for globally-read, infrequently-written data (think: feature
flags, static config). Session state is none of those things.

**Why not D1:**
D1 is an excellent fit for shared relational data with global reads. If we
built a public leaderboard of audited ASNs, D1 would be correct. But per-session
state doesn't need to be globally readable — it only needs to be consistent
within a session.

**Why Durable Objects:**
A Durable Object is a single-threaded execution context with co-located SQLite.
Every operation is sequentially consistent by construction — there is no
concurrent access to a single DO instance. The WebSocket connection lives inside
the DO, so there is no network hop between the message handler and the state
read. With the `new_sqlite_classes` migration, chat history and audit reports
share the same transactional SQLite instance — no partial writes are ever
visible to the UI. Additionally, DO hibernation means we pay CPU only while
a message is being processed, not while the user reads the response.

---

## Decision: Cloudflare Workflows for the ASN audit (not a long-running fetch)

**What we need:** An ASN audit requires 6 sequential API calls to Cloudflare
Radar plus one LLM inference call. Measured wall time is 15-30 seconds.

**Why not a long-running fetch:**
A Cloudflare Worker has a CPU time limit (50ms on the free plan, up to 30s
on paid plans with `waitUntil`). More importantly, a long-running fetch holds
the HTTP connection open — if the client disconnects, the work is lost. Network
jitter on a 30-second connection is not negligible.

**Why Workflows:**
A Workflow is a durable execution engine with checkpointing at every `step.do()`
boundary. If the RPKI prefix fetch fails with a 429 rate limit, the Workflow
retries only that step after a 2-second exponential backoff — the previous 4
steps' results are preserved. The calling Durable Object polls the Workflow
status via its `instance.status()` method without holding any connection open.
The UI shows an animated progress indicator during the poll loop.

The tradeoff: Workflows add cold-start overhead (~200ms) and the poll loop
introduces up to 2s of additional latency vs a direct call. For a 15-30s
operation, this is immaterial.

---

## Decision: Workers AI (not OpenAI / Anthropic)

**Model used:** `@cf/meta/llama-3.3-70b-instruct-fp8-fast`

**Why Workers AI:**
1. **Zero data egress.** The LLM call runs on Cloudflare's GPU infrastructure.
   No BGP routing data, ASN metadata, or user queries leave Cloudflare's
   network. For a security tool processing potentially sensitive network
   topology data, this matters.
2. **No secret rotation surface.** The `AI` binding is platform-managed.
   There is no API key in `.dev.vars` or a secrets manager. One fewer thing
   to rotate, one fewer breach vector.

**The tradeoff:**
Llama 3.3 70B FP8 produces lower-quality structured output than GPT-4o or
Claude Sonnet. We mitigate this with:
- Explicit JSON schema in the prompt (`workflow.ts`, system prompt)
- Post-parse validation against a `Set` of valid values (`VALID_RISK_LEVELS`)
- A heuristic fallback that derives risk level from raw numbers if the LLM
  output fails to parse (`deriveRiskLevel` function)

See `src/workflow.ts`, lines 108-135 for the full validation chain.

---

## Decision: Rust + Service Binding for prefix trie (not TypeScript)

**What we need:** Given a list of CIDR prefixes with their origin ASNs and
RPKI status, detect:
- More-specific prefixes that could be used as BGP hijack vectors
- Redundant sub-prefixes that can be aggregated
- Longest-prefix-match for a given IP address

**Why not TypeScript:**
These operations are CPU-bound and memory-layout-sensitive. TypeScript running
in V8 allocates JavaScript objects for each trie node — the V8 GC introduces
unpredictable pause times when walking a trie of 500+ nodes. For each
prefix-pair containment check, a naive TypeScript implementation requires
O(n²) string comparisons. Additionally, demonstrating that you know when to
reach for a systems language is itself the point.

**Why Rust:**
A binary trie over IPv4 address space in Rust allocates `Box<TrieNode>` on
the heap with precise layout. Each node is ~40 bytes. For 500 prefixes with
average depth 24, the trie uses ~480 KB. Every operation — insert, LPM,
containment check — is O(32) = O(1) with respect to the number of prefixes.
No GC pauses. Deterministic latency.

**Why a Service Binding (not Wasm in the main Worker):**
The Service Binding model lets the trie Worker version and deploy independently.
A bug fix to the aggregation algorithm does not require redeploying the entire
agent with its Durable Object migrations. The call overhead is <0.5ms because
Service Bindings execute within the same Cloudflare PoP — no inter-datacenter
network hop. The Rust Worker is stateless per-request; it builds the trie,
queries it, and returns. No persistent state is needed.

---

## Data flow: a single user message

```
1. User types "audit AS13335" → WebSocket frame → DO wakes from hibernation
2. DO passes message to RPKIScoutAgent.onChatMessage()
3. Workers AI (non-streaming) decides to call the `runAudit` tool
4. DO creates an ASNAuditWorkflow instance via AUDIT_WORKFLOW.create()
5. Workflow executes 6 steps, each checkpointed:
   a. getASNInfo()         → Radar /entities/asns/13335
   b. getBGPHijackEvents() → Radar /bgp/hijacks/events?involvedAsn=13335
   c. getBGPLeakEvents()   → Radar /bgp/leaks/events?involvedAsn=13335
   d. getASNPrefixes()     → Radar /bgp/routes/pfx2as?origin=13335
   e. getTrafficAnomalies()→ Radar /traffic_anomalies?asn=13335
   f. AI.run(Llama 3.3)   → generates risk level + summary + recommendations
6. DO polls Workflow every 2s until status = "complete"
7. Workers AI (streaming) generates a natural-language explanation of results
8. DO streams explanation back to client via AI SDK data stream protocol
9. If user follows up with "check for hijack vectors", the agent calls
   analyseHijackRisk, which calls PREFIX_TRIE.fetch() (Service Binding → Rust Worker)
10. Rust Worker builds trie, detects more-specifics, returns JSON
11. DO persists audit report to SQLite (atomic write, same DO instance)
```

---

## Extension paths

**IPv6 support in the prefix trie:**
Change `u32` → `u128`, `32` → `128`. Update `parse_ipv4` → `parse_ip` to
handle both `A.B.C.D` and `A:B:C:D:E:F:G:H` syntax. The algorithm is identical.

**Alerting on new hijack events:**
The `AgentState.watchedASNs` array in the DO is already persisted to SQLite.
A Workflow with a `step.sleep("1 hour")` between iterations could poll Radar
for new hijack events on watched ASNs and send alerts via Email Workers or
a webhook. The Durable Object's `alarm()` handler is the right trigger.

**Public ASN risk leaderboard:**
Write audit results to D1 (globally readable) in addition to the DO's SQLite
(session-local). A separate read-only Worker serves the leaderboard. This is
the one use case where D1 would be correct and Durable Objects would not.
