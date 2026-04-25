# RPKIScout

**BGP routing security intelligence agent — deployed entirely on Cloudflare's edge.**

Live demo: [cf-ai-rpkiscout.ruchitsingh13.workers.dev](https://cf-ai-rpkiscout.ruchitsingh13.workers.dev)

---

## What it does

RPKIScout is a conversational AI agent that analyses BGP routing security in real time. Ask it about any ASN or IP prefix and it will pull live data from Cloudflare Radar, run structural analysis, and explain what it finds.

**Capabilities:**
- Full BGP/RPKI security audit for any ASN (RPKI coverage, hijack events, route leaks, traffic anomalies)
- Real-time BGP hijack and route leak event feeds
- RPKI validation status for any IP prefix
- **Prefix hijack vector detection** — binary trie analysis that identifies more-specific prefixes announced by rogue ASes, the most common form of BGP hijacking
- Longest-prefix-match lookup and prefix aggregation

---

## Architecture

No origin server. Every component runs on Cloudflare's edge.

```
Browser
  │  WebSocket
  ▼
Durable Object: RPKIScoutAgent     ← session state + AI orchestration
  │
  ├── Cloudflare Radar API         ← live BGP/RPKI data
  ├── Workers AI (Llama 3.3 70B)  ← LLM inference, on-network
  ├── Workflow: ASNAuditWorkflow   ← durable 6-step audit pipeline
  └── Service Binding: prefix-trie ← Rust/Wasm binary trie Worker
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for full decision rationale on every component.

---

## Stack

| Component | Technology | Why |
|---|---|---|
| Frontend | React + Vite, served by Workers Assets | No CDN needed |
| AI agent | Cloudflare Durable Objects + Workers AI | Strong consistency, WebSocket hibernation, zero data egress |
| Audit pipeline | Cloudflare Workflows | Durable checkpointed execution for 15-30s multi-step jobs |
| Prefix trie | Rust → WebAssembly, Cloudflare Worker | Deterministic O(32) trie ops, no GC pauses |
| Data source | Cloudflare Radar API | Live BGP/RPKI data from 330+ cities |

---

## Project structure

```
cf-ai-rpkiscout/
├── prefix-trie/           ← Rust Worker (separate deploy unit)
│   ├── Cargo.toml
│   ├── wrangler.jsonc
│   └── src/lib.rs         ← binary trie: /aggregate, /lpm, /specifics
│
├── src/                   ← TypeScript Worker
│   ├── agent.ts           ← AI agent, tool definitions, WebSocket handler
│   ├── app.tsx            ← React UI, tool result cards
│   ├── workflow.ts        ← ASN audit Workflow (6 Radar API steps + LLM)
│   ├── radar.ts           ← Cloudflare Radar API client
│   └── index.ts           ← Worker entry point
│
├── wrangler.jsonc         ← bindings: AI, DO, Workflows, Service Binding
└── ARCHITECTURE.md        ← architecture decision record
```

---

## The prefix trie

The `prefix-trie` Worker is a binary trie over IPv4 address space compiled to WebAssembly. It exposes three endpoints called via Service Binding from the TypeScript agent:

- `POST /specifics` — detects more-specific hijack vectors across a set of prefixes, scoring each as CRITICAL / HIGH / MEDIUM / LOW based on origin AS and RPKI status
- `POST /lpm` — longest-prefix-match for a given IP (identical to a router FIB lookup)
- `POST /aggregate` — collapses redundant sub-prefixes and returns the reduction percentage

Every operation is O(32) regardless of how many prefixes are in the set. For an ASN with 500 prefixes, this is thousands of times faster than a flat array scan.

---

## Local development

```bash
# Install dependencies
npm install

# Rust toolchain (one-time)
rustup target add wasm32-unknown-unknown
cargo install worker-build

# Terminal 1 — Rust Worker
cd prefix-trie && npx wrangler dev

# Terminal 2 — TypeScript Worker
npm run dev
```

---

## Deploy

```bash
# Deploy Rust Worker first (TypeScript service binding requires it to exist)
cd prefix-trie && npx wrangler deploy

# Deploy TypeScript Worker
cd .. && npm run deploy
```

---

## Environment variables

Set in Cloudflare dashboard or `.dev.vars` for local dev:

| Variable | Description |
|---|---|
| `RADAR_API_TOKEN` | Cloudflare Radar API token |

---

## Built with

- [Cloudflare Workers](https://workers.cloudflare.com)
- [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects)
- [Cloudflare Workflows](https://developers.cloudflare.com/workflows)
- [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai)
- [workers-rs](https://github.com/cloudflare/workers-rs) — Rust SDK for Cloudflare Workers
- [Cloudflare Radar API](https://radar.cloudflare.com)
