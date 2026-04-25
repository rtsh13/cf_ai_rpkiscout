import { AIChatAgent } from "agents/ai-chat-agent";
import { createWorkersAI } from "workers-ai-provider";
import { streamText, tool } from "ai";
import type { StreamTextOnFinishCallback, ToolSet } from "ai";
import { z } from "zod";
import {
  getASNInfo,
  getBGPHijackEvents,
  getBGPLeakEvents,
  getPrefixRPKI,
  getTrafficAnomalies,
  getRealTimeRoutes,
  summariseRPKI,
} from "./radar";
import type { AuditReport } from "./workflow";

interface Env {
  AI: Ai;
  RADAR_API_TOKEN: string;
  AUDIT_WORKFLOW: Workflow;
}

interface AgentState {
  watchedASNs: number[];
  [key: string]: unknown;
}

const SYSTEM_PROMPT = `You are RPKIScout, an AI-powered BGP routing security analyst running on Cloudflare's global edge network.

You have real-time access to Cloudflare Radar — one of the world's largest Internet observability platforms, processing BGP data from 330+ route collectors across 125+ countries, updated every 2 hours.

## When to call tools vs answer directly

**Answer directly (no tools)** for conceptual or educational questions:
- "What is RPKI?" → explain from knowledge, no tool call needed
- "What is a BGP hijack?" → explain from knowledge
- "How does route origin validation work?" → explain from knowledge

**Call tools only when the user asks for live data** about a specific network entity:
- ASN number mentioned → lookupASN
- IP prefix in CIDR notation mentioned → checkRPKI
- "Recent hijacks/leaks?" → getHijacks / getLeaks
- "Is X down / any anomalies?" → getAnomalies
- "Audit AS X" / "Security check for AS X" → runAudit (takes 15-30s)
- "What routes does prefix X have?" → getRealTimeRoutes

**Never call tools speculatively** to illustrate a concept. If the user asks "what is RPKI?", explain it — do not call checkRPKI on a random prefix to demonstrate.

## Response style

- Lead every response with one plain-language sentence a CISO can understand
- Follow with technical depth for operators
- Use **bold** for critical findings (RPKI_INVALID, active hijacks, CRITICAL risk)
- Use bullet lists for recommendations; number them if prioritized
- All numbers must come from tool results — never fabricate statistics
- When you call multiple tools, synthesize the findings instead of listing them separately

## Risk thresholds

| Signal | Risk level |
|--------|-----------|
| RPKI coverage < 50% + any incident | CRITICAL |
| Any RPKI_INVALID prefix | HIGH |
| RPKI coverage < 50% | HIGH |
| Hijack or leak events (7d) | MEDIUM |
| Coverage 50-79%, no incidents | MEDIUM |
| Coverage ≥ 80%, no incidents | LOW |

## Watched ASNs

When you complete an audit, the ASN is automatically added to the session's watched list. If the user asks "what have I looked at?" or similar, retrieve the state to list them.`;

export class RPKIScoutAgent extends AIChatAgent<Env> {
  async onChatMessage(
    onFinish: StreamTextOnFinishCallback<ToolSet>,
    options?: { abortSignal?: AbortSignal }
  ) {
    const workersai = createWorkersAI({ binding: this.env.AI });

    const result = streamText({
      model: workersai("@cf/meta/llama-3.3-70b-instruct-fp8-fast"),
      system: SYSTEM_PROMPT,
      messages: this.messages,
      // workers-ai-provider@0.2.0 can hang on multi-step continuations after
      // a tool result. maxSteps:1 means one LLM call: it can generate text AND
      // call tools in that call, but no second LLM call after tool results.
      // The structured cards (audit, RPKI, hijacks…) are the full response.
      maxSteps: 1,
      abortSignal: options?.abortSignal,
      tools: {
        // ── Look up ASN metadata ────────────────────────────────────────────
        lookupASN: tool({
          description:
            "Look up metadata for an Autonomous System Number: name, country, organisation, and peer relationships. Use when the user mentions an ASN number or network operator name.",
          parameters: z.object({
            asn: z.number().int().positive().describe("The ASN number, e.g. 13335 for Cloudflare"),
          }),
          execute: async ({ asn }) => {
            try {
              const data = await getASNInfo(asn, this.env.RADAR_API_TOKEN);
              return { success: true, data };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── Check RPKI validation for a prefix ─────────────────────────────
        checkRPKI: tool({
          description:
            "Check the RPKI validation status (VALID / INVALID / UNKNOWN) of an IP prefix and its origin ASN mapping.",
          parameters: z.object({
            prefix: z
              .string()
              .describe("IP prefix in CIDR notation, e.g. 1.1.1.0/24"),
          }),
          execute: async ({ prefix }) => {
            try {
              const data = await getPrefixRPKI(prefix, this.env.RADAR_API_TOKEN);
              const summary = summariseRPKI(data);
              return { success: true, data, summary };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── BGP hijack events ───────────────────────────────────────────────
        getHijacks: tool({
          description:
            "Retrieve recent BGP hijack events from Cloudflare Radar (last 7 days). Optionally filter by a specific ASN to see events involving that network.",
          parameters: z.object({
            asn: z
              .number()
              .int()
              .positive()
              .optional()
              .describe("Filter hijacks involving this ASN"),
            limit: z.number().int().min(1).max(25).default(10),
          }),
          execute: async ({ asn, limit }) => {
            try {
              const data = await getBGPHijackEvents(this.env.RADAR_API_TOKEN, { asn, limit });
              return { success: true, data };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── BGP route leak events ───────────────────────────────────────────
        getLeaks: tool({
          description:
            "Retrieve recent BGP route leak events from Cloudflare Radar (last 7 days). Optionally filter by a specific ASN.",
          parameters: z.object({
            asn: z
              .number()
              .int()
              .positive()
              .optional()
              .describe("Filter leaks involving this ASN"),
            limit: z.number().int().min(1).max(25).default(10),
          }),
          execute: async ({ asn, limit }) => {
            try {
              const data = await getBGPLeakEvents(this.env.RADAR_API_TOKEN, { asn, limit });
              return { success: true, data };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── Traffic anomalies ───────────────────────────────────────────────
        getAnomalies: tool({
          description:
            "Retrieve internet traffic anomalies and outage signals detected by Cloudflare Radar. Optionally filter by ASN.",
          parameters: z.object({
            asn: z
              .number()
              .int()
              .positive()
              .optional()
              .describe("Filter anomalies for this ASN"),
            limit: z.number().int().min(1).max(20).default(10),
          }),
          execute: async ({ asn, limit }) => {
            try {
              const data = await getTrafficAnomalies(this.env.RADAR_API_TOKEN, { asn, limit });
              return { success: true, data };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── Real-time BGP routes for a prefix ──────────────────────────────
        getRealTimeRoutes: tool({
          description:
            "Get real-time BGP routes for a specific IP prefix from public route collectors (RouteViews and RIPE RIS). Use for AS path analysis.",
          parameters: z.object({
            prefix: z.string().describe("IP prefix in CIDR notation, e.g. 8.8.8.0/24"),
          }),
          execute: async ({ prefix }) => {
            try {
              const data = await getRealTimeRoutes(prefix, this.env.RADAR_API_TOKEN);
              return { success: true, data };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),

        // ── Full durable audit via Workflow ─────────────────────────────────
        runAudit: tool({
          description:
            "Run a comprehensive multi-step BGP/RPKI security audit for an ASN using a durable Cloudflare Workflow. Fetches ASN info, hijacks, leaks, RPKI coverage, and anomalies, then generates an AI risk report. Takes 15-30 seconds. Use for any 'audit', 'security check', or 'how secure is' request.",
          parameters: z.object({
            asn: z.number().int().positive().describe("The ASN number to audit"),
          }),
          execute: async ({ asn }) => {
            try {
              const instanceId = `audit-${asn}-${Date.now()}`;
              const instance = await this.env.AUDIT_WORKFLOW.create({
                id: instanceId,
                params: { asn },
              });

              // Poll for completion — Workflows are durable, survive disconnects
              for (let attempt = 0; attempt < 30; attempt++) {
                await new Promise<void>((r) => setTimeout(r, 2000));
                const status = await instance.status();

                if (status.status === "complete") {
                  const report = status.output as AuditReport;

                  // Persist to agent state so future turns can reference audited ASNs
                  const state = (this.state ?? {}) as AgentState;
                  const watched = Array.isArray(state.watchedASNs) ? state.watchedASNs : [];
                  if (!watched.includes(asn)) {
                    await this.setState({
                      ...state,
                      watchedASNs: [...watched, asn],
                      [`audit_${asn}`]: report,
                    } as AgentState);
                  }

                  return { success: true, report };
                }

                if (status.status === "errored") {
                  return {
                    success: false,
                    error: "Audit workflow encountered an error.",
                    details: String(status),
                  };
                }
              }

              return {
                success: false,
                error:
                  "Audit is taking longer than expected. The workflow is still running — check back shortly.",
              };
            } catch (e) {
              return { success: false, error: String(e) };
            }
          },
        }),
      },
      // Pass the callback directly — it's StreamTextOnFinishCallback and the
      // base class uses response.messages to persist the conversation to SQLite.
      onFinish,
    });

    return result.toDataStreamResponse();
  }
}
