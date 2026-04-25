import { AIChatAgent } from "agents/ai-chat-agent";
import type { StreamTextOnFinishCallback, ToolSet } from "ai";
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

// ── Types ────────────────────────────────────────────────────────────────────

interface Env {
  AI: Ai;
  RADAR_API_TOKEN: string;
  AUDIT_WORKFLOW: Workflow;
  // Service binding to the Rust prefix-trie Worker.
  // Type is `Fetcher` — the workers-types interface for service bindings.
  // Exposes a .fetch(request) method that calls the Rust Worker in-PoP.
  PREFIX_TRIE: Fetcher;
}

interface AgentState {
  watchedASNs: number[];
  [key: string]: unknown;
}

interface ToolDef {
  description: string;
  params: Record<string, { type: string; description: string; required?: boolean }>;
  execute: (args: Record<string, unknown>, env: Env) => Promise<unknown>;
}

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast" as BaseAiTextGenerationModels;

// ── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS: Record<string, ToolDef> = {
  lookupASN: {
    description: "Look up ASN metadata (name, country, org).",
    params: { asn: { type: "number", description: "ASN number e.g. 13335", required: true } },
    execute: async (args, env) => {
      const data = await getASNInfo(args.asn as number, env.RADAR_API_TOKEN);
      return { success: true, data };
    },
  },
  checkRPKI: {
    description: "Check RPKI validation for an IP prefix.",
    params: { prefix: { type: "string", description: "CIDR prefix e.g. 1.1.1.0/24", required: true } },
    execute: async (args, env) => {
      const data = await getPrefixRPKI(args.prefix as string, env.RADAR_API_TOKEN);
      const summary = summariseRPKI(data);
      return { success: true, data, summary };
    },
  },
  getHijacks: {
    description: "Get recent BGP hijack events (last 7 days).",
    params: {
      asn: { type: "number", description: "Filter by ASN" },
      limit: { type: "number", description: "Max results (default 10)" },
    },
    execute: async (args, env) => {
      const data = await getBGPHijackEvents(env.RADAR_API_TOKEN, {
        asn: args.asn as number | undefined,
        limit: (args.limit as number) ?? 10,
      });
      return { success: true, data };
    },
  },
  getLeaks: {
    description: "Get recent BGP route leak events (last 7 days).",
    params: {
      asn: { type: "number", description: "Filter by ASN" },
      limit: { type: "number", description: "Max results (default 10)" },
    },
    execute: async (args, env) => {
      const data = await getBGPLeakEvents(env.RADAR_API_TOKEN, {
        asn: args.asn as number | undefined,
        limit: (args.limit as number) ?? 10,
      });
      return { success: true, data };
    },
  },
  getAnomalies: {
    description: "Get traffic anomalies detected by Cloudflare Radar.",
    params: {
      asn: { type: "number", description: "Filter by ASN" },
      limit: { type: "number", description: "Max results (default 10)" },
    },
    execute: async (args, env) => {
      const data = await getTrafficAnomalies(env.RADAR_API_TOKEN, {
        asn: args.asn as number | undefined,
        limit: (args.limit as number) ?? 10,
      });
      return { success: true, data };
    },
  },
  getRealTimeRoutes: {
    description: "Get real-time BGP routes for a prefix.",
    params: { prefix: { type: "string", description: "CIDR prefix", required: true } },
    execute: async (args, env) => {
      const data = await getRealTimeRoutes(args.prefix as string, env.RADAR_API_TOKEN);
      return { success: true, data };
    },
  },
  runAudit: {
    description: "Run a comprehensive BGP/RPKI security audit for an ASN (15-30s).",
    params: { asn: { type: "number", description: "ASN to audit", required: true } },
    execute: async (args, env) => {
      const asn = args.asn as number;
      const instanceId = `audit-${asn}-${Date.now()}`;
      const instance = await env.AUDIT_WORKFLOW.create({ id: instanceId, params: { asn } });
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise<void>((r) => setTimeout(r, 2000));
        const status = await instance.status();
        if (status.status === "complete") return { success: true, report: status.output as AuditReport };
        if (status.status === "errored") return { success: false, error: "Audit workflow errored." };
      }
      return { success: false, error: "Audit timed out — workflow is still running." };
    },
  },
  analyseHijackRisk: {
    description:
      "Analyse a list of CIDR prefixes for BGP hijack vectors using a binary trie. " +
      "Detects more-specific prefixes announced by different origin ASes — the most " +
      "common form of BGP prefix hijack. Call this after getHijacks or runAudit when " +
      "you have a list of prefixes to check.",
    params: {
      prefixes: {
        type: "array",
        description:
          "Array of prefix objects with fields: prefix (CIDR string), " +
          "origin (ASN number), rpki_validation (VALID | INVALID | UNKNOWN).",
        required: true,
      },
    },
    execute: async (args: Record<string, unknown>, env: Env) => {
      // Call the Rust Worker via Service Binding.
      // The URL host is arbitrary for service bindings — only the path matters.
      const resp = await env.PREFIX_TRIE.fetch(
        new Request("https://internal/specifics", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prefixes: args.prefixes }),
        })
      );
      if (!resp.ok) {
        const text = await resp.text();
        return { success: false, error: `Prefix trie Worker returned ${resp.status}: ${text}` };
      }
      const data = await resp.json();
      return { success: true, data };
    },
  },
};

// ── Workers AI tool format ───────────────────────────────────────────────────

function workersAITools() {
  return Object.entries(TOOLS).map(([name, def]) => ({
    type: "function" as const,
    function: {
      name,
      description: def.description,
      parameters: {
        type: "object",
        properties: Object.fromEntries(
          Object.entries(def.params).map(([k, v]) => [k, { type: v.type, description: v.description }])
        ),
        required: Object.entries(def.params).filter(([, v]) => v.required).map(([k]) => k),
      },
    },
  }));
}

// ── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are RPKIScout, a BGP routing security analyst on Cloudflare's edge.

You have live access to Cloudflare Radar (330+ cities, 125+ countries).

RULES:
- For conceptual questions ("what is RPKI?", "explain BGP"), answer directly — do NOT call tools.
- Only call tools when the user asks for live data about a specific ASN, prefix, or event.
- Lead with a plain-language summary, then technical detail.
- Use **bold** for critical findings. Bullet lists for recommendations.
- All numbers must come from tool results — never fabricate.
- When explaining tool results, be thorough: explain what each metric means, why it matters, and what the operator should do.

Available tools: lookupASN, checkRPKI, getHijacks, getLeaks, getAnomalies, getRealTimeRoutes, runAudit, analyseHijackRisk.
Use analyseHijackRisk when you have prefix data and want to detect specific hijack vectors.`;

// ── AI SDK data stream protocol ──────────────────────────────────────────────

const ds = {
  text: (t: string) => `0:${JSON.stringify(t)}\n`,
  toolCall: (id: string, name: string, args: Record<string, unknown>) =>
    `9:${JSON.stringify({ toolCallId: id, toolName: name, args })}\n`,
  toolResult: (id: string, result: unknown) =>
    `a:${JSON.stringify({ toolCallId: id, result })}\n`,
  stepFinish: (reason: string) =>
    `e:${JSON.stringify({ finishReason: reason, usage: { promptTokens: 0, completionTokens: 0 }, isContinued: false })}\n`,
  messageFinish: (reason: string) =>
    `d:${JSON.stringify({ finishReason: reason, usage: { promptTokens: 0, completionTokens: 0 } })}\n`,
};

// ── Parse tool calls from text (Workers AI sometimes outputs JSON as text) ──

function extractToolCall(text: string): { name: string; arguments: Record<string, unknown> } | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{")) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed.name && TOOLS[parsed.name]) {
      return { name: parsed.name, arguments: parsed.parameters ?? parsed.arguments ?? {} };
    }
  } catch { /* not JSON */ }
  return null;
}

// ── Stream SSE from Workers AI ───────────────────────────────────────────────

async function streamWorkersAIResponse(
  response: ReadableStream,
  send: (chunk: string) => void
): Promise<string> {
  const reader = response.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  let fullText = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += value;
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const data = line.slice(6).trim();
      if (data === "[DONE]") continue;
      try {
        const chunk = JSON.parse(data);
        if (chunk.response) {
          fullText += chunk.response;
          send(ds.text(chunk.response));
        }
      } catch { /* skip */ }
    }
  }

  // Flush remaining buffer — last SSE line may not end with \n
  if (buffer.trim().startsWith("data: ")) {
    const data = buffer.trim().slice(6).trim();
    if (data && data !== "[DONE]") {
      try {
        const chunk = JSON.parse(data);
        if (chunk.response) {
          fullText += chunk.response;
          send(ds.text(chunk.response));
        }
      } catch { /* skip */ }
    }
  }

  return fullText;
}

// ── Agent ─────────────────────────────────────────────────────────────────────

export class RPKIScoutAgent extends AIChatAgent<Env> {
  async onChatMessage(
    onFinish: StreamTextOnFinishCallback<ToolSet>,
    options?: { abortSignal?: AbortSignal }
  ) {
    const encoder = new TextEncoder();
    const agent = this;
    const env = this.env;
    let fullResponseText = "";

    const aiMessages = [
      { role: "system" as const, content: SYSTEM_PROMPT },
      ...this.messages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: typeof m.content === "string" ? m.content : JSON.stringify(m.content),
      })),
    ];

    const stream = new ReadableStream({
      async start(controller) {
        const send = (chunk: string) => controller.enqueue(encoder.encode(chunk));

        try {
          // ── Step 1: Call Workers AI (non-streaming) to get tool decisions ──
          const response = (await env.AI.run(MODEL, {
            messages: aiMessages,
            tools: workersAITools(),
            max_tokens: 2048,
          })) as {
            response?: string;
            tool_calls?: Array<{ name: string; arguments: Record<string, unknown> }>;
          };

          const text = response.response ?? "";
          const structuredToolCalls = response.tool_calls ?? [];

          // Check if text output is actually a tool call in disguise
          const textToolCall = !structuredToolCalls.length ? extractToolCall(text) : null;

          const allToolCalls = structuredToolCalls.length > 0
            ? structuredToolCalls
            : textToolCall
              ? [textToolCall]
              : [];

          if (allToolCalls.length > 0) {
            // ── Step 2: Execute tool calls ─────────────────────────────────
            const toolResults: Array<{ name: string; callId: string; result: unknown }> = [];

            for (const tc of allToolCalls) {
              const toolDef = TOOLS[tc.name];
              if (!toolDef) continue;

              const callId = `call_${tc.name}_${Date.now()}`;
              send(ds.toolCall(callId, tc.name, tc.arguments ?? {}));

              try {
                const result = await toolDef.execute(tc.arguments ?? {}, env);
                toolResults.push({ name: tc.name, callId, result });

                // Persist audit results to state
                if (tc.name === "runAudit" && (result as { success?: boolean })?.success) {
                  const report = (result as { report?: AuditReport }).report;
                  if (report) {
                    const state = (agent.state ?? {}) as AgentState;
                    const watched = Array.isArray(state.watchedASNs) ? state.watchedASNs : [];
                    if (!watched.includes(report.asn)) {
                      await agent.setState({
                        ...state,
                        watchedASNs: [...watched, report.asn],
                        [`audit_${report.asn}`]: report,
                      } as AgentState);
                    }
                  }
                }

                send(ds.toolResult(callId, result));
              } catch (e) {
                const errResult = { success: false, error: String(e) };
                toolResults.push({ name: tc.name, callId, result: errResult });
                send(ds.toolResult(callId, errResult));
              }
            }

            // ── Step 3: Stream a follow-up explanation of the tool results ──
            const resultSummary = toolResults.map((tr) =>
              JSON.stringify(tr.result).slice(0, 2000)
            ).join("\n\n");

            const explainMessages = [
              { role: "system" as const, content: SYSTEM_PROMPT },
              ...aiMessages.slice(1), // skip system (already added)
              {
                role: "assistant" as const,
                content: `I called the ${allToolCalls.map(t => t.name).join(", ")} tool(s) and got results.`,
              },
              {
                role: "user" as const,
                content: `Here are the tool results:\n\n${resultSummary}\n\nNow provide a detailed, insightful analysis of these results. Explain what each key finding means, why it matters for network security, and give specific actionable recommendations. Be thorough — this is for a network operator who needs to understand the implications.`,
              },
            ];

            const explainResponse = (await env.AI.run(MODEL, {
              messages: explainMessages,
              max_tokens: 1500,
              stream: true,
            })) as ReadableStream;

            fullResponseText = await streamWorkersAIResponse(explainResponse, send);

          } else {
            // ── No tool calls — stream the text response directly ───────────
            if (text) {
              // If it's a plain text response, stream it from Workers AI
              const streamResponse = (await env.AI.run(MODEL, {
                messages: aiMessages,
                max_tokens: 2048,
                stream: true,
              })) as ReadableStream;

              fullResponseText = await streamWorkersAIResponse(streamResponse, send);
            }
          }

          send(ds.stepFinish("stop"));
          send(ds.messageFinish("stop"));
        } catch (e) {
          send(ds.text(`\n\n**Error:** ${String(e)}`));
          send(ds.stepFinish("error"));
          send(ds.messageFinish("error"));
        }

        controller.close();
      },
    });

    // Persist the assistant's response so follow-up questions have context
    onFinish({
      text: fullResponseText,
      reasoning: undefined,
      reasoningDetails: [],
      files: [],
      sources: [],
      finishReason: "stop",
      usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      toolCalls: [],
      toolResults: [],
      response: {
        id: crypto.randomUUID(),
        timestamp: new Date(),
        modelId: MODEL,
        headers: {},
        messages: [
          { role: "assistant" as const, content: [{ type: "text" as const, text: fullResponseText }] },
        ],
      },
      warnings: [],
      providerMetadata: undefined,
      experimental_providerMetadata: undefined,
      steps: [],
      request: {},
      rawResponse: undefined,
    } as Parameters<typeof onFinish>[0]);

    return new Response(stream, {
      headers: { "Content-Type": "text/plain; charset=utf-8", "X-Vercel-AI-Data-Stream": "v1" },
    });
  }
}
