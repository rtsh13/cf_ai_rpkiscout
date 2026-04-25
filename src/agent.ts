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

// ── Tool definitions (decoupled from AI SDK — we call them manually) ─────────

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
        if (status.status === "complete") {
          return { success: true, report: status.output as AuditReport };
        }
        if (status.status === "errored") {
          return { success: false, error: "Audit workflow errored." };
        }
      }
      return { success: false, error: "Audit timed out — workflow is still running." };
    },
  },
};

// ── Workers AI tool format (for function calling) ────────────────────────────

function buildToolsForWorkersAI() {
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
        required: Object.entries(def.params)
          .filter(([, v]) => v.required)
          .map(([k]) => k),
      },
    },
  }));
}

// ── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are RPKIScout, a BGP routing security analyst on Cloudflare's edge.

You have live access to Cloudflare Radar (330+ cities, 125+ countries, updated every 2 hours).

IMPORTANT RULES:
- For conceptual questions ("what is RPKI?", "explain BGP hijacks"), answer directly from knowledge — do NOT call any tools.
- Only call tools when the user asks for live data about a specific ASN, prefix, or event.
- Lead with a plain-language summary, then technical detail.
- Use **bold** for critical findings. Use bullet lists for recommendations.
- All numbers must come from tool results — never fabricate.

Available tools: lookupASN, checkRPKI, getHijacks, getLeaks, getAnomalies, getRealTimeRoutes, runAudit.`;

// ── AI SDK data stream format helpers ────────────────────────────────────────
//
// The data stream protocol used by useChat / useAgentChat:
//   0:<json-string>\n         → text part
//   9:<json-object>\n         → tool call start
//   a:<json-object>\n         → tool result
//   e:<json-object>\n         → step finish
//   d:<json-object>\n         → message finish

function dsText(text: string): string {
  return `0:${JSON.stringify(text)}\n`;
}

function dsToolCall(id: string, name: string, args: Record<string, unknown>): string {
  return `9:${JSON.stringify({ toolCallId: id, toolName: name, args })}\n`;
}

function dsToolResult(id: string, result: unknown): string {
  return `a:${JSON.stringify({ toolCallId: id, result })}\n`;
}

function dsFinishStep(reason: string): string {
  return `e:${JSON.stringify({ finishReason: reason, usage: { promptTokens: 0, completionTokens: 0 }, isContinued: false })}\n`;
}

function dsFinishMessage(reason: string): string {
  return `d:${JSON.stringify({ finishReason: reason, usage: { promptTokens: 0, completionTokens: 0 } })}\n`;
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
    const messages = this.messages;

    const stream = new ReadableStream({
      async start(controller) {
        const send = (chunk: string) => controller.enqueue(encoder.encode(chunk));

        try {
          // ── Step 1: Call Workers AI with streaming + tools ─────────────
          const aiMessages = [
            { role: "system" as const, content: SYSTEM_PROMPT },
            ...messages.map((m) => ({
              role: m.role as "user" | "assistant",
              content: typeof m.content === "string" ? m.content : JSON.stringify(m.content),
            })),
          ];

          const response = (await env.AI.run(
            "@cf/meta/llama-3.3-70b-instruct-fp8-fast" as BaseAiTextGenerationModels,
            {
              messages: aiMessages,
              tools: buildToolsForWorkersAI(),
              stream: true,
              max_tokens: 2048,
            }
          )) as ReadableStream;

          // ── Step 2: Consume the SSE stream from Workers AI ────────────
          let fullText = "";
          let toolCalls: Array<{ name: string; arguments: Record<string, unknown> }> = [];

          const reader = response.pipeThrough(new TextDecoderStream()).getReader();
          let buffer = "";

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

                // Text delta
                if (chunk.response) {
                  fullText += chunk.response;
                  send(dsText(chunk.response));
                }

                // Tool calls (non-streaming — returned in final chunk)
                if (chunk.tool_calls) {
                  toolCalls = chunk.tool_calls;
                }
              } catch {
                // skip malformed chunks
              }
            }
          }

          // ── Step 3: Execute tool calls (if any) ───────────────────────
          if (toolCalls.length > 0) {
            send(dsFinishStep("tool-calls"));

            for (const tc of toolCalls) {
              const toolDef = TOOLS[tc.name];
              if (!toolDef) continue;

              const callId = `call_${tc.name}_${Date.now()}`;
              send(dsToolCall(callId, tc.name, tc.arguments ?? {}));

              try {
                const result = await toolDef.execute(tc.arguments ?? {}, env);

                // Persist audit results to agent state
                if (tc.name === "runAudit" && (result as { success?: boolean })?.success) {
                  const report = (result as { report?: AuditReport }).report;
                  if (report) {
                    const state = (agent.state ?? {}) as AgentState;
                    const watched = Array.isArray(state.watchedASNs) ? state.watchedASNs : [];
                    const asn = report.asn;
                    if (!watched.includes(asn)) {
                      await agent.setState({
                        ...state,
                        watchedASNs: [...watched, asn],
                        [`audit_${asn}`]: report,
                      } as AgentState);
                    }
                  }
                }

                send(dsToolResult(callId, result));
              } catch (e) {
                send(dsToolResult(callId, { success: false, error: String(e) }));
              }
            }
          }

          // ── Step 4: Finish ────────────────────────────────────────────
          send(dsFinishStep(toolCalls.length > 0 ? "tool-calls" : "stop"));
          send(dsFinishMessage(toolCalls.length > 0 ? "tool-calls" : "stop"));
        } catch (e) {
          // Surface errors as text so the user sees something
          send(dsText(`\n\n**Error:** ${String(e)}`));
          send(dsFinishStep("error"));
          send(dsFinishMessage("error"));
        }

        controller.close();
      },
    });

    // Call onFinish with a minimal valid shape so the base class persists messages
    onFinish({
      text: "",
      reasoning: undefined,
      reasoningDetails: [],
      files: [],
      sources: [],
      finishReason: "stop",
      usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      toolCalls: [],
      toolResults: [],
      response: { id: "", timestamp: new Date(), modelId: "", headers: {}, messages: [] },
      warnings: [],
      providerMetadata: undefined,
      experimental_providerMetadata: undefined,
      steps: [],
      request: {},
      rawResponse: undefined,
    } as Parameters<typeof onFinish>[0]);

    return new Response(stream, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "X-Vercel-AI-Data-Stream": "v1",
      },
    });
  }
}
