import { routeAgentRequest } from "agents";
import { RPKIScoutAgent } from "./agent";
import { ASNAuditWorkflow } from "./workflow";

export { RPKIScoutAgent, ASNAuditWorkflow };

interface Env {
  AI: Ai;
  RADAR_API_TOKEN: string;
  AUDIT_WORKFLOW: Workflow;
  RPKI_SCOUT: DurableObjectNamespace;
  ASSETS: Fetcher;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Route WebSocket and REST requests to the agent Durable Object
    const agentResponse = await routeAgentRequest(request, env);
    if (agentResponse) return agentResponse;

    // Serve Vite-built static assets for the React frontend
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
