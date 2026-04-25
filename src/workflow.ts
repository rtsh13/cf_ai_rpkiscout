import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import {
  getASNInfo,
  getBGPHijackEvents,
  getBGPLeakEvents,
  getASNPrefixes,
  getTrafficAnomalies,
  summariseRPKI,
} from "./radar";
import type { RPKISummary } from "./radar";

export interface AuditParams {
  asn: number;
}

export interface AuditReport {
  asn: number;
  asnName: string;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  summary: string;
  rpki: RPKISummary;
  recentHijacks: number;
  recentLeaks: number;
  anomalies: number;
  recommendations: string[];
  generatedAt: string;
}

interface Env {
  AI: Ai;
  RADAR_API_TOKEN: string;
}

const VALID_RISK_LEVELS = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

function deriveRiskLevel(
  coveragePct: number,
  invalidCount: number,
  hijackCount: number,
  leakCount: number
): AuditReport["riskLevel"] {
  if (coveragePct < 50 && (hijackCount > 0 || leakCount > 0)) return "CRITICAL";
  if (invalidCount > 0) return "HIGH";
  if (coveragePct < 50) return "HIGH";
  if (hijackCount > 0 && leakCount > 0) return "HIGH";
  if (hijackCount > 0 || leakCount > 0) return "MEDIUM";
  if (coveragePct < 80) return "MEDIUM";
  return "LOW";
}

export class ASNAuditWorkflow extends WorkflowEntrypoint<Env, AuditParams> {
  async run(event: WorkflowEvent<AuditParams>, step: WorkflowStep): Promise<AuditReport> {
    const { asn } = event.payload;

    const retryConfig = {
      retries: { limit: 3, delay: "2 seconds" as const, backoff: "exponential" as const },
      timeout: "30 seconds" as const,
    };

    // Step 1: ASN metadata
    const asnInfo = await step.do("fetch-asn-info", retryConfig, () =>
      getASNInfo(asn, this.env.RADAR_API_TOKEN)
    );

    // Step 2: Recent BGP hijack events
    const hijacks = await step.do("fetch-hijack-events", retryConfig, () =>
      getBGPHijackEvents(this.env.RADAR_API_TOKEN, { asn, limit: 20 })
    );

    // Step 3: Recent route leak events
    const leaks = await step.do("fetch-leak-events", retryConfig, () =>
      getBGPLeakEvents(this.env.RADAR_API_TOKEN, { asn, limit: 20 })
    );

    // Step 4: All prefixes announced by this ASN with RPKI validation status
    const prefixData = await step.do("fetch-prefix-rpki", retryConfig, () =>
      getASNPrefixes(asn, this.env.RADAR_API_TOKEN)
    );

    // Step 5: Traffic anomalies
    const anomalyData = await step.do("fetch-traffic-anomalies", retryConfig, () =>
      getTrafficAnomalies(this.env.RADAR_API_TOKEN, { asn, limit: 10 })
    );

    // Step 6: LLM risk analysis
    const report = await step.do(
      "generate-risk-report",
      { retries: { limit: 2, delay: "5 seconds" as const }, timeout: "60 seconds" as const },
      async () => {
        const rpki = summariseRPKI(prefixData);
        const hijackArr = hijacks?.events ?? [];
        const leakArr = leaks?.events ?? [];
        const anomalyArr = anomalyData?.trafficAnomalies ?? [];
        const asnName = asnInfo?.asn?.nameLong ?? asnInfo?.asn?.name ?? `AS${asn}`;

        const systemPrompt = `You are a BGP and RPKI routing security expert. Analyse the provided data and produce a concise JSON risk assessment. Be precise, data-driven, and actionable. Respond ONLY with valid JSON — no prose, no markdown fences.`;

        const userPrompt = `Analyse AS${asn} (${asnName}):

RPKI: ${rpki.coveragePct}% coverage · ${rpki.valid} valid / ${rpki.invalid} invalid / ${rpki.unknown} unknown (${rpki.total} total prefixes)
BGP Hijack Events (last 7 days): ${hijackArr.length}
Route Leak Events (last 7 days): ${leakArr.length}
Traffic Anomalies: ${anomalyArr.length}

Sample hijack events: ${JSON.stringify(hijackArr.slice(0, 3))}
Sample leak events: ${JSON.stringify(leakArr.slice(0, 3))}

Risk thresholds to apply:
- RPKI coverage < 50% → HIGH or CRITICAL
- Any RPKI_INVALID prefixes → HIGH
- Hijacks AND leaks simultaneously → escalate one level
- No incidents, coverage ≥ 80% → LOW

Respond with exactly this JSON schema:
{"riskLevel":"LOW"|"MEDIUM"|"HIGH"|"CRITICAL","summary":"<2-3 sentences: one CISO-readable, one technical>","recommendations":["<actionable rec 1>","<actionable rec 2>","<actionable rec 3>"]}`;

        const aiResponse = (await this.env.AI.run(
          "@cf/meta/llama-3.3-70b-instruct-fp8-fast" as BaseAiTextGenerationModels,
          {
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userPrompt },
            ],
            max_tokens: 600,
          }
        )) as { response?: string };

        let parsed: {
          riskLevel: AuditReport["riskLevel"];
          summary: string;
          recommendations: string[];
        };

        try {
          const raw = aiResponse.response ?? "{}";
          const clean = raw
            .replace(/```json\s*/g, "")
            .replace(/```\s*/g, "")
            .trim();
          const candidate = JSON.parse(clean) as typeof parsed;

          // Validate shape — never trust the model blindly
          parsed = {
            riskLevel: VALID_RISK_LEVELS.has(candidate.riskLevel)
              ? candidate.riskLevel
              : deriveRiskLevel(rpki.coveragePct, rpki.invalid, hijackArr.length, leakArr.length),
            summary:
              typeof candidate.summary === "string" && candidate.summary.length > 10
                ? candidate.summary
                : `AS${asn} has ${rpki.coveragePct}% RPKI coverage with ${hijackArr.length} hijack and ${leakArr.length} leak events in the last 7 days.`,
            recommendations: Array.isArray(candidate.recommendations)
              ? candidate.recommendations.slice(0, 5)
              : [],
          };
        } catch {
          // Heuristic fallback — no LLM output is better than malformed output
          parsed = {
            riskLevel: deriveRiskLevel(rpki.coveragePct, rpki.invalid, hijackArr.length, leakArr.length),
            summary: `AS${asn} (${asnName}) shows ${rpki.coveragePct}% RPKI coverage across ${rpki.total} prefixes, with ${hijackArr.length} hijack and ${leakArr.length} route leak events in the past 7 days.`,
            recommendations: [
              "Deploy RPKI ROAs for all announced prefixes via your RIR portal.",
              "Enable route origin validation (ROV) on all eBGP sessions.",
              "Subscribe to Cloudflare Radar BGP alerts for this ASN.",
            ],
          };
        }

        const finalReport: AuditReport = {
          asn,
          asnName,
          riskLevel: parsed.riskLevel,
          summary: parsed.summary,
          rpki,
          recentHijacks: hijackArr.length,
          recentLeaks: leakArr.length,
          anomalies: anomalyArr.length,
          recommendations: parsed.recommendations,
          generatedAt: new Date().toISOString(),
        };

        return finalReport;
      }
    );

    return report as AuditReport;
  }
}
