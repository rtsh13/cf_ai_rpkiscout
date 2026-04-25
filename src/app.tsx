import React, { useState, useRef, useEffect } from "react";
import { useAgent } from "agents/react";
import { useAgentChat } from "agents/ai-react";
import type { UIMessage } from "ai";
import type {
  ASNInfo,
  HijackEventsResult,
  LeakEventsResult,
  PrefixRPKIResult,
  TrafficAnomaliesResult,
  RPKISummary,
} from "./radar";
import type { AuditReport } from "./workflow";

// ── Suggested prompts ──────────────────────────────────────────────────────────

const SUGGESTED = [
  { label: "Audit Cloudflare (AS13335)", prompt: "Run a full security audit for AS13335 (Cloudflare)." },
  { label: "Check 1.1.1.0/24 RPKI", prompt: "What is the RPKI status of prefix 1.1.1.0/24?" },
  { label: "Recent BGP hijacks", prompt: "Show me the most recent BGP hijack events globally." },
  { label: "Any route leaks today?", prompt: "Are there any BGP route leak events in the last 7 days?" },
  { label: "Audit Lumen (AS3356)", prompt: "Run a full security audit for AS3356 (Lumen Technologies)." },
  { label: "What is RPKI?", prompt: "Explain RPKI and why it matters for Internet routing security." },
];

// ── Date formatter ─────────────────────────────────────────────────────────────

function fmtTs(ts: string): string {
  try {
    return new Date(ts).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "UTC",
      timeZoneName: "short",
    });
  } catch {
    return ts;
  }
}

// ── Markdown renderer ──────────────────────────────────────────────────────────

function parseInline(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
      return <code key={i} className="inline-code">{part.slice(1, -1)}</code>;
    }
    return part || null;
  });
}

function renderMarkdown(raw: string): React.ReactNode {
  const lines = raw.split("\n");
  const nodes: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        code.push(lines[i]);
        i++;
      }
      nodes.push(
        <pre key={i} className="code-block">
          {lang && <span className="code-lang">{lang}</span>}
          <code>{code.join("\n")}</code>
        </pre>
      );
      i++;
      continue;
    }

    if (line.startsWith("### ")) {
      nodes.push(<h4 key={i} className="msg-h3">{parseInline(line.slice(4))}</h4>);
    } else if (line.startsWith("## ")) {
      nodes.push(<h3 key={i} className="msg-heading">{parseInline(line.slice(3))}</h3>);
    } else if (line.startsWith("# ")) {
      nodes.push(<h2 key={i} className="msg-h1">{parseInline(line.slice(2))}</h2>);
    } else if (/^\d+\.\s/.test(line)) {
      const m = line.match(/^\d+\.\s(.*)/);
      if (m) nodes.push(
        <div key={i} className="msg-ol">
          <span className="msg-li-dot">▸</span>
          <span>{parseInline(m[1])}</span>
        </div>
      );
    } else if (line.startsWith("- ") || line.startsWith("• ")) {
      nodes.push(
        <div key={i} className="msg-li">
          <span className="msg-li-dot">▸</span>
          <span>{parseInline(line.slice(2))}</span>
        </div>
      );
    } else if (line.startsWith("> ")) {
      nodes.push(<blockquote key={i} className="msg-quote">{parseInline(line.slice(2))}</blockquote>);
    } else if (line.trim() === "") {
      nodes.push(<div key={i} className="msg-gap" />);
    } else {
      nodes.push(<p key={i} className="msg-p">{parseInline(line)}</p>);
    }
    i++;
  }

  return <>{nodes}</>;
}

// ── Risk badge ─────────────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const cls: Record<string, string> = {
    LOW: "badge-low", MEDIUM: "badge-medium",
    HIGH: "badge-high", CRITICAL: "badge-critical",
  };
  return <span className={`risk-badge ${cls[level] ?? "badge-low"}`}>{level}</span>;
}

// ── RPKI coverage gauge ────────────────────────────────────────────────────────

function RPKIGauge({ pct }: { pct: number }) {
  const color = pct >= 80 ? "var(--green)" : pct >= 50 ? "var(--amber)" : "var(--red)";
  return (
    <div className="gauge-wrap">
      <div className="gauge-track">
        <div className="gauge-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="gauge-label" style={{ color }}>{pct}%</span>
    </div>
  );
}

// ── Tool card: lookupASN ───────────────────────────────────────────────────────

function ASNCard({ data }: { data: { success: boolean; data?: ASNInfo } }) {
  const info = data?.data?.asn;
  if (!info) return null;
  return (
    <div className="tool-card asn-card">
      <div className="tool-card-header">
        <span className="tool-card-icon">◉</span>
        <span className="tool-card-title">AS{info.asn}</span>
        {info.countryName && <span className="tool-card-tag">{info.countryName}</span>}
      </div>
      {(info.nameLong ?? info.name) && (
        <div className="asn-longname">{info.nameLong ?? info.name}</div>
      )}
      {info.nameLong && info.name && info.nameLong !== info.name && (
        <div className="asn-handle">Handle: {info.name}</div>
      )}
      {info.website && (
        <div className="asn-meta">
          <span className="meta-label">WEBSITE</span>
          <span className="meta-val">{info.website}</span>
        </div>
      )}
    </div>
  );
}

// ── Tool card: checkRPKI ───────────────────────────────────────────────────────

function RPKICard({ data }: { data: { success: boolean; data?: PrefixRPKIResult; summary?: RPKISummary } }) {
  const summary = data?.summary;
  const origins = data?.data?.prefix_origins ?? [];
  if (!summary) return null;
  return (
    <div className="tool-card rpki-card">
      <div className="tool-card-header">
        <span className="tool-card-icon">⊕</span>
        <span className="tool-card-title">RPKI VALIDATION</span>
        <span className="tool-card-tag">{summary.total} prefix{summary.total !== 1 ? "es" : ""}</span>
      </div>
      <RPKIGauge pct={summary.coveragePct} />
      <div className="rpki-stats">
        <div className="rpki-stat rpki-stat-valid">
          <span className="rpki-stat-val">{summary.valid}</span>
          <span className="rpki-stat-label">VALID</span>
        </div>
        <div className="rpki-stat rpki-stat-invalid">
          <span className="rpki-stat-val">{summary.invalid}</span>
          <span className="rpki-stat-label">INVALID</span>
        </div>
        <div className="rpki-stat rpki-stat-unknown">
          <span className="rpki-stat-val">{summary.unknown}</span>
          <span className="rpki-stat-label">UNKNOWN</span>
        </div>
      </div>
      {origins.length > 0 && (
        <div className="rpki-table">
          <div className="rpki-table-head">
            <span>PREFIX</span><span>ORIGIN</span><span>STATUS</span>
          </div>
          {origins.slice(0, 6).map((o, idx) => (
            <div key={idx} className="rpki-table-row">
              <span className="rpki-prefix">{o.prefix}</span>
              <span>AS{o.origin}</span>
              <span className={`rpki-val-status rpki-val-${(o.rpki_validation ?? "UNKNOWN").toLowerCase()}`}>
                {o.rpki_validation ?? "UNKNOWN"}
              </span>
            </div>
          ))}
          {origins.length > 6 && <div className="table-overflow">+{origins.length - 6} more</div>}
        </div>
      )}
    </div>
  );
}

// ── Tool card: getHijacks ──────────────────────────────────────────────────────

function HijackCard({ data }: { data: { success: boolean; data?: HijackEventsResult } }) {
  const events = data?.data?.events ?? [];
  return (
    <div className="tool-card events-card">
      <div className="tool-card-header">
        <span className="tool-card-icon" style={{ color: "var(--red)" }}>⚠</span>
        <span className="tool-card-title">BGP HIJACK EVENTS · LAST 7D</span>
        <span className={`tool-card-tag ${events.length > 0 ? "tag-red" : "tag-green"}`}>
          {events.length === 0 ? "NONE FOUND" : `${events.length} FOUND`}
        </span>
      </div>
      {events.length === 0 ? (
        <div className="events-empty">No BGP hijack events in the last 7 days.</div>
      ) : (
        <div className="events-table">
          <div className="events-head"><span>PREFIX</span><span>HIJACKER → VICTIM</span><span>DETECTED</span></div>
          {events.slice(0, 6).map((ev, idx) => (
            <div key={idx} className="events-row">
              <span className="ev-prefix">{ev.prefixes?.[0] ?? "—"}</span>
              <span className="ev-asn">AS{ev.hijacker_asn ?? "?"} → AS{ev.victim_asns?.[0] ?? "?"}</span>
              <span className="ev-ts">{ev.min_hijack_ts ? fmtTs(ev.min_hijack_ts) : "—"}</span>
            </div>
          ))}
          {events.length > 6 && <div className="table-overflow">+{events.length - 6} more</div>}
        </div>
      )}
    </div>
  );
}

// ── Tool card: getLeaks ────────────────────────────────────────────────────────

function LeakCard({ data }: { data: { success: boolean; data?: LeakEventsResult } }) {
  const events = data?.data?.events ?? [];
  return (
    <div className="tool-card events-card">
      <div className="tool-card-header">
        <span className="tool-card-icon" style={{ color: "var(--amber)" }}>⇌</span>
        <span className="tool-card-title">ROUTE LEAK EVENTS · LAST 7D</span>
        <span className={`tool-card-tag ${events.length > 0 ? "tag-amber" : "tag-green"}`}>
          {events.length === 0 ? "NONE FOUND" : `${events.length} FOUND`}
        </span>
      </div>
      {events.length === 0 ? (
        <div className="events-empty">No route leak events in the last 7 days.</div>
      ) : (
        <div className="events-table">
          <div className="events-head"><span>LEAKER</span><span>PREFIXES / ORIGINS</span><span>DETECTED</span></div>
          {events.slice(0, 6).map((ev, idx) => (
            <div key={idx} className="events-row">
              <span className="ev-prefix">AS{ev.leak_asn ?? "?"}</span>
              <span className="ev-asn">{ev.prefix_count ?? 0} prefixes · {ev.origin_count ?? 0} origins</span>
              <span className="ev-ts">{ev.detected_ts ? fmtTs(ev.detected_ts) : "—"}</span>
            </div>
          ))}
          {events.length > 6 && <div className="table-overflow">+{events.length - 6} more</div>}
        </div>
      )}
    </div>
  );
}

// ── Tool card: getAnomalies ────────────────────────────────────────────────────

function AnomalyCard({ data }: { data: { success: boolean; data?: TrafficAnomaliesResult } }) {
  const anomalies = data?.data?.trafficAnomalies ?? [];
  return (
    <div className="tool-card anomaly-card">
      <div className="tool-card-header">
        <span className="tool-card-icon" style={{ color: "var(--amber)" }}>◈</span>
        <span className="tool-card-title">TRAFFIC ANOMALIES</span>
        <span className={`tool-card-tag ${anomalies.length > 0 ? "tag-amber" : "tag-green"}`}>
          {anomalies.length === 0 ? "NONE FOUND" : `${anomalies.length} FOUND`}
        </span>
      </div>
      {anomalies.length === 0 ? (
        <div className="events-empty">No traffic anomalies detected.</div>
      ) : (
        <div className="anomaly-list">
          {anomalies.slice(0, 5).map((a, idx) => (
            <div key={idx} className="anomaly-item">
              <div className="anomaly-top">
                <span className={`anomaly-status ${a.status === "ONGOING" ? "status-ongoing" : "status-resolved"}`}>
                  {a.status ?? "UNKNOWN"}
                </span>
                {a.asnId && <span className="anomaly-asn">AS{a.asnId}{a.asnName ? ` · ${a.asnName}` : ""}</span>}
              </div>
              <div className="anomaly-time">
                Started: {a.startDate ? fmtTs(a.startDate) : "—"}
                {a.endDate ? ` · Ended: ${fmtTs(a.endDate)}` : ""}
              </div>
            </div>
          ))}
          {anomalies.length > 5 && <div className="table-overflow">+{anomalies.length - 5} more</div>}
        </div>
      )}
    </div>
  );
}

// ── Tool card: runAudit ────────────────────────────────────────────────────────

function AuditCard({ data }: { data: { success: boolean; report?: AuditReport } }) {
  const r = data?.report;
  if (!r) return null;
  return (
    <div className="audit-card">
      <div className="audit-header">
        <div className="audit-id">
          <span className="audit-asn">AS{r.asn}</span>
          <span className="audit-name">{r.asnName}</span>
        </div>
        <RiskBadge level={r.riskLevel} />
      </div>
      <p className="audit-summary">{r.summary}</p>
      <div className="audit-rpki-block">
        <div className="audit-rpki-label">RPKI COVERAGE</div>
        <RPKIGauge pct={r.rpki.coveragePct} />
        <div className="audit-rpki-detail">
          <span style={{ color: "var(--green)" }}>{r.rpki.valid} valid</span>
          {r.rpki.invalid > 0 && <span style={{ color: "var(--red)" }}> · {r.rpki.invalid} invalid</span>}
          <span style={{ color: "var(--dim)" }}> · {r.rpki.unknown} unknown · {r.rpki.total} total</span>
        </div>
      </div>
      <div className="audit-stats">
        <div className="stat">
          <span className="stat-label">HIJACKS (7D)</span>
          <span className="stat-val" style={{ color: r.recentHijacks > 0 ? "var(--red)" : "var(--green)" }}>{r.recentHijacks}</span>
        </div>
        <div className="stat">
          <span className="stat-label">LEAKS (7D)</span>
          <span className="stat-val" style={{ color: r.recentLeaks > 0 ? "var(--amber)" : "var(--green)" }}>{r.recentLeaks}</span>
        </div>
        <div className="stat">
          <span className="stat-label">ANOMALIES</span>
          <span className="stat-val" style={{ color: r.anomalies > 0 ? "var(--amber)" : "var(--fg)" }}>{r.anomalies}</span>
        </div>
      </div>
      {r.recommendations?.length > 0 && (
        <div className="audit-recs">
          <div className="recs-label">RECOMMENDATIONS</div>
          {r.recommendations.map((rec, idx) => (
            <div key={idx} className="rec-item">
              <span className="rec-num">{String(idx + 1).padStart(2, "0")}</span>
              <span>{rec}</span>
            </div>
          ))}
        </div>
      )}
      <div className="audit-ts">Generated {new Date(r.generatedAt).toUTCString()}</div>
    </div>
  );
}

// ── Tool card: analyseHijackRisk ──────────────────────────────────────────────

interface HijackCandidate {
  covering_prefix: string;
  covering_origin?: number;
  covering_rpki?: string;
  specific_prefix: string;
  specific_origin?: number;
  specific_rpki?: string;
  risk: string;
  reason: string;
}

interface HijackAnalysisData {
  success: boolean;
  data?: {
    hijack_candidates: HijackCandidate[];
    total_checked: number;
    total_flagged: number;
  };
}

function HijackAnalysisCard({ data }: { data: HijackAnalysisData }) {
  const result = data?.data;
  if (!result) return null;

  const riskColor: Record<string, string> = {
    CRITICAL: "var(--red)",
    HIGH:     "var(--red)",
    MEDIUM:   "var(--amber)",
    LOW:      "var(--dim)",
  };

  return (
    <div className="tool-card events-card">
      <div className="tool-card-header">
        <span className="tool-card-icon" style={{ color: "var(--red)" }}>⊗</span>
        <span className="tool-card-title">HIJACK VECTOR ANALYSIS · PREFIX TRIE</span>
        <span className={`tool-card-tag ${result.total_flagged > 0 ? "tag-red" : "tag-green"}`}>
          {result.total_flagged === 0
            ? "NO VECTORS FOUND"
            : `${result.total_flagged} of ${result.total_checked} FLAGGED`}
        </span>
      </div>

      {result.total_flagged === 0 ? (
        <div className="events-empty">
          No more-specific hijack vectors detected across {result.total_checked} prefixes.
        </div>
      ) : (
        <div className="anomaly-list">
          {result.hijack_candidates.map((c, idx) => (
            <div key={idx} className="anomaly-item">
              <div className="anomaly-top">
                <span
                  className="anomaly-status"
                  style={{
                    color: riskColor[c.risk] ?? "var(--dim)",
                    borderColor: riskColor[c.risk] ?? "var(--dim)",
                  }}
                >
                  {c.risk}
                </span>
                <span className="anomaly-asn" style={{ fontSize: "10px" }}>
                  {c.covering_prefix} → {c.specific_prefix}
                </span>
              </div>
              <div className="anomaly-time">
                Covering: AS{c.covering_origin ?? "?"} ({c.covering_rpki ?? "?"}) ·
                More-specific: AS{c.specific_origin ?? "?"} ({c.specific_rpki ?? "?"})
              </div>
              <div className="anomaly-time" style={{ color: "var(--dim)", fontStyle: "italic" }}>
                {c.reason}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Error card ─────────────────────────────────────────────────────────────────

function ErrorCard({ toolName, error }: { toolName: string; error?: string }) {
  return (
    <div className="tool-card error-card">
      <div className="tool-card-header">
        <span className="tool-card-icon" style={{ color: "var(--red)" }}>✕</span>
        <span className="tool-card-title" style={{ color: "var(--red)" }}>{toolName.toUpperCase()} FAILED</span>
      </div>
      {error && <div className="error-msg">{error}</div>}
    </div>
  );
}

// ── Tool call chip (with audit progress animation) ─────────────────────────────

const TOOL_LABELS: Record<string, string> = {
  lookupASN: "Looking up ASN",
  checkRPKI: "Checking RPKI validation",
  getHijacks: "Fetching hijack events",
  getLeaks: "Fetching route leak events",
  getAnomalies: "Fetching traffic anomalies",
  getRealTimeRoutes: "Fetching real-time routes",
  runAudit: "Running BGP/RPKI audit",
  analyseHijackRisk: "Analysing prefix hijack vectors",
};

const AUDIT_STEPS = [
  "Fetching ASN metadata",
  "Checking hijack events",
  "Checking route leaks",
  "Validating RPKI prefixes",
  "Scanning traffic anomalies",
  "Generating AI risk report",
];

function ToolCallChip({ name, args }: { name: string; args?: Record<string, unknown> }) {
  const mountRef = useRef(Date.now());
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (name !== "runAudit") return;
    const id = setInterval(() => {
      const elapsed = Date.now() - mountRef.current;
      const s = Math.min(Math.floor(elapsed / 4500), AUDIT_STEPS.length - 1);
      setStep(s);
      if (s >= AUDIT_STEPS.length - 1) clearInterval(id);
    }, 500);
    return () => clearInterval(id);
  }, [name]);

  if (name === "runAudit") {
    return (
      <div className="audit-progress-chip">
        <div className="apc-header">
          <span className="apc-spinner">◌</span>
          <span className="apc-title">RUNNING AUDIT{args?.asn ? ` · AS${args.asn}` : ""}</span>
        </div>
        <div className="apc-steps">
          {AUDIT_STEPS.map((s, i) => (
            <div key={i} className={`apc-step ${i < step ? "step-done" : i === step ? "step-active" : "step-pending"}`}>
              <span className="step-icon">{i < step ? "✓" : i === step ? "▸" : "○"}</span>
              <span>{s}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="tool-chip">
      <span className="tool-icon">⌁</span>
      <span>{TOOL_LABELS[name] ?? name}</span>
      {args?.asn != null && <span className="tool-chip-arg">AS{String(args.asn)}</span>}
      {args?.prefix != null && <span className="tool-chip-arg">{String(args.prefix)}</span>}
    </div>
  );
}

// ── Tool result dispatcher ─────────────────────────────────────────────────────

function renderToolResult(toolName: string, rawResult: unknown): React.ReactNode {
  const result =
    typeof rawResult === "string"
      ? (() => { try { return JSON.parse(rawResult); } catch { return rawResult; } })()
      : rawResult;

  const r = result as { success?: boolean; error?: string } | null;
  if (r?.success === false) return <ErrorCard toolName={toolName} error={r.error} />;

  switch (toolName) {
    case "lookupASN":    return <ASNCard    data={result as Parameters<typeof ASNCard>[0]["data"]}    />;
    case "checkRPKI":   return <RPKICard   data={result as Parameters<typeof RPKICard>[0]["data"]}   />;
    case "getHijacks":  return <HijackCard data={result as Parameters<typeof HijackCard>[0]["data"]} />;
    case "getLeaks":    return <LeakCard   data={result as Parameters<typeof LeakCard>[0]["data"]}   />;
    case "getAnomalies":return <AnomalyCard data={result as Parameters<typeof AnomalyCard>[0]["data"]} />;
    case "runAudit":    return <AuditCard  data={result as Parameters<typeof AuditCard>[0]["data"]}  />;
    case "analyseHijackRisk": return <HijackAnalysisCard data={result as HijackAnalysisData} />;
    default:
      if ((result as { report?: unknown })?.report) {
        return <AuditCard data={result as Parameters<typeof AuditCard>[0]["data"]} />;
      }
      return null;
  }
}

// ── Message bubble — uses UIMessage.parts (ai@4.3+) ───────────────────────────

function MessageBubble({ message }: { message: UIMessage }) {
  const isUser = message.role === "user";

  const body = () => {
    const parts = message.parts ?? [];

    return parts.map((part, i) => {
      if (part.type === "text") {
        // Llama 3.3 via workers-ai-provider can leak raw tool-call JSON into
        // the text stream alongside the structured tool-invocation part.
        // Detect and suppress it — the card renderer handles the real output.
        const trimmed = part.text.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
          try {
            const parsed = JSON.parse(trimmed) as Record<string, unknown>;
            if ("name" in parsed && "parameters" in parsed) return null;
          } catch { /* not JSON — render normally */ }
        }
        if (!trimmed) return null;
        return <div key={i}>{renderMarkdown(part.text)}</div>;
      }

      if (part.type === "tool-invocation") {
        const inv = part.toolInvocation;

        // Tool is in-flight → show animated chip
        if (inv.state === "call" || inv.state === "partial-call") {
          return (
            <ToolCallChip
              key={i}
              name={inv.toolName}
              args={inv.args as Record<string, unknown>}
            />
          );
        }

        // Tool completed → show result card
        if (inv.state === "result") {
          const rendered = renderToolResult(inv.toolName, inv.result);
          return rendered ? <div key={i}>{rendered}</div> : null;
        }
      }

      return null;
    });
  };

  return (
    <div className={`msg ${isUser ? "msg-user" : "msg-assistant"}`}>
      <div className="msg-role">{isUser ? "YOU" : "RPKISCOUT"}</div>
      <div className="msg-body">{body()}</div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  // Step 1: establish WebSocket connection to the Durable Object
  const agent = useAgent({ agent: "rpki-scout" });

  // Step 2: layer AI SDK chat on top of the connection.
  // getInitialMessages:null skips the HTTP /get-messages fetch (which can
  // return a non-JSON 404 in local dev and reject the promise). The agent
  // syncs existing messages automatically via the cf_agent_chat_messages
  // WebSocket event once the DO connection is established.
  const { messages, append, isLoading, clearHistory } = useAgentChat({
    agent,
    getInitialMessages: null,
  });

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = () => {
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;
    void append({ role: "user", content: trimmed });
    setInput("");
  };

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-left">
          <span className="logo-mark">◈</span>
          <span className="logo-text">RPKI<span className="logo-accent">SCOUT</span></span>
          <span className="logo-sub">BGP Security Intelligence · Powered by Cloudflare Radar</span>
        </div>
        <div className="topbar-right">
          {messages.length > 0 && (
            <button className="new-chat-btn" onClick={() => clearHistory()}>
              + New Chat
            </button>
          )}
          <span className="status-dot" />
          <span className="status-label">LIVE</span>
        </div>
      </header>

      <main className="main">
        {messages.length === 0 ? (
          <div className="empty-state">
            <div className="empty-glyph">◈</div>
            <h1 className="empty-title">BGP Routing Security Intelligence</h1>
            <p className="empty-desc">
              Real-time RPKI validation, BGP hijack detection, and route leak
              analysis powered by Cloudflare Radar — covering 330+ cities across
              125+ countries.
            </p>
            <div className="suggestions">
              {SUGGESTED.map((s) => (
                <button
                  key={s.label}
                  className="suggestion-btn"
                  onClick={() => void append({ role: "user", content: s.prompt })}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="messages">
            {messages.map((m) => <MessageBubble key={m.id} message={m} />)}
            {isLoading && (
              <div className="msg msg-assistant">
                <div className="msg-role">RPKISCOUT</div>
                <div className="typing"><span /><span /><span /></div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        )}
      </main>

      <footer className="inputbar">
        <textarea
          className="input-field"
          placeholder="Ask about an ASN, prefix, BGP hijack — or type 'audit AS13335'..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKey}
          rows={1}
          disabled={isLoading}
        />
        <button
          className="send-btn"
          onClick={send}
          disabled={!input.trim() || isLoading}
          aria-label="Send message"
        >
          ⏎
        </button>
      </footer>
    </div>
  );
}
