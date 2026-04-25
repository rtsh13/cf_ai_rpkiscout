/**
 * Cloudflare Radar API client
 * Docs: https://developers.cloudflare.com/api/resources/radar/
 *
 * All functions return the `result` key from the Radar API response.
 * Callers receive strongly-typed data; unknown casts are isolated here.
 */

const RADAR_BASE = "https://api.cloudflare.com/client/v4/radar";

// ── Response types ────────────────────────────────────────────────────────────

export interface ASNInfo {
  asn: {
    asn: number;
    name: string;
    nameLong?: string;
    country?: string;
    countryName?: string;
    website?: string;
    orgName?: string;
    estimatedUsers?: { estimatedUsers: number };
  };
}

export interface HijackEvent {
  id: string;
  hijackPrefix: string;
  hijackerAsn: number;
  hijackerAsnName: string;
  peerAsns?: Array<{ asn: number; asnName: string }>;
  detectedTs: string;
  eventType: string;
  maxHijackTs?: string;
}

export interface HijackEventsResult {
  events: HijackEvent[];
  meta?: { total: number };
}

export interface LeakEvent {
  id: string;
  leakPrefix: string;
  leakAsn: number;
  leakAsnName: string;
  originAsn?: number;
  originAsnName?: string;
  leakDetectedTs?: string;
  detectedTs?: string;
}

export interface LeakEventsResult {
  events: LeakEvent[];
  meta?: { total: number };
}

export interface PrefixOrigin {
  prefix: string;
  origin: number;
  rpki_validation: "VALID" | "INVALID" | "UNKNOWN" | "NOT_FOUND";
}

export interface PrefixRPKIResult {
  prefix_origins: PrefixOrigin[];
}

export interface TrafficAnomaly {
  type: string;
  asnId?: number;
  asnName?: string;
  startDate: string;
  endDate?: string | null;
  status: "ONGOING" | "RESOLVED";
  scope?: string;
}

export interface TrafficAnomaliesResult {
  trafficAnomalies: TrafficAnomaly[];
}

export interface RPKISummary {
  total: number;
  valid: number;
  invalid: number;
  unknown: number;
  coveragePct: number;
}

// ── Shared fetch helper ───────────────────────────────────────────────────────

async function radarFetch(
  path: string,
  apiToken: string,
  params: Record<string, string> = {}
): Promise<unknown> {
  const url = new URL(`${RADAR_BASE}${path}`);
  url.searchParams.set("format", "json");
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Radar API ${res.status}: ${text}`);
  }

  const json = (await res.json()) as { result: unknown };
  return json.result;
}

// ── ASN info ──────────────────────────────────────────────────────────────────

export async function getASNInfo(asn: number, apiToken: string): Promise<ASNInfo> {
  return radarFetch(`/entities/asns/${asn}`, apiToken) as Promise<ASNInfo>;
}

// ── BGP hijack events ─────────────────────────────────────────────────────────

export async function getBGPHijackEvents(
  apiToken: string,
  options: { asn?: number; limit?: number } = {}
): Promise<HijackEventsResult> {
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
    dateRange: "7d",
  };
  if (options.asn) params.involvedAsn = String(options.asn);
  return radarFetch("/bgp/hijacks/events", apiToken, params) as Promise<HijackEventsResult>;
}

// ── BGP route leak events ─────────────────────────────────────────────────────

export async function getBGPLeakEvents(
  apiToken: string,
  options: { asn?: number; limit?: number } = {}
): Promise<LeakEventsResult> {
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
    dateRange: "7d",
  };
  if (options.asn) params.involvedAsn = String(options.asn);
  return radarFetch("/bgp/leaks/events", apiToken, params) as Promise<LeakEventsResult>;
}

// ── Prefix → ASN mapping with RPKI ───────────────────────────────────────────

export async function getPrefixRPKI(
  prefix: string,
  apiToken: string
): Promise<PrefixRPKIResult> {
  return radarFetch("/bgp/routes/pfx2as", apiToken, { prefix }) as Promise<PrefixRPKIResult>;
}

// ── All prefixes announced by an ASN (origin) ────────────────────────────────

export async function getASNPrefixes(
  asn: number,
  apiToken: string
): Promise<PrefixRPKIResult> {
  return radarFetch("/bgp/routes/pfx2as", apiToken, {
    origin: String(asn),
    limit: "50",
  }) as Promise<PrefixRPKIResult>;
}

// ── Traffic anomalies (outage signals) ───────────────────────────────────────

export async function getTrafficAnomalies(
  apiToken: string,
  options: { asn?: number; limit?: number } = {}
): Promise<TrafficAnomaliesResult> {
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
  };
  if (options.asn) params.asn = String(options.asn);
  return radarFetch("/traffic_anomalies", apiToken, params) as Promise<TrafficAnomaliesResult>;
}

// ── Real-time BGP routes for a prefix ────────────────────────────────────────

export async function getRealTimeRoutes(prefix: string, apiToken: string): Promise<unknown> {
  return radarFetch("/bgp/routes/realtime", apiToken, { prefix });
}

// ── RPKI summary helper ───────────────────────────────────────────────────────

export function summariseRPKI(prefixData: PrefixRPKIResult | unknown): RPKISummary {
  const items =
    (prefixData as PrefixRPKIResult)?.prefix_origins ?? [];

  const counts = { valid: 0, invalid: 0, unknown: 0 };
  for (const item of items) {
    const status = item.rpki_validation?.toLowerCase();
    if (status === "valid") counts.valid++;
    else if (status === "invalid") counts.invalid++;
    else counts.unknown++;
  }

  const total = items.length;
  const coveragePct = total > 0 ? Math.round((counts.valid / total) * 100) : 0;

  return { total, ...counts, coveragePct };
}
