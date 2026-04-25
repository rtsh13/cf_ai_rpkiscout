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
  id: number;
  prefixes: string[];
  hijacker_asn: number;
  hijacker_country?: string;
  victim_asns: number[];
  victim_countries?: string[];
  confidence_score: number;
  min_hijack_ts: string;
  max_hijack_ts?: string;
  event_type: number;
  on_going_count: number;
  peer_asns?: number[];
  peer_ip_count?: number;
  is_stale?: boolean;
  tags?: Array<{ name: string; score: number }>;
}

export interface HijackEventsResult {
  events: HijackEvent[];
  meta?: { total: number };
}

export interface LeakEvent {
  id: number;
  leak_asn: number;
  leak_count: number;
  leak_type: number;
  leak_seg?: number[];
  countries?: string[];
  detected_ts: string;
  min_ts?: string;
  max_ts?: string;
  prefix_count: number;
  origin_count?: number;
  peer_count?: number;
  finished: boolean;
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

// ── Date helper ──────────────────────────────────────────────────────────────

function last7days(): { dateStart: string; dateEnd: string } {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  return {
    dateStart: weekAgo.toISOString(),
    dateEnd: now.toISOString(),
  };
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
  const dates = last7days();
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
    dateStart: dates.dateStart,
    dateEnd: dates.dateEnd,
  };
  if (options.asn) params.involvedAsn = String(options.asn);
  return radarFetch("/bgp/hijacks/events", apiToken, params) as Promise<HijackEventsResult>;
}

// ── BGP route leak events ─────────────────────────────────────────────────────

export async function getBGPLeakEvents(
  apiToken: string,
  options: { asn?: number; limit?: number } = {}
): Promise<LeakEventsResult> {
  const dates = last7days();
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
    dateStart: dates.dateStart,
    dateEnd: dates.dateEnd,
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
  const dates = last7days();
  const params: Record<string, string> = {
    limit: String(options.limit ?? 10),
    dateStart: dates.dateStart,
    dateEnd: dates.dateEnd,
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
