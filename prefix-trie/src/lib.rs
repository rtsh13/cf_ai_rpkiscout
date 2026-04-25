//! # CIDR Prefix Trie — Cloudflare Worker
//!
//! A binary trie over IPv4 address space, compiled to WebAssembly and
//! deployed as a Cloudflare Worker. Called via Service Binding from the
//! TypeScript RPKIScout agent.
//!
//! ## Why a trie?
//! Prefix lookup and containment checks on a flat Vec<String> are O(n).
//! A binary trie makes every operation O(prefix_length) = O(32) for IPv4,
//! regardless of how many prefixes are stored. Every production router FIB
//! (Forwarding Information Base) uses this structure. We use the same approach.
//!
//! ## IPv4 only
//! IPv6 requires a 128-bit trie — identical algorithm, wider address space.
//! The extension path is: change `u32` → `u128`, `32` → `128`, update the
//! IP parsing to handle both families.

use serde::{Deserialize, Serialize};
use worker::*;

// ── Panic hook ─────────────────────────────────────────────────────────────
// Without this, a Rust panic produces a silent Wasm trap in the Workers
// runtime. With it, panics emit a readable console.error() message.
fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

// ── IP / prefix parsing ─────────────────────────────────────────────────────

/// Parse a dotted-decimal IPv4 address ("1.2.3.4") into a u32.
/// The most-significant byte is the first octet (network byte order).
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut result: u32 = 0;
    for part in &parts {
        let byte: u8 = part.parse().ok()?;
        result = (result << 8) | (byte as u32);
    }
    Some(result)
}

/// Parse a CIDR prefix ("1.1.1.0/24") into (address_bits: u32, prefix_len: u8).
/// Host bits are masked off so "1.1.1.50/24" is treated as "1.1.1.0/24".
fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (addr_str, len_str) = s.split_once('/')?;
    let addr = parse_ipv4(addr_str)?;
    let len: u8 = len_str.parse().ok()?;
    if len > 32 {
        return None;
    }
    // Mask off host bits
    let mask = if len == 0 {
        0u32 // /0 = default route
    } else {
        !0u32 << (32 - len) // e.g. /24 → 0xFFFFFF00
    };
    Some((addr & mask, len))
}

/// Format a (u32, u8) back into a CIDR string like "1.1.1.0/24".
fn format_cidr(addr: u32, len: u8) -> String {
    let a = (addr >> 24) & 0xFF;
    let b = (addr >> 16) & 0xFF;
    let c = (addr >>  8) & 0xFF;
    let d =  addr        & 0xFF;
    format!("{}.{}.{}.{}/{}", a, b, c, d, len)
}

// ── Trie node ───────────────────────────────────────────────────────────────

/// A single node in the binary trie.
///
/// Memory layout: each node is ~40 bytes on a 64-bit platform.
/// For 500 prefixes with average length /24, the trie has at most
/// 500 * 24 = 12,000 nodes = ~480 KB. Well within Worker memory limits.
#[derive(Default)]
struct TrieNode {
    left:   Option<Box<TrieNode>>, // bit = 0
    right:  Option<Box<TrieNode>>, // bit = 1
    is_end: bool,
    prefix: Option<String>,
    origin: Option<u32>,
    rpki:   Option<String>,
}

// ── Trie ────────────────────────────────────────────────────────────────────

struct PrefixTrie {
    root: TrieNode,
}

impl PrefixTrie {
    fn new() -> Self {
        PrefixTrie { root: TrieNode::default() }
    }

    /// Insert a CIDR prefix into the trie.
    ///
    /// We examine each bit of `addr` from the most significant (bit 31) down
    /// to bit (32 - len). At each step we go left (bit=0) or right (bit=1),
    /// creating nodes as needed. At depth `len` we mark the node as an endpoint.
    fn insert(&mut self, addr: u32, len: u8, prefix_str: &str, origin: Option<u32>, rpki: Option<&str>) {
        let mut node = &mut self.root;
        for depth in 0..len {
            // depth=0 → bit 31 (MSB), depth=31 → bit 0 (LSB)
            let bit = (addr >> (31 - depth)) & 1;
            if bit == 0 {
                node = node.left.get_or_insert_with(|| Box::new(TrieNode::default()));
            } else {
                node = node.right.get_or_insert_with(|| Box::new(TrieNode::default()));
            }
        }
        node.is_end = true;
        node.prefix = Some(prefix_str.to_string());
        node.origin = origin;
        node.rpki   = rpki.map(|s| s.to_string());
    }

    /// Longest-prefix-match: walk the IP's bits and return the deepest
    /// endpoint node encountered. Identical to a router FIB lookup.
    fn lpm(&self, addr: u32) -> Option<(&str, u8)> {
        let mut node = &self.root;
        let mut best: Option<(&str, u8)> = None;
        if node.is_end {
            best = node.prefix.as_deref().map(|p| (p, 0u8));
        }
        for depth in 0..32u8 {
            let bit = (addr >> (31 - depth)) & 1;
            let next = if bit == 0 { node.left.as_ref() } else { node.right.as_ref() };
            match next {
                None => break,
                Some(child) => {
                    node = child;
                    if node.is_end {
                        best = node.prefix.as_deref().map(|p| (p, depth + 1));
                    }
                }
            }
        }
        best
    }

    /// Check whether a given (addr, len) is a sub-prefix of any endpoint
    /// already in the trie. Returns the covering prefix and its metadata.
    fn find_covering_prefix(&self, addr: u32, len: u8) -> Option<(&str, Option<u32>, Option<&str>)> {
        let mut node = &self.root;
        if node.is_end {
            return node.prefix.as_deref().map(|p| (p, node.origin, node.rpki.as_deref()));
        }
        for depth in 0..len {
            let bit = (addr >> (31 - depth)) & 1;
            let next = if bit == 0 { node.left.as_ref() } else { node.right.as_ref() };
            match next {
                None => return None,
                Some(child) => {
                    node = child;
                    if node.is_end {
                        // This endpoint is a supernet of (addr, len)
                        return node.prefix.as_deref().map(|p| (p, node.origin, node.rpki.as_deref()));
                    }
                }
            }
        }
        None
    }

    /// Post-order aggregation: collapse redundant sub-prefixes.
    /// Returns true if this subtree is fully covered.
    fn aggregate_node(node: &mut TrieNode) -> bool {
        let left_full = match &mut node.left {
            None => false,
            Some(child) => Self::aggregate_node(child),
        };
        let right_full = match &mut node.right {
            None => false,
            Some(child) => Self::aggregate_node(child),
        };

        if left_full && right_full {
            node.left  = None;
            node.right = None;
            node.is_end = true;
            return true;
        }

        node.is_end
    }

    /// Collect all endpoint prefixes after aggregation.
    /// `addr` and `depth` track the current prefix as we recurse.
    fn collect_endpoints(node: &TrieNode, addr: u32, depth: u8, out: &mut Vec<String>) {
        if node.is_end {
            // Use stored prefix if available; otherwise reconstruct from addr+depth
            let p = node.prefix.clone().unwrap_or_else(|| format_cidr(addr, depth));
            out.push(p);
            return; // don't recurse — children are redundant
        }
        if let Some(left) = &node.left {
            Self::collect_endpoints(left, addr, depth + 1, out);
        }
        if let Some(right) = &node.right {
            let next_addr = addr | (1 << (31 - depth));
            Self::collect_endpoints(right, next_addr, depth + 1, out);
        }
    }
}

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct AggregateRequest {
    prefixes: Vec<String>,
}

#[derive(Serialize)]
struct AggregateResponse {
    aggregated:    Vec<String>,
    removed:       Vec<String>,
    reduction_pct: u8,
}

#[derive(Deserialize)]
struct LpmRequest {
    ip:       String,
    prefixes: Vec<String>,
}

#[derive(Serialize)]
struct LpmResponse {
    matched_prefix: Option<String>,
    matched_length: Option<u8>,
    ip:             String,
}

#[derive(Deserialize, Clone)]
struct PrefixEntry {
    prefix:          String,
    origin:          Option<u32>,
    rpki_validation: Option<String>,
}

#[derive(Deserialize)]
struct SpecificsRequest {
    prefixes: Vec<PrefixEntry>,
}

#[derive(Serialize)]
struct HijackCandidate {
    covering_prefix: String,
    covering_origin: Option<u32>,
    covering_rpki:   Option<String>,
    specific_prefix: String,
    specific_origin: Option<u32>,
    specific_rpki:   Option<String>,
    risk:            String,
    reason:          String,
}

#[derive(Serialize)]
struct SpecificsResponse {
    hijack_candidates: Vec<HijackCandidate>,
    total_checked:     usize,
    total_flagged:     usize,
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

fn score_risk(
    covering_origin: Option<u32>,
    specific_origin: Option<u32>,
    specific_rpki: Option<&str>,
) -> (&'static str, &'static str) {
    let same_origin = covering_origin == specific_origin
        || covering_origin.is_none()
        || specific_origin.is_none();

    if same_origin {
        return ("LOW", "Same-origin de-aggregation, no hijack risk");
    }

    match specific_rpki {
        Some("INVALID") => (
            "CRITICAL",
            "More-specific announced by different origin AS with an INVALID ROA — active violation",
        ),
        Some("VALID") => (
            "MEDIUM",
            "More-specific announced by different origin AS but has a valid ROA — may be legitimate",
        ),
        _ => (
            "HIGH",
            "More-specific announced by different origin AS with no valid ROA — likely hijack vector",
        ),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_aggregate(mut req: Request) -> Result<Response> {
    let text = req.text().await?;
    let body: AggregateRequest = serde_json::from_str(&text)
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let original: Vec<String> = body.prefixes.clone();

    let mut trie = PrefixTrie::new();
    for prefix_str in &body.prefixes {
        if let Some((addr, len)) = parse_cidr(prefix_str) {
            trie.insert(addr, len, prefix_str, None, None);
        }
    }

    PrefixTrie::aggregate_node(&mut trie.root);

    let mut aggregated: Vec<String> = Vec::new();
    PrefixTrie::collect_endpoints(&trie.root, 0, 0, &mut aggregated);

    let aggregated_set: std::collections::HashSet<&str> =
        aggregated.iter().map(|s| s.as_str()).collect();

    let removed: Vec<String> = original
        .iter()
        .filter(|p| !aggregated_set.contains(p.as_str()))
        .cloned()
        .collect();

    let reduction_pct = if original.is_empty() {
        0u8
    } else {
        ((removed.len() as f32 / original.len() as f32) * 100.0) as u8
    };

    Response::from_json(&AggregateResponse { aggregated, removed, reduction_pct })
}

async fn handle_lpm(mut req: Request) -> Result<Response> {
    let text = req.text().await?;
    let body: LpmRequest = serde_json::from_str(&text)
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let ip_addr = match parse_ipv4(&body.ip) {
        Some(a) => a,
        None => return Response::error(format!("Invalid IP: {}", body.ip), 400),
    };

    let mut trie = PrefixTrie::new();
    for prefix_str in &body.prefixes {
        if let Some((addr, len)) = parse_cidr(prefix_str) {
            trie.insert(addr, len, prefix_str, None, None);
        }
    }

    let result = trie.lpm(ip_addr);
    Response::from_json(&LpmResponse {
        matched_prefix: result.map(|(p, _)| p.to_string()),
        matched_length: result.map(|(_, l)| l),
        ip: body.ip,
    })
}

async fn handle_specifics(mut req: Request) -> Result<Response> {
    let text = req.text().await?;
    let body: SpecificsRequest = serde_json::from_str(&text)
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let total_checked = body.prefixes.len();
    let mut candidates: Vec<HijackCandidate> = Vec::new();

    for entry in &body.prefixes {
        let (addr, len) = match parse_cidr(&entry.prefix) {
            Some(v) => v,
            None => continue,
        };

        // Build a trie of all OTHER prefixes that are less specific (shorter prefix).
        // A prefix cannot cover itself, and more-specifics can't be supernets.
        //
        // Note: This is O(n) trie builds for n entries = O(n²) total.
        // For typical ASNs (50-500 prefixes) this is fast (microseconds).
        // For tier-1 carriers with 50,000+ prefixes, a single-pass walk would
        // be needed. Documented here as a known trade-off.
        let mut search_trie = PrefixTrie::new();
        for other in &body.prefixes {
            if other.prefix == entry.prefix {
                continue;
            }
            if let Some((other_addr, other_len)) = parse_cidr(&other.prefix) {
                if other_len < len {
                    search_trie.insert(
                        other_addr,
                        other_len,
                        &other.prefix,
                        other.origin,
                        other.rpki_validation.as_deref(),
                    );
                }
            }
        }

        if let Some((covering_prefix, covering_origin, covering_rpki)) =
            search_trie.find_covering_prefix(addr, len)
        {
            let (risk, reason) = score_risk(
                covering_origin,
                entry.origin,
                entry.rpki_validation.as_deref(),
            );
            candidates.push(HijackCandidate {
                covering_prefix: covering_prefix.to_string(),
                covering_origin,
                covering_rpki: covering_rpki.map(|s| s.to_string()),
                specific_prefix: entry.prefix.clone(),
                specific_origin: entry.origin,
                specific_rpki: entry.rpki_validation.clone(),
                risk: risk.to_string(),
                reason: reason.to_string(),
            });
        }
    }

    let total_flagged = candidates.len();
    Response::from_json(&SpecificsResponse {
        hijack_candidates: candidates,
        total_checked,
        total_flagged,
    })
}

// ── Main fetch handler ────────────────────────────────────────────────────────

#[event(fetch)]
async fn fetch(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    set_panic_hook();

    let path = req.path();
    let method = req.method();

    match (method, path.as_str()) {
        (Method::Post, "/aggregate") => handle_aggregate(req).await,
        (Method::Post, "/lpm")       => handle_lpm(req).await,
        (Method::Post, "/specifics") => handle_specifics(req).await,
        (Method::Options, _)         => {
            let mut h = Headers::new();
            h.set("Access-Control-Allow-Origin", "*")?;
            h.set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
            h.set("Access-Control-Allow-Headers", "Content-Type")?;
            Ok(Response::empty()?.with_headers(h))
        }
        _ => Response::error(
            format!("Not found: {} {}", req.method(), path),
            404,
        ),
    }
}
