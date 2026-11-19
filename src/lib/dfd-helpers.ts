import type { DfdComponent, Threat } from "@/lib/stride-engine";

export type RiskLevel = Threat["risk"];

const RISK_RANK: Record<RiskLevel, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

const GENERIC_TOKENS = new Set([
  "service",
  "services",
  "server",
  "servers",
  "system",
  "systems",
  "component",
  "components",
  "layer",
  "layers",
  "app",
  "application",
  "applications",
  "module",
  "modules",
  "endpoint",
  "endpoints",
  "interface",
  "platform",
  "engine",
  "manager",
  "handler",
  "tier",
  "zone",
  "internal",
  "external",
  "primary",
  "main",
  "core",
  "backend",
  "frontend",
  "the",
  "and",
  "for",
  "with",
  "via",
  "from",
  "into",
]);

/** Canonical Mermaid node ID for the i-th component in a DFD. */
export function getDfdNodeId(index: number): string {
  return `N${index}`;
}

function normalizeLabel(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\s]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tokenize(s: string): string[] {
  return normalizeLabel(s)
    .split(" ")
    .filter((w) => w.length >= 2 && !GENERIC_TOKENS.has(w));
}

/** Validate and deduplicate raw threat IDs against an optional set of known IDs. */
export function sanitizeThreatIds(
  raw: unknown,
  validIds?: ReadonlySet<string>
): string[] {
  if (!Array.isArray(raw)) return [];

  // Map canonical numeric threat IDs (e.g. "T8" -> "T008") when validIds is supplied
  let numericLookup: Map<string, string> | null = null;
  if (validIds && validIds.size > 0) {
    numericLookup = new Map<string, string>();
    for (const id of validIds) {
      const m = id.match(/^T0*(\d+)$/);
      if (m) {
        const key = `T${parseInt(m[1], 10)}`;
        if (!numericLookup.has(key)) numericLookup.set(key, id);
      }
    }
  }

  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const rawUpper = item.trim().toUpperCase();
    if (!rawUpper) continue;

    // Normalize common variants like "T-001", "T_001", or "T8" -> "T008"
    const compact = rawUpper.replace(/^(T)[-_](\d{1,4})$/, "$1$2");
    let candidate = compact;
    if (validIds) {
      if (validIds.has(rawUpper)) {
        candidate = rawUpper;
      } else if (validIds.has(compact)) {
        candidate = compact;
      } else if (numericLookup) {
        const m = compact.match(/^T0*(\d+)$/);
        const resolved = m ? numericLookup.get(`T${parseInt(m[1], 10)}`) : undefined;
        if (!resolved) continue;
        candidate = resolved;
      } else {
        continue;
      }
    } else if (!/^T\d{1,4}$/.test(candidate)) {
      continue;
    }

    if (seen.has(candidate)) continue;
    seen.add(candidate);
    out.push(candidate);
    if (out.length >= 12) break;
  }
  return out;
}

/** Sort threat IDs by highest risk first, then numerically/alphabetically. */
export function sortThreatIds(
  ids: string[],
  threatById: Map<string, Threat>
): string[] {
  return [...ids].sort((a, b) => {
    const ra = RISK_RANK[threatById.get(a)?.risk ?? "Medium"] ?? 0;
    const rb = RISK_RANK[threatById.get(b)?.risk ?? "Medium"] ?? 0;
    if (rb !== ra) return rb - ra;
    return a.localeCompare(b, undefined, { numeric: true });
  });
}

const ROLE_SYNONYM_GROUPS: RegExp[] = [
  /\b(waf|cdn|cloudflare|edge|firewall|ddos)\b/i,
  /\b(gateway|ingress|proxy|load\s*balancer|router)\b/i,
  /\b(auth|authentication|oauth|oidc|saml|sso|jwt|token|identity|idp|cognito|okta|auth0)\b/i,
  /\b(llm|orchestrator|rag|agent|planner|prompt|inference|chatbot|completion)\b/i,
  /\b(embed|embedding|embeddings)\b/i,
  /\b(vector|pinecone|pgvector|qdrant|weaviate|milvus)\b/i,
  /\b(database|db|sql|postgres|postgresql|mysql|mongo|mongodb|dynamodb|storage|s3|blob|bucket|knowledge)\b/i,
  /\b(cache|redis|memcached|session)\b/i,
  /\b(secret|vault|kms|credential|key\s*management)\b/i,
  /\b(audit|log|logging|telemetry|siem|monitor)\b/i,
  /\b(user|browser|client|mobile|frontend|web\s*ui|portal|customer)\b/i,
];

function scoreComponentMatch(
  componentName: string,
  componentType: DfdComponent["type"],
  threatComponentRaw: string,
  threatTitle: string,
  threatDescription = ""
): number {
  const normComp = normalizeLabel(componentName);
  const normThreatComp = normalizeLabel(threatComponentRaw);
  if (!normComp) return 0;

  if (normThreatComp) {
    // Split composite threat component strings (e.g. "API Gateway / Auth Service")
    const segments = threatComponentRaw
      .split(/[/,;&+]|->|\band\b/i)
      .map((s) => normalizeLabel(s))
      .filter(Boolean);

    for (const seg of [normThreatComp, ...segments]) {
      if (seg === normComp) return 100;
      if (seg.length >= 4 && normComp.length >= 4) {
        if (seg.includes(normComp) || normComp.includes(seg)) return 75;
      }
    }
  }

  const compTokens = new Set(tokenize(componentName));
  const threatTokens = new Set([
    ...tokenize(threatComponentRaw),
    ...tokenize(threatTitle).filter((w) => compTokens.has(w)),
  ]);

  let overlap = 0;
  for (const tok of compTokens) {
    if (threatTokens.has(tok)) overlap++;
  }

  // Direct token overlap always outranks heuristic role fallbacks
  if (overlap > 0) {
    return 30 + overlap * 15;
  }

  // Exact component name mention inside the threat description when threat.component is broad
  if (normComp.length >= 5 && threatDescription) {
    const normDesc = normalizeLabel(threatDescription);
    if (normDesc.includes(normComp)) {
      return 26;
    }
  }

  // Semantic role-group fallback when exact wording differs (e.g., "RAG Pipeline" vs "AI Orchestrator")
  const threatContext = `${normThreatComp} ${normalizeLabel(threatTitle)}`;
  let roleHits = 0;
  for (const groupRe of ROLE_SYNONYM_GROUPS) {
    if (groupRe.test(normComp) && groupRe.test(threatContext)) {
      roleHits++;
    }
  }
  if (roleHits > 0) {
    return 18 + Math.min(2, roleHits) * 2;
  }

  // Fallback for database/cache/storage aliases when wording differs slightly
  if (componentType === "Data Store" && normThreatComp) {
    const storeHint = /\b(db|database|sql|postgres|mysql|mongo|store|storage|redis|cache|bucket|s3|vault|secret|vector)\b/i;
    if (storeHint.test(normThreatComp) && storeHint.test(normComp)) {
      return 18;
    }
  }

  return 0;
}

/**
 * Reconciles LLM-provided `threatIds` and deterministically links threats from
 * the STRIDE Threat Model onto matching DFD components.
 *
 * Ensures:
 * - Only real threat IDs from `threats` are kept (no hallucinated IDs).
 * - Exact-name affected components always receive their matching threat ID.
 * - Unlinked threats are matched cleanly to the best matching component(s)
 *   so diagrams reliably display real threat tags like `T008`, `T011`, etc.
 * - Tags are sorted by highest severity first.
 */
export function reconcileDfdComponentThreats(
  components: DfdComponent[],
  threats?: Threat[]
): DfdComponent[] {
  if (!threats || threats.length === 0) {
    return components.map((c) => ({
      ...c,
      threatIds: c.threatIds ? sanitizeThreatIds(c.threatIds) : undefined,
    }));
  }

  const threatById = new Map<string, Threat>();
  const validIds = new Set<string>();
  for (const t of threats) {
    const id = t.id.trim().toUpperCase().replace(/^(T)[-_](\d{1,4})$/, "$1$2");
    if (!id) continue;
    validIds.add(id);
    threatById.set(id, { ...t, id });
  }

  // Start with validated server-returned threatIds
  const sets = components.map((c) => new Set(sanitizeThreatIds(c.threatIds, validIds)));

  // Track which threats are already linked to at least one component
  const alreadyLinked = new Set<string>();
  for (const s of sets) {
    for (const id of s) alreadyLinked.add(id);
  }

  // Ensure exact-match affected components always carry their threat ID,
  // and deterministically match any unlinked threat to its strongest DFD component(s)
  for (const [id, threat] of threatById) {
    const scored = components
      .map((c, idx) => ({
        idx,
        score: scoreComponentMatch(
          c.name,
          c.type,
          threat.component || "",
          threat.threat || "",
          threat.description || ""
        ),
      }))
      .filter((x) => x.score >= 18)
      .sort((a, b) => b.score - a.score);

    if (scored.length === 0) continue;

    if (alreadyLinked.has(id)) {
      // If the threat names a DFD component verbatim, ensure that component has it too
      for (const match of scored) {
        if (match.score === 100) {
          sets[match.idx].add(id);
        }
      }
      continue;
    }

    const topScore = scored[0].score;
    // Always attach to top match; also attach a second match if tied or composite
    sets[scored[0].idx].add(id);
    if (scored[1] && scored[1].score >= Math.max(40, topScore - 15)) {
      sets[scored[1].idx].add(id);
    }
  }

  return components.map((c, idx) => {
    const sorted = sortThreatIds(Array.from(sets[idx]), threatById);
    return sorted.length > 0 ? { ...c, threatIds: sorted } : { ...c, threatIds: [] };
  });
}
