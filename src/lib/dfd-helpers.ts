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
  "management",
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
  "web",
  "internet",
  "facing",
  "cloud",
  "data",
  "flow",
  "the",
  "and",
  "for",
  "with",
  "via",
  "from",
  "into",
  "of",
  "to",
  "in",
  "on",
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

function tokenize(s: string, stopTokens?: ReadonlySet<string>): string[] {
  return normalizeLabel(s)
    .split(" ")
    .filter(
      (w) =>
        w.length >= 2 &&
        !GENERIC_TOKENS.has(w) &&
        !(stopTokens && stopTokens.has(w))
    );
}

/**
 * Detect brand/app-name tokens repeated across 3+ DFD components
 * (e.g. "mediportal" appearing in 3+ components). Treating these as
 * non-distinctive prevents unrelated components from sharing false matches.
 */
function findSharedPrefixTokens(components: DfdComponent[]): Set<string> {
  if (components.length < 3) return new Set();
  const docFreq = new Map<string, number>();
  for (const c of components) {
    const uniqueTokens = new Set(tokenize(c.name));
    for (const tok of uniqueTokens) {
      docFreq.set(tok, (docFreq.get(tok) ?? 0) + 1);
    }
  }
  const shared = new Set<string>();
  for (const [tok, count] of docFreq) {
    if (count >= 3) {
      shared.add(tok);
    }
  }
  return shared;
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
  /\b(web\s*app|webapp|web\s*application|web\s*portal|frontend|spa|website|internet\s*facing\s*web)\b/i,
  /\b(auth|authentication|oauth|oidc|saml|sso|jwt|token|identity|idp|cognito|okta|auth0)\b/i,
  /\b(rbac|authorization|authorisation|access\s*control|policy|acl|permission)\b/i,
  /\b(session|cookie|csrf)\b/i,
  /\b(llm|orchestrator|rag|agent|planner|prompt|inference|chatbot|completion)\b/i,
  /\b(embed|embedding|embeddings)\b/i,
  /\b(vector|pinecone|pgvector|qdrant|weaviate|milvus)\b/i,
  /\b(database|db|sql|postgres|postgresql|mysql|mongo|mongodb|dynamodb|storage|s3|blob|bucket|ehr|records)\b/i,
  /\b(cache|redis|memcached)\b/i,
  /\b(secret|vault|kms|credential|key\s*management)\b/i,
  /\b(audit|log|logging|telemetry|siem|monitor)\b/i,
];

const EXTERNAL_ACTOR_RE =
  /\b(user|browser|client|mobile|customer|patient|clinician|provider|partner|admin)\b/i;

const COMPOSITE_SPLIT_RE = /[/,;&+]|->|\band\b/i;

function splitCompositeSegments(raw: string): string[] {
  return raw
    .split(COMPOSITE_SPLIT_RE)
    .map((s) => normalizeLabel(s))
    .filter(Boolean);
}

/**
 * Score how accurately a single DFD component matches a single target
 * component phrase (either the full `threat.component` or one segment of a
 * composite `threat.component`).
 *
 * Scoring tiers (strictly ordered so exact/component-field matches always
 * beat fuzzy fallbacks and unrelated components score 0):
 *   100     Exact normalized match against target component phrase
 *   92      Exact distinctive-core match (ignoring shared brand prefix)
 *   78-88   Strong multi-word containment (weighted by coverage >= 45%)
 *   42-76   Distinctive token overlap (Jaccard/recall) against target phrase
 *   32-38   Exact component name mention inside threat title/description
 *   20-26   Semantic role-group / Data Store / External Entity fallback
 *   0       No reliable match
 */
function scoreComponentAgainstTarget(
  componentName: string,
  componentType: DfdComponent["type"],
  targetPhraseRaw: string,
  threatTitle: string,
  threatDescription: string,
  sharedTokens: ReadonlySet<string>
): number {
  const normComp = normalizeLabel(componentName);
  const normTarget = normalizeLabel(targetPhraseRaw);
  if (!normComp) return 0;

  // Strip shared brand/prefix tokens for clean distinctive matching
  const compDistinct = new Set(tokenize(componentName, sharedTokens));
  const compAllTokens = new Set(tokenize(componentName));

  if (normTarget) {
    // Tier 1: Exact normalized match
    if (normTarget === normComp) return 100;

    // Tier 2: Distinctive-core exact match or high-coverage containment
    const compCore = Array.from(compDistinct).join(" ");
    const targetDistinct = tokenize(normTarget, sharedTokens);
    const targetCore = targetDistinct.join(" ");

    if (compCore && targetCore && targetCore === compCore) {
      return 92;
    }

    if (normTarget.length >= 5 && normComp.length >= 5) {
      if (normTarget.includes(normComp) || normComp.includes(normTarget)) {
        const shorter = Math.min(normTarget.length, normComp.length);
        const longer = Math.max(normTarget.length, normComp.length);
        const ratio = shorter / longer;
        if (ratio >= 0.45) {
          return Math.round(78 + ratio * 10);
        }
      }
    }

    // Tier 3: Distinctive token overlap strictly against target component phrase
    const targetDistinctSet = new Set(targetDistinct);
    if (compDistinct.size > 0 && targetDistinctSet.size > 0) {
      let overlap = 0;
      for (const tok of compDistinct) {
        if (targetDistinctSet.has(tok)) overlap++;
      }
      if (overlap > 0) {
        const unionSize = compDistinct.size + targetDistinctSet.size - overlap;
        const jaccard = overlap / Math.max(1, unionSize);
        const recall = overlap / compDistinct.size;
        if (overlap >= 2 || jaccard >= 0.34 || recall >= 0.5) {
          return Math.round(42 + jaccard * 28 + Math.min(2, overlap - 1) * 4);
        }
      }
    }
  }

  // Tier 4: Exact component name mentioned verbatim in the threat title/description
  if (compDistinct.size >= 2) {
    const normTitle = normalizeLabel(threatTitle);
    const normDesc = normalizeLabel(threatDescription);
    if (normComp.length >= 6 && normTitle.includes(normComp)) {
      return 38;
    }
    if (normComp.length >= 6 && normDesc.includes(normComp)) {
      return 32;
    }
  } else if (compAllTokens.size >= 1) {
    const normTitle = normalizeLabel(threatTitle);
    if (normComp.length >= 6 && normTitle.includes(normComp)) {
      return 34;
    }
  }

  // Tier 5: Semantic role-group fallback strictly comparing componentName vs targetPhrase
  if (normTarget) {
    let roleHits = 0;
    for (const groupRe of ROLE_SYNONYM_GROUPS) {
      if (groupRe.test(normComp) && groupRe.test(normTarget)) {
        roleHits++;
      }
    }
    if (roleHits > 0) {
      return 22 + Math.min(2, roleHits) * 2;
    }

    // Data Store alias fallback strictly against targetPhrase
    if (componentType === "Data Store") {
      const storeHint = /\b(db|database|sql|postgres|mysql|mongo|store|storage|redis|cache|bucket|s3|vault|secret|vector)\b/i;
      if (storeHint.test(normTarget) && storeHint.test(normComp)) {
        return 20;
      }
    }

    // External Entity actor fallback strictly for External Entity nodes
    if (
      componentType === "External Entity" &&
      EXTERNAL_ACTOR_RE.test(normComp) &&
      EXTERNAL_ACTOR_RE.test(normTarget)
    ) {
      return 20;
    }
  }

  return 0;
}

/**
 * Reconciles LLM-provided `threatIds` and deterministically links threats from
 * the STRIDE Threat Model onto the exact matching DFD component(s).
 *
 * Accuracy guarantees:
 * - Rejects hallucinated or invalid threat IDs not present in `threats`.
 * - Audits LLM-assigned `threatIds` and drops misplaced tags when a threat
 *   clearly belongs to a different component (no wrong-component leakage).
 * - Ignores shared app-name prefixes (e.g. "MediPortal ...") during matching
 *   so distinct components never collide on the application name.
 * - Evaluates each segment of a composite `threat.component` (e.g. "A / B")
 *   independently so each segment binds to its exact component without
 *   bleeding onto a third unrelated node.
 * - Sorts threat IDs by highest severity first.
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

  const sharedTokens = findSharedPrefixTokens(components);

  // Collect sanitized LLM-proposed component assignments per threat
  const llmAssignedIndices = new Map<string, number[]>();
  components.forEach((c, idx) => {
    for (const id of sanitizeThreatIds(c.threatIds, validIds)) {
      const list = llmAssignedIndices.get(id) ?? [];
      list.push(idx);
      llmAssignedIndices.set(id, list);
    }
  });

  const sets = components.map(() => new Set<string>());

  for (const [id, threat] of threatById) {
    const compField = threat.component || "";
    const segments = splitCompositeSegments(compField);
    const targetPhrases = segments.length > 0 ? segments : [compField];
    const isComposite = targetPhrases.length > 1;

    // Score every component against each target segment independently
    const segmentScores = targetPhrases.map((phrase) =>
      components.map((c) =>
        scoreComponentAgainstTarget(
          c.name,
          c.type,
          phrase,
          threat.threat || "",
          threat.description || "",
          sharedTokens
        )
      )
    );

    // Best deterministic winner(s) per segment
    const segmentWinners = new Set<number>();
    const bestScorePerComp = components.map((_, idx) =>
      Math.max(0, ...segmentScores.map((s) => s[idx] ?? 0))
    );

    for (const scores of segmentScores) {
      const ranked = scores
        .map((score, idx) => ({ idx, score }))
        .filter((x) => x.score >= 20)
        .sort((a, b) => b.score - a.score);
      if (ranked.length === 0) continue;
      segmentWinners.add(ranked[0].idx);
      // Include an exact-score tie at >= 92 (e.g. duplicated component label)
      if (ranked[1] && ranked[1].score >= 92 && ranked[1].score === ranked[0].score) {
        segmentWinners.add(ranked[1].idx);
      }
    }

    const overallTopScore = Math.max(0, ...bestScorePerComp);
    const llmIdxs = llmAssignedIndices.get(id) ?? [];

    // 1. Validate LLM-assigned links: keep only links that are genuinely relevant
    //    and do not contradict a much stronger deterministic component match.
    const verifiedLlmIdxs: number[] = [];
    for (const idx of llmIdxs) {
      const s = bestScorePerComp[idx] ?? 0;
      if (overallTopScore >= 42) {
        const threshold = isComposite ? 42 : Math.max(42, overallTopScore - 10);
        if (s >= threshold) {
          verifiedLlmIdxs.push(idx);
        }
      } else if (overallTopScore >= 20) {
        if (s >= 20) {
          verifiedLlmIdxs.push(idx);
        }
      } else {
        // No lexical match at all (e.g. DFD completely renamed a component):
        // trust at most the first LLM assignment if the LLM explicitly linked it
        if (verifiedLlmIdxs.length === 0) {
          verifiedLlmIdxs.push(idx);
        }
      }
    }

    if (verifiedLlmIdxs.length > 0) {
      for (const idx of verifiedLlmIdxs) {
        sets[idx].add(id);
      }
      // Guarantee every deterministic segment winner with strong/exact match is linked
      for (const idx of segmentWinners) {
        if ((bestScorePerComp[idx] ?? 0) >= (isComposite ? 42 : 92)) {
          sets[idx].add(id);
        }
      }
      continue;
    }

    // 2. Deterministic attachment when LLM didn't link (or misplaced) the threat
    for (const idx of segmentWinners) {
      sets[idx].add(id);
    }
  }

  return components.map((c, idx) => {
    const sorted = sortThreatIds(Array.from(sets[idx]), threatById);
    return sorted.length > 0 ? { ...c, threatIds: sorted } : { ...c, threatIds: [] };
  });
}
