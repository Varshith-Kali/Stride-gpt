/**
 * STRIDE GPT — Threat modeling engine.
 * Calls the OpenAI Responses API (POST /v1/responses) using the user-provided
 * API key. The key is passed server-side only — never stored or logged.
 *
 * All functions in this module run server-side only (Next.js API routes).
 */
import type { LlmConfig } from "@/lib/llm-config";
import { sanitizeThreats, sanitizeText, clamp, LIMITS } from "@/lib/validation";

/**
 * A session-only image supplied by the user (architecture diagram etc.).
 * Held in React state client-side; sent as base64 data-URLs in the request
 * body — never persisted to any storage layer.
 */
export interface LlmImage {
  /** MIME type — one of the server-side ALLOWED_IMAGE_TYPES. */
  mimeType: "image/png" | "image/jpeg" | "image/webp";
  /** Full data-URL: "data:image/png;base64,..." */
  dataUrl: string;
  /** Original filename for display only. Never sent to the LLM. */
  name: string;
}

export type AppType =
  | "Web application"
  | "Mobile application"
  | "Desktop application"
  | "Cloud service/API"
  | "IoT device"
  | "Generative AI application"
  | "Agentic AI application"
  | "Microservice architecture"
  | "Other";

export type AuthMethod =
  | "None"
  | "Username/password"
  | "OAuth 2.0"
  | "SAML"
  | "SSO"
  | "API keys"
  | "JWT"
  | "Biometric"
  | "Certificate-based";


export interface ThreatModelInput {
  appName: string;
  appType: AppType;
  description: string;
  authentication: AuthMethod[];
  internetFacing: boolean;
  sensitiveData: boolean;
  usesCloud: boolean;
  hasMultipleTenants: boolean;
}

export interface Threat {
  id: string;
  category: string;
  threat: string;
  component: string;
  description: string;
  strideCategory:
    | "Spoofing"
    | "Tampering"
    | "Repudiation"
    | "Information Disclosure"
    | "Denial of Service"
    | "Elevation of Privilege";
  mitreAttack?: string[];
  risk: "Low" | "Medium" | "High" | "Critical";
}

export interface ThreatModelResult {
  threats: Threat[];
  summary: string;
  architectureNotes: string;
  detectedPatterns: string[];
}

export interface AttackTreeNode {
  goal: string;
  subgoals: AttackTreeNode[];
}

export interface AttackTreeResult {
  root: AttackTreeNode;
  mermaid: string;
  narrative: string;
}

export interface Mitigation {
  threat: string;
  mitigation: string;
  priority: "Low" | "Medium" | "High";
  owaspReference?: string;
}

export interface MitigationResult {
  mitigations: Mitigation[];
  hardeningChecklist: string[];
}

export interface DreadScore {
  threat: string;
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
  total: number;
  severity: "Low" | "Medium" | "High" | "Critical";
}

export interface DfdResult {
  mermaid: string;
  components: { name: string; type: string; trustLevel: string }[];
  flows: { from: string; to: string; description: string }[];
  narrative: string;
}

export interface GherkinResult {
  feature: string;
  scenarios: {
    title: string;
    given: string;
    when: string;
    then: string[];
  }[];
}

/** A single prioritized recommendation produced by generateRecommendations. */
export interface Recommendation {
  /** Threat IDs this recommendation addresses (e.g. ["T001", "T003"]). */
  threatIds: string[];
  /** One-sentence imperative action. */
  action: string;
  /** 3–5 concrete implementation steps. */
  steps: string[];
  /** Implementation effort relative estimate. */
  effort: "Low" | "Medium" | "High";
  /** Expected risk reduction summary. */
  riskReduction: string;
}

export interface RecommendationResult {
  recommendations: Recommendation[];
  executiveSummary: string;
}

const SYSTEM_PROMPT = `You are STRIDE GPT, an elite security architect specializing in threat modeling using the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). You are also an expert in OWASP LLM Top 10, OWASP Agentic AI Top 10 (ASI), MITRE ATT&CK Enterprise, and MITRE ATLAS for ML/AI systems. You produce precise, actionable, structured security analysis.`;

function buildContextString(input: ThreatModelInput): string {
  return `APPLICATION CONTEXT:
- Name: ${input.appName || "Unspecified"}
- Type: ${input.appType}
- Description: ${input.description}
- Authentication methods: ${input.authentication.length ? input.authentication.join(", ") : "None specified"}
- Internet-facing: ${input.internetFacing ? "Yes" : "No"}
- Processes sensitive data: ${input.sensitiveData ? "Yes" : "No"}
- Cloud-hosted: ${input.usesCloud ? "Yes" : "No"}
- Multi-tenant: ${input.hasMultipleTenants ? "Yes" : "No"}`;
}

/**
 * Parse loose LLM JSON output, stripping code fences and extracting the
 * first valid {...} or [...] block. Returns the parsed value cast to a
 * loose record type, or null on failure.
 *
 * Typed as `Record<string, unknown>` (rather than `any`) so callers get
 * IntelliSense on property access and cannot silently pass the result to
 * typed functions without explicit narrowing. Array results (e.g. DREAD)
 * are accessed at call sites via `parsed as unknown[]`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseJsonLoose(text: string): Record<string, any> | null {
  // Strip code fences and extract the first {...} or [...] block.
  const cleaned = text.replace(/```json\s*/gi, "").replace(/```\s*$/g, "").trim();
  const start = cleaned.search(/[{[]/);
  if (start === -1) return null;
  // Find matching close by scanning
  const openChar = cleaned[start];
  const closeChar = openChar === "{" ? "}" : "]";
  let depth = 0;
  let end = -1;
  let inString = false;
  let escape = false;
  for (let i = start; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (inString) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === '"') inString = false;
    } else {
      if (ch === '"') inString = true;
      else if (ch === openChar) depth++;
      else if (ch === closeChar) {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
  }
  if (end === -1) return null;
  const slice = cleaned.slice(start, end + 1);
  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return JSON.parse(slice);
  } catch {
    return null;
  }
}

/**
 * Normalize an LLM-returned threat label back to the closest canonical threat
 * title from the original input list.
 *
 * WHY: LLMs often paraphrase threat titles when generating mitigations or
 * DREAD scores (e.g. "Malicious Prompt Injection" vs "Prompt Injection Attack").
 * This causes the exact-key lookup in the Excel builder to miss, leaving the
 * Recommendation / DREAD columns blank.
 *
 * STRATEGY (3-tier, fast and dependency-free):
 * 1. Exact lowercase match  — handles the common case
 * 2. Substring containment  — handles "Prompt Injection" ⊂ "Malicious Prompt Injection"
 * 3. Word-overlap scoring   — handles rephrased titles with shared key words
 *    (only counts words ≥ 4 chars to skip stop-words like "the", "and", "via")
 *
 * Falls back to the original raw string if no match scores > 0.
 */
function closestThreatTitle(
  raw: string,
  canonicalTitles: Map<string, string>  // lowercase → original
): string {
  const key = raw.toLowerCase().trim();

  // Tier 1: exact match
  const exact = canonicalTitles.get(key);
  if (exact) return exact;

  // Tier 2: substring containment (either direction)
  for (const [k, v] of canonicalTitles) {
    if (key.includes(k) || k.includes(key)) return v;
  }

  // Tier 3: word-overlap scoring (skip stop-words shorter than 4 chars)
  const rawWords = new Set(key.split(/\W+/).filter((w) => w.length >= 4));
  let bestTitle = raw;
  let bestScore = 0;
  for (const [k, v] of canonicalTitles) {
    const score = k.split(/\W+/)
      .filter((w) => w.length >= 4 && rawWords.has(w)).length;
    if (score > bestScore) {
      bestScore = score;
      bestTitle = v;
    }
  }
  return bestScore > 0 ? bestTitle : raw;
}

/**
 * Standardized error thrown by all LLM calls. Carries a `kind` so the UI
 * can render appropriate guidance (geo-block vs. invalid key vs. timeout).
 */
export class LlmError extends Error {
  kind:
    | "geo-block"
    | "invalid-key"
    | "rate-limit"
    | "timeout"
    | "provider"
    | "network";
  status?: number;
  constructor(
    kind: LlmError["kind"],
    message: string,
    status?: number
  ) {
    super(message);
    this.name = "LlmError";
    this.kind = kind;
    this.status = status;
  }
}

/** Request timeout for all LLM calls (90s — generation can be slow). */
const LLM_TIMEOUT_MS = 90_000;

/**
 * Fetch with a timeout via AbortController. Rejects with an LlmError of kind
 * "timeout" if the provider doesn't respond within LLM_TIMEOUT_MS.
 */
async function fetchWithTimeout(
  url: string,
  // eslint-disable-next-line no-undef -- RequestInit is a valid TypeScript DOM global
  init: RequestInit,
  timeoutMs = LLM_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new LlmError(
        "timeout",
        `Request timed out after ${timeoutMs / 1000}s. The provider may be overloaded — try again.`
      );
    }
    throw new LlmError(
      "network",
      `Network error reaching provider: ${e instanceof Error ? e.message : "unknown"}`
    );

  } finally {
    clearTimeout(timer);
  }
}

/**
 * Classify an OpenAI HTTP error response into a typed LlmError.
 * Reference: https://platform.openai.com/docs/guides/error-codes
 */
function classifyOpenAIError(status: number, body: string): LlmError {
  // 401 — invalid or expired API key
  if (status === 401) {
    return new LlmError(
      "invalid-key",
      "Invalid OpenAI API key (401). Verify the key is correct and hasn't been revoked.",
      status
    );
  }
  // 403 — org-level restriction or key scope issue
  if (status === 403) {
    return new LlmError(
      "invalid-key",
      "Access denied (403). Your API key may lack permission to access this model. Check your OpenAI organization settings.",
      status
    );
  }
  // 429 — rate limit or quota
  if (status === 429) {
    return new LlmError(
      "rate-limit",
      "Rate limited (429). You have exceeded your OpenAI quota or request rate. Wait a moment and try again.",
      status
    );
  }
  // 400 — bad request (malformed body, model not found, content filter)
  if (status === 400) {
    if (body.includes("content_filter") || body.includes("content filter")) {
      return new LlmError(
        "provider",
        "OpenAI content filter blocked this request. Try rephrasing the application description.",
        status
      );
    }
    return new LlmError(
      "provider",
      `OpenAI rejected the request (400): ${body.slice(0, 200) || "bad request"}`,
      status
    );
  }
  // 5xx — server-side OpenAI error
  if (status >= 500) {
    return new LlmError(
      "provider",
      `OpenAI server error (${status}). The service may be temporarily unavailable — try again shortly.`,
      status
    );
  }
  return new LlmError(
    "provider",
    `OpenAI API error ${status}: ${body.slice(0, 200) || "unknown error"}`,
    status
  );
}

/**
 * Call the OpenAI Responses API.
 *
 * Endpoint: POST https://api.openai.com/v1/responses
 * Auth:     Authorization: Bearer <apiKey>
 * Docs:     https://platform.openai.com/docs/api-reference/responses
 *
 * IMPORTANT: The Responses API does NOT support role:"system" inside the
 * `input` array. The system instruction must go in the top-level
 * `instructions` field. The `input` array contains only user/assistant turns.
 *
 * Response shape:
 *   output[0].content[0].text  — standard output_text item
 *   output[0].content          — plain string (some model variants)
 *   output[0].text             — direct text field (some internal models)
 *
 * Security:
 * - API key travels only in the encrypted Authorization header of this
 *   server-side fetch. It is never logged, cached, or returned to the client.
 * - The request body is validated and sanitized upstream before reaching here.
 */
/**
 * A single content part for a multimodal LLM message.
 * Matches the OpenAI Responses API input_text / input_image shapes.
 */
type ContentPart =
  | { type: "input_text"; text: string }
  | { type: "input_image"; image_url: string };

type LlmMessage =
  | { role: "user" | "assistant"; content: string }
  | { role: "user"; content: ContentPart[] };

/**
 * Build a multimodal user message from a text prompt and optional images.
 * Images are appended as input_image parts after the text.
 * If no images, returns a plain string content message (lower token overhead).
 */
function buildUserMessage(
  text: string,
  images?: LlmImage[]
): LlmMessage {
  if (!images || images.length === 0) {
    return { role: "user", content: text };
  }
  const parts: ContentPart[] = [
    { type: "input_text", text },
    ...images.map((img): ContentPart => ({
      type: "input_image",
      image_url: img.dataUrl,
    })),
  ];
  return { role: "user", content: parts };
}

async function callLLM(
  config: LlmConfig,
  messages: LlmMessage[]
): Promise<string> {
  let res: Response;
  try {
    res = await fetchWithTimeout(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          model: config.model,
          // System prompt goes in `instructions`, NOT in the input array.
          instructions: SYSTEM_PROMPT,
          input: messages,
        }),
      }
    );
  } catch (e) {
    if (e instanceof LlmError) throw e;
    throw new LlmError(
      "network",
      `Failed to reach OpenAI: ${(e as Error).message}`
    );
  }

  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw classifyOpenAIError(res.status, errText);
  }

  const data = await res.json().catch(() => null) as Record<string, unknown> | null;

  // --- Extract text from all known Responses API output shapes ---
  //
  // GPT-5.5 is a reasoning model and returns MULTIPLE output items:
  //   output[0] = { type: "reasoning", content: [] }   ← empty, skip this
  //   output[1] = { type: "message",   content: [{type:"output_text", text:"..."}] }
  //
  // Standard models return a single output item:
  //   output[0] = { type: "message", content: [{type:"output_text", text:"..."}] }
  //
  // We must iterate ALL output items and find the first "message" type with content.

  const outputArr = Array.isArray(data?.output)
    ? (data.output as Record<string, unknown>[])
    : [];

  for (const outputItem of outputArr) {
    // Skip reasoning/thinking items — they have empty content
    if (outputItem.type === "reasoning") continue;

    // Shape 1 (standard): content is an array of items with .text
    if (Array.isArray(outputItem.content)) {
      const contentArr = outputItem.content as Record<string, unknown>[];
      for (const item of contentArr) {
        if (typeof item.text === "string" && item.text.length > 0) return item.text;
        if (typeof item.transcript === "string" && item.transcript.length > 0) return item.transcript;
      }
      // Check for content filter refusal
      for (const item of contentArr) {
        if (item.refusal) {
          throw new LlmError("provider", `OpenAI refused to generate a response: ${String(item.refusal)}`);
        }
      }
    }

    // Shape 2: content is a plain string
    if (typeof outputItem.content === "string" && outputItem.content.length > 0) {
      return outputItem.content;
    }

    // Shape 3: some models return .text directly on the output item
    if (typeof outputItem.text === "string" && outputItem.text.length > 0) {
      return outputItem.text;
    }
  }

  // Shape 4: top-level text field (non-standard but seen in some proxies)
  if (data && typeof (data as Record<string, unknown>).text === "string") {
    const t = (data as Record<string, unknown>).text as string;
    if (t.length > 0) return t;
  }

  // Log full structure for server-side debugging only — never reaches client
  console.error("[callLLM] Could not extract text. Full response:", JSON.stringify(data)?.slice(0, 2000));
  throw new LlmError("provider", "OpenAI returned an empty or unrecognized response.");

}


export async function generateThreatModel(
  config: LlmConfig,
  input: ThreatModelInput,
  images?: LlmImage[]
): Promise<ThreatModelResult> {
  const context = buildContextString(input);
  const isAi =
    input.appType === "Generative AI application" ||
    input.appType === "Agentic AI application";

  const prompt = `${context}${
    images && images.length > 0
      ? `\n- Architecture diagrams provided: ${images.length} image(s) — analyse them for additional trust boundaries, data flows, and components.`
      : ""
  }

TASK: Produce a comprehensive STRIDE threat model for this application.${
    isAi
      ? " Since this is an AI application, also incorporate OWASP LLM Top 10 (LLM01–LLM10) and, for agentic systems, OWASP ASI Top 10 (ASI01–ASI10)."
      : ""
  } Also detect any relevant architectural patterns (e.g., RAG pipeline, multi-agent system, code execution environment, tool/MCP ecosystem).

Return ONLY a JSON object (no prose, no markdown fences) with this exact shape:
{
  "threats": [
    {
      "id": "T001",
      "category": "short category label",
      "threat": "concise threat title",
      "component": "affected component",
      "description": "detailed explanation including attack vector and impact",
      "strideCategory": "one of: Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",
      "mitreAttack": ["TXXXX (optional technique id with name)"],
      "risk": "Low | Medium | High | Critical"
    }
  ],
  "summary": "2-3 sentence executive summary of the risk profile",
  "architectureNotes": "notes on architectural weak points and trust boundaries",
  "detectedPatterns": ["detected architectural pattern 1", "..."]
}

Produce at least 8 and up to 14 distinct threats covering all six STRIDE categories.`;

  const raw = await callLLM(config, [
    buildUserMessage(prompt, images),
  ]);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.threats)) {
    return {
      threats: [],
      summary: "Unable to parse threat model output. Please try again.",
      architectureNotes: "",
      detectedPatterns: [],
    };
  }
  return {
    threats: sanitizeThreats(parsed.threats),
    summary: clamp(sanitizeText(parsed.summary ?? ""), 1000),
    architectureNotes: clamp(sanitizeText(parsed.architectureNotes ?? ""), 4000),
    detectedPatterns: Array.isArray(parsed.detectedPatterns)
      ? parsed.detectedPatterns
          .filter((p: unknown) => typeof p === "string")
          .map((p: string) => clamp(sanitizeText(p), 100))
          .slice(0, 20)
      : [],
  };
}

export async function generateAttackTree(
  config: LlmConfig,
  input: ThreatModelInput
): Promise<AttackTreeResult> {
  const context = buildContextString(input);
  const prompt = `${context}

TASK: Build an attack tree showing how an adversary could compromise this application. The root node is the attacker's primary goal ("Compromise ${input.appName || "the application"}"). Sub-goals should decompose into concrete techniques, including at least 3 levels of depth and 6-8 leaf techniques.

Return ONLY a JSON object (no prose, no markdown fences) with this exact shape:
{
  "root": {
    "goal": "primary attacker goal",
    "subgoals": [
      {
        "goal": "sub-goal",
        "subgoals": [
          { "goal": "leaf technique", "subgoals": [] }
        ]
      }
    ]
  },
  "narrative": "2-3 paragraph narrative explaining the most plausible attack paths"
}

I will render the Mermaid diagram myself from the tree structure.`;

  const raw = await callLLM(config, [{ role: "user", content: prompt }]);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !parsed.root) {
    return {
      root: { goal: "Compromise application", subgoals: [] },
      mermaid: "graph TD\n  root[Compromise application]",
      narrative: "Unable to generate attack tree. Please try again.",
    };
  }
  return {
    root: parsed.root,
    mermaid: treeToMermaid(parsed.root),
    narrative: parsed.narrative ?? "",
  };
}

function sanitizeMermaidNode(label: string): string {
  return label.replace(/"/g, "'").replace(/[\[\]{}|><]/g, " ").trim();
}

function treeToMermaid(
  node: AttackTreeNode,
  parentId?: string,
  counter: { n: number } = { n: 0 }
): string {
  const id = parentId ? `n${counter.n++}` : "root";
  const safeLabel = sanitizeMermaidNode(node.goal);
  const lines = parentId
    ? [`  ${id}["${safeLabel}"]`, `  ${parentId} --> ${id}`]
    : [`  ${id}["${safeLabel}"]`];
  for (const child of node.subgoals ?? []) {
    lines.push(treeToMermaid(child, id, counter));
  }
  return lines.join("\n");
}

export async function generateMitigations(
  config: LlmConfig,
  input: ThreatModelInput,
  threats: Threat[]
): Promise<MitigationResult> {
  const context = buildContextString(input);
  const threatSummary = threats
    .map((t) => `- [${t.strideCategory}] ${t.threat}: ${t.description}`)
    .join("\n");
  const prompt = `${context}

IDENTIFIED THREATS:
${threatSummary}

TASK: For each threat above, propose a concrete, implementable mitigation. Also produce a hardening checklist of 6-10 security controls every team member should verify.

Return ONLY a JSON object (no prose, no markdown fences) with this exact shape:
{
  "mitigations": [
    {
      "threat": "the threat title being mitigated",
      "mitigation": "specific control or countermeasure with implementation guidance",
      "priority": "Low | Medium | High",
      "owaspReference": "optional reference e.g. A01:2021-Broken Access Control"
    }
  ],
  "hardeningChecklist": ["checklist item 1", "..."]
}`;

  const raw = await callLLM(config, [{ role: "user", content: prompt }]);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.mitigations)) {
    return { mitigations: [], hardeningChecklist: [] };
  }

  // Build a canonical-title lookup so we can normalise the LLM's threat labels
  // back to the exact titles used in the threat model (prevents blank Excel cells).
  const canonicalTitles = new Map<string, string>();
  for (const t of threats) {
    canonicalTitles.set(t.threat.toLowerCase().trim(), t.threat);
  }

  return {
    mitigations: parsed.mitigations
      .filter(
        (m: unknown): m is Record<string, unknown> =>
          m !== null && typeof m === "object" &&
          typeof (m as Record<string, unknown>).threat === "string" &&
          typeof (m as Record<string, unknown>).mitigation === "string"
      )
      .map((m: Record<string, unknown>) => ({
        // Normalise the LLM's threat label back to the exact canonical title
        // so the Excel builder's exact-key lookup always finds a match.
        threat:         closestThreatTitle(
                          clamp(sanitizeText(m.threat as string), LIMITS.THREAT_TITLE),
                          canonicalTitles
                        ),
        mitigation:     clamp(sanitizeText(m.mitigation as string), 2000),
        priority:       (["Low", "Medium", "High"] as readonly string[]).includes(m.priority as string)
                          ? (m.priority as "Low" | "Medium" | "High")
                          : "Medium",
        owaspReference: typeof m.owaspReference === "string"
                          ? clamp(sanitizeText(m.owaspReference), 100)
                          : undefined,
      }))
      .slice(0, LIMITS.MAX_MITIGATIONS),
    hardeningChecklist: Array.isArray(parsed.hardeningChecklist)
      ? (parsed.hardeningChecklist as unknown[])
          .filter((c): c is string => typeof c === "string")
          .map((c) => clamp(sanitizeText(c), 500))
          .slice(0, 20)
      : [],
  };
}


export async function generateDreadScores(
  config: LlmConfig,
  threats: Threat[]
): Promise<DreadScore[]> {
  const threatList = threats.map((t) => `- ${t.id}: ${t.threat}`).join("\n");
  const prompt = `THREATS TO SCORE:
${threatList}

TASK: Score each threat using the DREAD model. Each dimension is 1-10 (10 = worst). Total = sum of 5 dimensions. Severity bands: <10 Low, 10-19 Medium, 20-29 High, 30-50 Critical.

Return ONLY a JSON array (no prose, no markdown fences) with this shape:
[
  {
    "threat": "threat title",
    "damage": 1-10,
    "reproducibility": 1-10,
    "exploitability": 1-10,
    "affectedUsers": 1-10,
    "discoverability": 1-10,
    "total": number,
    "severity": "Low | Medium | High | Critical"
  }
]`;

  const raw = await callLLM(config, [{ role: "user", content: prompt }]);
  const parsed = parseJsonLoose(raw);

  // Build canonical-title lookup to normalise LLM's threat labels.
  const canonicalTitles = new Map<string, string>();
  for (const t of threats) {
    canonicalTitles.set(t.threat.toLowerCase().trim(), t.threat);
  }

  const SEVERITY_VALUES = ["Low", "Medium", "High", "Critical"] as const;
  const clampScore = (v: unknown): number => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.min(10, Math.max(1, Math.round(n))) : 5;
  };
  return (parsed as unknown[])
    .filter(
      (d): d is Record<string, unknown> =>
        !!d && typeof d === "object" && typeof (d as Record<string, unknown>).threat === "string"
    )
    .map((d: Record<string, unknown>) => {
      const damage          = clampScore(d.damage);
      const reproducibility = clampScore(d.reproducibility);
      const exploitability  = clampScore(d.exploitability);
      const affectedUsers   = clampScore(d.affectedUsers);
      const discoverability = clampScore(d.discoverability);
      const total = damage + reproducibility + exploitability + affectedUsers + discoverability;
      const severity: DreadScore["severity"] = SEVERITY_VALUES.includes(d.severity as DreadScore["severity"])
        ? (d.severity as DreadScore["severity"])
        : total >= 30 ? "Critical" : total >= 20 ? "High" : total >= 10 ? "Medium" : "Low";
      return {
        // Normalise the LLM's threat label so Excel DREAD columns map correctly.
        threat:          closestThreatTitle(
                           clamp(sanitizeText(d.threat as string), LIMITS.THREAT_TITLE),
                           canonicalTitles
                         ),
        damage,
        reproducibility,
        exploitability,
        affectedUsers,
        discoverability,
        total,
        severity,
      };
    })
    .slice(0, LIMITS.MAX_THREATS);
}



export async function generateDfd(
  config: LlmConfig,
  input: ThreatModelInput
): Promise<DfdResult> {
  const context = buildContextString(input);
  const prompt = `${context}

TASK: Generate a Level-0 Data Flow Diagram (DFD) for this application. Identify external entities, processes, data stores, and trust boundaries. Use concise component names (1-3 words, no special characters). Mark trust levels: "High" for trusted/internal services, "Medium" for processing layers, "Low" for anything internet-facing or third-party.

Return ONLY a JSON object (no prose, no markdown fences) with this shape:
{
  "components": [
    { "name": "concise name", "type": "External Entity | Process | Data Store | Trust Boundary", "trustLevel": "High | Medium | Low" }
  ],
  "flows": [
    { "from": "source component name (must match a component name exactly)", "to": "destination component name (must match a component name exactly)", "description": "what data flows, in 3-6 words" }
  ],
  "narrative": "2-3 sentence explanation of the data flow and trust boundaries"
}`;

  const raw = await callLLM(config, [{ role: "user", content: prompt }]);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.components)) {
    return { components: [], flows: [], narrative: "", mermaid: "graph LR" };
  }
  const result: DfdResult = {
    components: parsed.components,
    flows: parsed.flows ?? [],
    narrative: parsed.narrative ?? "",
    mermaid: dfdToMermaid(parsed.components, parsed.flows ?? []),
  };
  return result;
}

function dfdToMermaid(
  components: { name: string; type: string; trustLevel: string }[],
  flows: { from: string; to: string; description: string }[]
): string {
  // Use a stable ID derived from the component index so flow edges can reference
  // them reliably even if names contain characters Mermaid dislikes.
  const idMap = new Map<string, string>();
  components.forEach((c, i) => {
    idMap.set(c.name, `N${i}`);
  });

  const lines: string[] = ["flowchart LR"];

  // Trust boundary subgraph wrapper: group high-trust and low-trust nodes
  // into separate subgraphs so the diagram shows trust boundaries visually.
  const high = components.filter((c) => c.trustLevel === "High");
  const low = components.filter((c) => c.trustLevel === "Low");
  const mid = components.filter((c) => c.trustLevel === "Medium");

  const renderNode = (c: { name: string; type: string; trustLevel: string }) => {
    const id = idMap.get(c.name)!;
    const safeName = c.name.replace(/"/g, "'").replace(/\[/g, "(").replace(/\]/g, ")");
    // DFD shapes per standard conventions:
    //   External Entity  →  rounded rectangle  ([ ])
    //   Process          →  rectangle          [ ]
    //   Data Store       →  cylinder           [( )]
    //   Trust Boundary   →  hexagon            {{ }}
    const shape =
      c.type === "External Entity"
        ? `([${safeName}])`
        : c.type === "Data Store"
        ? `[(${safeName})]`
        : c.type === "Trust Boundary"
        ? `{{${safeName}}}`
        : `[${safeName}]`;
    return `  ${id}${shape}`;
  };

  if (high.length > 0) {
    lines.push(`  subgraph Trusted ["Trusted Zone"]`);
    high.forEach((c) => lines.push(renderNode(c)));
    lines.push(`  end`);
  }
  if (mid.length > 0) {
    lines.push(`  subgraph Internal ["Internal Zone"]`);
    mid.forEach((c) => lines.push(renderNode(c)));
    lines.push(`  end`);
  }
  if (low.length > 0) {
    lines.push(`  subgraph Untrusted ["Untrusted Zone"]`);
    low.forEach((c) => lines.push(renderNode(c)));
    lines.push(`  end`);
  }
  // Any components without a recognized trust level get rendered loose
  components
    .filter(
      (c) => c.trustLevel !== "High" && c.trustLevel !== "Medium" && c.trustLevel !== "Low"
    )
    .forEach((c) => lines.push(renderNode(c)));

  // Edges with concise, quote-safe labels
  flows.forEach((f) => {
    const fromId = idMap.get(f.from);
    const toId = idMap.get(f.to);
    if (!fromId || !toId) return;
    const label = f.description.replace(/"/g, "'").slice(0, 48);
    lines.push(`  ${fromId} -- "${label}" --> ${toId}`);
  });

  // Styling — neutral, draw.io-friendly
  lines.push("  classDef trusted fill:#ffffff,stroke:#171717,stroke-width:2px,color:#171717;");
  lines.push("  classDef internal fill:#f5f5f5,stroke:#525252,stroke-width:1.5px,color:#171717;");
  lines.push("  classDef untrusted fill:#fafafa,stroke:#a3a3a3,stroke-width:1.5px,stroke-dasharray:4 3,color:#525252;");

  high.forEach((c) => lines.push(`  class ${idMap.get(c.name)} trusted;`));
  mid.forEach((c) => lines.push(`  class ${idMap.get(c.name)} internal;`));
  low.forEach((c) => lines.push(`  class ${idMap.get(c.name)} untrusted;`));

  return lines.join("\n");
}

export async function generateGherkin(
  config: LlmConfig,
  threats: Threat[]
): Promise<GherkinResult> {
  const threatList = threats.map((t) => `- ${t.threat}: ${t.description}`).join("\n");
  const prompt = `THREATS:
${threatList}

TASK: Generate Gherkin (BDD) test cases that verify the system defends against each threat. Each scenario should be concrete and testable.

Return ONLY a JSON object (no prose, no markdown fences) with this shape:
{
  "feature": "Feature: Threat Mitigation Verification",
  "scenarios": [
    {
      "title": "Scenario: descriptive title",
      "given": "Given ... precondition",
      "when": "When ... action",
      "then": ["Then ... expected outcome 1", "And ... outcome 2"]
    }
  ]
}`;

  const raw = await callLLM(config, [{ role: "user", content: prompt }]);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.scenarios)) {
    return { feature: "Feature: Threat Mitigation Verification", scenarios: [] };
  }
  return {
    feature: clamp(
      sanitizeText(parsed.feature ?? "Feature: Threat Mitigation Verification"),
      200
    ),
    scenarios: Array.isArray(parsed.scenarios)
      ? (parsed.scenarios as unknown[])
          .filter(
            (s): s is Record<string, unknown> =>
              s !== null &&
              typeof s === "object" &&
              typeof (s as Record<string, unknown>).title === "string" &&
              typeof (s as Record<string, unknown>).given === "string" &&
              typeof (s as Record<string, unknown>).when  === "string" &&
              Array.isArray((s as Record<string, unknown>).then)
          )
          .map((s: Record<string, unknown>) => ({
            title: clamp(sanitizeText(s.title as string), 200),
            given: clamp(sanitizeText(s.given as string), 500),
            when:  clamp(sanitizeText(s.when  as string), 500),
            then:  (s.then as unknown[])
              .filter((t): t is string => typeof t === "string")
              .map((t) => clamp(sanitizeText(t), 500))
              .slice(0, 10),
          }))
          .slice(0, LIMITS.MAX_GHERKIN_SCENARIOS)
      : [],
  };
}

/**
 * Generate prioritized security recommendations.
 *
 * TOKEN-OPTIMIZED DESIGN:
 * Instead of re-sending the full original prompt (~1500 tokens), we send a
 * compact structured summary (~300-500 tokens) containing:
 *   1. One-line app summary (type, auth, flags, description excerpt)
 *   2. Each threat as one compact line: ID | STRIDE | Risk | Title
 *   3. Only justification lines where the analyst filled something in
 *   4. Images if provided (same session images as the threat model call)
 *
 * The LLM has all domain knowledge from training; it needs structured signal,
 * not repetition of the full description.
 */
export async function generateRecommendations(
  config: LlmConfig,
  threats: Threat[],
  justifications: Record<string, string>,
  appInput: ThreatModelInput,
  images?: LlmImage[]
): Promise<RecommendationResult> {
  // --- Compact app summary (~30 tokens) ---
  const flags = [
    appInput.internetFacing     ? "internet-facing" : null,
    appInput.sensitiveData      ? "sensitive-data"  : null,
    appInput.usesCloud          ? "cloud"           : null,
    appInput.hasMultipleTenants ? "multi-tenant"    : null,
  ].filter(Boolean).join(", ");

  const appSummary =
    `${appInput.appName || "App"} | ${appInput.appType} | ` +
    `Auth: ${appInput.authentication.join("+") || "none"} | ` +
    `Flags: ${flags || "none"} | ` +
    `Desc: ${clamp(sanitizeText(appInput.description), 300)}`;

  // --- Compact threat list: one line per threat, analyst note inline ---
  const threatLines = threats
    .map((t) => {
      const note = justifications[t.id]?.trim();
      return note
        ? `${t.id} [${t.strideCategory}/${t.risk}] ${t.threat} | ANALYST: ${clamp(sanitizeText(note), 200)}`
        : `${t.id} [${t.strideCategory}/${t.risk}] ${t.threat}`;
    })
    .join("\n");

  const hasNotes = threats.some((t) => justifications[t.id]?.trim());

  const prompt =
    `APPLICATION:\n${appSummary}` +
    (images && images.length > 0
      ? `\nARCHITECTURE DIAGRAMS: ${images.length} diagram(s) attached — use them for component-specific recommendations.`
      : "") +
    `\n\nTHREAT MODEL (${threats.length} threats):\n${threatLines}` +
    (hasNotes
      ? "\n\nNOTE: Lines marked ANALYST contain security architect context — weight these heavily when prioritising."
      : "") +
    `\n\nTASK: Generate concise, prioritized security recommendations. Group related threats where logical. Prioritize by risk level and analyst context. Be specific and actionable.\n\nReturn ONLY a JSON object (no prose, no markdown fences):\n{\n  "recommendations": [\n    {\n      "threatIds": ["T001", "T002"],\n      "action": "one-sentence imperative action",\n      "steps": ["concrete step 1", "step 2", "step 3"],\n      "effort": "Low | Medium | High",\n      "riskReduction": "what risk this eliminates or reduces"\n    }\n  ],\n  "executiveSummary": "2-3 sentence summary of the overall recommendation posture"\n}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
  const parsed = parseJsonLoose(raw);

  if (!parsed || !Array.isArray(parsed.recommendations)) {
    return {
      recommendations: [],
      executiveSummary: "Unable to generate recommendations. Please try again.",
    };
  }

  const recommendations: Recommendation[] = (parsed.recommendations as unknown[])
    .filter((r): r is Record<string, unknown> => !!r && typeof r === "object")
    .map((r: Record<string, unknown>) => ({
      threatIds: Array.isArray(r.threatIds)
        ? (r.threatIds as unknown[]).filter((id): id is string => typeof id === "string").slice(0, 20)
        : [],
      action: clamp(sanitizeText((r.action as string) ?? ""), 300),
      steps: Array.isArray(r.steps)
        ? (r.steps as unknown[])
            .filter((s): s is string => typeof s === "string")
            .map((s) => clamp(sanitizeText(s), 300))
            .slice(0, 8)
        : [],
      effort: (["Low", "Medium", "High"] as readonly string[]).includes(r.effort as string)
        ? (r.effort as Recommendation["effort"])
        : "Medium",
      riskReduction: clamp(sanitizeText((r.riskReduction as string) ?? ""), 300),
    }))
    .slice(0, 30);

  return {
    recommendations,
    executiveSummary: clamp(sanitizeText((parsed.executiveSummary as string) ?? ""), 1000),
  };
}
