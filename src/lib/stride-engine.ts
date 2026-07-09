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

/**
 * Safety evaluation for a single threat, assessed against the user-provided
 * existing controls. Verdict is one of three states:
 *   SAFE           — controls fully address the threat
 *   PARTIALLY_SAFE — controls partially address the threat; gaps remain
 *   UNSAFE         — controls are absent, insufficient, or bypassed
 */
export type SafetyVerdict = "SAFE" | "PARTIALLY_SAFE" | "UNSAFE";

export interface SafetyMetric {
  /** Threat ID (e.g. "T001") */
  threatId: string;
  /** Verbatim threat title from the threat model */
  threat: string;
  /** Evaluation verdict */
  verdict: SafetyVerdict;
  /**
   * 2–4 sentence reasoning explaining why the controls are sufficient,
   * insufficient, or absent. Grounded in the STRIDE category and MITRE ATT&CK
   * context. Actionable where possible.
   */
  reasoning: string;
  /**
   * 1–3 specific gaps or improvements the architect should address.
   * Empty array when verdict is SAFE.
   */
  gaps: string[];
}

export interface SafetyMetricsResult {
  metrics: SafetyMetric[];
  /** One-paragraph executive-level summary of the overall security posture. */
  overallPosture: string;
}

const SYSTEM_PROMPT = [
  "You are STRIDE GPT — a principal security architect and threat modeling authority.",
  "Specializations: STRIDE, OWASP LLM Top 10, OWASP Agentic AI / ASI Top 10, MITRE ATT&CK Enterprise, MITRE ATLAS for ML/AI.",
  "OUTPUT RULES (strictly enforced):",
  "  1. Return ONLY valid JSON matching the schema requested. No prose, no markdown fences, no commentary.",
  "  2. MITRE ATT&CK IDs must be real published techniques (e.g. T1078, T1190). Never invent IDs.",
  "  3. Risk levels (Low/Medium/High/Critical) must reflect realistic exploitability and impact — not worst-case by default.",
  "  4. Threat descriptions must name the specific attack vector, affected component, and realistic impact.",
  "  5. Do not repeat threats — each entry must be distinct in vector, component, or impact.",
].join("\n");

/**
 * Compact key=value context block. ~30% fewer tokens than prose format
 * with zero information loss. Faster TTFT on reasoning models.
 */
function buildContextString(input: ThreatModelInput): string {
  const flags = [
    input.internetFacing    ? "internet-facing"      : "internal-only",
    input.sensitiveData     ? "processes-PII/secrets" : "non-sensitive-data",
    input.usesCloud         ? "cloud-hosted"          : "on-premise",
    input.hasMultipleTenants ? "multi-tenant"         : "single-tenant",
  ].join(", ");
  return (
    `APP_NAME=${input.appName || "(unnamed)"}` +
    `\nAPP_TYPE=${input.appType}` +
    `\nAUTH=${input.authentication.length ? input.authentication.join("+") : "none"}` +
    `\nFLAGS=${flags}` +
    `\nDESCRIPTION:\n${input.description}`
  );
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

/**
 * Request timeout — 120 s matches the Next.js route `maxDuration = 120`.
 * GPT-5.5 is a reasoning model: TTFT is higher but structured JSON output
 * completes quickly once reasoning finishes. Align to the route cap.
 */
const LLM_TIMEOUT_MS = 120_000;

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
  // 429 — rate limit or quota; parse Retry-After if present
  if (status === 429) {
    const retryAfterMatch = body.match(/retry.after["\s:]+([\d.]+)/i);
    const retryHint = retryAfterMatch
      ? ` Retry after ${Math.ceil(parseFloat(retryAfterMatch[1]))}s.`
      : " Wait a moment and try again.";
    return new LlmError(
      "rate-limit",
      `Rate limited (429). You have exceeded your OpenAI quota or request rate.${retryHint}`,
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
          // Force JSON output — model CANNOT return markdown fences or prose.
          // Eliminates the parseJsonLoose fallback path on every call.
          response_format: { type: "json_object" },
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

  const hasImages = images && images.length > 0;

  const prompt =
    `${context}` +
    (hasImages
      ? `\n\nARCHITECTURE DIAGRAM ANALYSIS (${images!.length} diagram(s) attached):` +
        `\nBefore generating threats, carefully analyse every uploaded diagram to identify:` +
        `\n  - All components, services, APIs, databases, queues, caches, and external systems visible` +
        `\n  - Trust boundaries and network zones (DMZ, internal, cloud VPC, on-premise)` +
        `\n  - Data flows, protocols, and communication patterns between components` +
        `\n  - Authentication/authorisation touchpoints and where credentials are exchanged` +
        `\n  - Any misconfigurations, overly permissive rules, or security gaps visible in the diagram` +
        `\n  - Third-party integrations and supply chain touchpoints` +
        `\nThe diagram is the ground truth for architecture — the description supplements it. Prioritise what you see in the diagram.`
      : "") +
    `\n\nTASK: Produce a comprehensive STRIDE threat model for this application.` +
    (isAi
      ? " Since this is an AI application, also incorporate OWASP LLM Top 10 (LLM01–LLM10) and, for agentic systems, OWASP ASI Top 10 (ASI01–ASI10)."
      : "") +
    ` Detect any relevant architectural patterns (e.g., RAG pipeline, multi-agent system, code execution environment, tool/MCP ecosystem, microservices mesh, event-driven architecture).` +
    `\n\nThreat generation rules:` +
    `\n  - Every threat MUST reference a specific component or data flow from the application description${hasImages ? " or the uploaded diagram" : ""}` +
    `\n  - Include the realistic attack vector (not just the category)` +
    `\n  - Risk level must reflect exploitability given the authentication method(s) and deployment context` +
    `\n  - MITRE ATT&CK IDs must be real published techniques — never invent an ID` +
    `\n  - Cover all six STRIDE categories; complex or multi-service apps warrant 15–20 threats` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "threats": [\n` +
    `    {\n` +
    `      "id": "T001",\n` +
    `      "category": "short category label",\n` +
    `      "threat": "concise threat title naming the component and attack",\n` +
    `      "component": "exact component name from the architecture",\n` +
    `      "description": "attack vector, exploitation method, and business impact in 2-3 sentences",\n` +
    `      "strideCategory": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",\n` +
    `      "mitreAttack": ["T1078 Valid Accounts"],\n` +
    `      "risk": "Low | Medium | High | Critical"\n` +
    `    }\n` +
    `  ],\n` +
    `  "summary": "3-4 sentence executive summary of the overall risk profile and top-3 concerns",\n` +
    `  "architectureNotes": "specific weak points, trust boundary violations, and high-risk data flows identified",\n` +
    `  "detectedPatterns": ["pattern 1", "pattern 2"]\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
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
    summary: clamp(sanitizeText(parsed.summary ?? ""), 1500),
    architectureNotes: clamp(sanitizeText(parsed.architectureNotes ?? ""), 4000),
    detectedPatterns: Array.isArray(parsed.detectedPatterns)
      ? parsed.detectedPatterns
          .filter((p: unknown) => typeof p === "string")
          .map((p: string) => clamp(sanitizeText(p), 150))
          .slice(0, 20)
      : [],
  };
}

export async function generateAttackTree(
  config: LlmConfig,
  input: ThreatModelInput,
  images?: LlmImage[]
): Promise<AttackTreeResult> {
  const context = buildContextString(input);
  const hasImages = images && images.length > 0;
  const prompt =
    `${context}` +
    (hasImages
      ? `\n\nARCHITECTURE DIAGRAMS (${images!.length} attached): Use the visible components, entry points, and trust boundaries to ground the attack paths in the actual architecture.`
      : "") +
    `\n\nTASK: Build a realistic attack tree for this application. ` +
    `The root goal is "Compromise ${input.appName || "the application"}". ` +
    `Decompose into sub-goals and leaf techniques reflecting the actual components${hasImages ? " visible in the diagram" : " described"}. ` +
    `Minimum 3 levels of depth, 6-10 distinct leaf techniques. ` +
    `Leaf techniques must reference specific components (e.g., "Exploit JWT misconfiguration in Auth Service", not just "Authentication bypass").` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "root": {\n` +
    `    "goal": "Compromise ${input.appName || "the application"}",\n` +
    `    "subgoals": [\n` +
    `      {\n` +
    `        "goal": "sub-goal",\n` +
    `        "subgoals": [{ "goal": "leaf technique referencing a specific component", "subgoals": [] }]\n` +
    `      }\n` +
    `    ]\n` +
    `  },\n` +
    `  "narrative": "2-3 paragraph narrative of the most plausible attack paths and the critical chokepoints to defend"\n` +
    `}\n\nI will render the Mermaid diagram from the tree structure.`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
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
  threats: Threat[],
  images?: LlmImage[]
): Promise<MitigationResult> {
  const context = buildContextString(input);
  const threatSummary = threats
    .map((t) => `- [${t.strideCategory}] ${t.threat}: ${t.description}`)
    .join("\n");
  const hasImages = images && images.length > 0;
  const prompt =
    `${context}` +
    (hasImages
      ? `\n\nARCHITECTURE DIAGRAMS (${images!.length} attached): Use the visible components and architecture to make mitigations specific to the actual deployment — not generic advice.`
      : "") +
    `\n\nIDENTIFIED THREATS (${threats.length} total):\n${threatSummary}` +
    `\n\nTASK: For each threat above, propose a concrete, implementable mitigation tailored to this specific application and its architecture.` +
    `\n\nMitigation quality rules:` +
    `\n  - Each mitigation must be actionable by an engineering team, not generic advice` +
    `\n  - Reference the specific component, library, framework, or configuration that needs to change` +
    `\n  - Include the relevant OWASP or NIST control reference where applicable` +
    `\n  - Priority (High/Medium/Low) must reflect the threat's risk level AND ease of exploitation` +
    `\n  - Hardening checklist items must be verification steps, not just category headings` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "mitigations": [\n` +
    `    {\n` +
    `      "threat": "exact threat title from the list above",\n` +
    `      "mitigation": "specific, implementable control with component reference and configuration guidance",\n` +
    `      "priority": "Low | Medium | High",\n` +
    `      "owaspReference": "e.g. A01:2021-Broken Access Control or NIST SP 800-53 AC-3"\n` +
    `    }\n` +
    `  ],\n` +
    `  "hardeningChecklist": [\n` +
    `    "Verify: specific, testable security control for this application"\n` +
    `  ]\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
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
  threats: Threat[],
  input?: ThreatModelInput,
  images?: LlmImage[]
): Promise<DreadScore[]> {
  const context = input ? buildContextString(input) + "\n\n" : "";
  const threatList = threats.map((t) => `- ${t.id}: ${t.threat}`).join("\n");
  const hasImages = images && images.length > 0;
  const prompt =
    `${context}` +
    `\n\nTHREATS TO SCORE (${threats.length} total):\n${threatList}` +
    (hasImages
      ? `\n\nARCHITECTURE DIAGRAMS (${images!.length} attached): ` +
        `Use the visible deployment context — internet exposure, component criticality, data sensitivity — ` +
        `to calibrate scores. A component directly exposed to the internet warrants higher exploitability and discoverability scores.`
      : "") +
    `\n\nTASK: Score each threat using the DREAD model calibrated to this specific application context.` +
    `\n\nDREAD scoring rules:` +
    `\n  - Damage (1-10): potential business/data impact if the threat is fully exploited` +
    `\n  - Reproducibility (1-10): how reliably an attacker can reproduce the attack` +
    `\n  - Exploitability (1-10): skill/resources required (10 = unauthenticated, trivial exploit)` +
    `\n  - Affected Users (1-10): breadth of impact (10 = all users or all tenants)` +
    `\n  - Discoverability (1-10): how easily the vulnerability can be found (10 = publicly known)` +
    `\n  - Total = sum of all 5 dimensions. Severity: <10 Low, 10-19 Medium, 20-29 High, 30-50 Critical` +
    `\n  - Scores must be differentiated — avoid scoring every threat identically` +
    `\n\nReturn ONLY a JSON array (no prose, no markdown fences):\n` +
    `[\n` +
    `  {\n` +
    `    "threat": "exact threat title",\n` +
    `    "damage": 1-10,\n` +
    `    "reproducibility": 1-10,\n` +
    `    "exploitability": 1-10,\n` +
    `    "affectedUsers": 1-10,\n` +
    `    "discoverability": 1-10,\n` +
    `    "total": <sum>,\n` +
    `    "severity": "Low | Medium | High | Critical"\n` +
    `  }\n` +
    `]`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
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
  input: ThreatModelInput,
  images?: LlmImage[]
): Promise<DfdResult> {
  const context = buildContextString(input);
  const hasImages = images && images.length > 0;
  const prompt =
    `${context}` +
    (hasImages
      ? `\n\nARCHITECTURE DIAGRAMS (${images!.length} attached): Derive the component names, trust zones, and data flows directly from the diagram — do not invent components not visible or described.`
      : "") +
    `\n\nTASK: Generate a Level-0 Data Flow Diagram (DFD) for this application.` +
    (hasImages
      ? ` The diagram is the primary source — extract every visible component, service, database, queue, and external actor.`
      : "") +
    `\n\nDFD generation rules:` +
    `\n  - Component names: 1-4 words, no special characters, must be unique` +
    `\n  - Types: External Entity (users, third-party APIs), Process (services, functions), Data Store (DB, cache, queue), Trust Boundary` +
    `\n  - Trust levels: High = internal/trusted services, Medium = processing/middleware, Low = internet-facing or third-party` +
    `\n  - Flow "from"/"to" values MUST exactly match a component name in the components array` +
    `\n  - Flow descriptions: what data travels and in which direction (3-6 words)` +
    `\n  - Every internet-facing entry point must be a component` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences):\n` +
    `{\n` +
    `  "components": [\n` +
    `    { "name": "API Gateway", "type": "Process", "trustLevel": "Low" }\n` +
    `  ],\n` +
    `  "flows": [\n` +
    `    { "from": "API Gateway", "to": "Auth Service", "description": "JWT validation request" }\n` +
    `  ],\n` +
    `  "narrative": "2-3 sentence description of the data flow, trust zones, and primary security boundaries"\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);
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
  threats: Threat[],
  input?: ThreatModelInput
): Promise<GherkinResult> {
  const threatList = threats.map((t) => `- [${t.strideCategory}] ${t.threat}: ${t.description}`).join("\n");
  const appContext = input ? buildContextString(input) : "";
  const appName = input?.appName || "the application";
  const prompt =
    (appContext ? `APPLICATION CONTEXT:\n${appContext}\n\n` : "") +
    `STRIDE THREATS (${threats.length} total):\n${threatList}` +
    `\n\nTASK: Generate Gherkin (BDD) acceptance test scenarios that verify ${appName} defends against each threat above.` +
    `\n\nScenario rules:` +
    `\n  - Each scenario must be directly testable by a QA engineer using the application's actual stack` +
    `\n  - "Given" must name a real application state (logged in as X, with Y configured, etc.)` +
    `\n  - "When" must describe an attacker's concrete action against a specific component or endpoint` +
    `\n  - "Then" outcomes must be observable system responses, not abstract assertions` +
    `\n  - Cover both the attack attempt AND the expected defensive response` +
    `\n  - Generate one scenario per threat` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences):\n` +
    `{\n` +
    `  "feature": "Feature: Security Threat Mitigation Verification for ${appName}",\n` +
    `  "scenarios": [\n` +
    `    {\n` +
    `      "title": "Scenario: specific attack scenario title",\n` +
    `      "given": "Given a specific precondition naming the component or user role",\n` +
    `      "when": "When the attacker performs the specific action against the specific component",\n` +
    `      "then": ["Then the system responds with a specific defence", "And the attempt is logged"]\n` +
    `    }\n` +
    `  ]\n` +
    `}`;

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

/**
 * Evaluate the current security posture for each threat by comparing the
 * threat model line items against the user-provided existing controls.
 *
 * Each threat receives a verdict of SAFE / PARTIALLY_SAFE / UNSAFE plus
 * concise reasoning and a list of gaps to address.
 *
 * The full application context and any uploaded architecture diagrams are
 * included so the LLM has maximum signal for an accurate assessment.
 */
export async function generateSafetyMetrics(
  config: LlmConfig,
  input: ThreatModelInput,
  threats: import("@/lib/stride-engine").Threat[],
  /** Per-threat existing controls, keyed by threat ID. May be partial. */
  currentControls: Record<string, string>,
  images?: LlmImage[]
): Promise<SafetyMetricsResult> {
  if (threats.length === 0) {
    throw new LlmError("provider", "No threats to evaluate.");
  }

  const context = buildContextString(input);

  // Build a compact threat + controls summary for each threat
  const threatControlPairs = threats
    .map((t) => {
      const ctrl = (currentControls[t.id] ?? "").trim();
      return (
        `[${t.id}] STRIDE: ${t.strideCategory} | Risk: ${t.risk}\n` +
        `Threat: ${t.threat}\n` +
        `Description: ${t.description}\n` +
        `Component: ${t.component}\n` +
        (t.mitreAttack && t.mitreAttack.length > 0
          ? `MITRE ATT&CK: ${t.mitreAttack.join(", ")}\n`
          : "") +
        `Current Controls: ${ctrl || "NONE PROVIDED"}`
      );
    })
    .join("\n\n---\n\n");

  const prompt =
    `${context}` +
    (images && images.length > 0
      ? `\n\nARCHITECTURE DIAGRAMS (${images.length} attached): ` +
        `Use the visible deployment, network zones, and component interactions to assess whether listed controls ` +
        `would realistically be effective given the actual architecture.`
      : "") +
    `\n\nSECURITY POSTURE EVALUATION — ${threats.length} THREAT(S)` +
    `\n\nYou are evaluating whether the user's CURRENT SECURITY CONTROLS adequately mitigate each identified threat.` +
    `\nThis is NOT a mitigation recommendation exercise — it is a factual assessment of what is already in place.` +
    `\n\nVERDICT DEFINITIONS (strictly apply these):` +
    `\n  SAFE           — Controls FULLY and DEMONSTRABLY mitigate this threat. Coverage is unambiguous and defence-in-depth exists.` +
    `\n  PARTIALLY_SAFE — Controls exist but leave meaningful gaps: attack surface remains, edge cases are unaddressed, or only one layer of defence covers a multi-layer threat.` +
    `\n  UNSAFE         — No controls are listed, controls are irrelevant to this specific threat, or the listed controls are clearly insufficient.` +
    `\n\nEVALUATION CRITERIA:` +
    `\n  1. Judge against the SPECIFIC STRIDE category, attack vector, and MITRE ATT&CK technique(s) for each threat` +
    `\n  2. A control valid for one layer (e.g., network firewall) does NOT automatically cover application-layer or identity-layer threats` +
    `\n  3. Err toward PARTIALLY_SAFE over SAFE — real security requires defence-in-depth, not a single control` +
    `\n  4. If no controls are provided for a threat, the verdict MUST be UNSAFE — no exceptions` +
    `\n  5. Assess control QUALITY, not just presence: "we use HTTPS" is not a control for a SQL injection threat` +
    `\n  6. Reasoning must cite BOTH the specific control listed AND the specific gap or why the control is adequate` +
    `\n\nTHREATS AND CURRENT CONTROLS:\n${threatControlPairs}` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "metrics": [\n` +
    `    {\n` +
    `      "threatId": "T001",\n` +
    `      "threat": "verbatim threat title from the threat model",\n` +
    `      "verdict": "SAFE" | "PARTIALLY_SAFE" | "UNSAFE",\n` +
    `      "reasoning": "3-5 sentences citing: (1) what control is in place, (2) what the control does/does not address for this specific STRIDE category and attack vector, (3) why the verdict was assigned",\n` +
    `      "gaps": ["Specific gap 1 — what is missing or insufficient", "Specific gap 2"]\n` +
    `    }\n` +
    `  ],\n` +
    `  "overallPosture": "2-3 sentence executive assessment of the aggregate security posture: what proportion of threats are covered, what the most critical uncovered areas are, and a one-sentence recommended priority action"\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)]);

  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.metrics)) {
    throw new LlmError("provider", "Safety metrics response was not valid JSON.");
  }

  const VERDICTS: SafetyVerdict[] = ["SAFE", "PARTIALLY_SAFE", "UNSAFE"];

  const metrics: SafetyMetric[] = (parsed.metrics as unknown[])
    .filter((m): m is Record<string, unknown> => !!m && typeof m === "object")
    .map((m: Record<string, unknown>) => ({
      threatId: clamp(sanitizeText((m.threatId as string) ?? ""), 10),
      threat: clamp(sanitizeText((m.threat as string) ?? ""), 200),
      verdict: VERDICTS.includes(m.verdict as SafetyVerdict)
        ? (m.verdict as SafetyVerdict)
        : "UNSAFE",
      reasoning: clamp(sanitizeText((m.reasoning as string) ?? ""), 800),
      gaps: Array.isArray(m.gaps)
        ? (m.gaps as unknown[])
            .filter((g): g is string => typeof g === "string")
            .map((g) => clamp(sanitizeText(g), 300))
            .slice(0, 7)
        : [],
    }))
    .slice(0, 100);

  return {
    metrics,
    overallPosture: clamp(sanitizeText((parsed.overallPosture as string) ?? ""), 1500),
  };
}
