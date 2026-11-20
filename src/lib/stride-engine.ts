/**
 * STRIDE GPT -- Threat modeling engine.
 * Calls the OpenAI Responses API (POST /v1/responses) using the user-provided
 * API key. The key is passed server-side only -- never stored or logged.
 *
 * All functions in this module run server-side only (Next.js API routes).
 */
import type { LlmConfig } from "@/lib/llm-config";
import { sanitizeThreats, sanitizeText, clamp, LIMITS } from "@/lib/validation";
import {
  getDfdNodeId,
  reconcileDfdComponentThreats,
  sanitizeThreatIds,
} from "@/lib/dfd-helpers";

/**
 * A session-only image supplied by the user (architecture diagram etc.).
 * Held in React state client-side; sent as base64 data-URLs in the request
 * body -- never persisted to any storage layer.
 */
export interface LlmImage {
  /** MIME type -- one of the server-side ALLOWED_IMAGE_TYPES. */
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

export type DfdComponentType = "External Entity" | "Process" | "Data Store";
export type DfdTrustLevel = "External" | "DMZ" | "Internal" | "Secure";

export interface DfdComponent {
  name: string;
  type: DfdComponentType;
  trustLevel: DfdTrustLevel;
  threatIds?: string[];
}

export interface DfdFlow {
  from: string;
  to: string;
  description: string;
  bidirectional?: boolean;
}

export interface DfdResult {
  mermaid: string;
  components: DfdComponent[];
  flows: DfdFlow[];
  narrative: string;
}

/** A single prioritized recommendation produced by generateRecommendations. */
export interface Recommendation {
  /** Threat IDs this recommendation addresses (e.g. ["T001", "T003"]). */
  threatIds: string[];
  /** One-sentence imperative action. */
  action: string;
  /** 3-5 concrete implementation steps. */
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
 *   SAFE           -- controls fully address the threat
 *   PARTIALLY_SAFE -- controls partially address the threat; gaps remain
 *   UNSAFE         -- controls are absent, insufficient, or bypassed
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
   * 2-4 sentence reasoning explaining why the controls are sufficient,
   * insufficient, or absent. Grounded in the STRIDE category and MITRE ATT&CK
   * context. Actionable where possible.
   */
  reasoning: string;
  /**
   * 1-3 specific gaps or improvements the architect should address.
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
  "You are STRIDE GPT, a principal security architect and threat modeling authority.",
  "Specializations: STRIDE, OWASP LLM Top 10, OWASP Agentic AI / ASI Top 10, MITRE ATT&CK Enterprise, MITRE ATLAS for ML/AI.",
  "SOURCE PRIORITY & SCOPING RULES (strictly enforced):",
  "  1. Priority 1 - Recommendations / Suggestions in Application Description: If the Application Description includes explicit recommendations, suggestions, security review notes, or targeted change/integration items, center the threat modeling around those exact recommendations/suggestions and the components, APIs, and data flows they affect.",
  "  2. Priority 2 - Application Description Points: If no explicit recommendations or suggestions are provided, treat all points, components, integrations, and workflows in the Application Description as the primary authoritative scope.",
  "  3. Priority 3 - Attached Diagrams (Architecture, DFD, Sequence) as Supplementary Context: Use attached diagrams as additional architectural context and reasoning support (exact component names, protocols, sequence interactions, auth handshakes, trust boundaries, direct upstream/downstream dependencies). NEVER bloat or dilute the threat model with threats for unrelated components from a larger enterprise diagram when the Application Description focuses on a specific integration, feature, or subsystem.",
  "OUTPUT RULES (strictly enforced):",
  "  1. Return ONLY valid JSON matching the schema requested. No prose, no markdown fences, no commentary.",
  "  2. MITRE ATT&CK IDs must be real published techniques (e.g. T1078, T1190). Never invent IDs.",
  "  3. Risk levels (Low/Medium/High/Critical) must reflect realistic exploitability and impact -- not worst-case by default.",
  "  4. Threat descriptions must name the specific attack vector, affected component, and realistic impact.",
  "  5. Do not repeat threats -- each entry must be distinct in vector, component, or impact.",
].join("\n");

/**
 * Shared scoping and priority instructions for threat model generation so
 * streaming and non-streaming paths remain completely synchronized.
 */
function buildThreatModelPriorityBlock(hasImages: boolean, imageCount: number): string {
  return (
    `\n\nINPUT PRIORITY & SCOPING INSTRUCTIONS (follow in strict order):` +
    `\n  1. FIRST check DESCRIPTION for explicit recommendations, suggestions, security review comments, or targeted focus items.` +
    `\n     - If recommendations or suggestions are present, build the threat model specifically around those recommendations/suggestions and the directly interacting components, APIs, and data flows.` +
    `\n  2. SECOND, if no explicit recommendations or suggestions are present, derive the full threat modeling scope from the points, integrations, features, and components stated in DESCRIPTION.` +
    (hasImages
      ? `\n  3. ATTACHED DIAGRAMS -- SUPPLEMENTARY CONTEXT (${imageCount} diagram(s) attached: architecture diagram, DFD, or sequence diagram):` +
        `\n     - Use the attached diagram(s) as extra context and deeper technical reasoning for the in-scope areas identified in DESCRIPTION (exact component names, call sequences, protocols, trust boundaries, auth/token touchpoints, and directly connected data stores or services).` +
        `\n     - Do NOT generate threats for unrelated or out-of-scope components visible in a broader architecture diagram if DESCRIPTION scopes the review to a specific subsystem, feature, or API integration.`
      : "")
  );
}

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
 * typed functions without explicit narrowing.
 */
function parseJsonLoose(text: string): Record<string, any> | null {
  // Strip code fences and leading/trailing whitespace
  const cleaned = text.replace(/```json\s*/gi, "").replace(/```\s*$/g, "").trim();
  const start = cleaned.search(/[{[]/);
  if (start === -1) return null;

  // -- Attempt 1: find a balanced JSON block and parse it cleanly ------------
  const openChar = cleaned[start];
  const closeChar = openChar === "{" ? "}" : "]";
  let depth = 0, end = -1, inStr = false, esc = false;
  for (let i = start; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; }
    else { if (ch === '"') inStr = true; else if (ch === openChar) depth++; else if (ch === closeChar) { depth--; if (depth === 0) { end = i; break; } } }
  }
  if (end !== -1) {
    try { return JSON.parse(cleaned.slice(start, end + 1)) as Record<string, any>; } catch { /* fall through */ }
  }

  // -- Attempt 2: JSON is truncated (hit max_output_tokens mid-stream) --------
  // Walk the string to build a repair suffix of closing brackets/braces.
  const stack: string[] = [];
  let repairInStr = false, repairEsc = false;
  let lastSafeCommaPos = -1; // position of last ',' at depth 1 (last complete sibling)
  let repairDepth = 0;
  for (let i = start; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (repairInStr) {
      if (repairEsc) repairEsc = false;
      else if (ch === "\\") repairEsc = true;
      else if (ch === '"') repairInStr = false;
    } else {
      if (ch === '"') repairInStr = true;
      else if (ch === "{" || ch === "[") { stack.push(ch === "{" ? "}" : "]"); repairDepth++; }
      else if (ch === "}" || ch === "]") { if (stack.length) stack.pop(); repairDepth--; }
      else if (ch === "," && repairDepth === 1) lastSafeCommaPos = i;
    }
  }

  // Try A: close current string if mid-string, then close all open containers
  {
    const suffix = (repairInStr ? '"' : "") + stack.reverse().join("");
    try { return JSON.parse(cleaned.slice(start) + suffix) as Record<string, any>; } catch { /* ignore */ }
    stack.reverse(); // restore order for Try B
  }

  // Try B: truncate at last complete sibling (drop the incomplete last item)
  if (lastSafeCommaPos > start) {
    const partial = cleaned.slice(start, lastSafeCommaPos);
    const stack2: string[] = [];
    let s2 = false, e2 = false;
    for (const ch of partial) {
      if (s2) { if (e2) e2 = false; else if (ch === "\\") e2 = true; else if (ch === '"') s2 = false; }
      else { if (ch === '"') s2 = true; else if (ch === "{" || ch === "[") stack2.push(ch === "{" ? "}" : "]"); else if ((ch === "}" || ch === "]") && stack2.length) stack2.pop(); }
    }
    try { return JSON.parse(partial + stack2.reverse().join("")) as Record<string, any>; } catch { /* ignore */ }
  }

  return null;
}

/**
 * Normalize an LLM-returned threat label back to the closest canonical threat
 * title from the original input list.
 *
 * WHY: LLMs often paraphrase threat titles when generating mitigations
 * (e.g. "Malicious Prompt Injection" vs "Prompt Injection Attack").
 *
 * STRATEGY (3-tier, fast and dependency-free):
 * 1. Exact lowercase match  -- handles the common case
 * 2. Substring containment  -- handles "Prompt Injection" in "Malicious Prompt Injection"
 * 3. Word-overlap scoring   -- handles rephrased titles with shared key words
 *    (only counts words >= 4 chars to skip stop-words like "the", "and", "via")
 *
 * Falls back to the original raw string if no match scores > 0.
 */
function closestThreatTitle(
  raw: string,
  canonicalTitles: Map<string, string>  // lowercase -> original
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
 * Request timeout -- 120 s matches the Next.js route `maxDuration = 120`.
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
        `Request timed out after ${timeoutMs / 1000}s. The provider may be overloaded -- try again.`
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
  // 401 -- invalid or expired API key
  if (status === 401) {
    return new LlmError(
      "invalid-key",
      "Invalid OpenAI API key (401). Verify the key is correct and hasn't been revoked.",
      status
    );
  }
  // 403 -- org-level restriction or key scope issue
  if (status === 403) {
    return new LlmError(
      "invalid-key",
      "Access denied (403). Your API key may lack permission to access this model. Check your OpenAI organization settings.",
      status
    );
  }
  // 429 -- rate limit or quota; parse Retry-After if present
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
  // 400 -- bad request (malformed body, model not found, content filter)
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
  // 5xx -- server-side OpenAI error
  if (status >= 500) {
    return new LlmError(
      "provider",
      `OpenAI server error (${status}). The service may be temporarily unavailable -- try again shortly.`,
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
 *   output[0].content[0].text  -- standard output_text item
 *   output[0].content          -- plain string (some model variants)
 *   output[0].text             -- direct text field (some internal models)
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
// --- Per-operation token budgets ----------------------------------------------
// Sized so that well-formed output never gets truncated.
//   Threat model: 12-15 threats x ~350 chars each + metadata ~ 6,500 chars ~ 5,000 tokens
//   Mitigations:  1 per threat x ~200 chars ~ 3,500 chars at 15 threats
//   DFD:          20 components + 35 flows + narrative ~ 3,000 chars
//   Safety:       1 verdict per threat with reasoning ~ 4,000 chars
//   Recommendations: grouped actions ~ 3,000 chars

const MAX_TOKENS = {
  // Right-sized for GPT-5.5: lower cap = less reasoning budget consumed.
  THREAT_MODEL:    16384,  // reasoning + 12-15 detailed threats output
  MITIGATIONS:     12288,  // reasoning + 1 mitigation per threat
  DFD:             16384,  // reasoning for graph structure + 20 components + 35 flows
  SAFETY:          16384,  // reasoning overhead + full verdict per threat with citations
  RECOMMENDATIONS:  8192,  // reasoning + grouped actions
} as const;
type ContentPart =
  | { type: "input_text"; text: string }
  | { type: "input_image"; image_url: string };

type LlmMessage =
  | { role: "user" | "assistant"; content: string }
  | { role: "user"; content: ContentPart[] };

/**
 * Build a multimodal user message.
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
  messages: LlmMessage[],
  maxOutputTokens: number = 4096,

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
          instructions: SYSTEM_PROMPT,
          input: messages,
          text: { format: { type: "json_object" } },
          max_output_tokens: maxOutputTokens,
          // store:false skips server-side conversation persistence (faster + better privacy).
          store: false,
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
  //   output[0] = { type: "reasoning", content: [] }   <- empty, skip this
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
    // Skip reasoning/thinking items -- they have empty content
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

  // Log full structure for server-side debugging only -- never reaches client
  console.error("[callLLM] Could not extract text. Full response:", JSON.stringify(data)?.slice(0, 2000));
  throw new LlmError("provider", "OpenAI returned an empty or unrecognized response.");

}

// --- SSE Streaming ------------------------------------------------------------

/**
 * Stream tokens from OpenAI Responses API via Server-Sent Events.
 *
 * Yields raw text delta strings as they arrive. The caller is responsible
 * for accumulating deltas into a full string and then parsing JSON.
 *
 * WHY STREAMING:
 * - Non-streaming: waits 60-120s for the full JSON response before returning
 *   anything -> connection times out on slow/loaded models.
 * - Streaming: first tokens arrive within 2-5s -> client sees progress,
 *   connection stays alive, 120s window is almost never hit.
 *
 * OpenAI SSE event shape (Responses API):
 *   response.output_text.delta -> { delta: string }
 *   response.output_text.done  -> { text: string }  <- full accumulated text
 *   response.completed         -> stream is done
 *   error                      -> { message: string }
 */
async function* callLLMStream(
  config: LlmConfig,
  messages: LlmMessage[],
  maxOutputTokens: number = 4096,

): AsyncGenerator<{ kind: "delta" | "done"; text: string }, void, unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        model: config.model,
        instructions: SYSTEM_PROMPT,
        input: messages,
        max_output_tokens: maxOutputTokens,
        stream: true,
        // No reasoning effort param for GPT-5.5 (not an o-series model).
        store: false,
      }),
      signal: controller.signal,
    });
  } catch (e: unknown) {
    clearTimeout(timer);
    if (e instanceof LlmError) throw e;
    if (e instanceof Error && e.name === "AbortError") {
      throw new LlmError("timeout", `Request timed out after ${LLM_TIMEOUT_MS / 1000}s. The provider may be overloaded -- try again.`);
    }
    throw new LlmError("network", `Failed to reach OpenAI: ${e instanceof Error ? e.message : "unknown"}`);
  }

  if (!res.ok) {
    clearTimeout(timer);
    const errText = await res.text().catch(() => "");
    throw classifyOpenAIError(res.status, errText);
  }

  if (!res.body) {
    clearTimeout(timer);
    throw new LlmError("provider", "OpenAI returned an empty streaming body.");
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let lineBuffer = "";
  let finalText = "";
  let deltaBuffer = "";

  try {
    outer: while (true) {
      let chunk: Awaited<ReturnType<typeof reader.read>>;
      try {
        chunk = await reader.read();
      } catch (e: unknown) {
        if (e instanceof Error && e.name === "AbortError") {
          throw new LlmError("timeout", `Stream timed out after ${LLM_TIMEOUT_MS / 1000}s.`);
        }
        throw new LlmError("network", `Stream read error: ${e instanceof Error ? e.message : "unknown"}`);
      }

      if (chunk.done) {
        const trailing = lineBuffer.trim();
        if (trailing.startsWith("data:")) {
          const payload = trailing.slice(5).trim();
          if (payload && payload !== "[DONE]") {
            try {
              const evt = JSON.parse(payload) as Record<string, unknown>;
              if (evt["type"] === "response.output_text.done" && typeof evt["text"] === "string") {
                finalText = evt["text"] as string;
              } else if (evt["type"] === "response.output_text.delta" && typeof evt["delta"] === "string") {
                deltaBuffer += evt["delta"] as string;
              }
            } catch {
              // Ignore incomplete trailing JSON
            }
          }
        }
        break;
      }

      lineBuffer += decoder.decode(chunk.value, { stream: true });
      const lines = lineBuffer.split("\n");
      lineBuffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;
        const payload = trimmed.slice(5).trim();
        if (payload === "[DONE]") break outer;

        let evt: Record<string, unknown>;
        try { evt = JSON.parse(payload) as Record<string, unknown>; }
        catch { continue; }

        const evtType = evt["type"] as string | undefined;

        if (evtType === "response.output_text.delta" && typeof evt["delta"] === "string") {
          const delta = evt["delta"] as string;
          deltaBuffer += delta;
          // Yield each chunk so the caller can track live progress in the UI.
          yield { kind: "delta" as const, text: delta };
        } else if (evtType === "response.output_text.done" && typeof evt["text"] === "string") {
          // `done` event carries the complete authoritative output text.
          finalText = evt["text"] as string;
        } else if (evtType === "error") {
          const msg = (evt["message"] ?? JSON.stringify(evt)) as string;
          throw new LlmError("provider", `OpenAI stream error: ${msg}`);
        } else if (evtType === "response.failed") {
          throw new LlmError("provider", "OpenAI response failed during streaming.");
        }
      }
    }
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }

  // Prefer authoritative response.output_text.done, fall back to accumulated deltas.
  yield { kind: "done" as const, text: finalText || deltaBuffer };
}

/**
 * Streaming variant of generateThreatModel.
 * Yields `{ type: "progress", chars: number }` as tokens arrive so the
 * client can show a live counter, then yields `{ type: "done", data }` with
 * the parsed + validated ThreatModelResult.
 *
 * Route returns this as text/event-stream (SSE). Client reads it with
 * a ReadableStream reader.
 */
export type ThreatModelStreamEvent =
  | { type: "progress"; chars: number }
  | { type: "done"; data: ThreatModelResult }
  | { type: "error"; message: string };

export async function* streamGenerateThreatModel(
  config: LlmConfig,
  input: ThreatModelInput,
  images?: LlmImage[]
): AsyncGenerator<ThreatModelStreamEvent, void, unknown> {
  const context = buildContextString(input);
  const isAi =
    input.appType === "Generative AI application" ||
    input.appType === "Agentic AI application";
  const hasImages = images && images.length > 0;

  const prompt =
    `${context}` +
    buildThreatModelPriorityBlock(Boolean(hasImages), images?.length ?? 0) +
    `\n\nTASK: Produce a focused, high-signal STRIDE threat model aligned strictly with the prioritized scope above.` +
    (isAi
      ? " Since this is an AI application, also incorporate OWASP LLM Top 10 (LLM01-LLM10) and, for agentic systems, OWASP ASI Top 10 (ASI01-ASI10)."
      : "") +
    `\n\nThreat generation rules:` +
    `\n  - Generate 10-15 distinct, high-signal threats focused on the in-scope surface (do not pad with out-of-scope components)` +
    `\n  - Every threat MUST reference a specific in-scope component or data flow using a clear, consistent component name` +
    `\n  - Include the realistic attack vector (not just the category)` +
    `\n  - Risk level must reflect exploitability given the auth method(s) and deployment context` +
    `\n  - MITRE ATT&CK IDs must be real published techniques -- never invent an ID` +
    `\n  - Cover all applicable STRIDE categories across the scoped system` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "threats": [\n` +
    `    {\n` +
    `      "id": "T001",\n` +
    `      "category": "short category label",\n` +
    `      "threat": "concise threat title naming the component and attack",\n` +
    `      "component": "exact in-scope component name",\n` +
    `      "description": "attack vector, exploitation method, and business impact in 2-3 sentences",\n` +
    `      "strideCategory": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",\n` +
    `      "mitreAttack": ["T1078 Valid Accounts"],\n` +
    `      "risk": "Low | Medium | High | Critical"\n` +
    `    }\n` +
    `  ],\n` +
    `  "summary": "3-4 sentence executive summary of the scoped risk profile and top concerns",\n` +
    `  "architectureNotes": "specific weak points, trust boundary issues, and high-risk data flows within the scoped surface",\n` +
    `  "detectedPatterns": ["pattern 1", "pattern 2"]\n` +
    `}`;

  // --- Separate progress tracking from parsing ------------------------------
  // delta chunks   -> progress counter only (shown in UI, NOT used for parsing)
  // done.text      -> the authoritative JSON string from OpenAI (parsed below)
  //
  // CRITICAL: Never concatenate deltas for parsing. The 'done' event text from
  // response.output_text.done is the single, complete, reliable source.
  // Concatenating deltas + done.text would double the JSON and break parsing.
  let finalJson = "";
  let charCount = 0;

  for await (const chunk of callLLMStream(config, [buildUserMessage(prompt, images)], MAX_TOKENS.THREAT_MODEL)) {
    if (chunk.kind === "delta") {
      charCount += chunk.text.length;
      // Yield a progress event roughly every 200 chars for the live counter
      if (charCount % 200 < chunk.text.length) {
        yield { type: "progress", chars: charCount };
      }
    } else {
      // kind === "done" -- this is the complete authoritative output text
      finalJson = chunk.text;
    }
  }

  yield { type: "progress", chars: charCount };

  const parsed = parseJsonLoose(finalJson);
  if (!parsed || !Array.isArray(parsed.threats)) {
    // Log raw output server-side only for debugging -- never sent to client
    console.error("[streamGenerateThreatModel] parse failed. Output length:", finalJson.length, "Preview:", finalJson.slice(0, 300));
    yield {
      type: "done",
      data: {
        threats: [],
        summary: "Unable to parse threat model output. Please try again.",
        architectureNotes: "",
        detectedPatterns: [],
      },
    };
    return;
  }

  yield {
    type: "done",
    data: {
      threats: sanitizeThreats(parsed.threats),
      summary: clamp(sanitizeText(parsed.summary ?? ""), 1500),
      architectureNotes: clamp(sanitizeText(parsed.architectureNotes ?? ""), 4000),
      detectedPatterns: Array.isArray(parsed.detectedPatterns)
        ? parsed.detectedPatterns
            .filter((p: unknown) => typeof p === "string")
            .map((p: string) => clamp(sanitizeText(p), 150))
            .slice(0, 20)
        : [],
    },
  };
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
    buildThreatModelPriorityBlock(Boolean(hasImages), images?.length ?? 0) +
    `\n\nTASK: Produce a comprehensive, scoped STRIDE threat model aligned strictly with the prioritized scope above.` +
    (isAi
      ? " Since this is an AI application, also incorporate OWASP LLM Top 10 (LLM01-LLM10) and, for agentic systems, OWASP ASI Top 10 (ASI01-ASI10)."
      : "") +
    ` Detect any relevant architectural patterns (e.g., API integration, RAG pipeline, multi-agent system, code execution environment, tool/MCP ecosystem, microservices mesh, event-driven architecture).` +
    `\n\nThreat generation rules:` +
    `\n  - Every threat MUST reference a specific in-scope component or data flow from DESCRIPTION${hasImages ? " (enriched with exact component/flow context from the attached diagram(s))" : ""}` +
    `\n  - Include the realistic attack vector (not just the category)` +
    `\n  - Risk level must reflect exploitability given the authentication method(s) and deployment context` +
    `\n  - MITRE ATT&CK IDs must be real published techniques -- never invent an ID` +
    `\n  - Cover all applicable STRIDE categories; aim for 10-15 distinct, high-signal threats within the scoped surface (never pad with unrelated components)` +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences) with this exact shape:\n` +
    `{\n` +
    `  "threats": [\n` +
    `    {\n` +
    `      "id": "T001",\n` +
    `      "category": "short category label",\n` +
    `      "threat": "concise threat title naming the component and attack",\n` +
    `      "component": "exact in-scope component name",\n` +
    `      "description": "attack vector, exploitation method, and business impact in 2-3 sentences",\n` +
    `      "strideCategory": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",\n` +
    `      "mitreAttack": ["T1078 Valid Accounts"],\n` +
    `      "risk": "Low | Medium | High | Critical"\n` +
    `    }\n` +
    `  ],\n` +
    `  "summary": "3-4 sentence executive summary of the scoped risk profile and top-3 concerns",\n` +
    `  "architectureNotes": "specific weak points, trust boundary violations, and high-risk data flows within the scoped surface",\n` +
    `  "detectedPatterns": ["pattern 1", "pattern 2"]\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)], MAX_TOKENS.THREAT_MODEL);
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
      ? `\n\nATTACHED DIAGRAMS -- SUPPLEMENTARY CONTEXT (${images!.length} attached): Use the attached diagram(s) as additional architectural context so mitigations fit the actual deployment and in-scope components from DESCRIPTION -- not generic advice.`
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

  const raw = await callLLM(config, [buildUserMessage(prompt, images)], MAX_TOKENS.MITIGATIONS);
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


function normalizeDfdComponentType(raw: unknown): DfdComponentType {
  const s = typeof raw === "string" ? raw.toLowerCase().trim() : "";
  if (
    s.includes("external") ||
    s.includes("entity") ||
    s.includes("actor") ||
    s.includes("user") ||
    s.includes("client") ||
    s.includes("third-party") ||
    s.includes("third party") ||
    s.includes("provider")
  ) {
    return "External Entity";
  }
  if (
    s.includes("store") ||
    s.includes("database") ||
    s.includes("db") ||
    s.includes("cache") ||
    s.includes("bucket") ||
    s.includes("blob") ||
    s.includes("storage") ||
    s.includes("vault") ||
    s.includes("secret") ||
    s.includes("queue") ||
    s.includes("log")
  ) {
    return "Data Store";
  }
  return "Process";
}

function normalizeDfdTrustLevel(
  raw: unknown,
  type: DfdComponentType
): DfdTrustLevel {
  const s = typeof raw === "string" ? raw.toLowerCase().trim() : "";
  if (s === "external" || s === "untrusted" || s === "low") return "External";
  if (s === "dmz" || s.includes("edge") || s.includes("perimeter")) return "DMZ";
  if (s === "secure" || s === "high" || s === "restricted" || s === "sensitive") {
    return "Secure";
  }
  if (s === "internal" || s === "medium") return "Internal";
  if (type === "External Entity") return "External";
  if (type === "Data Store") return "Secure";
  return "Internal";
}

function cleanDfdLabel(raw: string, maxLen: number): string {
  return sanitizeText(raw)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/["'`]/g, "")
    .replace(/[[\]{}()|<>\\;]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen)
    .trim();
}

function mergeFlowLabels(a: string, b: string): string {
  const cleanA = cleanDfdLabel(a, 30);
  const cleanB = cleanDfdLabel(b, 30);
  if (!cleanA) return cleanB || "Data flow";
  if (!cleanB || cleanA.toLowerCase() === cleanB.toLowerCase()) return cleanA;
  // Prefer a short slash combination if it fits cleanly within 30 chars; otherwise keep the clearer label
  const combined = `${cleanA} / ${cleanB}`;
  if (combined.length <= 30) return combined;
  return cleanA.length <= 28 ? cleanA : cleanDfdLabel(cleanA, 28);
}

const CLIENT_ENTITY_RE = /\b(user|users|customer|client|browser|mobile|app\s*ui|web\s*ui|portal|admin|operator|developer|employee|patient|trader|cli|end\s*user|actor)\b/i;

function isClientExternalEntity(
  comp: DfdComponent,
  inboundCount: number,
  outboundCount: number
): boolean {
  if (CLIENT_ENTITY_RE.test(comp.name)) return true;
  // If an external entity primarily initiates inbound traffic and isn't named as an API/LLM/IdP/CRM/vendor
  const serviceHint = /\b(api|llm|model|provider|idp|identity|crm|webhook|gateway|vendor|smtp|email|sms|broker|ehr|kyc|embedding)\b/i;
  if (serviceHint.test(comp.name)) return false;
  return outboundCount > 0 && inboundCount === 0;
}

export async function generateDfd(
  config: LlmConfig,
  input: ThreatModelInput,
  images?: LlmImage[],
  threats?: Threat[]
): Promise<DfdResult> {
  const context = buildContextString(input);
  const hasImages = images && images.length > 0;
  const threatEntries = (threats ?? [])
    .map((t) => ({
      id: sanitizeText(t.id || "").trim().toUpperCase(),
      component: sanitizeText(t.component || "").trim(),
      title: clamp(sanitizeText(t.threat || "").trim(), 90),
    }))
    .filter((t) => t.id.length > 0 && t.component.length > 0)
    .slice(0, 30);

  const validThreatIdSet = new Set(threatEntries.map((t) => t.id));

  const prompt =
    `${context}` +
    `\n\nDFD SCOPING & SOURCE PRIORITY:` +
    `\n  - Priority 1: Focus the DFD on the in-scope components and flows defined by DESCRIPTION (especially any explicit recommendations, suggestions, or specific subsystem/API integration mentioned there)${threatEntries.length > 0 ? " and the IDENTIFIED THREATS list below" : ""}.` +
    (hasImages
      ? `\n  - Priority 2 -- ATTACHED DIAGRAMS AS SUPPLEMENTARY CONTEXT (${images!.length} attached: architecture, DFD, or sequence diagram): Use the diagram(s) for accurate component names, trust boundaries, protocols, and direct upstream/downstream touchpoints around the in-scope flows. Do NOT dump unrelated components from a larger enterprise diagram that are outside DESCRIPTION's scope.`
      : "") +
    (threatEntries.length > 0
      ? `\n\nIDENTIFIED THREATS & AFFECTED COMPONENTS (EVERY affected component below MUST appear as a clearly named component in the DFD with its matching threat IDs in "threatIds"):\n` +
        threatEntries.map((t) => `- ${t.id} | Component: ${t.component} | ${t.title}`).join("\n")
      : "") +
    `\n\nTASK: Generate a clean, uncluttered Level-1 Data Flow Diagram (DFD) covering the in-scope architectural components, data stores, external actors, and trust boundaries.` +
    `\n\nCOMPONENT COVERAGE REQUIREMENTS -- include all that apply within scope:` +
    `\n  EXTERNAL ENTITIES ("type": "External Entity", "trustLevel": "External"):` +
    `\n    - End users / clients (Browser Client, Mobile App, Admin Portal)` +
    `\n    - External Identity Providers (IdP) & Third-party APIs/LLM services` +
    `\n  DMZ / EDGE PROCESSES ("type": "Process", "trustLevel": "DMZ"):` +
    `\n    - CDN / WAF, API Gateway / Reverse Proxy` +
    `\n  INTERNAL PROCESSES ("type": "Process", "trustLevel": "Internal"):` +
    `\n    - Auth Service, Core Domain Services, Workers, AI/LLM Orchestrator` +
    `\n  DATA STORES ("type": "Data Store", "trustLevel": "Secure"):` +
    `\n    - Databases, Vector Store, Cache (Redis), Object Storage, Secrets Manager, Audit Log` +
    `\n\nDFD INTEGRITY & CLEAN-LAYOUT RULES:` +
    `\n  - Include 6-16 distinct, high-signal in-scope components. Every component MUST appear in at least one flow.` +
    `\n  - Include 8-22 flows MAX. Emit AT MOST ONE flow between any two components -- combine request and response into a single concise flow (e.g. "TLS OIDC exchange", "HTTPS embedding API", "Vector query & chunks") rather than separate forward and return arrows.` +
    `\n  - Every "from" and "to" MUST match a component "name" EXACTLY.` +
    `\n  - Keep component names concise (2-3 words, alphanumeric + spaces/hyphens only, no parentheses or slashes) and consistent with the component names in IDENTIFIED THREATS.` +
    `\n  - Keep flow descriptions ultra-concise (2-4 words, max 26 chars, e.g. "HTTPS JWT request", "TLS SQL query", "Embedding API call").` +
    `\n  - Use ONLY these exact values for "type": "External Entity" | "Process" | "Data Store".` +
    `\n  - Use ONLY these exact values for "trustLevel": "External" | "DMZ" | "Internal" | "Secure".` +
    (threatEntries.length > 0
      ? `\n  - For "threatIds", attach ONLY real matching IDs from the identified threats list above whose "Component:" directly matches THIS specific component (or [] if none apply). Do NOT attach a threat ID to neighboring or unrelated components.`
      : `\n  - Set "threatIds": [] when no threats list was provided.`) +
    `\n\nReturn ONLY a JSON object (no prose, no markdown fences):\n` +
    `{\n` +
    `  "components": [\n` +
    `    { "name": "Browser Client", "type": "External Entity", "trustLevel": "External", "threatIds": [] },\n` +
    `    { "name": "WAF and CDN", "type": "Process", "trustLevel": "DMZ", "threatIds": [] },\n` +
    `    { "name": "API Gateway", "type": "Process", "trustLevel": "DMZ", "threatIds": ["T001"] },\n` +
    `    { "name": "Auth Service", "type": "Process", "trustLevel": "Internal", "threatIds": [] },\n` +
    `    { "name": "Core App Service", "type": "Process", "trustLevel": "Internal", "threatIds": [] },\n` +
    `    { "name": "Primary Database", "type": "Data Store", "trustLevel": "Secure", "threatIds": [] },\n` +
    `    { "name": "Redis Cache", "type": "Data Store", "trustLevel": "Secure", "threatIds": [] },\n` +
    `    { "name": "Identity Provider", "type": "External Entity", "trustLevel": "External", "threatIds": [] }\n` +
    `  ],\n` +
    `  "flows": [\n` +
    `    { "from": "Browser Client", "to": "WAF and CDN", "description": "HTTPS user request", "bidirectional": true },\n` +
    `    { "from": "WAF and CDN", "to": "API Gateway", "description": "Filtered HTTPS traffic" },\n` +
    `    { "from": "API Gateway", "to": "Auth Service", "description": "JWT verification" },\n` +
    `    { "from": "Auth Service", "to": "Identity Provider", "description": "TLS OIDC exchange", "bidirectional": true },\n` +
    `    { "from": "API Gateway", "to": "Core App Service", "description": "Authenticated API call" },\n` +
    `    { "from": "Core App Service", "to": "Primary Database", "description": "TLS SQL query", "bidirectional": true },\n` +
    `    { "from": "Core App Service", "to": "Redis Cache", "description": "Session read/write", "bidirectional": true }\n` +
    `  ],\n` +
    `  "narrative": "3-4 sentence architectural summary covering data flows, trust boundary crossings, and key security controls."\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)], MAX_TOKENS.DFD);
  const parsed = parseJsonLoose(raw);
  if (!parsed || !Array.isArray(parsed.components)) {
    return {
      components: [],
      flows: [],
      narrative: "",
      mermaid: 'flowchart TB\n  empty["No components generated"]',
    };
  }

  // 1. Normalize and deduplicate components (case-insensitive)
  const rawComponents: DfdComponent[] = [];
  const canonicalNameByKey = new Map<string, string>();

  for (const rawComp of parsed.components as unknown[]) {
    if (!rawComp || typeof rawComp !== "object") continue;
    const c = rawComp as Record<string, unknown>;
    if (typeof c.name !== "string") continue;

    const cleanName = cleanDfdLabel(c.name, 44);
    if (!cleanName) continue;

    const key = cleanName.toLowerCase();
    if (canonicalNameByKey.has(key)) continue;

    const type = normalizeDfdComponentType(c.type);
    const trustLevel = normalizeDfdTrustLevel(c.trustLevel, type);
    const threatIds = sanitizeThreatIds(
      c.threatIds,
      validThreatIdSet.size > 0 ? validThreatIdSet : undefined
    );

    canonicalNameByKey.set(key, cleanName);
    rawComponents.push({
      name: cleanName,
      type,
      trustLevel,
      ...(threatIds.length > 0 ? { threatIds } : {}),
    });
    if (rawComponents.length >= 18) break;
  }

  // 2. Normalize flows and collapse parallel/opposing edges between the same pair
  //    into a single clean directional or bidirectional flow (prevents Mermaid label overlap).
  const flows: DfdFlow[] = [];
  const flowByPair = new Map<string, DfdFlow>();

  for (const rawFlow of (Array.isArray(parsed.flows) ? parsed.flows : []) as unknown[]) {
    if (!rawFlow || typeof rawFlow !== "object") continue;
    const f = rawFlow as Record<string, unknown>;
    if (typeof f.from !== "string" || typeof f.to !== "string") continue;

    const rawFrom = cleanDfdLabel(f.from, 44);
    const rawTo = cleanDfdLabel(f.to, 44);
    if (!rawFrom || !rawTo) continue;

    let from = canonicalNameByKey.get(rawFrom.toLowerCase());
    if (!from && rawComponents.length < 18) {
      from = rawFrom;
      canonicalNameByKey.set(rawFrom.toLowerCase(), from);
      rawComponents.push({ name: from, type: "Process", trustLevel: "Internal" });
    }

    let to = canonicalNameByKey.get(rawTo.toLowerCase());
    if (!to && rawComponents.length < 18) {
      to = rawTo;
      canonicalNameByKey.set(rawTo.toLowerCase(), to);
      rawComponents.push({ name: to, type: "Process", trustLevel: "Internal" });
    }

    if (!from || !to || from === to) continue;

    const desc =
      typeof f.description === "string"
        ? cleanDfdLabel(f.description, 30) || "Data flow"
        : "Data flow";
    const wantsBidirectional = Boolean(f.bidirectional);

    const pairKey = [from.toLowerCase(), to.toLowerCase()].sort().join("<->");
    const existing = flowByPair.get(pairKey);

    if (existing) {
      // Collapse reverse/duplicate parallel edge into one clean edge
      if (existing.from.toLowerCase() !== from.toLowerCase() || wantsBidirectional) {
        existing.bidirectional = true;
      }
      existing.description = mergeFlowLabels(existing.description, desc);
      continue;
    }

    const entry: DfdFlow = {
      from,
      to,
      description: desc,
      ...(wantsBidirectional ? { bidirectional: true } : {}),
    };
    flowByPair.set(pairKey, entry);
    flows.push(entry);
    if (flows.length >= 26) break;
  }

  // 3. Deterministically reconcile threat IDs across all components
  const reconciled = reconcileDfdComponentThreats(rawComponents, threats);

  // 4. Prune isolated orphan components (no flows AND no linked threats) so diagrams stay clean
  const connectedKeys = new Set<string>();
  for (const f of flows) {
    connectedKeys.add(f.from.toLowerCase());
    connectedKeys.add(f.to.toLowerCase());
  }
  const components =
    flows.length > 0
      ? reconciled.filter(
          (c) =>
            connectedKeys.has(c.name.toLowerCase()) ||
            (c.threatIds && c.threatIds.length > 0)
        )
      : reconciled;

  return {
    components,
    flows,
    narrative: clamp(sanitizeText(typeof parsed.narrative === "string" ? parsed.narrative : ""), 1200),
    mermaid: dfdToMermaid(components, flows),
  };
}

/**
 * Converts normalized DFD component + flow data into a Mermaid flowchart.
 *
 * Shapes follow classic Yourdon/DeMarco DFD conventions:
 *   External Entity : Rectangle        id["Label"]
 *   Process         : Stadium/Rounded  id(["Label"])
 *   Data Store      : Cylinder         id[("Label")]
 *
 * Layout: TB (top-to-bottom) stacked cleanly by architectural tier:
 *   External Clients -> DMZ Perimeter -> Internal Trust Zone -> Secure Data Zone & External APIs
 */
export function dfdToMermaid(
  components: DfdComponent[],
  flows: DfdFlow[]
): string {
  if (components.length === 0) {
    return 'flowchart TB\n  empty["No DFD components available"]';
  }

  const idMap = new Map<string, string>();
  components.forEach((c, i) => idMap.set(c.name.toLowerCase(), getDfdNodeId(i)));

  // Tally inbound/outbound edges to distinguish Client Actors from External Services cleanly
  const inboundCount = new Map<string, number>();
  const outboundCount = new Map<string, number>();
  for (const f of flows) {
    const fk = f.from.toLowerCase();
    const tk = f.to.toLowerCase();
    outboundCount.set(fk, (outboundCount.get(fk) ?? 0) + 1);
    inboundCount.set(tk, (inboundCount.get(tk) ?? 0) + 1);
  }

  const safeNodeLabel = (s: string) => cleanDfdLabel(s, 44) || "Component";
  const safeEdgeLabel = (s: string) => cleanDfdLabel(s, 30) || "Data flow";

  type ZoneBucketKey = "ExternalClients" | "DMZ" | "Internal" | "Secure" | "ExternalServices";
  const ZONES: Array<{
    key: ZoneBucketKey;
    label: string;
    direction?: "LR" | "TB";
    style: string;
    members: DfdComponent[];
  }> = [
    {
      key: "ExternalClients",
      label: "External Clients (Untrusted)",
      direction: "LR",
      style: "fill:#fef2f2,stroke:#9C1D26,stroke-width:1.5px,stroke-dasharray:6 4,color:#7f1d1d",
      members: [],
    },
    {
      key: "DMZ",
      label: "DMZ Perimeter",
      style: "fill:#fff7ed,stroke:#c2410c,stroke-width:1.5px,stroke-dasharray:6 4,color:#7c2d12",
      members: [],
    },
    {
      key: "Internal",
      label: "Internal Trust Zone",
      style: "fill:#f8fafc,stroke:#475569,stroke-width:1.5px,stroke-dasharray:6 4,color:#1e293b",
      members: [],
    },
    {
      key: "Secure",
      label: "Secure Data Zone",
      direction: "LR",
      style: "fill:#f0fdf4,stroke:#15803d,stroke-width:1.5px,stroke-dasharray:6 4,color:#14532d",
      members: [],
    },
    {
      key: "ExternalServices",
      label: "External APIs & Providers (Untrusted)",
      direction: "LR",
      style: "fill:#fef2f2,stroke:#9C1D26,stroke-width:1.5px,stroke-dasharray:6 4,color:#7f1d1d",
      members: [],
    },
  ];

  const zoneMap = new Map(ZONES.map((z) => [z.key, z]));
  for (const c of components) {
    if (c.trustLevel === "External") {
      const key = c.name.toLowerCase();
      const bucketKey: ZoneBucketKey = isClientExternalEntity(
        c,
        inboundCount.get(key) ?? 0,
        outboundCount.get(key) ?? 0
      )
        ? "ExternalClients"
        : "ExternalServices";
      zoneMap.get(bucketKey)!.members.push(c);
    } else {
      const zone = zoneMap.get(c.trustLevel) ?? zoneMap.get("Internal")!;
      zone.members.push(c);
    }
  }

  const lines: string[] = ["flowchart TB"];

  // Subgraphs -- one per non-empty architectural zone
  for (const zone of ZONES) {
    if (zone.members.length === 0) continue;
    lines.push(`  subgraph ${zone.key}["${zone.label}"]`);
    if (zone.direction) {
      lines.push(`    direction ${zone.direction}`);
    }
    for (const c of zone.members) {
      const id = idMap.get(c.name.toLowerCase());
      if (!id) continue;
      const label = safeNodeLabel(c.name);
      switch (c.type) {
        case "External Entity":
          lines.push(`    ${id}["${label}"]`);
          break;
        case "Process":
          lines.push(`    ${id}(["${label}"])`);
          break;
        case "Data Store":
          lines.push(`    ${id}[("${label}")]`);
          break;
      }
    }
    lines.push("  end");
  }

  // Collapse any remaining parallel pairs if dfdToMermaid is called directly
  const emittedPairs = new Map<string, { fromId: string; toId: string; label: string; bi: boolean }>();
  const orderedPairs: Array<{ fromId: string; toId: string; label: string; bi: boolean }> = [];

  for (const f of flows) {
    const fromId = idMap.get(f.from.toLowerCase());
    const toId = idMap.get(f.to.toLowerCase());
    if (!fromId || !toId || fromId === toId) continue;

    const pairKey = [fromId, toId].sort().join("<->");
    const label = safeEdgeLabel(f.description);
    const existing = emittedPairs.get(pairKey);

    if (existing) {
      if (existing.fromId !== fromId || f.bidirectional) existing.bi = true;
      existing.label = mergeFlowLabels(existing.label, label);
    } else {
      const item = { fromId, toId, label, bi: Boolean(f.bidirectional) };
      emittedPairs.set(pairKey, item);
      orderedPairs.push(item);
    }
  }

  for (const edge of orderedPairs) {
    const arrow = edge.bi ? "<-->" : "-->";
    lines.push(`  ${edge.fromId} ${arrow}|"${edge.label}"| ${edge.toId}`);
  }

  // High-contrast node & trust-boundary styles
  lines.push("  classDef entity    fill:#9C1D26,stroke:#6B1219,stroke-width:2px,color:#ffffff,font-weight:bold");
  lines.push("  classDef process   fill:#1e293b,stroke:#0f172a,stroke-width:2px,color:#ffffff,font-weight:bold");
  lines.push("  classDef datastore fill:#0f766e,stroke:#115e59,stroke-width:2px,color:#ffffff,font-weight:bold");

  for (const c of components) {
    const id = idMap.get(c.name.toLowerCase());
    if (!id) continue;
    if (c.type === "External Entity") lines.push(`  class ${id} entity`);
    else if (c.type === "Process") lines.push(`  class ${id} process`);
    else if (c.type === "Data Store") lines.push(`  class ${id} datastore`);
  }

  for (const zone of ZONES) {
    if (zone.members.length > 0) {
      lines.push(`  style ${zone.key} ${zone.style}`);
    }
  }

  return lines.join("\n");
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
      ? `\nATTACHED DIAGRAMS (SUPPLEMENTARY CONTEXT): ${images.length} diagram(s) attached -- use them as additional context for component-specific recommendations aligned with DESCRIPTION.`
      : "") +
    `\n\nTHREAT MODEL (${threats.length} threats):\n${threatLines}` +
    (hasNotes
      ? "\n\nNOTE: Lines marked ANALYST contain security architect context -- weight these heavily when prioritising."
      : "") +
    `\n\nTASK: Generate concise, prioritized security recommendations. Group related threats where logical. Prioritize by risk level and analyst context. Be specific and actionable.\n\nReturn ONLY a JSON object (no prose, no markdown fences):\n{\n  "recommendations": [\n    {\n      "threatIds": ["T001", "T002"],\n      "action": "one-sentence imperative action",\n      "steps": ["concrete step 1", "step 2", "step 3"],\n      "effort": "Low | Medium | High",\n      "riskReduction": "what risk this eliminates or reduces"\n    }\n  ],\n  "executiveSummary": "2-3 sentence summary of the overall recommendation posture"\n}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)], MAX_TOKENS.RECOMMENDATIONS);
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
      ? `\n\nATTACHED DIAGRAMS -- SUPPLEMENTARY CONTEXT (${images.length} attached): ` +
        `Use the attached diagram(s) as additional architectural context for deployment, network zones, and component interactions ` +
        `to assess whether listed controls realistically mitigate the in-scope threats.`
      : "") +
    `\n\nSECURITY POSTURE EVALUATION -- ${threats.length} THREAT(S)` +
    `\n\nYou are evaluating whether the user's CURRENT SECURITY CONTROLS adequately mitigate each identified threat.` +
    `\nThis is NOT a mitigation recommendation exercise -- it is a factual assessment of what is already in place.` +
    `\n\nVERDICT DEFINITIONS (strictly apply these):` +
    `\n  SAFE           -- Controls FULLY and DEMONSTRABLY mitigate this threat. Coverage is unambiguous and defence-in-depth exists.` +
    `\n  PARTIALLY_SAFE -- Controls exist but leave meaningful gaps: attack surface remains, edge cases are unaddressed, or only one layer of defence covers a multi-layer threat.` +
    `\n  UNSAFE         -- No controls are listed, controls are irrelevant to this specific threat, or the listed controls are clearly insufficient.` +
    `\n\nEVALUATION CRITERIA:` +
    `\n  1. Judge against the SPECIFIC STRIDE category, attack vector, and MITRE ATT&CK technique(s) for each threat` +
    `\n  2. A control valid for one layer (e.g., network firewall) does NOT automatically cover application-layer or identity-layer threats` +
    `\n  3. Err toward PARTIALLY_SAFE over SAFE -- real security requires defence-in-depth, not a single control` +
    `\n  4. If no controls are provided for a threat, the verdict MUST be UNSAFE -- no exceptions` +
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
    `      "reasoning": "3-5 sentences citing: (1) what control is in place, (2) what the control does/doesn't cover for this specific STRIDE vector, (3) whether compensating controls exist, (4) exploitability given the deployment context",\n` +
    `      "gaps": ["Specific gap 1 -- what is missing or insufficient", "Specific gap 2"]\n` +
    `    }\n` +
    `  ],\n` +
    `  "overallPosture": "2-3 sentence executive assessment of the aggregate security posture: what proportion of threats are covered, what the most critical uncovered areas are, and a one-sentence recommended priority action"\n` +
    `}`;

  const raw = await callLLM(config, [buildUserMessage(prompt, images)], MAX_TOKENS.SAFETY);

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
