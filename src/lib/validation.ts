/**
 * Input validation and sanitization for STRIDE GPT.
 *
 * All inputs received from the client are validated here before being passed
 * to the LLM. This prevents prompt injection via oversized inputs, control
 * characters, or malformed data.
 */
import type {
  AppType,
  AuthMethod,
  ThreatModelInput,
  Threat,
  LlmImage,
} from "@/lib/stride-engine";

const APP_TYPES: ReadonlySet<AppType> = new Set<AppType>([
  "Web application",
  "Mobile application",
  "Desktop application",
  "Cloud service/API",
  "IoT device",
  "Generative AI application",
  "Agentic AI application",
  "Microservice architecture",
  "Other",
]);

const AUTH_METHODS: ReadonlySet<AuthMethod> = new Set<AuthMethod>([
  "None",
  "Username/password",
  "OAuth 2.0",
  "SAML",
  "SSO",
  "API keys",
  "JWT",
  "Biometric",
  "Certificate-based",
]);

/** Max lengths — large enough for real apps, small enough to prevent abuse. */
export const LIMITS = {
  APP_NAME: 200,
  DESCRIPTION: 8000,
  THREAT_ID: 20,
  THREAT_TITLE: 300,
  THREAT_DESCRIPTION: 2000,
  THREAT_COMPONENT: 200,
  MAX_THREATS: 50,
  MAX_MITIGATIONS: 100,
  MAX_DFD_COMPONENTS: 50,
  MAX_DFD_FLOWS: 100,
  MAX_GHERKIN_SCENARIOS: 100,
} as const;

/**
 * Strip control characters and trim. Keeps newlines and tabs (which are
 * legitimate in descriptions) but removes NULL, vertical tabs, etc.
 */
export function sanitizeText(s: string): string {
  return s
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim();
}

/** Truncate to a max length. */
export function clamp(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) : s;
}

/**
 * Validate a ThreatModelInput received from the client.
 * Returns the sanitized input or null if invalid.
 */
export function validateThreatModelInput(
  raw: unknown
): ThreatModelInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Partial<ThreatModelInput>;

  const appName =
    typeof r.appName === "string"
      ? clamp(sanitizeText(r.appName), LIMITS.APP_NAME)
      : "";

  if (typeof r.description !== "string") return null;
  const description = sanitizeText(r.description);
  if (description.length < 10 || description.length > LIMITS.DESCRIPTION) {
    return null;
  }

  if (!r.appType || !APP_TYPES.has(r.appType as AppType)) return null;

  if (!Array.isArray(r.authentication)) return null;
  const authentication = r.authentication.filter(
    (a): a is AuthMethod => typeof a === "string" && AUTH_METHODS.has(a as AuthMethod)
  );

  return {
    appName,
    appType: r.appType as AppType,
    description: clamp(description, LIMITS.DESCRIPTION),
    authentication,
    internetFacing: !!r.internetFacing,
    sensitiveData: !!r.sensitiveData,
    usesCloud: !!r.usesCloud,
    hasMultipleTenants: !!r.hasMultipleTenants,
  };
}

/**
 * Validate an array of threats returned from the LLM before using them
 * downstream (e.g. for mitigations, DREAD scoring). Strips malformed entries.
 */
export function sanitizeThreats(threats: unknown[]): Threat[] {
  return threats
    .filter((t): t is Threat => {
      if (!t || typeof t !== "object") return false;
      const th = t as Partial<Threat>;
      return (
        typeof th.threat === "string" &&
        typeof th.description === "string" &&
        typeof th.strideCategory === "string"
      );
    })
    .map((th) => ({
      id: typeof th.id === "string" ? clamp(sanitizeText(th.id), LIMITS.THREAT_ID) : "",
      category: typeof th.category === "string" ? clamp(sanitizeText(th.category), 100) : "",
      threat: clamp(sanitizeText(th.threat), LIMITS.THREAT_TITLE),
      component: clamp(sanitizeText(th.component || ""), LIMITS.THREAT_COMPONENT),
      description: clamp(sanitizeText(th.description), LIMITS.THREAT_DESCRIPTION),
      strideCategory: th.strideCategory,
      mitreAttack: Array.isArray(th.mitreAttack)
        ? th.mitreAttack
            .filter((m) => typeof m === "string")
            .map((m) => clamp(sanitizeText(m), 60))
            .slice(0, 10)
        : [],
      risk: ["Low", "Medium", "High", "Critical"].includes(th.risk as string)
        ? (th.risk as Threat["risk"])
        : "Medium",
    }))
    .slice(0, LIMITS.MAX_THREATS);
}

/** Allowed image MIME types for architecture diagram uploads. */
const ALLOWED_IMAGE_TYPES = new Set<LlmImage["mimeType"]>([
  "image/png",
  "image/jpeg",
  "image/webp",
]);

/** Max images per request. */
const MAX_IMAGES = 5;

/** Max base64 string length per image (~4 MB raw = ~5.5 MB base64). */
const MAX_IMAGE_B64_CHARS = 5_592_405;

/**
 * Validate an array of LlmImage objects received from the client.
 * Silently drops invalid entries so generation is never blocked by a bad image.
 * Returns at most MAX_IMAGES validated images.
 */
export function validateImages(raw: unknown): LlmImage[] {
  if (!Array.isArray(raw)) return [];
  return (raw as unknown[])
    .filter((item): item is LlmImage => {
      if (!item || typeof item !== "object") return false;
      const img = item as Record<string, unknown>;
      if (!ALLOWED_IMAGE_TYPES.has(img.mimeType as LlmImage["mimeType"])) return false;
      if (typeof img.dataUrl !== "string") return false;
      // Verify it looks like a data-URL with the declared MIME type
      if (!img.dataUrl.startsWith(`data:${img.mimeType as string};base64,`)) return false;
      // Size guard — reject oversized images server-side too
      if (img.dataUrl.length > MAX_IMAGE_B64_CHARS) return false;
      return true;
    })
    .map((img) => ({
      mimeType: img.mimeType as LlmImage["mimeType"],
      dataUrl:  img.dataUrl as string,
      name:     typeof img.name === "string" ? clamp(sanitizeText(img.name), 200) : "image",
    }))
    .slice(0, MAX_IMAGES);
}
/**
 * Validate and sanitize the per-threat current controls map sent by the client.
 * Keys must be non-empty strings (threat IDs). Values are plain text clamped to
 * 500 chars. Unknown or malformed entries are dropped silently.
 */
export function validateCurrentControls(
  raw: unknown
): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const result: Record<string, string> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (count >= LIMITS.MAX_THREATS) break;
    if (typeof k !== "string" || k.length === 0 || k.length > LIMITS.THREAT_ID) continue;
    if (typeof v !== "string") continue;
    const sanitized = clamp(sanitizeText(v), 500);
    result[k] = sanitized;
    count++;
  }
  return result;
}
