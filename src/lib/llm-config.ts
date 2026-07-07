/**
 * LLM provider configuration for STRIDE GPT.
 *
 * The app calls Groq or Google Gemini directly from server-side API routes
 * using the user-provided API key. No third-party SDK (z.ai, OpenRouter, etc.)
 * is used for content generation.
 *
 * Supported providers:
 *   - groq   → OpenAI-compatible endpoint at api.groq.com
 *   - gemini → Google generateContent at generativelanguage.googleapis.com
 */

export type Provider = "groq" | "gemini";

export interface LlmConfig {
  provider: Provider;
  apiKey: string;
  model: string;
}

export interface ProviderModel {
  id: string;
  label: string;
  note: string;
}

export const PROVIDER_MODELS: Record<Provider, ProviderModel[]> = {
  groq: [
    {
      id: "llama-3.3-70b-versatile",
      label: "Llama 3.3 70B Versatile",
      note: "Best reasoning · Groq free tier",
    },
    {
      id: "llama-3.1-8b-instant",
      label: "Llama 3.1 8B Instant",
      note: "Fastest · Groq free tier",
    },
    {
      id: "deepseek-r1-distill-llama-70b",
      label: "DeepSeek R1 Distill Llama 70B",
      note: "Reasoning model · Groq free tier",
    },
    {
      id: "qwen-2.5-32b",
      label: "Qwen 2.5 32B",
      note: "Strong analysis · Groq free tier",
    },
    {
      id: "qwen/qwen3-32b",
      label: "Qwen 3 32B",
      note: "Latest Qwen · Groq free tier",
    },
    {
      id: "moonshotai/kimi-k2-instruct",
      label: "Kimi K2 Instruct",
      note: "Long context · Groq free tier",
    },
    {
      id: "openai/gpt-oss-20b",
      label: "GPT-OSS 20B",
      note: "OpenAI open weights · Groq free tier",
    },
    {
      id: "gemma2-9b-it",
      label: "Gemma 2 9B IT",
      note: "Lightweight · Groq free tier",
    },
  ],
  gemini: [
    {
      id: "gemini-2.5-flash",
      label: "Gemini 2.5 Flash",
      note: "Fast + capable · Gemini free tier",
    },
    {
      id: "gemini-2.5-pro",
      label: "Gemini 2.5 Pro",
      note: "Most capable · Gemini free tier",
    },
    {
      id: "gemini-2.5-flash-lite",
      label: "Gemini 2.5 Flash Lite",
      note: "Lowest latency · Gemini free tier",
    },
    {
      id: "gemini-2.0-flash",
      label: "Gemini 2.0 Flash",
      note: "Stable · Gemini free tier",
    },
    {
      id: "gemini-2.0-flash-thinking-exp",
      label: "Gemini 2.0 Flash Thinking",
      note: "Reasoning · experimental",
    },
    {
      id: "gemini-1.5-flash",
      label: "Gemini 1.5 Flash",
      note: "Legacy stable · Gemini free tier",
    },
    {
      id: "gemini-1.5-pro",
      label: "Gemini 1.5 Pro",
      note: "Legacy large · Gemini free tier",
    },
  ],
};

export const DEFAULT_MODEL: Record<Provider, string> = {
  groq: "llama-3.3-70b-versatile",
  gemini: "gemini-2.5-flash",
};

/**
 * Allowlist of valid model IDs per provider. Incoming configs are validated
 * against this so a compromised client can't make the server call arbitrary
 * model strings (which could be used for prompt injection via model name).
 */
export const ALLOWED_MODELS: Record<Provider, ReadonlySet<string>> = {
  groq: new Set(PROVIDER_MODELS.groq.map((m) => m.id)),
  gemini: new Set(PROVIDER_MODELS.gemini.map((m) => m.id)),
};

export function isConfigured(c: LlmConfig | null | undefined): c is LlmConfig {
  return !!c && !!c.apiKey && !!c.provider && !!c.model;
}

/**
 * Validates a config object received from the client. Returns the typed
 * config if valid, or null. Rejects unknown providers, models not in the
 * allowlist, or malformed API keys.
 */
export function validateConfig(
  raw: unknown
): LlmConfig | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Partial<LlmConfig>;
  if (c.provider !== "groq" && c.provider !== "gemini") return null;
  if (typeof c.apiKey !== "string" || c.apiKey.trim().length < 10) return null;
  if (typeof c.model !== "string") return null;
  if (!ALLOWED_MODELS[c.provider].has(c.model)) return null;
  return {
    provider: c.provider,
    apiKey: c.apiKey.trim(),
    model: c.model,
  };
}
