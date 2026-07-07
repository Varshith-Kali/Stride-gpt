import { NextRequest } from "next/server";
import { DEFAULT_MODEL } from "@/lib/llm-config";
import { readJsonRequest, handleError } from "@/lib/api-utils";

export const runtime = "nodejs";
export const maxDuration = 30;

/**
 * Tests the user's API key by calling the provider's lightweight endpoint:
 *  - Groq:   GET /openai/v1/models (returns 200 + model list when valid)
 *  - Gemini: GET /v1beta/models?key=... (returns 200 + model list when valid)
 *
 * Distinguishes between:
 *  - geo-block (Groq Cloudflare 403, or Gemini "User location is not supported")
 *  - invalid key (401, or Gemini 400 "API key not valid")
 *  - rate limited (429)
 *  - success (200 + model list)
 */
export async function POST(req: NextRequest) {
  try {
    const parsed = await readJsonRequest<{
      config?: { provider?: string; apiKey?: string; model?: string };
    }>(req);
    if (!parsed.ok) return parsed.error;

    // readJsonRequest already validates data.config against the allowlist
    // and returns it typed. If the client sent a config that didn't validate,
    // config will be null here.
    let { config } = parsed;
    if (!config) {
      // The dialog sends { config: {...} }. If validateConfig rejected it
      // (e.g. model not in allowlist), fall back to the provider's default
      // model so the key test can still run. This is safe because we only
      // use the model for the test endpoint, not for generation.
      const rawConfig = (parsed.data as any)?.config;
      if (
        (rawConfig?.provider === "groq" || rawConfig?.provider === "gemini") &&
        typeof rawConfig?.apiKey === "string" &&
        rawConfig.apiKey.trim().length >= 10
      ) {
        const provider = rawConfig.provider as "groq" | "gemini";
        config = {
          provider,
          apiKey: rawConfig.apiKey.trim(),
          model: DEFAULT_MODEL[provider],
        };
      }
    }
    if (!config) {
      return Response.json(
        {
          ok: false,
          error:
            "Invalid config. Provider must be 'groq' or 'gemini' with a valid API key.",
        },
        { status: 200 }
      );
    }

    let url: string;
    const headers: Record<string, string> = {};
    if (config.provider === "groq") {
      url = "https://api.groq.com/openai/v1/models";
      headers["Authorization"] = `Bearer ${config.apiKey}`;
    } else {
      url = `https://generativelanguage.googleapis.com/v1beta/models?key=${config.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    let res: Response;
    try {
      res = await fetch(url, { method: "GET", headers, signal: controller.signal });
    } catch (e: any) {
      clearTimeout(timer);
      return Response.json(
        {
          ok: false,
          error: `Network error reaching ${config.provider}: ${e?.message ?? "unknown"}`,
        },
        { status: 200 }
      );
    }
    clearTimeout(timer);

    const text = await res.text().catch(() => "");

    let models: string[] = [];
    try {
      const j = JSON.parse(text);
      if (Array.isArray(j?.data)) {
        models = j.data.map((m: any) => m.id).filter(Boolean).slice(0, 12);
      } else if (Array.isArray(j?.models)) {
        models = j.models.map((m: any) => m.name || m.id).filter(Boolean).slice(0, 12);
      }
    } catch {
      /* not json */
    }

    if (res.ok) {
      const provName = config.provider === "groq" ? "Groq" : "Google Gemini";
      return Response.json({
        ok: true,
        message: `Connected to ${provName} successfully. Key is valid.`,
        models,
      });
    }

    // Groq geo-block: Cloudflare 403 with tiny "Forbidden" body
    if (
      config.provider === "groq" &&
      res.status === 403 &&
      (text.includes("Forbidden") || text.length < 60)
    ) {
      return Response.json({
        ok: false,
        error:
          "Groq is blocking requests from this server's region (Cloudflare 403). Your API key is valid — this is a geo-block. Switch to the Google Gemini provider (or vice versa if Gemini is blocked).",
        status: res.status,
      });
    }

    // Gemini geo-block: 400 "User location is not supported"
    if (
      config.provider === "gemini" &&
      res.status === 400 &&
      text.includes("User location is not supported")
    ) {
      return Response.json({
        ok: false,
        error:
          "Google Gemini is not available in this server's region. Your API key is valid — this is a geo-block. Switch to the Groq provider (or vice versa if Groq is blocked).",
        status: res.status,
      });
    }

    // Invalid key
    if (
      res.status === 401 ||
      (res.status === 400 && text.includes("API key not valid"))
    ) {
      return Response.json({
        ok: false,
        error: `Invalid API key (${res.status}). Check that you copied the full key.`,
        status: res.status,
      });
    }

    if (res.status === 429) {
      return Response.json({
        ok: false,
        error: "Rate limited (429). Wait a moment and try again.",
        status: res.status,
      });
    }

    return Response.json({
      ok: false,
      error: `Provider returned ${res.status}: ${text.slice(0, 200) || res.statusText}`,
      status: res.status,
    });
  } catch (e) {
    return handleError(e);
  }
}
