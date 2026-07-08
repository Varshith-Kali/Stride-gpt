import { NextRequest } from "next/server";
import { DEFAULT_MODEL } from "@/lib/llm-config";
import { readJsonRequest, handleError } from "@/lib/api-utils";

export const runtime = "nodejs";
export const maxDuration = 30;

/**
 * Tests the user's OpenAI API key by sending a minimal request to the
 * OpenAI Responses API (POST /v1/responses) with the smallest possible input.
 *
 * Why /v1/responses instead of /v1/models?
 * - The user's internal model ("gpt-5.5") may not appear in the public
 *   /v1/models list, so querying it would always return "model not found".
 * - A minimal Responses call with max_output_tokens=1 validates:
 *     (a) the API key is valid and authorized
 *     (b) the model is accessible to this key
 *   while consuming essentially no tokens.
 *
 * Security:
 * - API key travels only in the Authorization header of this server-side fetch.
 * - It is never returned to the client, logged, or stored.
 */
export async function POST(req: NextRequest) {
  try {
    const parsed = await readJsonRequest<{
      config?: { provider?: string; apiKey?: string; model?: string };
    }>(req);
    if (!parsed.ok) return parsed.error;

    let { config } = parsed;
    if (!config) {
      const rawConfig = (parsed.data as any)?.config;
      if (
        rawConfig?.provider === "openai" &&
        typeof rawConfig?.apiKey === "string" &&
        rawConfig.apiKey.trim().length >= 10
      ) {
        config = {
          provider: "openai",
          apiKey: rawConfig.apiKey.trim(),
          model: DEFAULT_MODEL.openai,
        };
      }
    }

    if (!config) {
      return Response.json(
        {
          ok: false,
          error: "Invalid config. Provider must be 'openai' with a valid API key.",
        },
        { status: 200 }
      );
    }

    // Minimal test call to OpenAI Responses API — 1 output token max.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
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
          input: [{ role: "user", content: "ping" }],
          max_output_tokens: 1,
        }),
        signal: controller.signal,
      });
    } catch (e: unknown) {
      clearTimeout(timer);
      return Response.json(
        {
          ok: false,
          error: `Network error reaching OpenAI: ${e instanceof Error ? e.message : "unknown"}`,
        },
        { status: 200 }
      );
    }
    clearTimeout(timer);

    if (res.ok) {
      return Response.json({
        ok: true,
        message: `Connected to OpenAI successfully. Model "${config.model}" is accessible.`,
      });
    }

    const text = await res.text().catch(() => "");

    // 401 — invalid or revoked key
    if (res.status === 401) {
      return Response.json({
        ok: false,
        error: "Invalid API key (401). Verify the key is correct and hasn't been revoked.",
        status: res.status,
      });
    }

    // 403 — insufficient permissions for this model
    if (res.status === 403) {
      return Response.json({
        ok: false,
        error: `Access denied (403). Your API key may not have permission to access "${config.model}". Check your OpenAI organization settings.`,
        status: res.status,
      });
    }

    // 404 — model not found (likely internal model not yet provisioned)
    if (res.status === 404) {
      return Response.json({
        ok: false,
        error: `Model "${config.model}" not found (404). Ensure this model is provisioned for your API key.`,
        status: res.status,
      });
    }

    // 429 — rate limit or quota exceeded
    if (res.status === 429) {
      return Response.json({
        ok: false,
        error: "Rate limited (429). Wait a moment and try again.",
        status: res.status,
      });
    }

    // Generic error
    return Response.json({
      ok: false,
      error: `OpenAI returned ${res.status}: ${text.slice(0, 200) || res.statusText}`,
      status: res.status,
    });
  } catch (e) {
    return handleError(e);
  }
}
