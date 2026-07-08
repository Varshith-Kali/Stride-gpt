import { NextRequest, NextResponse } from "next/server";
import { validateConfig, LlmConfig } from "@/lib/llm-config";
import { LlmError } from "@/lib/stride-engine";

/** Max request body size (1 MB) — protects against oversized payloads. */
const MAX_BODY_BYTES = 1_048_576;

/**
 * Safely parse a JSON request body with size and content-type guards.
 * Returns `{ ok: false, error }` on any failure, or `{ ok: true, data, config }`
 * where `config` is the validated LlmConfig (null if not present).
 *
 * Usage:
 *   const parsed = await readJsonRequest(req);
 *   if (!parsed.ok) return parsed.error;
 *   const { data, config } = parsed;
 */
export async function readJsonRequest<T = unknown>(
  req: NextRequest
): Promise<
  | { ok: true; data: T; config: LlmConfig | null }
  | { ok: false; error: NextResponse }
> {
  // Content-Type check — reject non-JSON to prevent content sniffing.
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().includes("application/json")) {
    return {
      ok: false,
      error: NextResponse.json(
        { error: "Content-Type must be application/json." },
        { status: 415 }
      ),
    };
  }

  // Read body as text and enforce size limit.
  let bodyText: string;
  try {
    bodyText = await req.text();
  } catch {
    return {
      ok: false,
      error: NextResponse.json(
        { error: "Failed to read request body." },
        { status: 400 }
      ),
    };
  }

  if (bodyText.length > MAX_BODY_BYTES) {
    return {
      ok: false,
      error: NextResponse.json(
        { error: "Request body too large (max 1 MB)." },
        { status: 413 }
      ),
    };
  }

  // Parse JSON.
  let data: unknown;
  try {
    data = JSON.parse(bodyText);
  } catch {
    return {
      ok: false,
      error: NextResponse.json(
        { error: "Invalid JSON in request body." },
        { status: 400 }
      ),
    };
  }

  // Validate the LLM config if present.
  const config = validateConfig(
    data !== null && typeof data === "object" ? (data as Record<string, unknown>).config : undefined
  );
  // Note: config may legitimately be null if not provided; routes that need
  // a config should check `if (!config) return error`.

  return { ok: true, data: data as T, config };
}

/**
 * Standard error response for a missing or invalid LLM config.
 */
export function configRequiredError(): NextResponse {
  return NextResponse.json(
    {
      error:
        "LLM provider not configured. Open Settings and enter your OpenAI API key.",
    },
    { status: 400 }
  );
}


/**
 * Wrap a handler with structured error handling.
 *
 * SECURITY: Never expose raw exception messages or stack traces to the client.
 *
 * - LlmError: deliberately user-facing (geo-block, invalid-key, rate-limit,
 *   timeout, provider). These are safe to surface because they contain only
 *   provider guidance, not server internals.
 * - All other errors: return a generic "Internal server error" message.
 *   The full error is logged server-side for debugging.
 */
export function handleError(e: unknown): NextResponse {
  console.error("[api] error:", e);

  if (e instanceof LlmError) {
    // LlmError messages are intentionally user-facing.
    return NextResponse.json({ error: e.message }, { status: 502 });
  }

  // Never leak internal error messages, file paths, or stack traces.
  return NextResponse.json(
    { error: "Internal server error. Please try again." },
    { status: 500 }
  );
}
