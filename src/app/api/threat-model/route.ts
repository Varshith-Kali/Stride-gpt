import { NextRequest } from "next/server";
import {
  streamGenerateThreatModel,
  type ThreatModelStreamEvent,
  type LlmImage,
} from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  checkRateLimit,
} from "@/lib/api-utils";
import { validateThreatModelInput, validateImages } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

/**
 * POST /api/threat-model
 *
 * Returns a text/event-stream (SSE) response so the client receives
 * live progress while the LLM is generating.
 *
 * Event format:   data: <JSON>\n\n
 *
 *   { type: "progress", chars: number }  — tokens received so far
 *   { type: "done",     data: {...} }    — final parsed threat model
 *   { type: "error",    message: string }— failure with user-readable message
 *
 * WHY SSE instead of plain JSON:
 *   Reasoning models (GPT-5.5, o-series) can take 60-120 s to produce the
 *   full JSON. A plain await would hit the 120 s maxDuration wall and return
 *   a 502 to the client. With SSE, the connection stays alive because data
 *   is actively flowing from the first token (~2-5 s in), and the client
 *   shows a live progress indicator instead of a frozen spinner.
 */
export async function POST(req: NextRequest) {
  // Rate-limit before doing ANY body parsing — cheap early exit
  const rateLimitError = checkRateLimit(req);
  if (rateLimitError) return rateLimitError;

  // Parse and validate request body
  const parsed = await readJsonRequest<{
    input?: unknown;
    images?: unknown;
  }>(req).catch(() => null);

  if (!parsed || !parsed.ok) {
    return Response.json(
      { error: "Invalid request body." },
      { status: 400 }
    );
  }

  const { config, data } = parsed;
  if (!config) return configRequiredError();

  const input = validateThreatModelInput(data.input);
  if (!input) {
    return Response.json(
      {
        error:
          "Invalid application input. Description must be 10–8000 chars; appType and authentication must be from the allowed sets.",
      },
      { status: 400 }
    );
  }

  // Images are optional — silently drop invalid ones
  const images: LlmImage[] = validateImages(data.images);

  // Build the SSE streaming response
  const encoder = new TextEncoder();

  const body = new ReadableStream({
    async start(controller) {
      const send = (evt: ThreatModelStreamEvent | { type: "error"; message: string }) => {
        try {
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify(evt)}\n\n`)
          );
        } catch {
          // Controller already closed — ignore
        }
      };

      try {
        for await (const event of streamGenerateThreatModel(config, input, images)) {
          send(event);
          if (event.type === "done" || event.type === "error") break;
        }
      } catch (e: unknown) {
        // Surface the actual LLM error to the client (rate limit, auth, timeout, etc.)
        const msg =
          e instanceof Error ? e.message : "An unexpected error occurred.";
        send({ type: "error", message: msg });
      } finally {
        try { controller.close(); } catch { /* already closed */ }
      }
    },
  });

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-store, no-transform",
      // Prevent Nginx / proxies from buffering the SSE stream
      "X-Accel-Buffering": "no",
    },
  });
}
