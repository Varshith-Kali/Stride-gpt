import { NextRequest } from "next/server";
import { generateDreadScores } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
  checkRateLimit,
} from "@/lib/api-utils";
import {
  validateThreatModelInput,
  sanitizeThreats,
  validateImages,
  LIMITS,
} from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  const rateLimitError = checkRateLimit(req);
  if (rateLimitError) return rateLimitError;

  try {
    const parsed = await readJsonRequest<{
      input?: unknown;
      threats?: unknown;
      images?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

    const { config, data } = parsed;
    if (!config) return configRequiredError();

    // input is optional context for DREAD scoring — validate if provided
    const input = data.input ? validateThreatModelInput(data.input) : null;

    if (!Array.isArray(data.threats) || data.threats.length === 0) {
      return Response.json(
        { error: "Missing or empty threats array." },
        { status: 400 }
      );
    }
    if (data.threats.length > LIMITS.MAX_THREATS) {
      return Response.json(
        { error: `Too many threats (max ${LIMITS.MAX_THREATS}).` },
        { status: 400 }
      );
    }

    const threats = sanitizeThreats(data.threats);
    // Optional multimodal images — session-only, never stored
    const images = validateImages(data.images);

    const result = await generateDreadScores(
      config,
      threats,
      input ?? undefined,
      images.length > 0 ? images : undefined
    );
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
