import { NextRequest } from "next/server";
import { generateSafetyMetrics } from "@/lib/stride-engine";
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
  validateCurrentControls,
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
      currentControls?: unknown;
      images?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

    const { config, data } = parsed;
    if (!config) return configRequiredError();

    // Validate application context
    const input = validateThreatModelInput(data.input);
    if (!input) {
      return Response.json(
        { error: "Invalid application input." },
        { status: 400 }
      );
    }

    // Validate threats array
    if (!Array.isArray(data.threats) || data.threats.length === 0) {
      return Response.json(
        { error: "No threat model items provided. Generate a threat model first." },
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
    const currentControls = validateCurrentControls(data.currentControls);
    // Optional multimodal images — session-only, never stored
    const images = validateImages(data.images);

    const result = await generateSafetyMetrics(
      config,
      input,
      threats,
      currentControls,
      images.length > 0 ? images : undefined
    );

    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
