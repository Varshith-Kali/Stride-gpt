import { NextRequest } from "next/server";
import { generateDfd } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
  checkRateLimit,
} from "@/lib/api-utils";
import { validateThreatModelInput, validateImages } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  const rateLimitError = checkRateLimit(req);
  if (rateLimitError) return rateLimitError;

  try {
    const parsed = await readJsonRequest<{
      input?: unknown;
      images?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

    const { config, data } = parsed;
    if (!config) return configRequiredError();

    const input = validateThreatModelInput(data.input);
    if (!input) {
      return Response.json(
        { error: "Invalid application input." },
        { status: 400 }
      );
    }

    // Optional multimodal images — session-only, never stored
    const images = validateImages(data.images);

    const result = await generateDfd(config, input, images.length > 0 ? images : undefined);
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
