import { NextRequest } from "next/server";
import { generateAttackTree } from "@/lib/stride-engine";
import type { LlmImage } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
} from "@/lib/api-utils";
import { validateThreatModelInput, validateImages } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
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

    // Images are optional — validate if present, silently drop invalid ones.
    const images: LlmImage[] = validateImages(data.images);
    const result = await generateAttackTree(config, input, images);
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
