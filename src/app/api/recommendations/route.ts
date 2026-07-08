import { NextRequest } from "next/server";
import { generateRecommendations } from "@/lib/stride-engine";
import type { LlmImage } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
} from "@/lib/api-utils";
import { sanitizeThreats, validateImages, sanitizeText, clamp } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  try {
    const parsed = await readJsonRequest<{
      threats?: unknown;
      justifications?: unknown;
      appInput?: unknown;
      images?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

    const { config, data } = parsed;
    if (!config) return configRequiredError();

    // Validate threats array
    if (!Array.isArray(data.threats) || data.threats.length === 0) {
      return Response.json(
        { error: "threats array is required and must not be empty." },
        { status: 400 }
      );
    }
    const threats = sanitizeThreats(data.threats);
    if (threats.length === 0) {
      return Response.json(
        { error: "No valid threats found after sanitization." },
        { status: 400 }
      );
    }

    // Validate justifications — Record<threatId, text>
    const justifications: Record<string, string> = {};
    if (data.justifications && typeof data.justifications === "object") {
      for (const [key, val] of Object.entries(
        data.justifications as Record<string, unknown>
      )) {
        if (typeof val === "string" && val.trim()) {
          justifications[clamp(sanitizeText(key), 20)] = clamp(
            sanitizeText(val),
            500
          );
        }
      }
    }

    // Validate appInput (minimal — we only need it for the compact summary)
    if (!data.appInput || typeof data.appInput !== "object") {
      return Response.json(
        { error: "appInput is required." },
        { status: 400 }
      );
    }
    const raw = data.appInput as Record<string, unknown>;
    const appInput = {
      appName: typeof raw.appName === "string" ? clamp(sanitizeText(raw.appName), 200) : "",
      appType: typeof raw.appType === "string" ? raw.appType : "Web application",
      description:
        typeof raw.description === "string"
          ? clamp(sanitizeText(raw.description), 8000)
          : "",
      authentication: Array.isArray(raw.authentication)
        ? (raw.authentication as unknown[]).filter((a): a is string => typeof a === "string")
        : [],
      internetFacing: !!raw.internetFacing,
      sensitiveData: !!raw.sensitiveData,
      usesCloud: !!raw.usesCloud,
      hasMultipleTenants: !!raw.hasMultipleTenants,
    } as import("@/lib/stride-engine").ThreatModelInput;

    // Images are optional
    const images: LlmImage[] = validateImages(data.images);

    const result = await generateRecommendations(
      config,
      threats,
      justifications,
      appInput,
      images
    );
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
