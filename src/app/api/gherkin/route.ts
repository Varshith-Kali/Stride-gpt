import { NextRequest } from "next/server";
import { generateGherkin } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
} from "@/lib/api-utils";
import { sanitizeThreats, LIMITS } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  try {
    const parsed = await readJsonRequest<{
      threats?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

    const { config, data } = parsed;
    if (!config) return configRequiredError();

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
    const result = await generateGherkin(config, threats);
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
