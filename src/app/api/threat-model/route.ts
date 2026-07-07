import { NextRequest } from "next/server";
import { generateThreatModel } from "@/lib/stride-engine";
import {
  readJsonRequest,
  configRequiredError,
  handleError,
} from "@/lib/api-utils";
import { validateThreatModelInput } from "@/lib/validation";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  try {
    const parsed = await readJsonRequest<{
      input?: unknown;
    }>(req);
    if (!parsed.ok) return parsed.error;

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

    const result = await generateThreatModel(config, input);
    return Response.json(result);
  } catch (e) {
    return handleError(e);
  }
}
