"use client";

import { useCallback, useSyncExternalStore } from "react";
import {
  type LlmConfig,
  type Provider,
  PROVIDER_MODELS,
  DEFAULT_MODEL,
} from "@/lib/llm-config";

/**
 * SECURITY NOTE — API key storage trade-off:
 *
 * The user's LLM API key is stored in browser localStorage. This is an
 * intentional design decision for a local developer tool:
 *
 * - The key is NEVER sent to the server as a standalone value — it travels
 *   only within the encrypted request body of each API call, bound to the
 *   user's specific generation request.
 * - The Content-Security-Policy header restricts which origins the page
 *   can connect to (Groq and Gemini only), reducing the exfiltration attack
 *   surface.
 * - The alternative (server-side session) would require authentication
 *   infrastructure (NextAuth, DB, JWTs) that is intentionally out of scope
 *   for a self-hosted developer tool.
 *
 * Risk accepted. Revisit if this tool is ever exposed to untrusted users.
 */
const STORAGE_KEY = "stride-gpt-llm-config";

// --- Module-level cache so useSyncExternalStore returns a stable reference ---
let cachedConfig: LlmConfig | null = null;
let cacheInitialized = false;

function readStored(): LlmConfig | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<LlmConfig>;
    if (
      (parsed.provider === "groq" || parsed.provider === "gemini") &&
      typeof parsed.apiKey === "string" &&
      typeof parsed.model === "string"
    ) {
      return { provider: parsed.provider, apiKey: parsed.apiKey, model: parsed.model };
    }
  } catch {
    /* ignore */
  }
  return null;
}

function writeStored(c: LlmConfig | null) {
  if (typeof window === "undefined") return;
  try {
    if (c) {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(c));
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    /* ignore */
  }
}

// Refresh the module-level cache from localStorage.
function refreshCache() {
  cachedConfig = readStored();
  cacheInitialized = true;
}

let listeners: Array<() => void> = [];
function emitChange() {
  refreshCache();
  for (const l of listeners) l();
}
function subscribe(listener: () => void) {
  listeners.push(listener);
  // Also listen to cross-tab storage events.
  if (typeof window !== "undefined") {
    const handler = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY || e.key === null) emitChange();
    };
    window.addEventListener("storage", handler);
    return () => {
      listeners = listeners.filter((l) => l !== listener);
      window.removeEventListener("storage", handler);
    };
  }
  return () => {
    listeners = listeners.filter((l) => l !== listener);
  };
}

const getServerSnapshot = () => null;
function getClientSnapshot(): LlmConfig | null {
  if (!cacheInitialized) refreshCache();
  return cachedConfig;
}

export function useLLMConfig() {
  const config = useSyncExternalStore(
    subscribe,
    getClientSnapshot,
    getServerSnapshot
  );

  const hydrated = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false
  );

  const save = useCallback(
    (provider: Provider, apiKey: string, model?: string) => {
      const m =
        model ||
        PROVIDER_MODELS[provider].find((x) => x.id === model)?.id ||
        DEFAULT_MODEL[provider];
      const next: LlmConfig = { provider, apiKey: apiKey.trim(), model: m };
      writeStored(next);
      emitChange();
      return next;
    },
    []
  );

  const clear = useCallback(() => {
    writeStored(null);
    emitChange();
  }, []);

  return { config, save, clear, hydrated };
}
