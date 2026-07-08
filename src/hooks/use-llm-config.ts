"use client";

import { useCallback, useRef, useState } from "react";
import { type LlmConfig, type Provider, DEFAULT_MODEL } from "@/lib/llm-config";

/**
 * SECURITY — Session-memory-only API key storage.
 *
 * The user's OpenAI API key is held EXCLUSIVELY in React component state
 * (heap memory). It is NEVER written to:
 *   - localStorage / sessionStorage / IndexedDB / cookies
 *   - Any server-side store or session
 *   - Any log, console, or network telemetry
 *
 * The key lives only for the duration of the browser tab. Closing the tab
 * or refreshing the page clears it completely. The user must re-enter it
 * each session — this is intentional and is the most secure design for a
 * tool that handles third-party credentials without a backend auth layer.
 *
 * In transit: the key travels only within the encrypted HTTPS request body
 * of each generation call, bound to a specific user action. It is never sent
 * as a header or URL parameter from the client.
 */

// Module-level ref so the config survives React re-renders without localStorage.
// It is cleared when the module is unloaded (i.e. page refresh / tab close).
let _sessionConfig: LlmConfig | null = null;
const _listeners = new Set<() => void>();

function notifyAll() {
  for (const l of _listeners) l();
}

export function useLLMConfig() {
  // Local state drives re-renders; module ref is the single source of truth.
  const [, forceRender] = useState(0);

  // Subscribe this component to config changes from other components.
  const isSubscribed = useRef(false);
  if (!isSubscribed.current) {
    isSubscribed.current = true;
    _listeners.add(() => forceRender((n) => n + 1));
  }

  const config = _sessionConfig;

  const save = useCallback(
    (provider: Provider, apiKey: string, model?: string) => {
      const m = model ?? DEFAULT_MODEL[provider];
      const next: LlmConfig = { provider, apiKey: apiKey.trim(), model: m };
      _sessionConfig = next;
      notifyAll();
      return next;
    },
    []
  );

  const clear = useCallback(() => {
    _sessionConfig = null;
    notifyAll();
  }, []);

  return { config, save, clear };
}
