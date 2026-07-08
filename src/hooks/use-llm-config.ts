"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { type LlmConfig, type Provider, DEFAULT_MODEL } from "@/lib/llm-config";

/**
 * SECURITY — Session-memory-only API key storage.
 *
 * The user's OpenAI API key is held EXCLUSIVELY in module-level memory.
 * It is NEVER written to:
 *   - localStorage / sessionStorage / IndexedDB / cookies
 *   - Any server-side store or session
 *   - Any log, console, or network telemetry
 *
 * The key lives only for the duration of the browser tab. Closing the tab
 * or refreshing the page clears it completely. This is intentional — it is
 * the most secure design for a tool handling third-party credentials without
 * a backend auth layer.
 *
 * In transit: the key travels only within the encrypted HTTPS request body
 * of each generation call. It is never sent as a URL parameter or header
 * from the client side.
 */

// Module-level config store — cleared on page unload automatically (heap memory).
let _sessionConfig: LlmConfig | null = null;
const _listeners = new Set<() => void>();

function notifyAll() {
  for (const l of _listeners) l();
}

export function useLLMConfig() {
  const [, forceRender] = useState(0);
  const cleanupRef = useRef<(() => void) | null>(null);

  // Register this component as a listener on mount, unregister on unmount.
  // Using useEffect ensures we never access refs during render (lint: react-hooks/refs).
  useEffect(() => {
    const listener = () => forceRender((n) => n + 1);
    _listeners.add(listener);
    cleanupRef.current = () => _listeners.delete(listener);
    return () => {
      _listeners.delete(listener);
      cleanupRef.current = null;
    };
  }, []);

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
