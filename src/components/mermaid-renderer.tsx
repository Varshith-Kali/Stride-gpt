"use client";

import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

// SECURITY: Use "strict" security level to prevent XSS via LLM-generated
// diagram labels. "loose" allows arbitrary HTML in node labels — a jailbroken
// LLM could inject <script> tags through the diagram source.
// htmlLabels is disabled for the same reason.
mermaid.initialize({
  startOnLoad: false,
  theme: "neutral",
  themeVariables: {
    fontFamily:
      'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: "14px",
    primaryColor: "#ffffff",
    primaryTextColor: "#171717",
    primaryBorderColor: "#171717",
    lineColor: "#525252",
    secondaryColor: "#f5f5f5",
    tertiaryColor: "#fafafa",
  },
  flowchart: {
    curve: "basis",
    padding: 20,
    nodeSpacing: 50,
    rankSpacing: 60,
    // SECURITY: htmlLabels disabled — prevents LLM-injected HTML in node labels.
    htmlLabels: false,
  },
  // SECURITY: strict mode — mermaid sanitizes all label content.
  securityLevel: "strict",
});

let renderCounter = 0;

/**
 * Strip dangerous patterns from mermaid source before rendering.
 *
 * SECURITY: Pre-sanitizer for LLM-generated diagram source.
 * Mermaid's strict mode handles most cases, but we add defense-in-depth
 * by removing known injection vectors before the string reaches mermaid.
 */
function sanitizeMermaidSource(source: string): string {
  return source
    // Remove script tags and javascript: URIs
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/javascript\s*:/gi, "")
    // Remove iframe / object / embed
    .replace(/<(iframe|object|embed|form|input|link)[^>]*>/gi, "")
    // Remove event handlers like onclick=, onerror=, onload=
    .replace(/\bon\w+\s*=/gi, "")
    // Remove data: URIs (could carry base64-encoded scripts)
    .replace(/data\s*:/gi, "")
    // Normalize line endings
    .replace(/\r\n/g, "\n")
    .trim();
}

/**
 * Renders a Mermaid source string as SVG. Re-renders when `source` changes.
 * Falls back to a <pre> with the source if rendering fails.
 */
export function MermaidRenderer({
  source,
  className = "",
}: {
  source: string;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [rendering, setRendering] = useState(true);

  useEffect(() => {
    let cancelled = false;

    // These setState calls are intentional initialization inside useEffect —
    // we need to reset state synchronously before the async render starts.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRendering(true);
    setError(null);

    const id = `mmd-${++renderCounter}`;
    const cleaned = sanitizeMermaidSource(source);

    mermaid
      .render(id, cleaned)
      .then(({ svg: renderedSvg }) => {
        if (!cancelled) {
          setSvg(renderedSvg);
          setRendering(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          // SECURITY: Never surface internal mermaid parser error messages —
          // they can contain file paths or internal parser state. Show a
          // generic message instead.
          setError(
            "Diagram syntax error — the AI may have generated an invalid diagram. The source is shown below."
          );
          setRendering(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [source]);

  if (rendering) {
    return (
      <div className={`flex items-center justify-center py-12 ${className}`}>
        <div className="text-sm text-neutral-400">Rendering diagram…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={className}>
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-amber-900 text-xs mb-3">
          {error}
        </div>
        <pre className="text-xs font-mono text-neutral-700 whitespace-pre-wrap p-4 rounded-xl bg-neutral-50 border border-neutral-200 overflow-x-auto">
          {source}
        </pre>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`mermaid-container flex justify-center overflow-x-auto ${className}`}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
