"use client";

import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import { ZoomIn, ZoomOut, RotateCcw, Download, X, ArrowUpRight } from "lucide-react";

// SECURITY: Use "strict" security level to prevent XSS via LLM-generated
// diagram labels. "loose" allows arbitrary HTML in node labels -- a jailbroken
// LLM could inject <script> tags through the diagram source.
// htmlLabels is disabled for the same reason.
mermaid.initialize({
  startOnLoad: false,
  theme: "neutral",
  themeVariables: {
    fontFamily:
      'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: "13px",
    primaryColor: "#ffffff",
    primaryTextColor: "#171717",
    primaryBorderColor: "#171717",
    lineColor: "#475569",
    secondaryColor: "#f8fafc",
    tertiaryColor: "#f1f5f9",
  },
  flowchart: {
    curve: "basis",
    padding: 26,
    nodeSpacing: 95,
    rankSpacing: 115,
    wrappingWidth: 190,
    useMaxWidth: true,
    // SECURITY: htmlLabels disabled -- prevents LLM-injected HTML in node labels.
    htmlLabels: false,
  },
  // SECURITY: strict mode -- mermaid sanitizes all label content.
  securityLevel: "strict",
});

let renderCounter = 0;

export interface DiagramTagItem {
  id: string;
  title?: string;
  risk?: "Low" | "Medium" | "High" | "Critical";
}

export interface DiagramNodeTags {
  componentName: string;
  tags: DiagramTagItem[];
}

const RISK_PILL_COLORS: Record<string, { fill: string; hover: string }> = {
  Critical: { fill: "#991b1b", hover: "#7f1d1d" },
  High: { fill: "#c2410c", hover: "#9a3412" },
  Medium: { fill: "#334155", hover: "#1e293b" },
  Low: { fill: "#475569", hover: "#334155" },
  Overflow: { fill: "#171717", hover: "#0a0a0a" },
};

const RISK_BADGE_CLASSES: Record<string, string> = {
  Critical: "bg-red-700 text-white border-red-800",
  High: "bg-orange-700 text-white border-orange-800",
  Medium: "bg-slate-700 text-white border-slate-800",
  Low: "bg-slate-500 text-white border-slate-600",
};

function normalizeNodeText(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

/**
 * Index all Mermaid flowchart node `<g>` elements by logical node ID (e.g. `N0`).
 * Mermaid v11 sets `id="${diagramId}-flowchart-${nodeId}-${counter}"` and omits `data-id`.
 */
function indexMermaidNodes(svgEl: SVGSVGElement): {
  byId: Map<string, SVGGElement>;
  byLabel: Map<string, SVGGElement>;
} {
  const byId = new Map<string, SVGGElement>();
  const byLabel = new Map<string, SVGGElement>();
  const nodes = svgEl.querySelectorAll("g.node");

  nodes.forEach((el) => {
    if (!(el instanceof SVGGElement)) return;
    const dataId = el.getAttribute("data-id");
    if (dataId && !byId.has(dataId)) {
      byId.set(dataId, el);
    }

    const domId = el.getAttribute("id") ?? "";
    const match = domId.match(/^(?:.+-)?flowchart-([A-Za-z0-9_]+)-\d+$/);
    if (match?.[1] && !byId.has(match[1])) {
      byId.set(match[1], el);
    } else if (domId && !byId.has(domId)) {
      byId.set(domId, el);
    }

    const text = normalizeNodeText(el.textContent ?? "");
    if (text && !byLabel.has(text)) {
      byLabel.set(text, el);
    }
  });

  return { byId, byLabel };
}

/**
 * Bounded post-render de-overlap pass for Mermaid `g.edgeLabel` elements.
 * When multiple flows fan out from a hub node, Dagre can place adjacent edge
 * labels slightly overlapping each other. This gently nudges colliding labels
 * apart vertically while keeping each label anchored near its edge.
 */
function deoverlapEdgeLabels(svgEl: SVGSVGElement): void {
  const labelNodes = Array.from(svgEl.querySelectorAll("g.edgeLabel")).filter(
    (el): el is SVGGElement => el instanceof SVGGElement
  );
  if (labelNodes.length < 2) return;

  interface PlacedLabel {
    el: SVGGElement;
    tx: number;
    ty: number;
    origTy: number;
    x: number;
    y: number;
    w: number;
    h: number;
  }

  const placed: PlacedLabel[] = [];
  for (const el of labelNodes) {
    const transform = el.getAttribute("transform") ?? "";
    const match = transform.match(/translate\(\s*([-\d.]+)[,\s]+([-\d.]+)\s*\)/);
    if (!match) continue;
    const tx = parseFloat(match[1]);
    const ty = parseFloat(match[2]);
    if (!Number.isFinite(tx) || !Number.isFinite(ty)) continue;

    let bbox: DOMRect;
    try {
      bbox = el.getBBox();
    } catch {
      continue;
    }
    if (!bbox || bbox.width <= 1 || bbox.height <= 1) continue;

    // Soften edge label halo rects slightly so labels remain crisp over lines
    const bgRect = el.querySelector("rect");
    if (bgRect) {
      bgRect.setAttribute("rx", "4");
      bgRect.setAttribute("ry", "4");
    }

    placed.push({
      el,
      tx,
      ty,
      origTy: ty,
      x: tx + bbox.x,
      y: ty + bbox.y,
      w: bbox.width,
      h: bbox.height,
    });
  }

  if (placed.length < 2) return;
  placed.sort((a, b) => a.y - b.y || a.x - b.x);

  const PAD_X = 6;
  const PAD_Y = 5;
  const MAX_SHIFT = 32;

  for (let pass = 0; pass < 3; pass++) {
    let moved = false;
    for (let i = 0; i < placed.length; i++) {
      for (let j = i + 1; j < placed.length; j++) {
        const a = placed[i];
        const b = placed[j];
        const xOverlap = a.x < b.x + b.w + PAD_X && a.x + a.w + PAD_X > b.x;
        const yOverlap = a.y < b.y + b.h + PAD_Y && a.y + a.h + PAD_Y > b.y;
        if (!xOverlap || !yOverlap) continue;

        const needed = a.y + a.h + PAD_Y - b.y;
        if (needed <= 0) continue;

        // Split adjustment symmetrically when possible so labels stay close to their edges
        const pushDown = Math.min(needed * 0.65, Math.max(0, b.origTy + MAX_SHIFT - b.ty));
        const pushUp = Math.min(needed - pushDown, Math.max(0, a.ty - (a.origTy - MAX_SHIFT)));

        if (pushDown > 0.25) {
          b.ty += pushDown;
          b.y += pushDown;
          moved = true;
        }
        if (pushUp > 0.25) {
          a.ty -= pushUp;
          a.y -= pushUp;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }

  for (const item of placed) {
    if (Math.abs(item.ty - item.origTy) > 0.25) {
      item.el.setAttribute(
        "transform",
        `translate(${item.tx.toFixed(1)}, ${item.ty.toFixed(1)})`
      );
    }
  }
}

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
    // Remove dangerous data: URI schemes without stripping legitimate "Data: ..." labels
    .replace(/\bdata\s*:\s*(?:text|application|image|audio|video|font)\b/gi, "")
    // Normalize line endings
    .replace(/\r\n/g, "\n")
    .trim();
}

/**
 * Renders a Mermaid source string as SVG. Re-renders when `source` changes.
 * Optionally overlays neat, clickable SVG threat pills on matching nodes.
 * Falls back to a <pre> with the source if rendering fails.
 */
export function MermaidRenderer({
  source,
  className = "",
  showControls = true,
  downloadFilename = "diagram.svg",
  nodeTags,
  onTagClick,
}: {
  source: string;
  className?: string;
  showControls?: boolean;
  downloadFilename?: string;
  nodeTags?: Record<string, DiagramNodeTags>;
  onTagClick?: (tagId: string) => void;
}) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const mountedSvgRef = useRef<string>("");
  const onTagClickRef = useRef(onTagClick);
  useEffect(() => {
    onTagClickRef.current = onTagClick;
  }, [onTagClick]);

  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [rendering, setRendering] = useState(true);
  const [zoom, setZoom] = useState(1);

  const [hoveredInfo, setHoveredInfo] = useState<{
    id: string;
    label: string;
    risk?: string;
    componentName: string;
    x: number;
    y: number;
  } | null>(null);

  const [expandedNode, setExpandedNode] = useState<DiagramNodeTags | null>(null);

  useEffect(() => {
    let cancelled = false;

    // These setState calls are intentional initialization inside useEffect --
    // we need to reset state synchronously before the async render starts.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRendering(true);
    setError(null);
    setZoom(1);
    setHoveredInfo(null);
    setExpandedNode(null);
    mountedSvgRef.current = "";

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
          // SECURITY: Never surface internal mermaid parser error messages --
          // they can contain file paths or internal parser state. Show a
          // generic message instead.
          setError(
            "Diagram syntax error -- the AI may have generated an invalid diagram. The source is shown below."
          );
          setRendering(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [source]);

  // Mount the Mermaid SVG imperatively (never via dangerouslySetInnerHTML) and
  // attach clickable SVG threat pills directly onto rendered nodes. Keeping SVG
  // DOM ownership out of React's reconciler guarantees hover/zoom/tooltip
  // re-renders can never reset innerHTML and wipe out threat pills or listeners.
  useEffect(() => {
    if (rendering || error || !svg) return;
    const container = containerRef.current;
    if (!container) return;

    const needsMount =
      mountedSvgRef.current !== svg || !container.querySelector("svg");
    if (needsMount) {
      container.innerHTML = svg;
      mountedSvgRef.current = svg;
    }

    const svgEl = container.querySelector("svg");
    if (!svgEl) return;

    if (needsMount) {
      const initialVb = svgEl.getAttribute("viewBox") ?? "";
      svgEl.dataset.baseViewBox = initialVb;
      // Prevent adjacent edge labels from overlapping on dense hub nodes
      deoverlapEdgeLabels(svgEl);
    }

    // Clean up any previous tag overlay layers before rebuilding
    svgEl.querySelectorAll('[data-mmd-tag-layer="true"]').forEach((el) => el.remove());

    const cleanups: Array<() => void> = [];
    const handleSvgLeave = () => setHoveredInfo(null);
    svgEl.addEventListener("mouseleave", handleSvgLeave);
    cleanups.push(() => svgEl.removeEventListener("mouseleave", handleSvgLeave));

    if (!nodeTags || Object.keys(nodeTags).length === 0) {
      if (svgEl.dataset.baseViewBox) {
        svgEl.setAttribute("viewBox", svgEl.dataset.baseViewBox);
      }
      return () => {
        cleanups.forEach((fn) => fn());
      };
    }

    const SVG_NS = "http://www.w3.org/2000/svg";
    const { byId, byLabel } = indexMermaidNodes(svgEl);

    for (const [nodeId, info] of Object.entries(nodeTags)) {
      if (!info || info.tags.length === 0) continue;

      const nodeEl =
        byId.get(nodeId) ??
        byLabel.get(normalizeNodeText(info.componentName)) ??
        null;
      if (!nodeEl) continue;

      let bbox: DOMRect;
      try {
        bbox = nodeEl.getBBox();
      } catch {
        continue;
      }
      if (!bbox || bbox.width <= 0 || bbox.height <= 0) continue;

      // Keep each node clean & uncluttered: show at most 3 pills (2 tags + +N overflow)
      type PillSpec =
        | { kind: "tag"; tag: DiagramTagItem; label: string; colors: { fill: string; hover: string } }
        | { kind: "overflow"; count: number; label: string; colors: { fill: string; hover: string } };

      const pills: PillSpec[] =
        info.tags.length <= 3
          ? info.tags.map((tag) => ({
              kind: "tag" as const,
              tag,
              label: tag.id,
              colors: RISK_PILL_COLORS[tag.risk ?? "Medium"] ?? RISK_PILL_COLORS.Medium,
            }))
          : [
              ...info.tags.slice(0, 2).map((tag) => ({
                kind: "tag" as const,
                tag,
                label: tag.id,
                colors: RISK_PILL_COLORS[tag.risk ?? "Medium"] ?? RISK_PILL_COLORS.Medium,
              })),
              {
                kind: "overflow" as const,
                count: info.tags.length - 2,
                label: `+${info.tags.length - 2}`,
                colors: RISK_PILL_COLORS.Overflow,
              },
            ];

      const pillHeight = 18;
      const gap = 4;
      const widths = pills.map((p) =>
        Math.max(p.kind === "overflow" ? 28 : 40, Math.round(p.label.length * 6.5 + 12))
      );
      const totalWidth = widths.reduce((a, b) => a + b, 0) + gap * (pills.length - 1);

      let cursorX = bbox.x + bbox.width / 2 - totalWidth / 2;
      const pillY = bbox.y + bbox.height - 4;

      const layer = document.createElementNS(SVG_NS, "g");
      layer.setAttribute("data-mmd-tag-layer", "true");

      pills.forEach((pill, idx) => {
        const w = widths[idx];
        const g = document.createElementNS(SVG_NS, "g");
        g.setAttribute("role", "button");
        g.setAttribute("tabindex", "0");
        g.setAttribute(
          "aria-label",
          pill.kind === "tag"
            ? `Inspect threat ${pill.tag.id} on ${info.componentName}`
            : `Show all ${info.tags.length} threats on ${info.componentName}`
        );
        g.style.cursor = "pointer";

        const rect = document.createElementNS(SVG_NS, "rect");
        rect.setAttribute("x", String(cursorX));
        rect.setAttribute("y", String(pillY));
        rect.setAttribute("width", String(w));
        rect.setAttribute("height", String(pillHeight));
        rect.setAttribute("rx", "9");
        rect.setAttribute("ry", "9");
        rect.setAttribute("fill", pill.colors.fill);
        rect.setAttribute("stroke", "#ffffff");
        rect.setAttribute("stroke-width", "1.75");

        const text = document.createElementNS(SVG_NS, "text");
        text.setAttribute("x", String(cursorX + w / 2));
        text.setAttribute("y", String(pillY + pillHeight / 2 + 0.5));
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("dominant-baseline", "central");
        text.setAttribute("fill", "#ffffff");
        text.setAttribute("font-size", "10");
        text.setAttribute("font-weight", "700");
        text.setAttribute(
          "font-family",
          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace'
        );
        text.style.pointerEvents = "none";
        text.textContent = pill.label;

        const nativeTitle = document.createElementNS(SVG_NS, "title");
        nativeTitle.textContent =
          pill.kind === "tag"
            ? `${pill.tag.id}${pill.tag.risk ? ` (${pill.tag.risk})` : ""}${pill.tag.title ? `: ${pill.tag.title}` : ""} - Click to view in Threat Model`
            : `${info.tags.length} threats on ${info.componentName} - Click to view all`;

        g.appendChild(nativeTitle);
        g.appendChild(rect);
        g.appendChild(text);

        const handleEnter = () => {
          rect.setAttribute("fill", pill.colors.hover);
          const wrapRect = wrapperRef.current?.getBoundingClientRect();
          const pillRect = rect.getBoundingClientRect();
          if (wrapRect && pillRect.width > 0) {
            const rawX = pillRect.left - wrapRect.left + pillRect.width / 2;
            const minX = Math.min(136, wrapRect.width / 2);
            const maxX = Math.max(minX, wrapRect.width - 136);
            setHoveredInfo({
              id: pill.kind === "tag" ? pill.tag.id : pill.label,
              label:
                pill.kind === "tag"
                  ? pill.tag.title || `Inspect ${pill.tag.id} in Threat Model`
                  : `${info.tags.length} threats on ${info.componentName} - click to pick`,
              risk: pill.kind === "tag" ? pill.tag.risk : undefined,
              componentName: info.componentName,
              x: Math.max(minX, Math.min(maxX, rawX)),
              y: pillRect.top - wrapRect.top,
            });
          }
        };

        const handleLeave = () => {
          rect.setAttribute("fill", pill.colors.fill);
          setHoveredInfo(null);
        };

        const handleActivate = (e: Event) => {
          e.stopPropagation();
          if (pill.kind === "tag") {
            setExpandedNode(null);
            setHoveredInfo(null);
            onTagClickRef.current?.(pill.tag.id);
          } else {
            setHoveredInfo(null);
            setExpandedNode((prev) =>
              prev?.componentName === info.componentName ? null : info
            );
          }
        };

        const handleKeyDown = (e: KeyboardEvent) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handleActivate(e);
          }
        };

        g.addEventListener("mouseenter", handleEnter);
        g.addEventListener("mouseleave", handleLeave);
        g.addEventListener("click", handleActivate);
        g.addEventListener("keydown", handleKeyDown);

        cleanups.push(() => {
          g.removeEventListener("mouseenter", handleEnter);
          g.removeEventListener("mouseleave", handleLeave);
          g.removeEventListener("click", handleActivate);
          g.removeEventListener("keydown", handleKeyDown);
        });

        layer.appendChild(g);
        cursorX += w + gap;
      });

      nodeEl.appendChild(layer);
    }

    // Pad viewBox slightly from the original base viewBox if overlay pills extend past diagram bounds
    try {
      const fullBox = svgEl.getBBox();
      const rawVb = svgEl.dataset.baseViewBox || svgEl.getAttribute("viewBox");
      if (rawVb && fullBox.width > 0 && fullBox.height > 0) {
        const parts = rawVb.trim().split(/\s+/).map(Number);
        if (parts.length === 4 && parts.every(Number.isFinite)) {
          const [vx, vy, vw, vh] = parts;
          const minX = Math.min(vx, Math.floor(fullBox.x - 14));
          const minY = Math.min(vy, Math.floor(fullBox.y - 14));
          const maxX = Math.max(vx + vw, Math.ceil(fullBox.x + fullBox.width + 14));
          const maxY = Math.max(vy + vh, Math.ceil(fullBox.y + fullBox.height + 20));
          svgEl.setAttribute("viewBox", `${minX} ${minY} ${maxX - minX} ${maxY - minY}`);
        }
      }
    } catch {
      // Ignore getBBox errors when SVG is temporarily hidden
    }

    return () => {
      cleanups.forEach((fn) => fn());
    };
  }, [svg, rendering, error, nodeTags]);

  useEffect(() => {
    if (!expandedNode) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setExpandedNode(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [expandedNode]);

  const handleDownloadSvg = () => {
    const svgEl = containerRef.current?.querySelector("svg");
    const serialized = svgEl
      ? new XMLSerializer().serializeToString(svgEl)
      : svg;
    if (!serialized) return;
    const blob = new Blob([serialized], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = downloadFilename;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (rendering) {
    return (
      <div className={`flex items-center justify-center py-12 ${className}`}>
        <div className="text-sm text-neutral-400">Rendering diagram...</div>
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
    <div ref={wrapperRef} className={`relative ${className}`}>
      {showControls && (
        <div className="flex items-center justify-between gap-2 mb-3 pb-2.5 border-b border-neutral-100 flex-wrap">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-[11px] font-mono text-neutral-400">
              Zoom: {Math.round(zoom * 100)}%
            </span>
            {nodeTags && Object.values(nodeTags).some((n) => n.tags.length > 0) && (
              <span className="text-[11px] text-neutral-500">
                Click any threat pill (e.g. <span className="font-mono font-semibold text-neutral-700">T001</span>) to inspect it in Threat Model
              </span>
            )}
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setZoom((z) => Math.max(0.5, +(z - 0.25).toFixed(2)))}
              disabled={zoom <= 0.5}
              className="inline-flex items-center justify-center h-7 w-7 rounded-lg border border-neutral-200 text-neutral-600 hover:bg-neutral-100 disabled:opacity-40 transition-colors"
              title="Zoom out"
              aria-label="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setZoom(1)}
              disabled={zoom === 1}
              className="inline-flex items-center justify-center h-7 px-2 rounded-lg border border-neutral-200 text-[11px] font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-40 transition-colors gap-1"
              title="Reset zoom"
              aria-label="Reset zoom"
            >
              <RotateCcw className="w-3 h-3" />
              Reset
            </button>
            <button
              type="button"
              onClick={() => setZoom((z) => Math.min(2.5, +(z + 0.25).toFixed(2)))}
              disabled={zoom >= 2.5}
              className="inline-flex items-center justify-center h-7 w-7 rounded-lg border border-neutral-200 text-neutral-600 hover:bg-neutral-100 disabled:opacity-40 transition-colors"
              title="Zoom in"
              aria-label="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleDownloadSvg}
              className="inline-flex items-center justify-center h-7 px-2.5 ml-1 rounded-lg border border-neutral-200 text-[11px] font-medium text-neutral-700 hover:bg-neutral-100 transition-colors gap-1"
              title="Download SVG"
            >
              <Download className="w-3 h-3" />
              SVG
            </button>
          </div>
        </div>
      )}

      {/* Expanded component threats bar when clicking "+N" overflow pill */}
      {expandedNode && (
        <div className="mb-3 p-3 rounded-xl bg-neutral-50 border border-neutral-200 flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-neutral-900">
              Threats mapped to {expandedNode.componentName} ({expandedNode.tags.length})
            </span>
            <button
              type="button"
              onClick={() => setExpandedNode(null)}
              className="p-1 rounded-md text-neutral-400 hover:text-neutral-700 hover:bg-neutral-200/60 transition-colors"
              aria-label="Close component threat list"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {expandedNode.tags.map((tag) => (
              <button
                key={tag.id}
                type="button"
                onClick={() => {
                  setExpandedNode(null);
                  onTagClick?.(tag.id);
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white border border-neutral-200 hover:border-neutral-900 text-xs text-neutral-800 transition-colors shadow-2xs"
              >
                <span
                  className={`px-1.5 py-0.2 rounded-full font-mono text-[10px] font-semibold border ${
                    RISK_BADGE_CLASSES[tag.risk ?? "Medium"] ?? RISK_BADGE_CLASSES.Medium
                  }`}
                >
                  {tag.id}
                </span>
                {tag.title && (
                  <span className="truncate max-w-[220px]">{tag.title}</span>
                )}
                <ArrowUpRight className="w-3 h-3 text-neutral-400 shrink-0" />
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="w-full overflow-auto">
        <div
          ref={containerRef}
          style={{
            width: `${Math.round(zoom * 100)}%`,
          }}
          className="mermaid-container mx-auto [&_svg]:w-full [&_svg]:!max-w-none [&_svg]:h-auto [&_svg]:mx-auto [&_svg]:block [&_.edgeLabel_rect]:!fill-white [&_.edgeLabel_rect]:!opacity-95 [&_.labelBkg]:!bg-white/95 [&_.edgeLabel]:!text-[11px] [&_.edgeLabel_text]:!text-[11px] [&_.edgeLabel_tspan]:!text-[11px] [&_.cluster-label_text]:!font-semibold transition-[width] duration-150"
        />
      </div>

      {/* Floating tooltip for hovered SVG threat pill */}
      {hoveredInfo && (
        <div
          style={{
            left: `${hoveredInfo.x}px`,
            top: `${Math.max(8, hoveredInfo.y - 8)}px`,
          }}
          className="pointer-events-none absolute z-30 -translate-x-1/2 -translate-y-full max-w-[260px] px-2.5 py-1.5 rounded-lg bg-neutral-900 text-white shadow-lg text-[11px] leading-snug"
        >
          <div className="flex items-center gap-1.5 font-mono font-semibold">
            <span>{hoveredInfo.id}</span>
            {hoveredInfo.risk && (
              <span className="text-[10px] text-neutral-300 font-sans font-medium">
                &middot; {hoveredInfo.risk}
              </span>
            )}
          </div>
          <div className="text-neutral-200 mt-0.5 line-clamp-2">{hoveredInfo.label}</div>
        </div>
      )}
    </div>
  );
}
