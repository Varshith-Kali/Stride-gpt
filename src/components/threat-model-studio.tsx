"use client";

import { useState, useCallback, useRef, useEffect, useMemo, useDeferredValue, type DragEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Wrench,
  Workflow,
  Loader2,
  AlertCircle,
  Sparkles,
  Download,
  Copy,
  Check,
  ChevronRight,
  Lock,
  Globe,
  Cloud,
  Users,
  FileSpreadsheet,
  ImagePlus,
  X,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  ArrowLeftRight,
} from "lucide-react";
import { useImageUpload } from "@/hooks/use-image-upload";
import type { UploadedImage } from "@/hooks/use-image-upload";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { toast } from "sonner";
import { BrandMark } from "@/components/brand-mark";
import { MermaidRenderer, type DiagramNodeTags } from "@/components/mermaid-renderer";
import {
  getDfdNodeId,
  reconcileDfdComponentThreats,
} from "@/lib/dfd-helpers";
import type {
  AppType,
  AuthMethod,
  Threat,
  ThreatModelResult,
  MitigationResult,
  DfdResult,
  DfdTrustLevel,
  SafetyMetricsResult,
} from "@/lib/stride-engine";
import {
  threatsToMarkdown,
  threatsToCSV,
  mitigationsToMarkdown,
  mitigationsToCSV,
  dfdToMarkdown,
  downloadText,
  downloadExcel,
  type ExcelBundle,
} from "@/lib/export-utils";

const STRIDE_CATEGORIES = [
  {
    name: "Spoofing",
    short: "S",
    color: "bg-neutral-900 text-white",
    desc: "Impersonating users or systems",
  },
  {
    name: "Tampering",
    short: "T",
    color: "bg-neutral-700 text-white",
    desc: "Modifying data or code",
  },
  {
    name: "Repudiation",
    short: "R",
    color: "bg-neutral-500 text-white",
    desc: "Denying actions without proof",
  },
  {
    name: "Information Disclosure",
    short: "I",
    color: "bg-neutral-800 text-white",
    desc: "Exposing data to unauthorized actors",
  },
  {
    name: "Denial of Service",
    short: "D",
    color: "bg-neutral-600 text-white",
    desc: "Disrupting service availability",
  },
  {
    name: "Elevation of Privilege",
    short: "E",
    color: "bg-neutral-900 text-white",
    desc: "Gaining unauthorized capabilities",
  },
] as const;

const APP_TYPES: AppType[] = [
  "Web application",
  "Mobile application",
  "Desktop application",
  "Cloud service/API",
  "IoT device",
  "Generative AI application",
  "Agentic AI application",
  "Microservice architecture",
  "Other",
];

const AUTH_METHODS: AuthMethod[] = [
  "None",
  "Username/password",
  "OAuth 2.0",
  "SAML",
  "SSO",
  "API keys",
  "JWT",
  "Biometric",
  "Certificate-based",
];


const EXAMPLE_APPS = [
  {
    label: "Fintech Mobile App",
    appName: "PayWave",
    appType: "Mobile application" as AppType,
    description:
      "A consumer mobile banking app that lets users view account balances, transfer money to contacts via phone number, deposit checks via photo capture, and receive push notifications for transactions. The app communicates with a backend API gateway which routes requests to microservices for auth, transactions, notifications, and fraud detection. PII and PCI data are stored in an encrypted PostgreSQL database. A third-party KYC vendor is called during onboarding.",
    authentication: ["JWT", "Biometric"] as AuthMethod[],
    internetFacing: true,
    sensitiveData: true,
    usesCloud: true,
    hasMultipleTenants: false,
  },
  {
    label: "RAG Customer Support Bot",
    appName: "SupportMind",
    appType: "Generative AI application" as AppType,
    description:
      "A retrieval-augmented generation chatbot embedded in a SaaS helpdesk. Customer questions are embedded via a hosted embedding model, queried against a vector store built from internal knowledge base articles and prior tickets, and a frontier LLM generates an answer with citations. The bot can escalate to a human agent and write draft replies. Tools include a search API, a ticketing API, and a CRM lookup. The system runs on a managed Kubernetes cluster.",
    authentication: ["OAuth 2.0", "API keys"] as AuthMethod[],
    internetFacing: true,
    sensitiveData: true,
    usesCloud: true,
    hasMultipleTenants: true,
  },
  {
    label: "Agentic Trading Platform",
    appName: "AutoTradeX",
    appType: "Agentic AI application" as AppType,
    description:
      "An autonomous trading agent platform where multiple LLM-powered agents monitor markets, execute trades via broker APIs, and reconcile positions. A planner agent decomposes user intents, a researcher agent queries market data and news, an executor agent places orders, and a risk agent enforces position limits. Agents communicate over an internal message bus and persist memory in a shared store. Users define strategies via a web UI and grant the agents scoped API credentials.",
    authentication: ["OAuth 2.0", "API keys"] as AuthMethod[],
    internetFacing: true,
    sensitiveData: true,
    usesCloud: true,
    hasMultipleTenants: true,
  },
  {
    label: "Healthcare Web Portal",
    appName: "MediPortal",
    appType: "Web application" as AppType,
    description:
      "A web portal where patients book appointments, view lab results, message providers, and pay bills. Providers use a separate dashboard to manage schedules and review patient records. The portal integrates with an EHR system via HL7 FHIR APIs. PHI is stored encrypted at rest. The system must comply with HIPAA. SSO is offered to partner clinics via SAML.",
    authentication: ["SAML", "Username/password"] as AuthMethod[],
    internetFacing: true,
    sensitiveData: true,
    usesCloud: true,
    hasMultipleTenants: false,
  },
];

type TabId =
  | "threats"
  | "mitigations"
  | "dfd"
  | "safety";

const TABS: {
  id: TabId;
  label: string;
  icon: typeof Shield;
  description: string;
}[] = [
  {
    id: "threats",
    label: "Threat Model",
    icon: Shield,
    description: "STRIDE-categorized threats",
  },
  {
    id: "mitigations",
    label: "Mitigations",
    icon: Wrench,
    description: "Concrete countermeasures",
  },
  {
    id: "dfd",
    label: "Data Flow",
    icon: Workflow,
    description: "Trust-boundary diagram",
  },
  {
    id: "safety",
    label: "Safety Metrics",
    icon: Lock,
    description: "Posture evaluation",
  },
];

const riskColor = (risk: string) => {
  switch (risk) {
    case "Critical":
      return "bg-neutral-900 text-white";
    case "High":
      return "bg-neutral-700 text-white";
    case "Medium":
      return "bg-neutral-400 text-white";
    case "Low":
      return "bg-neutral-200 text-neutral-900";
    default:
      return "bg-neutral-200 text-neutral-900";
  }
};

export function ThreatModelStudio({
  config,
  onOpenConfig,
  onReset,
}: {
  config: import("@/lib/llm-config").LlmConfig | null;
  onOpenConfig: () => void;
  onReset?: (resetFn: () => void) => void;
}) {
  const [appName, setAppName] = useState("");
  const [appType, setAppType] = useState<AppType>("Web application");
  const [description, setDescription] = useState("");
  const deferredDescription = useDeferredValue(description);
  const [authentication, setAuthentication] = useState<AuthMethod[]>(["JWT"]);
  const [internetFacing, setInternetFacing] = useState(true);
  const [sensitiveData, setSensitiveData] = useState(true);
  const [usesCloud, setUsesCloud] = useState(true);
  const [hasMultipleTenants, setHasMultipleTenants] = useState(false);

  const [activeTab, setActiveTab] = useState<TabId>("threats");
  const [loading, setLoading] = useState<TabId | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Streaming progress -- chars received from SSE stream during threat model generation
  const [streamProgress, setStreamProgress] = useState(0);

  const [threatModel, setThreatModel] = useState<ThreatModelResult | null>(null);
  const [mitigations, setMitigations] = useState<MitigationResult | null>(null);
  const [dfd, setDfd] = useState<DfdResult | null>(null);
  const [safetyMetrics, setSafetyMetrics] = useState<SafetyMetricsResult | null>(null);
  const [highlightedThreatId, setHighlightedThreatId] = useState<string | null>(null);
  // Per-threat current controls -- keyed by threat ID. Session-only state.
  const [currentControls, setCurrentControls] = useState<Record<string, string>>({});

  // Session-only image upload state -- never persisted to any storage.
  const { images, addFiles, removeImage, clearAll: clearImages, isFull } = useImageUpload();

  const resultsRef = useRef<HTMLDivElement>(null);

  /** Reset ALL analysis state -- form fields + results + controls + images.
   *  API key is intentionally NOT touched (session-only, cleared only on tab close/refresh). */
  const resetStudio = useCallback(() => {
    setAppName("");
    setAppType("Web application");
    setDescription("");
    setAuthentication(["JWT"]);
    setInternetFacing(true);
    setSensitiveData(true);
    setUsesCloud(true);
    setHasMultipleTenants(false);
    setActiveTab("threats");
    setLoading(null);
    setError(null);
    setStreamProgress(0);
    setThreatModel(null);
    setMitigations(null);
    setDfd(null);
    setSafetyMetrics(null);
    setHighlightedThreatId(null);
    setCurrentControls({});
    clearImages();
    // Scroll back to the top of the studio
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [clearImages]);

  // Register reset function with parent so NavBar can trigger it
  useEffect(() => {
    onReset?.(resetStudio);
  }, [onReset, resetStudio]);

  const navigateToThreat = useCallback((threatId: string) => {
    const normalized = threatId.trim().toUpperCase();
    setHighlightedThreatId(normalized);
    setActiveTab("threats");
  }, []);

  // Scroll smoothly to a threat card after switching from DFD -> Threat Model tab
  useEffect(() => {
    if (activeTab !== "threats" || !highlightedThreatId) return;

    let attempts = 0;
    let rafOrTimer: ReturnType<typeof setTimeout> | null = null;
    let clearTimer: ReturnType<typeof setTimeout> | null = null;

    const tryScroll = () => {
      const el = document.getElementById(`threat-card-${highlightedThreatId}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        clearTimer = setTimeout(() => setHighlightedThreatId(null), 2600);
        return;
      }
      if (attempts < 16) {
        attempts++;
        rafOrTimer = setTimeout(tryScroll, 50);
      }
    };

    // Wait slightly for AnimatePresence mode="wait" (250ms) to mount ThreatsTab
    rafOrTimer = setTimeout(tryScroll, 280);

    return () => {
      if (rafOrTimer) clearTimeout(rafOrTimer);
      if (clearTimer) clearTimeout(clearTimer);
    };
  }, [activeTab, highlightedThreatId]);

  const loadExample = (idx: number) => {
    const ex = EXAMPLE_APPS[idx];
    setAppName(ex.appName);
    setAppType(ex.appType);
    setDescription(ex.description);
    setAuthentication(ex.authentication);
    setInternetFacing(ex.internetFacing);
    setSensitiveData(ex.sensitiveData);
    setUsesCloud(ex.usesCloud);
    setHasMultipleTenants(ex.hasMultipleTenants);
    toast.success(`Loaded example: ${ex.label}`);
  };

  const toggleAuth = (m: AuthMethod) => {
    setAuthentication((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]
    );
  };

  const buildInput = () => ({
    appName,
    appType,
    description,
    authentication,
    internetFacing,
    sensitiveData,
    usesCloud,
    hasMultipleTenants,
  });

  const requireConfig = () => {
    if (!config) {
      toast.error("Configure your LLM API key first.");
      onOpenConfig();
      return false;
    }
    return true;
  };

  const generateThreats = useCallback(async () => {
    if (!requireConfig()) return;
    if (description.trim().length < 10) {
      toast.error("Please describe your application (at least 10 characters).");
      return;
    }
    setLoading("threats");
    setError(null);
    setActiveTab("threats");
    setStreamProgress(0);

    try {
      const res = await fetch("/api/threat-model", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config,
          input: buildInput(),
          // Images are base64 data-URLs -- zero server persistence
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });

      if (!res.ok || !res.body) {
        const err = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(err.error || `Failed to generate threat model (${res.status})`);
      }

      // --- Read the SSE stream ------------------------------------------
      // The route sends `data: {...}\n\n` events:
      //   { type: "progress", chars: N }  -- live token counter
      //   { type: "done",     data: {...} } -- final parsed result
      //   { type: "error",    message: "..." } -- LLM error
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let lineBuffer = "";
      let finalResult: ThreatModelResult | null = null;

      outer: while (true) {
        const { done, value } = await reader.read();
        if (value) {
          lineBuffer += decoder.decode(value, { stream: !done });
        } else if (done) {
          lineBuffer += decoder.decode();
        }

        // SSE events are delimited by double newlines; flush remaining buffer when done
        const parts = lineBuffer.split("\n\n");
        lineBuffer = done ? "" : (parts.pop() ?? "");

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();

          let evt: { type: string; chars?: number; data?: ThreatModelResult; message?: string };
          try { evt = JSON.parse(payload) as typeof evt; } catch { continue; }

          if (evt.type === "progress" && typeof evt.chars === "number") {
            setStreamProgress(evt.chars);
          } else if (evt.type === "done" && evt.data) {
            finalResult = evt.data;
            break outer;
          } else if (evt.type === "error") {
            throw new Error(evt.message || "Failed to generate threat model");
          }
        }

        if (done) break;
      }

      if (!finalResult) {
        throw new Error("Threat model generation completed but returned no result.");
      }

      setThreatModel(finalResult);
      // Reset downstream artifacts and current controls on new threat model
      setMitigations(null);
      setDfd(null);
      setSafetyMetrics(null);
      setCurrentControls({});
      toast.success(
        `Identified ${finalResult.threats.length} threats across STRIDE categories`
      );
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        200
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error generating threat model";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(null);
      setStreamProgress(0);
    }
  }, [config, onOpenConfig, appName, appType, description, authentication, internetFacing, sensitiveData, usesCloud, hasMultipleTenants, images]);


  const generateMitigations = useCallback(async () => {
    if (!requireConfig()) return;
    if (!threatModel || threatModel.threats.length === 0) {
      toast.error("Generate a threat model first.");
      return;
    }
    setLoading("mitigations");
    setError(null);
    setActiveTab("mitigations");
    try {
      const res = await fetch("/api/mitigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config,
          input: buildInput(),
          threats: threatModel.threats,
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(errBody.error || `Failed to generate mitigations (${res.status})`);
      }
      const data: MitigationResult = await res.json();
      setMitigations(data);
      toast.success(`Generated ${data.mitigations.length} mitigations`);
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        200
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error generating mitigations";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(null);
    }
  }, [config, onOpenConfig, threatModel, appName, appType, description, authentication, internetFacing, sensitiveData, usesCloud, hasMultipleTenants, images]);

  const generateDfd = useCallback(async () => {
    if (!requireConfig()) return;
    if (description.trim().length < 10) {
      toast.error("Describe your application first.");
      return;
    }
    setLoading("dfd");
    setError(null);
    setActiveTab("dfd");
    try {
      const res = await fetch("/api/dfd", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config,
          input: buildInput(),
          threats: threatModel?.threats,
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(errBody.error || `Failed to generate DFD (${res.status})`);
      }
      const data: DfdResult = await res.json();
      setDfd(data);
      toast.success("Data flow diagram generated");
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        200
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error generating DFD";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(null);
    }
  }, [config, onOpenConfig, appName, appType, description, authentication, internetFacing, sensitiveData, usesCloud, hasMultipleTenants, images, threatModel]);

  /** Generate Safety Metrics -- evaluates each threat against its current control. */
  const handleGenerateSafety = useCallback(async () => {
    if (!requireConfig()) return;
    if (!threatModel || threatModel.threats.length === 0) {
      toast.error("Generate a threat model first.");
      return;
    }
    setLoading("safety");
    setError(null);
    setActiveTab("safety");
    try {
      const res = await fetch("/api/safety-metrics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config,
          input: buildInput(),
          threats: threatModel.threats,
          currentControls,
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(errBody.error || `Failed to generate safety metrics (${res.status})`);
      }
      const data: SafetyMetricsResult = await res.json();
      setSafetyMetrics(data);
      toast.success("Safety metrics evaluated");
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        200
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error generating safety metrics";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(null);
    }
  }, [config, onOpenConfig, appName, appType, description, authentication, internetFacing, sensitiveData, usesCloud, hasMultipleTenants, images, threatModel, currentControls]);

  const hasAnyResult = threatModel || mitigations || dfd || safetyMetrics;

  // useMemo: only recompute when safetyMetrics changes -- not on every keystroke.
  const safetyMetricsMap = useMemo(
    () =>
      safetyMetrics
        ? Object.fromEntries(safetyMetrics.metrics.map((m) => [m.threatId, m]))
        : undefined,
    [safetyMetrics]
  );

  // useMemo: stable object reference stops child components re-rendering on
  // every form keystroke when the bundle contents haven't actually changed.
  const excelBundle = useMemo<ExcelBundle>(
    () => ({
      threatModel: threatModel ?? undefined,
      currentControls,
      safetyMetrics: safetyMetricsMap,
    }),
    [threatModel, currentControls, safetyMetricsMap]
  );
  const hasExcelContent = !!threatModel;

  return (
    <section id="studio" className="relative pt-2 pb-6 sm:pt-3 sm:pb-10 flex-1 overflow-x-clip">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Tool header */}
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 sm:gap-4 mb-5 sm:mb-6">
          <div className="min-w-0">
            <h2 className="text-title text-neutral-900">
              Analysis Workspace
            </h2>
            <p className="text-xs sm:text-sm text-neutral-500 mt-1 leading-relaxed">
              Describe the system &middot; generate threat models, mitigations, safety metrics, and data flow diagrams.
            </p>
          </div>
          <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-3 flex-wrap shrink-0">
            {hasExcelContent && (
              <div className="flex items-center gap-2 flex-wrap">
                <Button
                  size="sm"
                  onClick={() => {
                    try {
                      downloadExcel("stride-gpt-report.xlsx", excelBundle);
                      toast.success("Downloaded stride-gpt-report.xlsx");
                    } catch {
                      toast.error("Failed to generate Excel file. Please try again.");
                    }
                  }}
                  className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800 h-9 px-3.5 sm:px-4 text-xs sm:text-sm whitespace-nowrap"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 shrink-0" />
                  Export Excel
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    try {
                      const payload = {
                        threatModel,
                        mitigations,
                        dfd,
                        currentControls,
                        safetyMetrics,
                      };
                      downloadText(
                        "stride-gpt-report.json",
                        JSON.stringify(payload, null, 2),
                        "application/json"
                      );
                      toast.success("Downloaded stride-gpt-report.json");
                    } catch {
                      toast.error("Failed to export JSON.");
                    }
                  }}
                  className="rounded-full border-neutral-300 h-9 px-3.5 sm:px-4 text-xs sm:text-sm whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5 shrink-0" />
                  Export JSON
                </Button>
              </div>
            )}
            <div className="flex items-center gap-2 sm:gap-3 text-[11px] sm:text-xs text-neutral-400 font-mono flex-wrap">
              <span className="flex items-center gap-1.5 whitespace-nowrap">
                <span className="w-1.5 h-1.5 rounded-full bg-neutral-900 shrink-0" />
                STRIDE
              </span>
              <span className="text-neutral-300">|</span>
              <span className="whitespace-nowrap">OWASP LLM/ASI</span>
              <span className="text-neutral-300">|</span>
              <span className="whitespace-nowrap">MITRE ATT&CK</span>
            </div>
          </div>
        </div>

        {/* Input panel */}
        <Card className="p-4 sm:p-6 lg:p-8 apple-card">
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 lg:gap-8">
            {/* Left: form */}
            <div className="lg:col-span-3 space-y-5 sm:space-y-6 min-w-0">
              <div className="space-y-2.5">
                <h3 className="text-title text-neutral-900">
                  Application Profile
                </h3>
                <div className="flex items-start gap-2">
                  <span className="text-xs font-medium text-neutral-400 h-7 inline-flex items-center shrink-0">
                    Try:
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {EXAMPLE_APPS.map((ex, i) => (
                      <Button
                        key={ex.label}
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => loadExample(i)}
                        className="h-7 px-2.5 text-xs font-medium text-neutral-700 border-neutral-200 hover:border-neutral-400 hover:bg-neutral-50 rounded-full whitespace-nowrap"
                      >
                        {ex.label}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2 min-w-0">
                  <Label htmlFor="appName" className="text-xs text-neutral-500">
                    Application name
                  </Label>
                  <Input
                    id="appName"
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    placeholder="e.g. PayWave"
                    className="h-11 rounded-xl w-full"
                  />
                </div>
                <div className="space-y-2 min-w-0">
                  <Label className="text-xs text-neutral-500">
                    Application type
                  </Label>
                  <Select
                    value={appType}
                    onValueChange={(v) => setAppType(v as AppType)}
                  >
                    <SelectTrigger className="w-full !h-11 rounded-xl">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {APP_TYPES.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label
                  htmlFor="description"
                  className="text-xs text-neutral-500"
                >
                  Application description
                </Label>
                <Textarea
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Describe the application or review scope (primary input). If you include specific recommendations, suggestions, or a targeted focus area such as an API integration, threat modeling will center around those first; attached diagrams provide extra architectural context..."
                  className="min-h-[140px] rounded-xl resize-y"
                />
                <div className="flex items-center justify-between text-xs text-neutral-400">
                  <span>{deferredDescription.length} characters</span>
                  {description.length > 0 && description.length < 10 && (
                    <span className="text-amber-600">
                      Add a few more details
                    </span>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-xs text-neutral-500">
                  Authentication methods
                </Label>
                <div className="flex flex-wrap gap-2">
                  {AUTH_METHODS.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => toggleAuth(m)}
                      className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all border ${
                        authentication.includes(m)
                          ? "bg-neutral-900 text-white border-neutral-900"
                          : "bg-white text-neutral-700 border-neutral-300 hover:border-neutral-500"
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {/* Image Upload Zone -- optional, session-only */}
              <ImageUploadZone
                images={images}
                isFull={isFull}
                onAdd={addFiles}
                onRemove={removeImage}
                onClearAll={clearImages}
              />
            </div>

            {/* Right: toggles + CTA */}
            <div className="lg:col-span-2 space-y-4 min-w-0">
              <h3 className="text-title text-neutral-900">Architecture</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-3">
                <ToggleRow
                  icon={Globe}
                  label="Internet-facing"
                  description="Publicly accessible entry points"
                  checked={internetFacing}
                  onCheckedChange={setInternetFacing}
                />
                <ToggleRow
                  icon={Lock}
                  label="Processes sensitive data"
                  description="PII, PHI, PCI, etc."
                  checked={sensitiveData}
                  onCheckedChange={setSensitiveData}
                />
                <ToggleRow
                  icon={Cloud}
                  label="Cloud-hosted"
                  description="Runs on AWS / GCP / Azure"
                  checked={usesCloud}
                  onCheckedChange={setUsesCloud}
                />
                <ToggleRow
                  icon={Users}
                  label="Multi-tenant"
                  description="Shared infra across customers"
                  checked={hasMultipleTenants}
                  onCheckedChange={setHasMultipleTenants}
                />
              </div>

              <div className="pt-2 sm:pt-4">
                <Button
                  size="lg"
                  onClick={generateThreats}
                  disabled={loading !== null}
                  className="w-full h-12 rounded-full bg-neutral-900 text-white hover:bg-neutral-800 text-sm sm:text-base font-medium"
                >
                  {loading === "threats" ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 shrink-0" />
                      Generate Threat Model
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* Results */}
        <div ref={resultsRef} className="mt-8 sm:mt-10">
          {error && (
            <div className="mb-6 flex items-start sm:items-center gap-3 p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 break-words">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 sm:mt-0" />
              <span className="text-sm min-w-0 flex-1">{error}</span>
            </div>
          )}

          {hasAnyResult ? (
            <div className="space-y-6">
              {/* Tab bar */}
              <div className="sticky top-14 z-20 -mx-4 px-4 sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8 py-2.5 tabbar-solid">
                <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
                  {TABS.map((tab) => {
                    const Icon = tab.icon;
                    const hasResult = (() => {
                      switch (tab.id) {
                        case "threats":
                          return !!threatModel;
                        case "mitigations":
                          return !!mitigations;
                        case "dfd":
                          return !!dfd;
                        case "safety":
                          return !!safetyMetrics;
                        default:
                          return false;
                      }
                    })();
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-1.5 sm:gap-2 px-3.5 sm:px-4 py-2 rounded-full text-xs sm:text-sm font-medium transition-all whitespace-nowrap shrink-0 ${
                          activeTab === tab.id
                            ? "bg-neutral-900 text-white"
                            : "text-neutral-600 hover:bg-neutral-100"
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4 shrink-0" />
                        {tab.label}
                        {hasResult && (
                          <span
                            className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                              activeTab === tab.id
                                ? "bg-white"
                                : "bg-neutral-900"
                            }`}
                          />
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Tab content */}
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                >
                  {activeTab === "threats" && (
                    <ThreatsTab
                      result={threatModel}
                      loading={loading === "threats"}
                      streamProgress={streamProgress}
                      highlightedThreatId={highlightedThreatId}
                      onNext={generateMitigations}
                      onDfd={generateDfd}
                      currentControls={currentControls}
                      onCurrentControlsChange={(id, val) =>
                        setCurrentControls((prev) => ({ ...prev, [id]: val }))
                      }
                      bundle={excelBundle}
                    />
                  )}
                  {activeTab === "mitigations" && (
                    <MitigationsTab
                      result={mitigations}
                      loading={loading === "mitigations"}
                      onGenerate={generateMitigations}
                      bundle={excelBundle}
                    />
                  )}
                  {activeTab === "dfd" && (
                    <DfdTab
                      result={dfd}
                      threats={threatModel?.threats}
                      loading={loading === "dfd"}
                      onGenerate={generateDfd}
                      onSelectThreat={navigateToThreat}
                      appName={appName}
                      bundle={excelBundle}
                    />
                  )}
                  {activeTab === "safety" && (
                    <SafetyMetricsTab
                      result={safetyMetrics}
                      loading={loading === "safety"}
                      onGenerate={handleGenerateSafety}
                      hasThreats={!!(threatModel && threatModel.threats.length > 0)}
                    />
                  )}
                </motion.div>
              </AnimatePresence>
            </div>
          ) : (
            !loading && (
              <EmptyState />
            )
          )}
        </div>
      </div>
    </section>
  );
}

/* ---------------- Safety Metrics Tab ---------------- */

const verdictConfig: Record<
  string,
  { label: string; bg: string; text: string; border: string; dot: string }
> = {
  SAFE: {
    label: "SAFE",
    bg: "bg-green-50",
    text: "text-green-800",
    border: "border-green-200",
    dot: "bg-green-500",
  },
  PARTIALLY_SAFE: {
    label: "PARTIALLY SAFE",
    bg: "bg-amber-50",
    text: "text-amber-800",
    border: "border-amber-200",
    dot: "bg-amber-400",
  },
  UNSAFE: {
    label: "UNSAFE",
    bg: "bg-red-50",
    text: "text-red-800",
    border: "border-red-200",
    dot: "bg-red-500",
  },
};

function SafetyMetricsTab({
  result,
  loading,
  onGenerate,
  hasThreats,
}: {
  result: SafetyMetricsResult | null;
  loading: boolean;
  onGenerate: () => void;
  hasThreats: boolean;
}) {
  if (loading) return <LoadingBlock label="Evaluating security posture" />;

  if (!result) {
    return (
      <Card className="p-6 sm:p-12 apple-card text-center">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-neutral-100 mb-4">
          <Lock className="w-6 h-6 text-neutral-400" />
        </div>
        <h3 className="text-title text-neutral-900 mb-2">Safety Metrics</h3>
        <p className="text-sm sm:text-base text-neutral-500 max-w-md mx-auto mb-2">
          Evaluate each threat against your existing controls. The AI will assess
          whether your current security posture is <span className="font-medium text-green-700">SAFE</span>,{" "}
          <span className="font-medium text-amber-700">PARTIALLY SAFE</span>, or{" "}
          <span className="font-medium text-red-700">UNSAFE</span> for each identified threat.
        </p>
        {!hasThreats && (
          <p className="text-xs text-neutral-400 mb-6">Generate a threat model first.</p>
        )}
        {hasThreats && (
          <p className="text-xs text-neutral-400 mb-6">
            Add current controls on threat cards for a more accurate evaluation.
          </p>
        )}
        <Button
          onClick={onGenerate}
          disabled={!hasThreats}
          className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
        >
          <Lock className="w-4 h-4" />
          Generate Safety Metrics
        </Button>
      </Card>
    );
  }

  // Tally verdicts
  const counts = result.metrics.reduce(
    (acc, m) => {
      acc[m.verdict] = (acc[m.verdict] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-6">
      {/* Overall posture card */}
      <Card className="p-4 sm:p-6 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div className="min-w-0">
            <h3 className="text-title text-neutral-900 mb-1">Safety Metrics</h3>
            <p className="text-xs sm:text-sm text-neutral-500">
              Security posture evaluated against existing controls
            </p>
          </div>
          <Button
            size="sm"
            onClick={onGenerate}
            variant="outline"
            className="rounded-full border-neutral-300 shrink-0"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Re-evaluate
          </Button>
        </div>

        {/* Summary badges */}
        <div className="flex items-center gap-2 sm:gap-3 flex-wrap mb-4">
          {(["SAFE", "PARTIALLY_SAFE", "UNSAFE"] as const).map((v) => {
            const cfg = verdictConfig[v];
            const count = counts[v] ?? 0;
            return (
              <div
                key={v}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs sm:text-sm font-medium tabular-nums ${cfg.bg} ${cfg.text} ${cfg.border}`}
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot}`} />
                {count} {cfg.label}
              </div>
            );
          })}
        </div>

        {/* Overall posture text */}
        <div className="p-3.5 sm:p-4 rounded-xl bg-neutral-50 border border-neutral-200">
          <p className="text-xs font-semibold text-neutral-500 uppercase tracking-wide mb-2">
            Overall Security Posture
          </p>
          <p className="text-sm text-neutral-700 leading-relaxed break-words">{result.overallPosture}</p>
        </div>
      </Card>

      {/* Per-threat metric cards */}
      <div className="space-y-3">
        {result.metrics.map((m) => {
          const cfg = verdictConfig[m.verdict] ?? verdictConfig["UNSAFE"];
          return (
            <Card key={m.threatId} className="p-4 sm:p-5 apple-card">
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-neutral-400 font-mono">{m.threatId}</span>
                </div>
                <span
                  className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-semibold border ${cfg.bg} ${cfg.text} ${cfg.border} flex-shrink-0`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                  {cfg.label}
                </span>
              </div>

              <h4 className="text-sm font-semibold text-neutral-900 mb-2 leading-snug break-words">
                {m.threat}
              </h4>

              <p className="text-sm text-neutral-600 leading-relaxed mb-3 break-words">{m.reasoning}</p>

              {m.gaps.length > 0 && (
                <div className="mt-2">
                  <p className="text-xs font-semibold text-neutral-500 uppercase tracking-wide mb-1.5">
                    Gaps to Address
                  </p>
                  <ul className="space-y-1">
                    {m.gaps.map((gap, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-neutral-700 break-words">
                        <span className="mt-1.5 w-1 h-1 rounded-full bg-amber-400 flex-shrink-0" />
                        <span className="min-w-0 flex-1">{gap}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function ToggleRow({
  icon: Icon,
  label,
  description,
  checked,
  onCheckedChange,
}: {
  icon: typeof Globe;
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 p-3 rounded-xl bg-neutral-50 border border-neutral-200">
      <div className="flex items-center gap-3 min-w-0">
        <div className="w-9 h-9 rounded-lg bg-white border border-neutral-200 flex items-center justify-center shrink-0">
          <Icon className="w-4 h-4 text-neutral-700" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-medium text-neutral-900 leading-snug">{label}</div>
          <div className="text-xs text-neutral-500 leading-snug">{description}</div>
        </div>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} className="shrink-0" />
    </div>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-10 sm:py-16 px-4">
      <div className="inline-flex items-center justify-center w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-neutral-900 mb-5 sm:mb-6">
        <BrandMark className="w-8 h-8 sm:w-9 sm:h-9 text-white" mono />
      </div>
      <h3 className="text-title text-neutral-900 mb-2">
        Your analysis will appear here
      </h3>
      <p className="text-sm sm:text-base text-neutral-500 max-w-md mx-auto leading-relaxed">
        Fill in the application profile above, then click{" "}
        <span className="font-medium text-neutral-900">Generate Threat Model</span>{" "}
        to start. Results for Threat Model, Mitigations, Data Flow, and Safety Metrics live in the tabs.
      </p>
    </div>
  );
}

/* ---------------- Threats Tab ---------------- */

function ThreatsTab({
  result,
  loading,
  streamProgress,
  highlightedThreatId,
  onNext,
  onDfd,
  currentControls,
  onCurrentControlsChange,
  bundle,
}: {
  result: ThreatModelResult | null;
  loading: boolean;
  /** Chars received from SSE stream so far -- 0 when not streaming. */
  streamProgress?: number;
  highlightedThreatId?: string | null;
  onNext: () => void;
  onDfd: () => void;
  currentControls: Record<string, string>;
  onCurrentControlsChange: (id: string, val: string) => void;
  bundle: ExcelBundle;
}) {
  if (loading) return <LoadingBlock label="Identifying STRIDE threats" progress={streamProgress} />;
  if (!result) return null;

  const counts = STRIDE_CATEGORIES.map((c) => ({
    ...c,
    count: result.threats.filter(
      (t) => t.strideCategory === c.name
    ).length,
  }));

  return (
    <div className="space-y-6">
      <Card className="p-4 sm:p-6 lg:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <h3 className="text-title text-neutral-900 mb-2">Executive Summary</h3>
            <p className="text-sm sm:text-base text-neutral-600 leading-relaxed break-words">{result.summary}</p>
          </div>
          <ExportMenu
            label="Threat Model"
            formats={{
              xlsx: { bundle, filename: "threat-model.xlsx" },
              markdown: {
                content: threatsToMarkdown(result),
                filename: "threat-model.md",
              },
              csv: { content: threatsToCSV(result), filename: "threat-model.csv" },
              json: {
                content: JSON.stringify(result, null, 2),
                filename: "threat-model.json",
              },
            }}
          />
        </div>

        {result.detectedPatterns.length > 0 && (
          <div className="mt-5 sm:mt-6 pt-5 sm:pt-6 border-t border-neutral-200">
            <p className="text-xs text-neutral-500 mb-3">
              DETECTED ARCHITECTURAL PATTERNS
            </p>
            <div className="flex flex-wrap gap-2">
              {result.detectedPatterns.map((p, i) => (
                <Badge
                  key={i}
                  variant="outline"
                  className="rounded-full border-neutral-300 text-neutral-700 whitespace-normal text-left"
                >
                  {p}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </Card>

      {/* STRIDE category strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 sm:gap-3">
        {counts.map((c) => (
          <div
            key={c.name}
            className="p-3.5 sm:p-4 rounded-2xl bg-white border border-neutral-200 hover:border-neutral-400 transition-colors"
          >
            <div
              className={`w-8 h-8 rounded-lg ${c.color} flex items-center justify-center font-semibold text-sm mb-2.5 sm:mb-3`}
            >
              {c.short}
            </div>
            <div className="text-xl sm:text-2xl font-semibold text-neutral-900 tabular-nums">
              {c.count}
            </div>
            <div className="text-xs text-neutral-500 mt-1 leading-snug">{c.name}</div>
          </div>
        ))}
      </div>

      {/* Threat list */}
      <div className="space-y-3">
        {result.threats.map((t, i) => {
          const normalizedId = t.id.trim().toUpperCase();
          return (
            <ThreatCard
              key={normalizedId || i}
              threat={t}
              isHighlighted={highlightedThreatId === normalizedId}
              currentControl={currentControls[t.id] ?? ""}
              onCurrentControlChange={(val) => onCurrentControlsChange(t.id, val)}
            />
          );
        })}
      </div>

      {result.architectureNotes && (
        <Card className="p-4 sm:p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-2">
            Architecture Notes
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed whitespace-pre-wrap break-words">
            {result.architectureNotes}
          </p>
        </Card>
      )}

      {/* Next actions */}
      <div className="flex flex-col sm:flex-row flex-wrap gap-2.5 sm:gap-3">
        <Button
          onClick={onNext}
          className="w-full sm:w-auto rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
        >
          <Wrench className="w-4 h-4" />
          Generate Mitigations
        </Button>
        <Button
          onClick={onDfd}
          variant="outline"
          className="w-full sm:w-auto rounded-full border-neutral-300"
        >
          <Workflow className="w-4 h-4" />
          Generate Data Flow Diagram
        </Button>
      </div>
    </div>
  );
}

function ThreatCard({
  threat,
  isHighlighted = false,
  currentControl,
  onCurrentControlChange,
}: {
  threat: Threat;
  isHighlighted?: boolean;
  currentControl: string;
  onCurrentControlChange: (val: string) => void;
}) {
  const [showControl, setShowControl] = useState(false);
  const cat = STRIDE_CATEGORIES.find((c) => c.name === threat.strideCategory);
  const normalizedThreatId = threat.id.trim().toUpperCase();
  return (
    <Card
      id={`threat-card-${normalizedThreatId}`}
      className={`p-4 sm:p-5 apple-card scroll-mt-28 transition-all duration-300 ${
        isHighlighted
          ? "ring-2 ring-neutral-900 border-neutral-900 bg-neutral-50/70 shadow-md"
          : ""
      }`}
    >
      <div className="flex items-start gap-3 sm:gap-4">
        <div
          className={`w-9 h-9 sm:w-10 sm:h-10 rounded-xl ${
            cat?.color || "bg-neutral-700 text-white"
          } flex items-center justify-center font-semibold text-sm sm:text-base flex-shrink-0`}
        >
          {cat?.short || "?"}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2 sm:gap-3 mb-1">
            <div className="flex items-center gap-2 flex-wrap min-w-0">
              <span className="text-xs text-neutral-400 font-mono">
                {threat.id}
              </span>
              <span className="text-xs text-neutral-500 break-words">{threat.category}</span>
              {isHighlighted && (
                <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-neutral-900 text-white">
                  Linked from DFD
                </span>
              )}
            </div>
            <span
              className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${riskColor(
                threat.risk
              )}`}
            >
              {threat.risk}
            </span>
          </div>
          <h4 className="text-sm sm:text-base font-semibold text-neutral-900 mb-1.5 leading-snug break-words">
            {threat.threat}
          </h4>
          <p className="text-xs sm:text-sm text-neutral-600 leading-relaxed mb-2.5 break-words">
            {threat.description}
          </p>

          {/* Component + MITRE metadata -- its own dedicated row */}
          <div className="flex items-center gap-x-3 gap-y-1.5 flex-wrap text-xs pb-1">
            <span className="text-neutral-500 break-words">
              <span className="text-neutral-400">Component:</span>{" "}
              {threat.component}
            </span>
            {threat.mitreAttack && threat.mitreAttack.length > 0 && (
              <div className="flex items-center gap-1 flex-wrap">
                <span className="text-neutral-400">MITRE:</span>
                {threat.mitreAttack.map((m, i) => (
                  <span
                    key={i}
                    className="px-1.5 py-0.5 rounded bg-neutral-100 text-neutral-700 font-mono text-[10px] break-all sm:break-normal"
                  >
                    {m}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Current controls -- always a full-width block below metadata, left-anchored */}
          <div className="mt-3 pt-3 border-t border-neutral-100">
            <button
              type="button"
              onClick={() => setShowControl((v) => !v)}
              className="flex items-center gap-1.5 text-xs text-neutral-500 hover:text-neutral-700 transition-colors py-0.5"
            >
              {showControl ? (
                <ChevronUp className="w-3 h-3 shrink-0" />
              ) : (
                <ChevronDown className="w-3 h-3 shrink-0" />
              )}
              {currentControl
                ? "Edit current controls"
                : "Add current controls (optional)"}
              {currentControl && (
                <span className="ml-1 w-1.5 h-1.5 rounded-full bg-neutral-900 shrink-0" />
              )}
            </button>
            <AnimatePresence>
              {showControl && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <textarea
                    id={`control-${threat.id}`}
                    value={currentControl}
                    onChange={(e) => onCurrentControlChange(e.target.value)}
                    placeholder={`Describe existing controls for ${threat.id}... e.g. "MFA enforced on all admin accounts via Azure AD Conditional Access; WAF rules block common injection patterns"`}
                    maxLength={500}
                    rows={3}
                    className="mt-2 w-full text-xs text-neutral-700 placeholder-neutral-400 bg-neutral-50 border border-neutral-200 rounded-lg p-3 resize-y focus:outline-none focus:ring-1 focus:ring-neutral-400 min-h-[84px]"
                  />
                  <div className="flex justify-between items-center gap-2 mt-1 flex-wrap">
                    <span className="text-[10px] text-neutral-400">
                      Used in Excel export &amp; as context for the LLM
                    </span>
                    <span className="text-[10px] text-neutral-400 tabular-nums">{currentControl.length}/500</span>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </Card>
  );
}

/* ---------------- Mitigations Tab ---------------- */

function MitigationsTab({
  result,
  loading,
  onGenerate,
  bundle,
}: {
  result: MitigationResult | null;
  loading: boolean;
  onGenerate: () => void;
  bundle: ExcelBundle;
}) {
  if (loading) return <LoadingBlock label="Designing countermeasures" />;
  if (!result)
    return (
      <PromptToGenerate
        title="Mitigations"
        description="Generate concrete, implementable countermeasures for each identified threat."
        onGenerate={onGenerate}
        requiresThreats
      />
    );
  return (
    <div className="space-y-6">
      <Card className="p-4 sm:p-6 lg:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div className="min-w-0">
            <h3 className="text-title text-neutral-900 mb-1">Mitigations</h3>
            <p className="text-xs sm:text-sm text-neutral-500">
              {result.mitigations.length} countermeasures across all threats.
            </p>
          </div>
          <ExportMenu
            label="Mitigations"
            formats={{
              xlsx: { bundle, filename: "mitigations-report.xlsx" },
              markdown: {
                content: mitigationsToMarkdown(result),
                filename: "mitigations.md",
              },
              csv: {
                content: mitigationsToCSV(result),
                filename: "mitigations.csv",
              },
              json: {
                content: JSON.stringify(result, null, 2),
                filename: "mitigations.json",
              },
            }}
          />
        </div>
        <div className="space-y-3">
          {result.mitigations.map((m, i) => (
            <div
              key={i}
              className="p-3.5 sm:p-4 rounded-xl bg-neutral-50 border border-neutral-200"
            >
              <div className="flex items-start justify-between gap-2.5 sm:gap-3 mb-2">
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-neutral-500 mb-1 break-words">
                    MITIGATES: {m.threat}
                  </p>
                  <p className="text-sm text-neutral-900 leading-relaxed break-words">
                    {m.mitigation}
                  </p>
                </div>
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${riskColor(
                    m.priority
                  )}`}
                >
                  {m.priority}
                </span>
              </div>
              {m.owaspReference && (
                <span className="inline-block text-xs px-2 py-0.5 rounded bg-neutral-200 text-neutral-700 font-mono break-words max-w-full">
                  {m.owaspReference}
                </span>
              )}
            </div>
          ))}
        </div>
      </Card>

      {result.hardeningChecklist.length > 0 && (
        <Card className="p-4 sm:p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-4">
            Hardening Checklist
          </h4>
          <ul className="space-y-2">
            {result.hardeningChecklist.map((c, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="w-5 h-5 rounded-full border border-neutral-400 flex items-center justify-center text-[10px] text-neutral-500 flex-shrink-0 mt-0.5 tabular-nums">
                  {i + 1}
                </span>
                <span className="text-neutral-700 break-words min-w-0 flex-1">{c}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

/* ---------------- DFD Tab ---------------- */

const TRUST_ZONE_META: Record<
  DfdTrustLevel,
  { badge: string; dot: string; label: string }
> = {
  External: {
    badge: "bg-red-50 text-red-900 border-red-200",
    dot: "bg-[#9C1D26]",
    label: "External (Untrusted)",
  },
  DMZ: {
    badge: "bg-orange-50 text-orange-900 border-orange-200",
    dot: "bg-orange-600",
    label: "DMZ Perimeter",
  },
  Internal: {
    badge: "bg-slate-100 text-slate-800 border-slate-300",
    dot: "bg-slate-700",
    label: "Internal Zone",
  },
  Secure: {
    badge: "bg-emerald-50 text-emerald-900 border-emerald-200",
    dot: "bg-teal-700",
    label: "Secure Data Zone",
  },
};

const THREAT_TAG_STYLE: Record<string, string> = {
  Critical: "bg-red-700 text-white border-red-800 hover:bg-red-800",
  High: "bg-orange-700 text-white border-orange-800 hover:bg-orange-800",
  Medium: "bg-slate-700 text-white border-slate-800 hover:bg-slate-800",
  Low: "bg-slate-500 text-white border-slate-600 hover:bg-slate-600",
};

function DfdTab({
  result,
  threats,
  loading,
  onGenerate,
  onSelectThreat,
  appName,
  bundle,
}: {
  result: DfdResult | null;
  threats?: Threat[];
  loading: boolean;
  onGenerate: () => void;
  onSelectThreat: (threatId: string) => void;
  appName: string;
  bundle: ExcelBundle;
}) {
  const threatMap = useMemo(() => {
    const m = new Map<string, Threat>();
    for (const t of threats ?? []) {
      if (t.id) m.set(t.id.trim().toUpperCase(), t);
    }
    return m;
  }, [threats]);

  const reconciledComponents = useMemo(() => {
    if (!result) return [];
    return reconcileDfdComponentThreats(result.components, threats);
  }, [result, threats]);

  const nodeTags = useMemo(() => {
    const out: Record<string, DiagramNodeTags> = {};
    reconciledComponents.forEach((comp, idx) => {
      const ids = comp.threatIds ?? [];
      if (ids.length === 0) return;
      out[getDfdNodeId(idx)] = {
        componentName: comp.name,
        tags: ids.map((id) => {
          const t = threatMap.get(id);
          return {
            id,
            title: t?.threat,
            risk: t?.risk,
          };
        }),
      };
    });
    return out;
  }, [reconciledComponents, threatMap]);

  if (loading) return <LoadingBlock label="Generating data flow diagram" />;
  if (!result)
    return (
      <PromptToGenerate
        title="Data Flow Diagram"
        description="Visualize external entities, processes, data stores, and trust boundaries."
        onGenerate={onGenerate}
      />
    );

  const safeSlug =
    appName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "stride-gpt";

  const zoneCounts = reconciledComponents.reduce(
    (acc, c) => {
      acc[c.trustLevel] = (acc[c.trustLevel] ?? 0) + 1;
      return acc;
    },
    {} as Partial<Record<DfdTrustLevel, number>>
  );

  const linkedThreatCount = new Set(
    reconciledComponents.flatMap((c) => c.threatIds ?? [])
  ).size;

  const exportResult: DfdResult = {
    ...result,
    components: reconciledComponents,
  };

  return (
    <div className="space-y-6">
      <Card className="p-4 sm:p-6 lg:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div className="min-w-0">
            <h3 className="text-title text-neutral-900 mb-1">
              Data Flow Diagram
            </h3>
            <p className="text-xs sm:text-sm text-neutral-500">
              {reconciledComponents.length} components &middot; {result.flows.length} data flows
              {linkedThreatCount > 0
                ? ` - ${linkedThreatCount} threat tags linked`
                : !threats || threats.length === 0
                  ? " - Generate Threat Model to display threat tags"
                  : ""}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              size="sm"
              variant="outline"
              onClick={onGenerate}
              className="rounded-full border-neutral-300 shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Regenerate
            </Button>
            <ExportMenu
              label="DFD"
              formats={{
                xlsx: { bundle, filename: "dfd-report.xlsx" },
                markdown: {
                  content: dfdToMarkdown(exportResult),
                  filename: "dfd.md",
                },
                mermaid: {
                  content: result.mermaid,
                  filename: "dfd.mmd",
                },
                json: {
                  content: JSON.stringify(exportResult, null, 2),
                  filename: "dfd.json",
                },
              }}
            />
          </div>
        </div>

        {/* DFD shape & trust-zone legend */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl bg-neutral-50 border border-neutral-200 mb-4 text-xs">
          <div className="flex items-center gap-3 flex-wrap text-neutral-600">
            <span className="font-medium text-neutral-800">Shapes:</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-2.5 rounded-[2px] bg-[#9C1D26] inline-block" />
              External Entity
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3.5 h-2.5 rounded-full bg-slate-800 inline-block" />
              Process
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-2.5 rounded-b-sm rounded-t-[2px] bg-teal-700 inline-block" />
              Data Store
            </span>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {(["External", "DMZ", "Internal", "Secure"] as const).map((zone) => {
              const count = zoneCounts[zone] ?? 0;
              if (count === 0) return null;
              const meta = TRUST_ZONE_META[zone];
              return (
                <span
                  key={zone}
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[11px] font-medium tabular-nums ${meta.badge}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                  {zone}: {count}
                </span>
              );
            })}
          </div>
        </div>

        {/* Rendered Mermaid DFD */}
        <div className="rounded-xl bg-white border border-neutral-200 p-3 sm:p-4 mb-5 overflow-visible">
          <MermaidRenderer
            source={result.mermaid}
            downloadFilename={`${safeSlug}-dfd.svg`}
            nodeTags={nodeTags}
            onTagClick={onSelectThreat}
          />
        </div>

        {/* Copy Mermaid for draw.io / mermaid.live */}
        <CopyMermaidBar source={result.mermaid} />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          <div className="min-w-0">
            <h4 className="text-xs text-neutral-500 mb-3">COMPONENTS</h4>
            <div className="space-y-2">
              {reconciledComponents.map((c, i) => {
                const meta = TRUST_ZONE_META[c.trustLevel] ?? TRUST_ZONE_META.Internal;
                const tagIds = c.threatIds ?? [];
                return (
                  <div
                    key={i}
                    className="flex items-start justify-between gap-3 p-3 rounded-lg bg-neutral-50 border border-neutral-200"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium text-neutral-900 break-words">
                        {c.name}
                      </div>
                      <div className="text-xs text-neutral-500 break-words">{c.type}</div>
                      {tagIds.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap mt-2">
                          {tagIds.map((id) => {
                            const matched = threatMap.get(id);
                            const styleClass =
                              THREAT_TAG_STYLE[matched?.risk ?? "Medium"] ??
                              THREAT_TAG_STYLE.Medium;
                            return (
                              <button
                                key={id}
                                type="button"
                                onClick={() => onSelectThreat(id)}
                                title={
                                  matched
                                    ? `${id} (${matched.risk}): ${matched.threat} -- Open in Threat Model`
                                    : `Inspect ${id} in Threat Model`
                                }
                                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border font-mono text-[10px] font-semibold transition-colors cursor-pointer ${styleClass}`}
                              >
                                {id}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                    <span
                      className={`text-xs px-2.5 py-0.5 rounded-full border font-medium shrink-0 ${meta.badge}`}
                    >
                      {c.trustLevel}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="min-w-0">
            <h4 className="text-xs text-neutral-500 mb-3">DATA FLOWS</h4>
            <div className="space-y-2">
              {result.flows.map((f, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg bg-neutral-50 border border-neutral-200"
                >
                  <div className="flex items-center gap-1.5 sm:gap-2 text-sm flex-wrap">
                    <span className="font-medium text-neutral-900 break-words">
                      {f.from}
                    </span>
                    {f.bidirectional ? (
                      <ArrowLeftRight className="w-3.5 h-3.5 text-neutral-500 shrink-0" />
                    ) : (
                      <ChevronRight className="w-3 h-3 text-neutral-400 shrink-0" />
                    )}
                    <span className="font-medium text-neutral-900 break-words">
                      {f.to}
                    </span>
                  </div>
                  <div className="text-xs text-neutral-500 mt-1 break-words">
                    {f.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <details className="mt-5 group">
          <summary className="cursor-pointer text-sm font-medium text-neutral-700 hover:text-neutral-900 flex items-center gap-2">
            <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform shrink-0" />
            View Mermaid source
          </summary>
          <pre className="mt-3 p-3 sm:p-4 rounded-xl bg-neutral-50 border border-neutral-200 text-xs font-mono text-neutral-700 overflow-x-auto">
            {result.mermaid}
          </pre>
        </details>
      </Card>
      {result.narrative && (
        <Card className="p-4 sm:p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-3">
            Trust Boundary Narrative
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed break-words">
            {result.narrative}
          </p>
        </Card>
      )}
    </div>
  );
}

/* ---------------- Shared bits ---------------- */

function CopyMermaidBar({ source }: { source: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(source);
    setCopied(true);
    toast.success("Mermaid source copied -- paste into mermaid.live or draw.io");
    setTimeout(() => setCopied(false), 2500);
  };
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 sm:p-3.5 rounded-xl bg-neutral-50 border border-neutral-200">
      <div className="flex items-start sm:items-center gap-2.5 min-w-0">
        <Workflow className="w-4 h-4 text-neutral-500 flex-shrink-0 mt-0.5 sm:mt-0" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-neutral-900">
            Mermaid diagram ready
          </p>
          <p className="text-xs text-neutral-500 leading-relaxed">
            Paste into mermaid.live, draw.io (Arrange -&gt; Insert -&gt; Advanced -&gt; Mermaid), or any Markdown editor.
          </p>
        </div>
      </div>
      <Button
        size="sm"
        onClick={copy}
        className="w-full sm:w-auto rounded-full bg-neutral-900 text-white hover:bg-neutral-800 flex-shrink-0"
      >
        {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        {copied ? "Copied" : "Copy Mermaid"}
      </Button>
    </div>
  );
}

function LoadingBlock({ label, progress }: { label: string; progress?: number }) {
  const hasProgress = typeof progress === "number" && progress > 0;
  return (
    <Card className="p-8 sm:p-12 apple-card">
      <div className="flex flex-col items-center justify-center text-center">
        <Loader2 className="w-8 h-8 animate-spin text-neutral-900 mb-4" />
        <p className="text-sm font-medium text-neutral-900">{label}...</p>
        {hasProgress ? (
          <div className="mt-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-neutral-900 animate-pulse" />
            <p className="text-xs text-neutral-500">
              Receiving{" "}
              <span className="font-mono font-medium text-neutral-700 tabular-nums">
                {progress! >= 1000
                  ? `${(progress! / 1000).toFixed(1)}k`
                  : progress}
              </span>{" "}
              chars
            </p>
          </div>
        ) : (
          <p className="text-xs text-neutral-500 mt-1">
            The AI agent is reasoning through your application.
          </p>
        )}
      </div>
    </Card>
  );
}

function PromptToGenerate({
  title,
  description,
  onGenerate,
  requiresThreats,
}: {
  title: string;
  description: string;
  onGenerate: () => void;
  requiresThreats?: boolean;
}) {
  return (
    <Card className="p-6 sm:p-12 apple-card text-center">
      <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-neutral-100 mb-4">
        <Sparkles className="w-6 h-6 text-neutral-400" />
      </div>
      <h3 className="text-title text-neutral-900 mb-2">{title}</h3>
      <p className="text-sm sm:text-base text-neutral-500 max-w-md mx-auto mb-6">{description}</p>
      <Button
        onClick={onGenerate}
        className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
      >
        <Sparkles className="w-4 h-4" />
        Generate {title}
      </Button>
      {requiresThreats && (
        <p className="text-xs text-neutral-400 mt-4">
          Requires a threat model first.
        </p>
      )}
    </Card>
  );
}

function ExportMenu({
  label,
  formats,
}: {
  label: string;
  formats: {
    markdown?: { content: string; filename: string };
    csv?: { content: string; filename: string };
    json?: { content: string; filename: string };
    text?: { content: string; filename: string };
    mermaid?: { content: string; filename: string };
    xlsx?: { bundle: ExcelBundle; filename: string };
  };
}) {
  const [open, setOpen] = useState(false);

  type Item =
    | { kind: "text"; fmt: string; label: string; sub: string; content: string; filename: string; mime: string }
    | { kind: "xlsx"; fmt: string; label: string; sub: string; bundle: ExcelBundle; filename: string };

  const items: Item[] = [];
  if (formats.xlsx)
    items.push({
      kind: "xlsx",
      fmt: "Excel",
      label: "Excel",
      sub: ".xlsx - single STRIDE sheet",
      bundle: formats.xlsx.bundle,
      filename: formats.xlsx.filename,
    });
  if (formats.markdown)
    items.push({
      kind: "text",
      fmt: "Markdown",
      label: "Markdown",
      sub: ".md - formatted table",
      content: formats.markdown.content,
      filename: formats.markdown.filename,
      mime: "text/markdown",
    });
  if (formats.csv)
    items.push({
      kind: "text",
      fmt: "CSV",
      label: "CSV",
      sub: ".csv - spreadsheet-ready",
      content: formats.csv.content,
      filename: formats.csv.filename,
      mime: "text/csv",
    });
  if (formats.json)
    items.push({
      kind: "text",
      fmt: "JSON",
      label: "JSON",
      sub: ".json - structured",
      content: formats.json.content,
      filename: formats.json.filename,
      mime: "application/json",
    });
  if (formats.mermaid)
    items.push({
      kind: "text",
      fmt: "Mermaid",
      label: "Mermaid",
      sub: ".mmd - draw.io / mermaid.live",
      content: formats.mermaid.content,
      filename: formats.mermaid.filename,
      mime: "text/plain",
    });
  if (formats.text)
    items.push({
      kind: "text",
      fmt: "Text",
      label: "Text",
      sub: ".txt - plain text",
      content: formats.text.content,
      filename: formats.text.filename,
      mime: "text/plain",
    });

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="rounded-full border-neutral-300 shrink-0"
        >
          <Download className="w-3 h-3" />
          Export
          <ChevronRight className="w-3 h-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="w-56 rounded-xl border-neutral-200"
      >
        <DropdownMenuLabel className="text-xs text-neutral-500">
          Export {label}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {items.map((it) => (
          <DropdownMenuItem
            key={it.fmt}
            onClick={() => {
              try {
                if (it.kind === "xlsx") {
                  downloadExcel(it.filename, it.bundle);
                } else {
                  downloadText(it.filename, it.content, it.mime);
                }
                toast.success(`Downloaded ${it.filename}`);
              } catch {
                toast.error(`Failed to generate ${it.filename}. Please try again.`);
              }
              setOpen(false);
            }}
            className="cursor-pointer rounded-lg py-2"
          >
            <div className="flex flex-col">
              <span className="text-sm font-medium text-neutral-900">
                {it.label}
              </span>
              <span className="text-xs text-neutral-500">{it.sub}</span>
            </div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/* ---------------- Image Upload Zone ---------------- */

function ImageUploadZone({
  images,
  isFull,
  onAdd,
  onRemove,
  onClearAll,
}: {
  images: UploadedImage[];
  isFull: boolean;
  onAdd: (files: FileList | File[]) => Promise<string[]>;
  onRemove: (id: string) => void;
  onClearAll: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleFiles = async (files: FileList | File[]) => {
    const errors = await onAdd(files);
    errors.forEach((e) => toast.error(e));
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start sm:items-center justify-between gap-2 flex-wrap">
        <Label className="text-xs text-neutral-500 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 leading-relaxed">
          <ImagePlus className="w-3.5 h-3.5 shrink-0" />
          <span>Reference diagrams</span>
          <span className="text-neutral-400 font-normal">(optional supplementary context &middot; Architecture, DFD, or Sequence &middot; up to 5 &middot; max 4 MB each)</span>
        </Label>
        {images.length > 0 && (
          <button
            type="button"
            onClick={onClearAll}
            className="text-xs text-neutral-400 hover:text-neutral-600 transition-colors whitespace-nowrap shrink-0"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Drop zone */}
      {!isFull && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          className={`relative flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed cursor-pointer transition-colors px-4 py-5 sm:py-6 ${
            dragging
              ? "border-neutral-500 bg-neutral-100"
              : "border-neutral-300 bg-neutral-50 hover:border-neutral-400 hover:bg-neutral-100"
          }`}
        >
          <ImagePlus className="w-6 h-6 text-neutral-400 shrink-0" />
          <p className="text-xs text-neutral-500 text-center leading-relaxed">
            Drag &amp; drop architecture, DFD, or sequence diagrams here, or{" "}
            <span className="font-medium text-neutral-700">click to browse</span>
            <br />
            <span className="text-neutral-400">Used as extra architectural context alongside your Application Description &middot; PNG &middot; JPEG &middot; WebP</span>
          </p>
          <input
            ref={inputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            multiple
            className="hidden"
            onChange={(e) => { if (e.target.files) handleFiles(e.target.files); e.target.value = ""; }}
          />
        </div>
      )}

      {/* Thumbnails */}
      {images.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 sm:gap-3">
          {images.map((img) => (
            <div
              key={img.id}
              className="relative group rounded-xl overflow-hidden border border-neutral-200 bg-neutral-50"
            >
              <img
                src={img.previewUrl}
                alt={img.name}
                className="w-full h-24 sm:h-28 object-cover"
              />
              <div className="absolute inset-0 bg-black/0 sm:group-hover:bg-black/40 transition-colors flex items-start justify-end p-1.5 sm:p-0 sm:items-center sm:justify-center pointer-events-none">
                <button
                  type="button"
                  onClick={() => onRemove(img.id)}
                  className="pointer-events-auto opacity-100 sm:opacity-0 sm:group-hover:opacity-100 focus:opacity-100 transition-opacity w-7 h-7 rounded-full bg-white/95 shadow-sm flex items-center justify-center hover:bg-white"
                  title="Remove image"
                  aria-label={`Remove ${img.name}`}
                >
                  <X className="w-4 h-4 text-neutral-800" />
                </button>
              </div>
              <div className="px-2 py-1.5 border-t border-neutral-200">
                <p className="text-[10px] text-neutral-600 truncate font-medium">{img.name}</p>
                <p className="text-[10px] text-neutral-400 tabular-nums">{img.sizeLabel}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
