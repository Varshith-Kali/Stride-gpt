"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Wrench,
  Gauge,
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
  KeyRound,
  FileSpreadsheet,
  ImagePlus,
  X,
  ChevronDown,
  ChevronUp,
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
import { MermaidRenderer } from "@/components/mermaid-renderer";
import {
  threatsToMarkdown,
  threatsToCSV,
  mitigationsToMarkdown,
  mitigationsToCSV,
  dreadToMarkdown,
  dreadToCSV,
  dfdToMarkdown,
  attackTreeToMarkdown,
  gherkinToText,
  downloadText,
  downloadExcel,
  type ExcelBundle,
} from "@/lib/export-utils";

type AppType =
  | "Web application"
  | "Mobile application"
  | "Desktop application"
  | "Cloud service/API"
  | "IoT device"
  | "Generative AI application"
  | "Agentic AI application"
  | "Microservice architecture"
  | "Other";

type AuthMethod =
  | "None"
  | "Username/password"
  | "OAuth 2.0"
  | "SAML"
  | "SSO"
  | "API keys"
  | "JWT"
  | "Biometric"
  | "Certificate-based";


interface Threat {
  id: string;
  category: string;
  threat: string;
  component: string;
  description: string;
  strideCategory:
    | "Spoofing"
    | "Tampering"
    | "Repudiation"
    | "Information Disclosure"
    | "Denial of Service"
    | "Elevation of Privilege";
  mitreAttack?: string[];
  risk: "Low" | "Medium" | "High" | "Critical";
}

interface ThreatModelResult {
  threats: Threat[];
  summary: string;
  architectureNotes: string;
  detectedPatterns: string[];
}

interface AttackTreeNode {
  goal: string;
  subgoals: AttackTreeNode[];
}

interface AttackTreeResult {
  root: AttackTreeNode;
  mermaid: string;
  narrative: string;
}


interface MitigationResult {
  mitigations: {
    threat: string;
    mitigation: string;
    priority: "Low" | "Medium" | "High";
    owaspReference?: string;
  }[];
  hardeningChecklist: string[];
}

interface DreadScore {
  threat: string;
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
  total: number;
  severity: "Low" | "Medium" | "High" | "Critical";
}

interface DfdResult {
  mermaid: string;
  components: { name: string; type: string; trustLevel: string }[];
  flows: { from: string; to: string; description: string }[];
  narrative: string;
}

interface GherkinResult {
  feature: string;
  scenarios: { title: string; given: string; when: string; then: string[] }[];
}

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
  | "dread"
  | "dfd";

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
    id: "dread",
    label: "DREAD Score",
    icon: Gauge,
    description: "Risk prioritization",
  },
  {
    id: "dfd",
    label: "Data Flow",
    icon: Workflow,
    description: "Trust-boundary diagram",
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
}: {
  config: import("@/lib/llm-config").LlmConfig | null;
  onOpenConfig: () => void;
}) {
  const [appName, setAppName] = useState("");
  const [appType, setAppType] = useState<AppType>("Web application");
  const [description, setDescription] = useState("");
  const [authentication, setAuthentication] = useState<AuthMethod[]>(["JWT"]);
  const [internetFacing, setInternetFacing] = useState(true);
  const [sensitiveData, setSensitiveData] = useState(true);
  const [usesCloud, setUsesCloud] = useState(true);
  const [hasMultipleTenants, setHasMultipleTenants] = useState(false);

  const [activeTab, setActiveTab] = useState<TabId>("threats");
  const [loading, setLoading] = useState<TabId | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [threatModel, setThreatModel] = useState<ThreatModelResult | null>(null);
  const [mitigations, setMitigations] = useState<MitigationResult | null>(null);
  const [dreadScores, setDreadScores] = useState<DreadScore[] | null>(null);
  const [dfd, setDfd] = useState<DfdResult | null>(null);
  // Per-threat current controls â€” keyed by threat ID. Session-only state.
  const [currentControls, setCurrentControls] = useState<Record<string, string>>({});

  // Session-only image upload state â€” never persisted to any storage.
  const { images, addFiles, removeImage, clearAll: clearImages, isFull } = useImageUpload();

  const resultsRef = useRef<HTMLDivElement>(null);

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
    try {
      const res = await fetch("/api/threat-model", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config,
          input: buildInput(),
          // Images are base64 data-URLs â€” zero server persistence
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Failed to generate threat model");
      }
      const data: ThreatModelResult = await res.json();
      setThreatModel(data);
      // Reset downstream artifacts and current controls on new threat model
      setMitigations(null);
      setDreadScores(null);
      setDfd(null);
      setCurrentControls({});
      toast.success(
        `Identified ${data.threats.length} threats across STRIDE categories`
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
      if (!res.ok) throw new Error("Failed to generate mitigations");
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

  const generateDread = useCallback(async () => {
    if (!requireConfig()) return;
    if (!threatModel || threatModel.threats.length === 0) {
      toast.error("Generate a threat model first.");
      return;
    }
    setLoading("dread");
    setError(null);
    setActiveTab("dread");
    try {
      const res = await fetch("/api/dread", {
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
      if (!res.ok) throw new Error("Failed to generate DREAD scores");
      const data: DreadScore[] = await res.json();
      setDreadScores(data);
      toast.success("DREAD risk scores computed");
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        200
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error computing DREAD scores";
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
          images: images.length > 0
            ? images.map((img) => ({ mimeType: img.mimeType, dataUrl: img.dataUrl, name: img.name }))
            : undefined,
        }),
      });
      if (!res.ok) throw new Error("Failed to generate DFD");
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
  }, [config, onOpenConfig, appName, appType, description, authentication, internetFacing, sensitiveData, usesCloud, hasMultipleTenants, images]);

  const hasAnyResult = threatModel || mitigations || dreadScores || dfd;

  // Bundle for Excel export â€” single STRIDE sheet, with current controls per threat.
  const excelBundle: ExcelBundle = {
    threatModel: threatModel ?? undefined,
    currentControls: currentControls,
  };
  const hasExcelContent = !!threatModel;

  return (
    <section id="studio" className="relative pt-2 pb-4 sm:pt-3 sm:pb-6 flex-1">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Tool header */}
        <div className="flex items-end justify-between gap-4 mb-6 flex-wrap">
          <div>
            <h2 className="text-title text-neutral-900">
              Analysis Workspace
            </h2>
            <p className="text-sm text-neutral-500 mt-1">
            Describe the system Â· generate threat models, mitigations, DREAD scores, and data flow diagrams.
            </p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            {hasExcelContent && (
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
                className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800 h-9 px-4"
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                Export All as Excel
              </Button>
            )}
            <div className="flex items-center gap-3 text-xs text-neutral-400 font-mono">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-neutral-900" />
                STRIDE
              </span>
              <span>Â·</span>
              <span>OWASP LLM/ASI</span>
              <span>Â·</span>
              <span>MITRE ATT&CK</span>
            </div>
          </div>
        </div>

        {/* Input panel */}
        <Card className="p-6 sm:p-8 apple-card">
          <div className="grid lg:grid-cols-5 gap-8">
            {/* Left: form */}
            <div className="lg:col-span-3 space-y-6">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <h3 className="text-title text-neutral-900">
                  Application Profile
                </h3>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-neutral-500 hidden sm:inline">
                    Try:
                  </span>
                  {EXAMPLE_APPS.map((ex, i) => (
                    <Button
                      key={ex.label}
                      variant="outline"
                      size="sm"
                      onClick={() => loadExample(i)}
                      className="h-7 px-3 text-xs rounded-full"
                    >
                      {ex.label}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="appName" className="text-xs text-neutral-500">
                    Application name
                  </Label>
                  <Input
                    id="appName"
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    placeholder="e.g. PayWave"
                    className="h-11 rounded-xl"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-neutral-500">
                    Application type
                  </Label>
                  <Select
                    value={appType}
                    onValueChange={(v) => setAppType(v as AppType)}
                  >
                    <SelectTrigger className="h-11 rounded-xl">
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
                  placeholder="Describe the application: what it does, who uses it, key technologies, integrations, data flows, trust boundariesâ€¦"
                  className="min-h-[140px] rounded-xl resize-y"
                />
                <div className="flex items-center justify-between text-xs text-neutral-400">
                  <span>{description.length} characters</span>
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

              {/* Image Upload Zone â€” optional, session-only */}
              <ImageUploadZone
                images={images}
                isFull={isFull}
                onAdd={addFiles}
                onRemove={removeImage}
                onClearAll={clearImages}
              />
            </div>

            {/* Right: toggles + CTA */}
            <div className="lg:col-span-2 space-y-4">
              <h3 className="text-title text-neutral-900">Architecture</h3>
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
                description="PII, PHI, PCI, credentials, etc."
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

              <div className="pt-4">
                <Button
                  size="lg"
                  onClick={generateThreats}
                  disabled={loading !== null}
                  className="w-full h-12 rounded-full bg-neutral-900 text-white hover:bg-neutral-800 text-base font-medium"
                >
                  {loading === "threats" ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Analyzingâ€¦
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      Generate Threat Model
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* Results */}
        <div ref={resultsRef} className="mt-10">
          {error && (
            <div className="mb-6 flex items-center gap-3 p-4 rounded-xl bg-red-50 border border-red-200 text-red-900">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          {hasAnyResult ? (
            <div className="space-y-6">
              {/* Tab bar */}
              <div className="sticky top-14 z-20 -mx-4 px-4 py-2.5 tabbar-solid">
                <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
                  {TABS.map((tab) => {
                    const Icon = tab.icon;
                    const hasResult = (() => {
                      switch (tab.id) {
                        case "threats":
                          return !!threatModel;
                        case "mitigations":
                          return !!mitigations;
                        case "dread":
                          return !!dreadScores;
                        case "dfd":
                          return !!dfd;
                      }
                    })();
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all whitespace-nowrap ${
                          activeTab === tab.id
                            ? "bg-neutral-900 text-white"
                            : "text-neutral-600 hover:bg-neutral-100"
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                        {tab.label}
                        {hasResult && (
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
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
                      onNext={generateMitigations}
                      onDread={generateDread}
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
                  {activeTab === "dread" && (
                    <DreadTab
                      result={dreadScores}
                      loading={loading === "dread"}
                      onGenerate={generateDread}
                      bundle={excelBundle}
                    />
                  )}
                  {activeTab === "dfd" && (
                    <DfdTab
                      result={dfd}
                      loading={loading === "dfd"}
                      onGenerate={generateDfd}
                      bundle={excelBundle}
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
    <div className="flex items-center justify-between p-3 rounded-xl bg-neutral-50 border border-neutral-200">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-white border border-neutral-200 flex items-center justify-center">
          <Icon className="w-4 h-4 text-neutral-700" />
        </div>
        <div>
          <div className="text-sm font-medium text-neutral-900">{label}</div>
          <div className="text-xs text-neutral-500">{description}</div>
        </div>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-16">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-neutral-900 mb-6">
        <BrandMark className="w-9 h-9 text-white" mono />
      </div>
      <h3 className="text-title text-neutral-900 mb-2">
        Your analysis will appear here
      </h3>
      <p className="text-neutral-500 max-w-md mx-auto">
        Fill in the application profile above, then click{" "}
        <span className="font-medium text-neutral-900">Generate Threat Model</span>{" "}
        to start. Results for all six analyses live in the tabs.
      </p>
    </div>
  );
}

/* ---------------- Threats Tab ---------------- */

function ThreatsTab({
  result,
  loading,
  onNext,
  onDread,
  currentControls,
  onCurrentControlsChange,
  bundle,
}: {
  result: ThreatModelResult | null;
  loading: boolean;
  onNext: () => void;
  onDread: () => void;
  currentControls: Record<string, string>;
  onCurrentControlsChange: (id: string, val: string) => void;
  bundle: ExcelBundle;
}) {
  if (loading) return <LoadingBlock label="Identifying STRIDE threats" />;
  if (!result) return null;

  const counts = STRIDE_CATEGORIES.map((c) => ({
    ...c,
    count: result.threats.filter(
      (t) => t.strideCategory === c.name
    ).length,
  }));

  return (
    <div className="space-y-6">
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <h3 className="text-title text-neutral-900 mb-2">Executive Summary</h3>
            <p className="text-neutral-600 leading-relaxed">{result.summary}</p>
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
          <div className="mt-6 pt-6 border-t border-neutral-200">
            <p className="text-xs text-neutral-500 mb-3">
              DETECTED ARCHITECTURAL PATTERNS
            </p>
            <div className="flex flex-wrap gap-2">
              {result.detectedPatterns.map((p, i) => (
                <Badge
                  key={i}
                  variant="outline"
                  className="rounded-full border-neutral-300 text-neutral-700"
                >
                  {p}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </Card>

      {/* STRIDE category strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {counts.map((c) => (
          <div
            key={c.name}
            className="p-4 rounded-2xl bg-white border border-neutral-200 hover:border-neutral-400 transition-colors"
          >
            <div
              className={`w-8 h-8 rounded-lg ${c.color} flex items-center justify-center font-semibold text-sm mb-3`}
            >
              {c.short}
            </div>
            <div className="text-2xl font-semibold text-neutral-900">
              {c.count}
            </div>
            <div className="text-xs text-neutral-500 mt-1">{c.name}</div>
          </div>
        ))}
      </div>

      {/* Threat list */}
      <div className="space-y-3">
        {result.threats.map((t, i) => (
          <ThreatCard
            key={t.id || i}
            threat={t}
            currentControl={currentControls[t.id] ?? ""}
            onCurrentControlChange={(val) => onCurrentControlsChange(t.id, val)}
          />
        ))}
      </div>

      {result.architectureNotes && (
        <Card className="p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-2">
            Architecture Notes
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed whitespace-pre-wrap">
            {result.architectureNotes}
          </p>
        </Card>
      )}

      {/* Next actions */}
      <div className="flex flex-wrap gap-3">
        <Button
          onClick={onNext}
          className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
        >
          <Wrench className="w-4 h-4" />
          Generate Mitigations
        </Button>
        <Button
          onClick={onDread}
          variant="outline"
          className="rounded-full border-neutral-300"
        >
          <Gauge className="w-4 h-4" />
          Score with DREAD
        </Button>
      </div>
    </div>
  );
}

function ThreatCard({
  threat,
  currentControl,
  onCurrentControlChange,
}: {
  threat: Threat;
  currentControl: string;
  onCurrentControlChange: (val: string) => void;
}) {
  const [showControl, setShowControl] = useState(false);
  const cat = STRIDE_CATEGORIES.find((c) => c.name === threat.strideCategory);
  return (
    <Card className="p-5 apple-card">
      <div className="flex items-start gap-4">
        <div
          className={`w-10 h-10 rounded-xl ${
            cat?.color || "bg-neutral-700 text-white"
          } flex items-center justify-center font-semibold flex-shrink-0`}
        >
          {cat?.short || "?"}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3 mb-1">
            <div className="flex items-center gap-2 flex-wrap min-w-0">
              <span className="text-xs text-neutral-400 font-mono">
                {threat.id}
              </span>
              <span className="text-xs text-neutral-500">{threat.category}</span>
            </div>
            <span
              className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${riskColor(
                threat.risk
              )}`}
            >
              {threat.risk}
            </span>
          </div>
          <h4 className="text-base font-semibold text-neutral-900 mb-1.5 leading-snug">
            {threat.threat}
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed mb-2.5">
            {threat.description}
          </p>
          <div className="flex items-center gap-3 flex-wrap text-xs pt-1">
            <span className="text-neutral-500">
              <span className="text-neutral-400">Component:</span>{" "}
              {threat.component}
            </span>
            {threat.mitreAttack && threat.mitreAttack.length > 0 && (
              <div className="flex items-center gap-1 flex-wrap">
                <span className="text-neutral-400">MITRE:</span>
                {threat.mitreAttack.map((m, i) => (
                  <span
                    key={i}
                    className="px-1.5 py-0.5 rounded bg-neutral-100 text-neutral-700 font-mono text-[10px]"
                  >
                    {m}
                  </span>
                ))}
              </div>
            )}
           {/* Collapsible current controls textarea */}
          <div className="mt-3 pt-3 border-t border-neutral-100">
            <button
              type="button"
              onClick={() => setShowControl((v) => !v)}
              className="flex items-center gap-1.5 text-xs text-neutral-500 hover:text-neutral-700 transition-colors"
            >
              {showControl ? (
                <ChevronUp className="w-3 h-3" />
              ) : (
                <ChevronDown className="w-3 h-3" />
              )}
              {currentControl
                ? "Edit current controls"
                : "Add current controls (optional)"}
              {currentControl && (
                <span className="ml-1 w-1.5 h-1.5 rounded-full bg-neutral-900" />
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
                    placeholder={`Describe existing controls in your organization for ${threat.id}â€¦ e.g. "MFA enforced on all admin accounts via Azure AD Conditional Access"`}
                    maxLength={500}
                    rows={3}
                    className="mt-2 w-full text-xs text-neutral-700 placeholder-neutral-400 bg-neutral-50 border border-neutral-200 rounded-lg p-3 resize-none focus:outline-none focus:ring-1 focus:ring-neutral-400"
                  />
                  <div className="flex justify-end mt-1">
                    <span className="text-[10px] text-neutral-400">{currentControl.length}/500</span>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

/* ---------------- Attack Tree Tab ---------------- */

function AttackTreeTab({
  result,
  loading,
  onGenerate,
  bundle,
}: {
  result: AttackTreeResult | null;
  loading: boolean;
  onGenerate: () => void;
  bundle: ExcelBundle;
}) {
  if (loading)
    return <LoadingBlock label="Building adversary attack tree" />;
  if (!result)
    return (
      <PromptToGenerate
        title="Attack Tree"
        description="Decompose the attacker's primary goal into concrete sub-goals and techniques."
        onGenerate={onGenerate}
      />
    );
  return (
    <div className="space-y-6">
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div>
            <h3 className="text-title text-neutral-900 mb-1">Attack Tree</h3>
            <p className="text-sm text-neutral-500">
              Adversary goal decomposition â€” root goal flows down to leaf techniques.
            </p>
          </div>
          <ExportMenu
            label="Attack Tree"
            formats={{
              xlsx: { bundle, filename: "attack-tree-report.xlsx" },
              markdown: {
                content: attackTreeToMarkdown(result),
                filename: "attack-tree.md",
              },
              mermaid: {
                content: result.mermaid,
                filename: "attack-tree.mmd",
              },
              json: {
                content: JSON.stringify(result, null, 2),
                filename: "attack-tree.json",
              },
            }}
          />
        </div>
        <div className="mt-5 rounded-xl bg-white border border-neutral-200 p-4">
          <MermaidRenderer source={result.mermaid} />
        </div>
        <details className="mt-4 group">
          <summary className="cursor-pointer text-sm font-medium text-neutral-700 hover:text-neutral-900 flex items-center gap-2">
            <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" />
            View Mermaid source
          </summary>
          <pre className="mt-3 p-4 rounded-xl bg-neutral-50 border border-neutral-200 text-xs font-mono text-neutral-700 overflow-x-auto">
            {result.mermaid}
          </pre>
        </details>
        <details className="mt-3 group">
          <summary className="cursor-pointer text-sm font-medium text-neutral-700 hover:text-neutral-900 flex items-center gap-2">
            <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" />
            View as nested tree
          </summary>
          <div className="mt-3 pl-4 border-l-2 border-neutral-200">
            <TreeView node={result.root} depth={0} />
          </div>
        </details>
      </Card>
      {result.narrative && (
        <Card className="p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-3">
            Attack Path Narrative
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed whitespace-pre-wrap">
            {result.narrative}
          </p>
        </Card>
      )}
    </div>
  );
}

function TreeView({
  node,
  depth,
}: {
  node: AttackTreeNode;
  depth: number;
}) {
  return (
    <div className="space-y-1">
      <div
        className={`text-sm ${
          depth === 0
            ? "font-semibold text-neutral-900"
            : "text-neutral-700"
        }`}
        style={{ paddingLeft: `${depth * 16}px` }}
      >
        {depth > 0 && <span className="text-neutral-400 mr-2">â””â”€</span>}
        {node.goal}
      </div>
      {(node.subgoals || []).map((sg: AttackTreeNode, i: number) => (
        <TreeView key={i} node={sg} depth={depth + 1} />
      ))}
    </div>
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
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div>
            <h3 className="text-title text-neutral-900 mb-1">Mitigations</h3>
            <p className="text-sm text-neutral-500">
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
              className="p-4 rounded-xl bg-neutral-50 border border-neutral-200"
            >
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex-1">
                  <p className="text-xs text-neutral-500 mb-1">
                    MITIGATES: {m.threat}
                  </p>
                  <p className="text-sm text-neutral-900 leading-relaxed">
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
                <span className="inline-block text-xs px-2 py-0.5 rounded bg-neutral-200 text-neutral-700 font-mono">
                  {m.owaspReference}
                </span>
              )}
            </div>
          ))}
        </div>
      </Card>

      {result.hardeningChecklist.length > 0 && (
        <Card className="p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-4">
            Hardening Checklist
          </h4>
          <ul className="space-y-2">
            {result.hardeningChecklist.map((c, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="w-5 h-5 rounded-full border border-neutral-400 flex items-center justify-center text-[10px] text-neutral-500 flex-shrink-0 mt-0.5">
                  {i + 1}
                </span>
                <span className="text-neutral-700">{c}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

/* ---------------- DREAD Tab ---------------- */

function DreadTab({
  result,
  loading,
  onGenerate,
  bundle,
}: {
  result: DreadScore[] | null;
  loading: boolean;
  onGenerate: () => void;
  bundle: ExcelBundle;
}) {
  if (loading) return <LoadingBlock label="Scoring with DREAD model" />;
  if (!result || result.length === 0)
    return (
      <PromptToGenerate
        title="DREAD Risk Scores"
        description="Score each threat on Damage, Reproducibility, Exploitability, Affected Users, Discoverability."
        onGenerate={onGenerate}
        requiresThreats
      />
    );

  const sorted = [...result].sort((a, b) => b.total - a.total);
  const max = 50;

  return (
    <div className="space-y-6">
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
          <div>
            <h3 className="text-title text-neutral-900 mb-1">
              DREAD Risk Scoring
            </h3>
            <p className="text-sm text-neutral-500">
              Prioritized by total DREAD score (max 50). Higher = more severe.
            </p>
          </div>
          <ExportMenu
            label="DREAD Scores"
            formats={{
              xlsx: { bundle, filename: "dread-report.xlsx" },
              markdown: {
                content: dreadToMarkdown(sorted),
                filename: "dread-scores.md",
              },
              csv: {
                content: dreadToCSV(sorted),
                filename: "dread-scores.csv",
              },
              json: {
                content: JSON.stringify(sorted, null, 2),
                filename: "dread-scores.json",
              },
            }}
          />
        </div>

        <div className="space-y-4">
          {sorted.map((d, i) => (
            <div key={i} className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${riskColor(
                      d.severity
                    )}`}
                  >
                    {d.severity}
                  </span>
                  <span className="text-sm text-neutral-900 truncate">
                    {d.threat}
                  </span>
                </div>
                <span className="text-sm font-mono font-semibold text-neutral-900 flex-shrink-0">
                  {d.total}
                  <span className="text-neutral-400">/50</span>
                </span>
              </div>
              <div className="h-2 rounded-full bg-neutral-100 overflow-hidden">
                <div
                  className="h-full bg-neutral-900 rounded-full transition-all"
                  style={{ width: `${(d.total / max) * 100}%` }}
                />
              </div>
              <div className="grid grid-cols-5 gap-2 mt-2">
                {[
                  { label: "Damage", v: d.damage },
                  { label: "Repro", v: d.reproducibility },
                  { label: "Exploit", v: d.exploitability },
                  { label: "Users", v: d.affectedUsers },
                  { label: "Discover", v: d.discoverability },
                ].map((dim) => (
                  <div
                    key={dim.label}
                    className="text-center p-2 rounded-lg bg-neutral-50"
                  >
                    <div className="text-xs text-neutral-400">
                      {dim.label}
                    </div>
                    <div className="text-sm font-semibold text-neutral-900">
                      {dim.v}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

/* ---------------- DFD Tab ---------------- */

function DfdTab({
  result,
  loading,
  onGenerate,
  bundle,
}: {
  result: DfdResult | null;
  loading: boolean;
  onGenerate: () => void;
  bundle: ExcelBundle;
}) {
  if (loading) return <LoadingBlock label="Generating data flow diagram" />;
  if (!result)
    return (
      <PromptToGenerate
        title="Data Flow Diagram"
        description="Visualize external entities, processes, data stores, and trust boundaries."
        onGenerate={onGenerate}
      />
    );
  return (
    <div className="space-y-6">
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div>
            <h3 className="text-title text-neutral-900 mb-1">
              Data Flow Diagram
            </h3>
            <p className="text-sm text-neutral-500">
              {result.components.length} components Â· {result.flows.length} data flows
            </p>
          </div>
          <ExportMenu
            label="DFD"
            formats={{
              xlsx: { bundle, filename: "dfd-report.xlsx" },
              markdown: {
                content: dfdToMarkdown(result),
                filename: "dfd.md",
              },
              mermaid: {
                content: result.mermaid,
                filename: "dfd.mmd",
              },
              json: {
                content: JSON.stringify(result, null, 2),
                filename: "dfd.json",
              },
            }}
          />
        </div>

        {/* Rendered Mermaid DFD */}
        <div className="rounded-xl bg-white border border-neutral-200 p-4 mb-5">
          <MermaidRenderer source={result.mermaid} />
        </div>

        {/* Copy Mermaid for draw.io / mermaid.live */}
        <CopyMermaidBar source={result.mermaid} />

        <div className="grid lg:grid-cols-2 gap-6 mt-6">
          <div>
            <h4 className="text-xs text-neutral-500 mb-3">COMPONENTS</h4>
            <div className="space-y-2">
              {result.components.map((c, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-3 rounded-lg bg-neutral-50 border border-neutral-200"
                >
                  <div>
                    <div className="text-sm font-medium text-neutral-900">
                      {c.name}
                    </div>
                    <div className="text-xs text-neutral-500">{c.type}</div>
                  </div>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full ${
                      c.trustLevel === "High"
                        ? "bg-neutral-900 text-white"
                        : c.trustLevel === "Medium"
                        ? "bg-neutral-400 text-white"
                        : "bg-neutral-200 text-neutral-700"
                    }`}
                  >
                    {c.trustLevel}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4 className="text-xs text-neutral-500 mb-3">DATA FLOWS</h4>
            <div className="space-y-2">
              {result.flows.map((f, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg bg-neutral-50 border border-neutral-200"
                >
                  <div className="flex items-center gap-2 text-sm">
                    <span className="font-medium text-neutral-900">
                      {f.from}
                    </span>
                    <ChevronRight className="w-3 h-3 text-neutral-400" />
                    <span className="font-medium text-neutral-900">
                      {f.to}
                    </span>
                  </div>
                  <div className="text-xs text-neutral-500 mt-1">
                    {f.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <details className="mt-5 group">
          <summary className="cursor-pointer text-sm font-medium text-neutral-700 hover:text-neutral-900 flex items-center gap-2">
            <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" />
            View Mermaid source
          </summary>
          <pre className="mt-3 p-4 rounded-xl bg-neutral-50 border border-neutral-200 text-xs font-mono text-neutral-700 overflow-x-auto">
            {result.mermaid}
          </pre>
        </details>
      </Card>
      {result.narrative && (
        <Card className="p-6 apple-card">
          <h4 className="text-sm font-semibold text-neutral-900 mb-3">
            Trust Boundary Narrative
          </h4>
          <p className="text-sm text-neutral-600 leading-relaxed">
            {result.narrative}
          </p>
        </Card>
      )}
    </div>
  );
}

/* ---------------- Gherkin Tab ---------------- */

function GherkinTab({
  result,
  loading,
  onGenerate,
  bundle,
}: {
  result: GherkinResult | null;
  loading: boolean;
  onGenerate: () => void;
  bundle: ExcelBundle;
}) {
  const [copied, setCopied] = useState(false);
  if (loading) return <LoadingBlock label="Generating BDD test cases" />;
  if (!result)
    return (
      <PromptToGenerate
        title="Gherkin Test Cases"
        description="Generate BDD scenarios (Given/When/Then) that verify your system defends against each threat."
        onGenerate={onGenerate}
        requiresThreats
      />
    );

  const fullText = `${result.feature}\n\n${result.scenarios
    .map(
      (s) =>
        `${s.title}\n  ${s.given}\n  ${s.when}\n${s.then
          .map((t) => `  ${t}`)
          .join("\n")}`
    )
    .join("\n\n")}`;

  const copyAll = async () => {
    await navigator.clipboard.writeText(fullText);
    setCopied(true);
    toast.success("Copied Gherkin to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <Card className="p-6 sm:p-8 apple-card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
          <div>
            <h3 className="text-title text-neutral-900 mb-1">
              Gherkin Test Cases
            </h3>
            <p className="text-sm text-neutral-500">
              {result.scenarios.length} BDD scenarios ready for your test suite.
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={copyAll}
              className="rounded-full border-neutral-300"
            >
              {copied ? (
                <Check className="w-3 h-3" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
              Copy all
            </Button>
            <ExportMenu
              label="Gherkin Tests"
              formats={{
                xlsx: { bundle, filename: "gherkin-report.xlsx" },
                text: {
                  content: gherkinToText(result),
                  filename: "gherkin-tests.feature",
                },
                json: {
                  content: JSON.stringify(result, null, 2),
                  filename: "gherkin-tests.json",
                },
              }}
            />
          </div>
        </div>

        <div className="space-y-4">
          {result.scenarios.map((s, i) => (
            <div
              key={i}
              className="p-4 rounded-xl bg-neutral-50 border border-neutral-200"
            >
              <div className="text-sm font-semibold text-neutral-900 mb-2">
                {s.title}
              </div>
              <div className="space-y-1 text-sm font-mono">
                <div className="text-neutral-700">
                  <span className="text-neutral-400">Given</span> {s.given.replace(/^Given\s/, "")}
                </div>
                <div className="text-neutral-700">
                  <span className="text-neutral-400">When</span> {s.when.replace(/^When\s/, "")}
                </div>
                {s.then.map((t, j) => (
                  <div key={j} className="text-neutral-700">
                    <span className="text-neutral-400">
                      {j === 0 ? "Then" : "And"}
                    </span>{" "}
                    {t.replace(/^(Then|And)\s/, "")}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

/* ---------------- Shared bits ---------------- */

function CopyMermaidBar({ source }: { source: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(source);
    setCopied(true);
    toast.success("Mermaid source copied â€” paste into mermaid.live or draw.io");
    setTimeout(() => setCopied(false), 2500);
  };
  return (
    <div className="flex items-center justify-between gap-3 p-3 rounded-xl bg-neutral-50 border border-neutral-200">
      <div className="flex items-center gap-2 min-w-0">
        <Workflow className="w-4 h-4 text-neutral-500 flex-shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-neutral-900 truncate">
            Mermaid diagram ready
          </p>
          <p className="text-xs text-neutral-500">
            Paste into mermaid.live, draw.io (Arrange â†’ Insert â†’ Advanced â†’ Mermaid), or any Markdown editor.
          </p>
        </div>
      </div>
      <Button
        size="sm"
        onClick={copy}
        className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800 flex-shrink-0"
      >
        {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        {copied ? "Copied" : "Copy Mermaid"}
      </Button>
    </div>
  );
}

function LoadingBlock({ label }: { label: string }) {
  return (
    <Card className="p-12 apple-card">
      <div className="flex flex-col items-center justify-center text-center">
        <Loader2 className="w-8 h-8 animate-spin text-neutral-900 mb-4" />
        <p className="text-sm font-medium text-neutral-900">{label}â€¦</p>
        <p className="text-xs text-neutral-500 mt-1">
          The AI agent is reasoning through your application.
        </p>
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
    <Card className="p-12 apple-card text-center">
      <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-neutral-100 mb-4">
        <Sparkles className="w-6 h-6 text-neutral-400" />
      </div>
      <h3 className="text-title text-neutral-900 mb-2">{title}</h3>
      <p className="text-neutral-500 max-w-md mx-auto mb-6">{description}</p>
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
      sub: ".xlsx Â· multi-sheet workbook",
      bundle: formats.xlsx.bundle,
      filename: formats.xlsx.filename,
    });
  if (formats.markdown)
    items.push({
      kind: "text",
      fmt: "Markdown",
      label: "Markdown",
      sub: ".md Â· formatted table",
      content: formats.markdown.content,
      filename: formats.markdown.filename,
      mime: "text/markdown",
    });
  if (formats.csv)
    items.push({
      kind: "text",
      fmt: "CSV",
      label: "CSV",
      sub: ".csv Â· spreadsheet-ready",
      content: formats.csv.content,
      filename: formats.csv.filename,
      mime: "text/csv",
    });
  if (formats.json)
    items.push({
      kind: "text",
      fmt: "JSON",
      label: "JSON",
      sub: ".json Â· structured",
      content: formats.json.content,
      filename: formats.json.filename,
      mime: "application/json",
    });
  if (formats.mermaid)
    items.push({
      kind: "text",
      fmt: "Mermaid",
      label: "Mermaid",
      sub: ".mmd Â· draw.io / mermaid.live",
      content: formats.mermaid.content,
      filename: formats.mermaid.filename,
      mime: "text/plain",
    });
  if (formats.text)
    items.push({
      kind: "text",
      fmt: "Text",
      label: "Text",
      sub: ".txt Â· plain",
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
          className="rounded-full border-neutral-300"
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

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-neutral-500 flex items-center gap-1.5">
          <ImagePlus className="w-3.5 h-3.5" />
          Architecture diagrams
          <span className="text-neutral-400 font-normal">(optional Â· up to 5 Â· PNG/JPEG/WebP Â· max 4 MB each)</span>
        </Label>
        {images.length > 0 && (
          <button
            type="button"
            onClick={onClearAll}
            className="text-xs text-neutral-400 hover:text-neutral-600 transition-colors"
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
          className={`relative flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed cursor-pointer transition-colors py-6 ${
            dragging
              ? "border-neutral-500 bg-neutral-100"
              : "border-neutral-300 bg-neutral-50 hover:border-neutral-400 hover:bg-neutral-100"
          }`}
        >
          <ImagePlus className="w-6 h-6 text-neutral-400" />
          <p className="text-xs text-neutral-500 text-center leading-relaxed">
            Drag &amp; drop diagrams here, or{" "}
            <span className="font-medium text-neutral-700">click to browse</span>
            <br />
            <span className="text-neutral-400">PNG Â· JPEG Â· WebP Â· max 4 MB each Â· up to 5 images</span>
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
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {images.map((img) => (
            <div
              key={img.id}
              className="relative group rounded-xl overflow-hidden border border-neutral-200 bg-neutral-50"
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={img.previewUrl}
                alt={img.name}
                className="w-full h-28 object-cover"
              />
              <div className="absolute inset-0 bg-black/0 group-hover:bg-black/40 transition-colors flex items-center justify-center">
                <button
                  type="button"
                  onClick={() => onRemove(img.id)}
                  className="opacity-0 group-hover:opacity-100 transition-opacity w-7 h-7 rounded-full bg-white/90 flex items-center justify-center hover:bg-white"
                  title="Remove image"
                >
                  <X className="w-4 h-4 text-neutral-800" />
                </button>
              </div>
              <div className="px-2 py-1.5 border-t border-neutral-200">
                <p className="text-[10px] text-neutral-600 truncate font-medium">{img.name}</p>
                <p className="text-[10px] text-neutral-400">{img.sizeLabel}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
