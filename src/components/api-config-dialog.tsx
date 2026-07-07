"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Eye, EyeOff, Zap, Check, ExternalLink, Loader2, AlertTriangle } from "lucide-react";
import {
  type Provider,
  type LlmConfig,
  PROVIDER_MODELS,
  DEFAULT_MODEL,
} from "@/lib/llm-config";

export function ApiConfigDialog({
  open,
  onOpenChange,
  current,
  onSave,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  current: LlmConfig | null;
  onSave: (provider: Provider, apiKey: string, model?: string) => void;
}) {
  const [provider, setProvider] = useState<Provider>(
    current?.provider ?? "groq"
  );
  const [apiKey, setApiKey] = useState(current?.apiKey ?? "");
  const [model, setModel] = useState(
    current?.model ?? DEFAULT_MODEL[current?.provider ?? "groq"]
  );
  const [showKey, setShowKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<
    { ok: boolean; message: string; models?: string[] } | null
  >(null);

  // Re-sync when the dialog opens with the current config.
  useEffect(() => {
    if (open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setProvider(current?.provider ?? "groq");
      setApiKey(current?.apiKey ?? "");
      setModel(current?.model ?? DEFAULT_MODEL[current?.provider ?? "groq"]);
      setTestResult(null);
    }
  }, [open, current]);


  // When the provider switches, reset the model to that provider's default.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setModel(DEFAULT_MODEL[provider]);
    setTestResult(null);
  }, [provider]);

  const handleSave = () => {
    if (!apiKey.trim()) {
      toast.error("Please enter your API key.");
      return;
    }
    onSave(provider, apiKey.trim(), model);
    toast.success(
      `Connected to ${provider === "groq" ? "Groq" : "Google Gemini"} · ${
        PROVIDER_MODELS[provider].find((m) => m.id === model)?.label ?? model
      }`
    );
    onOpenChange(false);
  };

  const handleTest = async () => {
    if (!apiKey.trim()) {
      toast.error("Enter an API key first.");
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch("/api/test-connection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config: { provider, apiKey: apiKey.trim(), model },
        }),
      });
      const data = await res.json();
      setTestResult({
        ok: !!data.ok,
        message: data.ok ? data.message : data.error,
        models: data.models,
      });
      if (data.ok) {
        toast.success("Connection successful");
      } else {
        toast.error(data.error || "Connection failed");
      }
    } catch (e: any) {
      setTestResult({ ok: false, message: e?.message ?? "Network error" });
      toast.error(e?.message ?? "Network error");
    } finally {
      setTesting(false);
    }
  };

  const models = PROVIDER_MODELS[provider];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md rounded-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg font-semibold">
            <Zap className="w-4 h-4 text-neutral-900" />
            LLM API Configuration
          </DialogTitle>
          <DialogDescription className="text-sm text-neutral-500">
            Choose a free-tier provider and paste your API key. The key is stored
            in your browser only and sent directly to the provider — never to any
            third party.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-2">
          {/* Provider tabs */}
          <div className="space-y-2">
            <Label className="text-xs text-neutral-500">PROVIDER</Label>
            <Tabs
              value={provider}
              onValueChange={(v) => setProvider(v as Provider)}
            >
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="groq">Groq</TabsTrigger>
                <TabsTrigger value="gemini">Google Gemini</TabsTrigger>
              </TabsList>
            </Tabs>
            <a
              href={
                provider === "groq"
                  ? "https://console.groq.com/keys"
                  : "https://aistudio.google.com/apikey"
              }
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-900 transition-colors"
            >
              {provider === "groq"
                ? "Get a free Groq API key"
                : "Get a free Gemini API key"}
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          {/* API key */}
          <div className="space-y-2">
            <Label htmlFor="api-key" className="text-xs text-neutral-500">
              API KEY
            </Label>
            <div className="relative">
              <Input
                id="api-key"
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  provider === "groq" ? "gsk_..." : "AIza..."
                }
                className="h-11 rounded-xl pr-10 font-mono text-sm"
                autoComplete="off"
                spellCheck={false}
              />
              <button
                type="button"
                onClick={() => setShowKey((s) => !s)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-400 hover:text-neutral-700"
                aria-label={showKey ? "Hide key" : "Show key"}
              >
                {showKey ? (
                  <EyeOff className="w-4 h-4" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* Model */}
          <div className="space-y-2">
            <Label className="text-xs text-neutral-500">MODEL</Label>
            <Select value={model} onValueChange={setModel}>
              <SelectTrigger className="h-11 rounded-xl">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {models.map((m) => (
                  <SelectItem key={m.id} value={m.id} className="py-2">
                    <div className="flex flex-col">
                      <span className="text-sm font-medium">{m.label}</span>
                      <span className="text-xs text-neutral-500">{m.note}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={`flex items-start gap-2 p-3 rounded-xl text-xs ${
              testResult.ok
                ? "bg-green-50 border border-green-200 text-green-900"
                : "bg-amber-50 border border-amber-200 text-amber-900"
            }`}
          >
            {testResult.ok ? (
              <Check className="w-4 h-4 flex-shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            )}
            <div className="min-w-0">
              <p className="leading-relaxed">{testResult.message}</p>
              {testResult.models && testResult.models.length > 0 && (
                <p className="mt-1 text-[10px] opacity-70 font-mono truncate">
                  Available: {testResult.models.slice(0, 5).join(", ")}
                  {testResult.models.length > 5 ? "…" : ""}
                </p>
              )}
            </div>
          </div>
        )}

        <DialogFooter className="gap-2">
          {current && (
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="rounded-full border-neutral-300"
            >
              Cancel
            </Button>
          )}
          <Button
            variant="outline"
            onClick={handleTest}
            disabled={testing || !apiKey.trim()}
            className="rounded-full border-neutral-300"
          >
            {testing ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Zap className="w-4 h-4" />
            )}
            Test Connection
          </Button>
          <Button
            onClick={handleSave}
            className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
          >
            <Check className="w-4 h-4" />
            Save & Connect
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
