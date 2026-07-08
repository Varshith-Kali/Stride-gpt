"use client";

import { useState } from "react";
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
import { toast } from "sonner";
import { Eye, EyeOff, Zap, Check, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
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
  const provider: Provider = "openai";
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(current?.model ?? DEFAULT_MODEL.openai);
  const [showKey, setShowKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<
    { ok: boolean; message: string } | null
  >(null);


  const handleSave = () => {
    if (!apiKey.trim()) {
      toast.error("Please enter your OpenAI API key.");
      return;
    }
    onSave(provider, apiKey.trim(), model);
    toast.success(
      `Connected · ${PROVIDER_MODELS.openai.find((m) => m.id === model)?.label ?? model}`
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
      });
      if (data.ok) {
        toast.success("Connection successful");
      } else {
        toast.error(data.error || "Connection failed");
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Network error";
      setTestResult({ ok: false, message: msg });
      toast.error(msg);
    } finally {
      setTesting(false);
    }
  };

  const models = PROVIDER_MODELS.openai;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md rounded-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg font-semibold">
            <Zap className="w-4 h-4 text-neutral-900" />
            OpenAI API Configuration
          </DialogTitle>
          <DialogDescription className="text-sm text-neutral-500">
            Enter your OpenAI API key to connect. Your key is held in session
            memory only — it is never saved to disk, browser storage, or any
            server. It will be cleared when you close or refresh the tab.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-2">
          {/* Security badge */}
          <div className="flex items-center gap-2 p-3 rounded-xl bg-neutral-50 border border-neutral-200">
            <ShieldCheck className="w-4 h-4 text-neutral-600 flex-shrink-0" />
            <p className="text-xs text-neutral-600 leading-relaxed">
              <span className="font-semibold">Zero persistence.</span> Key lives in
              session memory only. Cleared on refresh. Never logged or stored.
            </p>
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
                placeholder="sk-..."
                className="h-11 rounded-xl pr-10 font-mono text-sm"
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                data-1p-ignore       // disable 1Password autofill
                data-lpignore="true" // disable LastPass autofill
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
            <p className="leading-relaxed">{testResult.message}</p>
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
