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
import { toast } from "sonner";
import { Eye, EyeOff, Zap, Check, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import {
  type Provider,
  type LlmConfig,
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
    onSave(provider, apiKey.trim(), "gpt-5.5");
    toast.success("Connected · GPT-5.5");
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
          config: { provider, apiKey: apiKey.trim(), model: "gpt-5.5" },
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


  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md rounded-2xl max-h-[90dvh] overflow-y-auto p-4 sm:p-6">
        <DialogHeader className="text-left">
          <DialogTitle className="flex items-center gap-2 text-base sm:text-lg font-semibold pr-6">
            <Zap className="w-4 h-4 text-neutral-900 shrink-0" />
            <span>OpenAI API Configuration</span>
          </DialogTitle>
          <DialogDescription className="text-xs sm:text-sm text-neutral-500 leading-relaxed">
            Enter your OpenAI API key to connect. Your key is held in session
            memory only — it is never saved to disk, browser storage, or any
            server. It will be cleared when you close or refresh the tab.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 sm:space-y-5 py-1 sm:py-2">
          {/* Security badge */}
          <div className="flex items-start sm:items-center gap-2.5 p-3 rounded-xl bg-neutral-50 border border-neutral-200">
            <ShieldCheck className="w-4 h-4 text-neutral-600 flex-shrink-0 mt-0.5 sm:mt-0" />
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
                className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-neutral-400 hover:text-neutral-700"
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

          {/* Model — fixed to GPT-5.5, displayed as read-only */}
          <div className="space-y-2">
            <Label className="text-xs text-neutral-500">MODEL</Label>
            <div className="min-h-11 py-2 rounded-xl border border-neutral-200 bg-neutral-50 px-3.5 sm:px-4 flex items-center justify-between gap-2 flex-wrap">
              <span className="text-sm font-medium text-neutral-900 whitespace-nowrap">GPT-5.5</span>
              <span className="text-xs text-neutral-400">Latest · Internal enterprise model</span>
            </div>
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={`flex items-start gap-2 p-3 rounded-xl text-xs break-words ${
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
            <p className="leading-relaxed min-w-0 flex-1">{testResult.message}</p>
          </div>
        )}

        <DialogFooter className="gap-2 sm:gap-2">
          {current && (
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="w-full sm:w-auto rounded-full border-neutral-300"
            >
              Cancel
            </Button>
          )}
          <Button
            variant="outline"
            onClick={handleTest}
            disabled={testing || !apiKey.trim()}
            className="w-full sm:w-auto rounded-full border-neutral-300"
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
            className="w-full sm:w-auto rounded-full bg-neutral-900 text-white hover:bg-neutral-800"
          >
            <Check className="w-4 h-4" />
            Save & Connect
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
