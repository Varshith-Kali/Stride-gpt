"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { Settings, Zap, Check, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThreatModelStudio } from "@/components/threat-model-studio";
import { BrandMark } from "@/components/brand-mark";
import { ApiConfigDialog } from "@/components/api-config-dialog";
import { useLLMConfig } from "@/hooks/use-llm-config";
import { PROVIDER_MODELS } from "@/lib/llm-config";

export default function Page() {
  const { config, save } = useLLMConfig();
  const [configOpen, setConfigOpen] = useState(false);

  // resetRef holds the reset function registered by ThreatModelStudio.
  // Using a ref avoids unnecessary re-renders on the parent.
  const resetRef = useRef<(() => void) | null>(null);

  const handleReset = useCallback((fn: () => void) => {
    resetRef.current = fn;
  }, []);

  const triggerReset = useCallback(() => {
    resetRef.current?.();
  }, []);

  return (
    <main className="min-h-screen flex flex-col bg-background">
      <NavBar
        configured={!!config}
        providerLabel={config ? providerLabel(config.provider, config.model) : null}
        onOpenConfig={() => setConfigOpen(true)}
        onNewAnalysis={triggerReset}
      />
      <CompactHero />
      <ThreatModelStudio
        config={config}
        onOpenConfig={() => setConfigOpen(true)}
        onReset={handleReset}
      />
      <Footer />
      <ApiConfigDialog
        open={configOpen}
        onOpenChange={setConfigOpen}
        current={config}
        onSave={save}
      />
    </main>
  );
}

function providerLabel(_provider: string, model: string): string {
  const found = PROVIDER_MODELS.openai.find((m) => m.id === model);
  return found ? `OpenAI · ${found.label}` : "OpenAI";
}

/* ----------------- NavBar ----------------- */

function NavBar({
  configured,
  providerLabel,
  onOpenConfig,
  onNewAnalysis,
}: {
  configured: boolean;
  providerLabel: string | null;
  onOpenConfig: () => void;
  onNewAnalysis: () => void;
}) {
  const [scrolled, setScrolled] = useState(false);
  // "done" flash — shows a brief checkmark after reset completes
  const [justReset, setJustReset] = useState(false);
  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Clean up the flash timer on unmount
  useEffect(() => {
    return () => {
      if (flashTimer.current) clearTimeout(flashTimer.current);
    };
  }, []);

  const handleNewAnalysis = () => {
    onNewAnalysis();
    setJustReset(true);
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => setJustReset(false), 1800);
  };

  return (
    <header
      className={`sticky top-0 z-50 navbar-solid transition-shadow${
        scrolled ? " shadow-sm" : ""
      }`}
    >
      <div className="mx-auto max-w-7xl px-3 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-2 min-w-0">
        <Link href="/" className="flex items-center gap-2 sm:gap-2.5 shrink-0 min-w-0">
          <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-neutral-900 flex items-center justify-center shrink-0">
            <BrandMark className="w-4 h-4 sm:w-5 sm:h-5 text-white" mono />
          </div>
          <span className="font-semibold tracking-tight text-neutral-900 text-sm sm:text-base whitespace-nowrap">
            STRIDE GPT
          </span>
          <span className="hidden md:inline text-neutral-300">|</span>
          <span className="hidden md:inline text-xs text-neutral-400 font-mono whitespace-nowrap">
            threat modeling studio
          </span>
        </Link>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {/* API config button */}
          <button
            onClick={onOpenConfig}
            className={`inline-flex items-center gap-1.5 h-9 px-2.5 sm:px-3 rounded-full text-xs font-medium transition-all border whitespace-nowrap shrink-0 ${
              configured
                ? "border-neutral-300 text-neutral-700 hover:bg-neutral-100"
                : "border-amber-300 bg-amber-50 text-amber-900 hover:bg-amber-100"
            }`}
            title={providerLabel ?? "Configure LLM provider"}
          >
            {configured ? (
              <>
                <Check className="w-3 h-3 text-neutral-900 shrink-0" />
                <span className="hidden sm:inline">{providerLabel}</span>
                <span className="sm:hidden">LLM Ready</span>
                <Settings className="w-3 h-3 sm:hidden shrink-0" />
              </>
            ) : (
              <>
                <Zap className="w-3 h-3 shrink-0" />
                <span className="hidden min-[380px]:inline">Configure LLM</span>
                <span className="min-[380px]:hidden">LLM Key</span>
              </>
            )}
          </button>

          {/* New Analysis button — resets all form + results, preserves API key */}
          <Button
            size="sm"
            onClick={handleNewAnalysis}
            className={`rounded-full h-9 px-3 sm:px-4 text-xs sm:text-sm whitespace-nowrap shrink-0 transition-all duration-300 ${
              justReset
                ? "bg-green-700 hover:bg-green-700 text-white"
                : "bg-neutral-900 hover:bg-neutral-800 text-white"
            }`}
            title="Clear all analysis data and start fresh (API key is preserved)"
          >
            {justReset ? (
              <>
                <Check className="w-3.5 h-3.5 shrink-0" />
                <span>Cleared</span>
              </>
            ) : (
              <>
                <RotateCcw className="w-3.5 h-3.5 shrink-0" />
                <span className="hidden min-[420px]:inline">New Analysis</span>
                <span className="min-[420px]:hidden">New</span>
              </>
            )}
          </Button>
        </div>
      </div>
    </header>
  );
}

/* ----------------- Compact Hero ----------------- */

function CompactHero() {
  return (
    <section className="relative pt-4 pb-2 sm:pt-6 sm:pb-3 overflow-hidden">
      {/* Background grid */}
      <div className="absolute inset-0 grain-overlay opacity-60" aria-hidden />
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)",
          backgroundSize: "64px 64px",
        }}
        aria-hidden
      />

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <motion.h1
            initial={false}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-2xl sm:text-3xl md:text-4xl font-semibold tracking-tight text-neutral-900 leading-tight text-balance"
          >
            Threat model
            <br />
            <span className="text-neutral-400">in minutes, not weeks.</span>
          </motion.h1>
        </div>
      </div>
    </section>
  );
}

/* ----------------- Footer ----------------- */

function Footer() {
  return (
    <footer className="mt-auto border-t border-neutral-200 bg-neutral-50/50">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 sm:gap-4 text-xs text-neutral-500 text-center sm:text-left">
          <div className="flex items-center justify-center sm:justify-start gap-2 flex-wrap">
            <div className="w-6 h-6 rounded-md bg-neutral-900 flex items-center justify-center shrink-0">
              <BrandMark className="w-4 h-4 text-white" mono />
            </div>
            <span className="font-medium text-neutral-700 whitespace-nowrap">STRIDE GPT</span>
            <span className="text-neutral-400" aria-hidden="true">·</span>
            <span>AI-powered threat modeling</span>
          </div>
          <span className="text-neutral-400 whitespace-nowrap">
            © {new Date().getFullYear()} STRIDE GPT
          </span>
        </div>
      </div>
    </footer>
  );
}
