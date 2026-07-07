"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { Settings, Zap, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThreatModelStudio } from "@/components/threat-model-studio";
import { BrandMark } from "@/components/brand-mark";
import { ApiConfigDialog } from "@/components/api-config-dialog";
import { useLLMConfig } from "@/hooks/use-llm-config";
import { PROVIDER_MODELS } from "@/lib/llm-config";

export default function Page() {
  const { config, save } = useLLMConfig();
  const [configOpen, setConfigOpen] = useState(false);

  return (
    <main className="min-h-screen flex flex-col bg-background">
      <NavBar
        configured={!!config}
        providerLabel={config ? providerLabel(config.provider, config.model) : null}
        onOpenConfig={() => setConfigOpen(true)}
      />
      <CompactHero />
      <ThreatModelStudio config={config} onOpenConfig={() => setConfigOpen(true)} />
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

function providerLabel(provider: "groq" | "gemini", model: string): string {
  const list = PROVIDER_MODELS[provider];
  const found = list.find((m) => m.id === model);
  const provName = provider === "groq" ? "Groq" : "Gemini";
  return found ? `${provName} · ${found.label}` : provName;
}

/* ----------------- NavBar ----------------- */

function NavBar({
  configured,
  providerLabel,
  onOpenConfig,
}: {
  configured: boolean;
  providerLabel: string | null;
  onOpenConfig: () => void;
}) {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`sticky top-0 z-50 navbar-solid transition-shadow${
        scrolled ? " shadow-sm" : ""
      }`}
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-neutral-900 flex items-center justify-center">
            <BrandMark className="w-5 h-5 text-white" mono />
          </div>
          <span className="font-semibold tracking-tight text-neutral-900">
            STRIDE GPT
          </span>
          <span className="hidden sm:inline text-xs text-neutral-400 ml-2 font-mono">
            threat-modeling studio
          </span>
        </Link>

        <div className="flex items-center gap-2">
          <button
            onClick={onOpenConfig}
            className={`inline-flex items-center gap-1.5 h-9 px-3 rounded-full text-xs font-medium transition-all border ${
              configured
                ? "border-neutral-300 text-neutral-700 hover:bg-neutral-100"
                : "border-amber-300 bg-amber-50 text-amber-900 hover:bg-amber-100"
            }`}
            title={providerLabel ?? "Configure LLM provider"}
          >
            {configured ? (
              <>
                <Check className="w-3 h-3 text-neutral-900" />
                <span className="hidden sm:inline">{providerLabel}</span>
                <Settings className="w-3 h-3 sm:hidden" />
              </>
            ) : (
              <>
                <Zap className="w-3 h-3" />
                <span>Configure LLM</span>
              </>
            )}
          </button>
          <a href="#studio">
            <Button
              size="sm"
              className="rounded-full bg-neutral-900 text-white hover:bg-neutral-800 h-9 px-4"
            >
              New Analysis
            </Button>
          </a>
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
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-2xl sm:text-3xl md:text-4xl font-semibold tracking-tight text-neutral-900 leading-tight"
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
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex flex-wrap items-center justify-between gap-4 text-xs text-neutral-500">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-md bg-neutral-900 flex items-center justify-center">
              <BrandMark className="w-4 h-4 text-white" mono />
            </div>
            <span className="font-medium text-neutral-700">STRIDE GPT</span>
            <span className="text-neutral-400">·</span>
            <span>AI-powered threat modeling</span>
          </div>
          <span className="text-neutral-400">
            © {new Date().getFullYear()} STRIDE GPT
          </span>
        </div>
      </div>
    </footer>
  );
}
