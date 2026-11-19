import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";

// --- Fonts --------------------------------------------------------------------
// `display: "swap"` prevents FOIT (invisible text during font load).
const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
});

// --- SEO Metadata -------------------------------------------------------------
export const metadata: Metadata = {
  title: "STRIDE GPT | AI-Powered Threat Modeling",
  description:
    "AI-powered threat modeling studio for generating STRIDE threat models, mitigations, safety metrics, and data flow diagrams.",
  keywords: [
    "STRIDE",
    "threat modeling",
    "security",
    "AI",
    "mitigations",
    "safety metrics",
    "data flow diagram",
    "OWASP",
    "MITRE ATT&CK",
    "cybersecurity",
  ],
  authors: [{ name: "STRIDE GPT" }],
  openGraph: {
    title: "STRIDE GPT | AI-Powered Threat Modeling",
    description:
      "Modern, Apple-inspired AI threat modeling studio. Generate threat models, mitigations, safety metrics, and data flow diagrams.",
    type: "website",
  },
};

// --- Root Layout --------------------------------------------------------------
// CSP nonce is generated in src/proxy.ts per-request and threaded into all
// Next.js-injected scripts automatically via the x-nonce request header.
// No layout-level nonce handling is required.
export default function RootLayout({
  children,
}: Readonly<{
  children: ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased bg-background text-foreground`}
      >
        {children}
        {/* Sonner toast notifications -- the only toast system in use. */}
        <Toaster />
      </body>
    </html>
  );
}
