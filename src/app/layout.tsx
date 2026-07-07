import * as React from "react";
import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as SonnerToaster } from "@/components/ui/sonner";


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

export const metadata: Metadata = {
  title: "STRIDE GPT — AI-Powered Threat Modeling",
  description:
    "Generate STRIDE threat models, attack trees, mitigations, DREAD risk scores, data flow diagrams, and Gherkin test cases with AI. A modern, Apple-inspired security analysis studio.",
  keywords: [
    "STRIDE",
    "threat modeling",
    "security",
    "AI",
    "attack trees",
    "DREAD",
    "OWASP",
    "MITRE ATT&CK",
    "cybersecurity",
  ],
  authors: [{ name: "STRIDE GPT" }],
  openGraph: {
    title: "STRIDE GPT — AI-Powered Threat Modeling",
    description:
      "Modern, Apple-inspired AI threat modeling studio. Generate threat models, attack trees, mitigations, and more.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
        <SonnerToaster />
      </body>
    </html>
  );
}
