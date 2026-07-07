<div align="center">

<img src="public/placeholder.svg" alt="STRIDE GPT" width="56" height="56" style="border-radius:12px" />

# STRIDE GPT

**AI-powered threat modelling studio — STRIDE · OWASP · MITRE ATT&CK**

[![Next.js](https://img.shields.io/badge/Next.js_15-black?logo=next.js&logoColor=white)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript_5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

STRIDE GPT is an open-source, browser-based security analysis studio that turns a plain-text application description into a complete, industry-grade threat model in seconds. Bring your own API key — no data is ever stored on the server.

---

## Features

### 🛡️ STRIDE Threat Model
Generate a structured threat model mapped to all six STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Each threat includes:
- Unique threat ID, component affected, and risk rating (Low / Medium / High / Critical)
- MITRE ATT&CK technique mapping
- Executive summary and detected architectural patterns

### 🌲 Attack Tree
Decompose the attacker's primary goal into a nested tree of sub-goals and leaf techniques with at least 3 levels of depth. Rendered as an interactive Mermaid diagram with a downloadable source.

### 🔧 Mitigations
For each identified threat, generates a concrete, implementable countermeasure with:
- OWASP reference (e.g. `A01:2021-Broken Access Control`)
- Priority rating (Low / Medium / High)
- A hardening checklist of 6–10 security controls

### 📊 DREAD Risk Scoring
Scores every threat across five DREAD dimensions (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) on a 1–10 scale, producing a total out of 50 and a severity band.

### 🔀 Data Flow Diagram (DFD)
Generates a trust-boundary DFD rendered as a Mermaid flowchart, listing all components (with trust levels) and data flows between them.

### 🧪 Gherkin / BDD Test Cases
Converts each threat into a Given / When / Then BDD scenario ready to drop into Cucumber, Behave, or any Gherkin-compatible test framework.

### 📥 Rich Export Pipeline
Every section can be exported independently or as a combined report:

| Format | Contents |
|--------|----------|
| **Excel (.xlsx)** | One row per threat · Finding, Description, Risk, MITRE, Recommendation, Priority, OWASP, DREAD scores |
| **Markdown (.md)** | Full tables with all metadata |
| **CSV (.csv)** | Machine-readable for SIEM/GRC tools |
| **JSON (.json)** | Raw structured output for pipelines |
| **Mermaid (.mmd)** | Diagram source for Attack Tree and DFD |

The Excel workbook is generated entirely in-browser with a custom OOXML/ZIP writer — no external spreadsheet libraries and no SheetJS (removed due to high-severity CVEs).

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Framework | [Next.js 15](https://nextjs.org) — App Router, server-side API routes |
| Language | TypeScript 5 — strict mode |
| Styling | Tailwind CSS v4 + custom Apple-inspired design system |
| UI Components | [shadcn/ui](https://ui.shadcn.com) (Radix UI primitives) |
| Animations | [Framer Motion](https://www.framer.com/motion) |
| Diagrams | [Mermaid.js](https://mermaid.js.org) (strict security mode) |
| Toast Notifications | [Sonner](https://sonner.emilkowal.ski) |
| Fonts | Inter · JetBrains Mono (Google Fonts) |
| LLM Providers | Groq (Llama 3, DeepSeek) · Google Gemini |

---

## How It Works

```
User describes their system
        │
        ▼
 [Next.js API Route]          ← validates input, enforces body-size limits,
        │                        strips control characters, allowlists provider/model
        ▼
 [LLM Provider]               ← Groq or Gemini, called server-side with
        │                        user's API key from the request body
        ▼
 [Output Sanitiser]           ← clamps field lengths, strips injection patterns,
        │                        normalises threat titles for cross-tab correlation
        ▼
 [Browser: React State]       ← renders results across 6 tabs
        │
        ▼
 [Export Engine]              ← pure-browser OOXML writer, no external deps
```

API keys travel **only** within the encrypted HTTPS request body. They are stored in `localStorage` on the client and are never persisted server-side.

---

## Getting Started

### Prerequisites
- Node.js 18+
- A free API key from [Groq](https://console.groq.com) or [Google AI Studio](https://aistudio.google.com)

### Installation

```bash
git clone https://github.com/Varshith-Kali/Stride-gpt.git
cd Stride-gpt/stride-gpt
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

Click **Configure LLM** in the top-right corner, paste your API key, and select your preferred model. Your key stays in your browser.

### Environment

No environment variables are required to run the application. The `.env.local` file is included for reference only and is excluded from version control.

---

## Security

| Control | Detail |
|---------|--------|
| HTTP security headers | CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy |
| Input validation | Content-Type guard, 1 MB body limit, control-character stripping, provider/model allowlist |
| Output sanitisation | Field-length clamping, XSS pattern stripping on all LLM outputs |
| No secrets on server | API keys never stored server-side; travel only in encrypted request bodies |
| XSS prevention | Mermaid `securityLevel: "strict"`, `htmlLabels: false`, pre-render source sanitiser |
| Dependency hygiene | SheetJS removed (high-severity CVEs); OOXML generated with a self-contained writer |
| Static analysis | ESLint with `no-debugger`, `prefer-const`, `no-undef`, `no-redeclare` enforced as errors |

---

## Supported Models

**Groq**
- `meta-llama/llama-4-scout-17b-16e-instruct`
- `meta-llama/llama-4-maverick-17b-128e-instruct`
- `llama-3.3-70b-versatile`
- `deepseek-r1-distill-llama-70b`

**Google Gemini**
- `gemini-2.0-flash`
- `gemini-2.5-flash-preview-05-20`
- `gemini-2.5-pro-preview-06-05`

---

## License

MIT © 2025 STRIDE GPT
