/**
 * Export helpers for STRIDE threat model artifacts.
 * Produces clean Markdown tables, CSV, JSON, and Excel (.xlsx)
 * for any combination of threat model, mitigations, DREAD scores, DFD,
 * attack tree, and Gherkin test cases.
 *
 * NOTE: The `xlsx` (SheetJS community) package was intentionally removed due to
 * unresolved high-severity vulnerabilities (GHSA-4r6h-8v6p-xvw6 Prototype
 * Pollution, GHSA-5pgg-2g8v-p4x9 ReDoS). Excel export is implemented via a
 * minimal self-contained OOXML writer with no external dependencies.
 */
import type {
  ThreatModelResult,
  Threat,
  MitigationResult,
  DreadScore,
  DfdResult,
  AttackTreeResult,
  GherkinResult,
} from "@/lib/stride-engine";

export type ExportFormat = "markdown" | "csv" | "json" | "xlsx";

const csvEscape = (v: unknown): string => {
  const s = String(v ?? "");
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
};

const markdownEscape = (v: unknown): string =>
  String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");

/* ------------------------------------------------------------------ */
/* Threat Model                                                        */
/* ------------------------------------------------------------------ */

export function threatsToMarkdown(result: ThreatModelResult): string {
  const header = `# STRIDE Threat Model\n\n**Generated:** ${new Date().toISOString()}\n\n## Executive Summary\n\n${result.summary}\n`;
  const patterns = result.detectedPatterns.length
    ? `\n## Detected Architectural Patterns\n\n${result.detectedPatterns
        .map((p) => `- ${p}`)
        .join("\n")}\n`
    : "";
  const notes = result.architectureNotes
    ? `\n## Architecture Notes\n\n${result.architectureNotes}\n`
    : "";

  const cols = [
    "ID",
    "STRIDE",
    "Threat",
    "Component",
    "Description",
    "MITRE ATT&CK",
    "Risk",
  ];
  const sep = cols.map(() => "---").join(" | ");
  const head = cols.join(" | ");
  const rows = result.threats
    .map((t) =>
      [
        t.id,
        t.strideCategory,
        markdownEscape(t.threat),
        markdownEscape(t.component),
        markdownEscape(t.description),
        markdownEscape((t.mitreAttack ?? []).join(", ")),
        t.risk,
      ].join(" | ")
    )
    .join("\n");

  const table = `## Threats\n\n| ${head} |\n| ${sep} |\n${rows
    .split("\n")
    .map((r) => `| ${r} |`)
    .join("\n")}\n`;

  return `${header}${patterns}${table}${notes}`;
}

export function threatsToCSV(result: ThreatModelResult): string {
  const header = [
    "ID",
    "STRIDE Category",
    "Threat",
    "Component",
    "Description",
    "MITRE ATT&CK",
    "Risk",
  ].join(",");
  const rows = result.threats.map((t) =>
    [
      t.id,
      t.strideCategory,
      csvEscape(t.threat),
      csvEscape(t.component),
      csvEscape(t.description),
      csvEscape((t.mitreAttack ?? []).join("; ")),
      t.risk,
    ].join(",")
  );
  return [header, ...rows].join("\n");
}

/* ------------------------------------------------------------------ */
/* Mitigations                                                         */
/* ------------------------------------------------------------------ */

export function mitigationsToMarkdown(result: MitigationResult): string {
  const head = ["Threat", "Mitigation", "Priority", "OWASP Reference"].join(
    " | "
  );
  const sep = ["---", "---", "---", "---"].join(" | ");
  const rows = result.mitigations
    .map((m) =>
      [
        markdownEscape(m.threat),
        markdownEscape(m.mitigation),
        m.priority,
        markdownEscape(m.owaspReference ?? ""),
      ].join(" | ")
    )
    .join("\n");
  const checklist = result.hardeningChecklist.length
    ? `\n## Hardening Checklist\n\n${result.hardeningChecklist
        .map((c, i) => `${i + 1}. ${c}`)
        .join("\n")}\n`
    : "";
  return `# Mitigations\n\n## Countermeasures\n\n| ${head} |\n| ${sep} |\n${rows
    .split("\n")
    .map((r) => `| ${r} |`)
    .join("\n")}\n${checklist}`;
}

export function mitigationsToCSV(result: MitigationResult): string {
  const header = [
    "Threat",
    "Mitigation",
    "Priority",
    "OWASP Reference",
  ].join(",");
  const rows = result.mitigations.map((m) =>
    [
      csvEscape(m.threat),
      csvEscape(m.mitigation),
      m.priority,
      csvEscape(m.owaspReference ?? ""),
    ].join(",")
  );
  return [header, ...rows].join("\n");
}

/* ------------------------------------------------------------------ */
/* DREAD Scores                                                        */
/* ------------------------------------------------------------------ */

export function dreadToMarkdown(scores: DreadScore[]): string {
  const head = [
    "Threat",
    "Damage",
    "Reproducibility",
    "Exploitability",
    "Affected Users",
    "Discoverability",
    "Total",
    "Severity",
  ].join(" | ");
  const sep = Array(8).fill("---").join(" | ");
  const rows = scores
    .map((d) =>
      [
        markdownEscape(d.threat),
        d.damage,
        d.reproducibility,
        d.exploitability,
        d.affectedUsers,
        d.discoverability,
        d.total,
        d.severity,
      ].join(" | ")
    )
    .join("\n");
  return `# DREAD Risk Scores\n\n| ${head} |\n| ${sep} |\n${rows
    .split("\n")
    .map((r) => `| ${r} |`)
    .join("\n")}\n`;
}

export function dreadToCSV(scores: DreadScore[]): string {
  const header = [
    "Threat",
    "Damage",
    "Reproducibility",
    "Exploitability",
    "Affected Users",
    "Discoverability",
    "Total",
    "Severity",
  ].join(",");
  const rows = scores.map((d) =>
    [
      csvEscape(d.threat),
      d.damage,
      d.reproducibility,
      d.exploitability,
      d.affectedUsers,
      d.discoverability,
      d.total,
      d.severity,
    ].join(",")
  );
  return [header, ...rows].join("\n");
}

/* ------------------------------------------------------------------ */
/* DFD                                                                 */
/* ------------------------------------------------------------------ */

export function dfdToMarkdown(result: DfdResult): string {
  const compHead = ["Component", "Type", "Trust Level"].join(" | ");
  const compSep = ["---", "---", "---"].join(" | ");
  const compRows = result.components
    .map((c) =>
      [
        markdownEscape(c.name),
        markdownEscape(c.type),
        markdownEscape(c.trustLevel),
      ].join(" | ")
    )
    .join("\n");

  const flowHead = ["From", "To", "Data Flow"].join(" | ");
  const flowSep = ["---", "---", "---"].join(" | ");
  const flowRows = result.flows
    .map((f) =>
      [
        markdownEscape(f.from),
        markdownEscape(f.to),
        markdownEscape(f.description),
      ].join(" | ")
    )
    .join("\n");

  return `# Data Flow Diagram\n\n## Narrative\n\n${result.narrative}\n\n## Mermaid Source\n\n\`\`\`mermaid\n${result.mermaid}\n\`\`\`\n\n## Components\n\n| ${compHead} |\n| ${compSep} |\n${compRows
    .split("\n")
    .map((r) => `| ${r} |`)
    .join("\n")}\n\n## Data Flows\n\n| ${flowHead} |\n| ${flowSep} |\n${flowRows
    .split("\n")
    .map((r) => `| ${r} |`)
    .join("\n")}\n`;
}

/* ------------------------------------------------------------------ */
/* Attack Tree                                                         */
/* ------------------------------------------------------------------ */

/** Recursive attack-tree node — mirrors the shape returned by stride-engine. */
interface AttackTreeNode {
  goal: string;
  subgoals: AttackTreeNode[];
}

function attackTreeToLines(
  node: AttackTreeNode,
  depth: number
): string[] {
  const lines = [`${"  ".repeat(depth)}- ${node.goal}`];
  for (const sg of node.subgoals ?? []) {
    lines.push(...attackTreeToLines(sg, depth + 1));
  }
  return lines;
}

export function attackTreeToMarkdown(result: AttackTreeResult): string {
  return `# Attack Tree\n\n## Mermaid Source\n\n\`\`\`mermaid\n${result.mermaid}\n\`\`\`\n\n## Tree Structure\n\n${attackTreeToLines(
    result.root,
    0
  ).join("\n")}\n\n## Narrative\n\n${result.narrative}\n`;
}

/* ------------------------------------------------------------------ */
/* Gherkin                                                             */
/* ------------------------------------------------------------------ */

export function gherkinToText(result: GherkinResult): string {
  const scenarios = result.scenarios
    .map((s) => {
      const thens = s.then.map((t) => `  ${t}`).join("\n");
      return `${s.title}\n  ${s.given}\n  ${s.when}\n${thens}`;
    })
    .join("\n\n");
  return `${result.feature}\n\n${scenarios}\n`;
}

/* ------------------------------------------------------------------ */
/* Excel row helpers                                                   */
/* ------------------------------------------------------------------ */

const threatRows = (r: ThreatModelResult) =>
  r.threats.map((t) => ({
    ID: t.id,
    "STRIDE Category": t.strideCategory,
    Threat: t.threat,
    Component: t.component,
    Description: t.description,
    "MITRE ATT&CK": (t.mitreAttack ?? []).join("; "),
    Risk: t.risk,
  }));

const mitigationRows = (r: MitigationResult) =>
  r.mitigations.map((m) => ({
    Threat: m.threat,
    Mitigation: m.mitigation,
    Priority: m.priority,
    "OWASP Reference": m.owaspReference ?? "",
  }));

const dreadRows = (scores: DreadScore[]) =>
  scores.map((d) => ({
    Threat: d.threat,
    Damage: d.damage,
    Reproducibility: d.reproducibility,
    Exploitability: d.exploitability,
    "Affected Users": d.affectedUsers,
    Discoverability: d.discoverability,
    Total: d.total,
    Severity: d.severity,
  }));

const dfdComponentRows = (r: DfdResult) =>
  r.components.map((c) => ({
    Component: c.name,
    Type: c.type,
    "Trust Level": c.trustLevel,
  }));

const dfdFlowRows = (r: DfdResult) =>
  r.flows.map((f) => ({
    From: f.from,
    To: f.to,
    "Data Flow": f.description,
  }));

const gherkinRows = (r: GherkinResult) =>
  r.scenarios.map((s) => ({
    Scenario: s.title,
    Given: s.given,
    When: s.when,
    Then: s.then.join("\n"),
  }));

/* ================================================================== */
/* Minimal OOXML .xlsx writer — no external dependencies               */
/*                                                                      */
/* The root cause of the "corrupt workbook" error was <Sheet> (capital */
/* S). XML is case-sensitive; the OOXML spec requires lowercase        */
/* <sheet>. This implementation also uses a proper shared-string table */
/* and a DataView-based ZIP builder for reliable little-endian I/O.    */
/* ================================================================== */

/** Escape a value for safe inclusion in XML text or attribute content. */
function xmlEsc(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** 0-based column index → Excel column letter (A … Z, AA …). */
function colLetter(n: number): string {
  let s = "";
  for (let c = n + 1; c > 0; ) {
    c--;
    s = String.fromCharCode(65 + (c % 26)) + s;
    c = Math.floor(c / 26);
  }
  return s;
}

/**
 * Build one <worksheet> XML string.
 * - String cells use type "s" (index into shared-string table).
 * - Numeric cells use bare <v> with no explicit type attribute.
 * `sst` and `sstMap` are shared across all sheets and mutated in-place.
 */
function buildSheetXml(
  rows: Record<string, unknown>[],
  sst: string[],
  sstMap: Map<string, number>
): string {
  const addStr = (s: string): number => {
    const existing = sstMap.get(s);
    if (existing !== undefined) return existing;
    const idx = sst.length;
    sst.push(s);
    sstMap.set(s, idx);
    return idx;
  };

  const NS = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`;

  if (rows.length === 0) {
    return (
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
      `<worksheet ${NS}><sheetData/></worksheet>`
    );
  }

  const keys = Object.keys(rows[0]);
  // First row is the header; subsequent rows are data.
  const allRows: unknown[][] = [
    keys,
    ...rows.map((r) => keys.map((k) => r[k])),
  ];

  const rowsXml = allRows
    .map((row, ri) => {
      const cells = (row as unknown[])
        .map((val, ci) => {
          const ref = `${colLetter(ci)}${ri + 1}`;
          if (typeof val === "number" && Number.isFinite(val)) {
            return `<c r="${ref}"><v>${val}</v></c>`;
          }
          const idx = addStr(String(val ?? ""));
          return `<c r="${ref}" t="s"><v>${idx}</v></c>`;
        })
        .join("");
      return `<row r="${ri + 1}">${cells}</row>`;
    })
    .join("");

  return (
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<worksheet ${NS}><sheetData>${rowsXml}</sheetData></worksheet>`
  );
}

/* ------------------------------------------------------------------ */
/* CRC-32 lookup table (standard polynomial 0xEDB88320)               */
/* ------------------------------------------------------------------ */

const _CRC32: readonly number[] = (() => {
  const t = new Array<number>(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();

function calcCrc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++)
    c = _CRC32[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* ------------------------------------------------------------------ */
/* ZIP builder — stored (no compression), DataView for byte order     */
/* ------------------------------------------------------------------ */

interface ZipEntry {
  name: string;
  data: Uint8Array;
}

/**
 * Assemble ZIP entries into a valid .zip / .xlsx archive.
 * Uses DataView so all multi-byte integers are written little-endian
 * regardless of the host platform's native byte order.
 */
function buildZip(entries: ZipEntry[]): Uint8Array {
  const enc = new TextEncoder();

  // Pre-compute per-entry metadata
  const meta = entries.map((e) => ({
    nb: enc.encode(e.name), // UTF-8 name bytes
    crc: calcCrc32(e.data),
    sz: e.data.length,
    data: e.data,
  }));

  // Fixed header sizes (bytes)
  const LF_FIXED = 30; // local file header
  const CD_FIXED = 46; // central directory entry
  const EOCD_SZ  = 22; // end-of-central-directory record

  let localTotal = 0;
  for (const m of meta) localTotal += LF_FIXED + m.nb.length + m.sz;
  let cdTotal = 0;
  for (const m of meta) cdTotal += CD_FIXED + m.nb.length;

  const ab = new ArrayBuffer(localTotal + cdTotal + EOCD_SZ);
  const u8 = new Uint8Array(ab);
  const dv = new DataView(ab);
  let p = 0;
  const lfOffsets: number[] = [];

  // ── Local file headers + file data ──────────────────────────────
  for (const m of meta) {
    lfOffsets.push(p);
    dv.setUint32(p, 0x04034b50, true); p += 4; // PK\3\4 signature
    dv.setUint16(p, 20,         true); p += 2; // version needed (2.0)
    dv.setUint16(p, 0,          true); p += 2; // general purpose flags
    dv.setUint16(p, 0,          true); p += 2; // compression: stored (0)
    dv.setUint16(p, 0,          true); p += 2; // last mod time
    dv.setUint16(p, 0,          true); p += 2; // last mod date
    dv.setUint32(p, m.crc,      true); p += 4; // CRC-32
    dv.setUint32(p, m.sz,       true); p += 4; // compressed size
    dv.setUint32(p, m.sz,       true); p += 4; // uncompressed size
    dv.setUint16(p, m.nb.length,true); p += 2; // filename length
    dv.setUint16(p, 0,          true); p += 2; // extra field length
    u8.set(m.nb,   p); p += m.nb.length;
    u8.set(m.data, p); p += m.sz;
  }

  // ── Central directory ─────────────────────────────────────────────
  const cdStart = p;
  for (let i = 0; i < meta.length; i++) {
    const m = meta[i];
    dv.setUint32(p, 0x02014b50,   true); p += 4; // PK\1\2 signature
    dv.setUint16(p, 20,           true); p += 2; // version made by
    dv.setUint16(p, 20,           true); p += 2; // version needed
    dv.setUint16(p, 0,            true); p += 2; // flags
    dv.setUint16(p, 0,            true); p += 2; // compression
    dv.setUint16(p, 0,            true); p += 2; // last mod time
    dv.setUint16(p, 0,            true); p += 2; // last mod date
    dv.setUint32(p, m.crc,        true); p += 4; // CRC-32
    dv.setUint32(p, m.sz,         true); p += 4; // compressed size
    dv.setUint32(p, m.sz,         true); p += 4; // uncompressed size
    dv.setUint16(p, m.nb.length,  true); p += 2; // filename length
    dv.setUint16(p, 0,            true); p += 2; // extra field length
    dv.setUint16(p, 0,            true); p += 2; // file comment length
    dv.setUint16(p, 0,            true); p += 2; // disk number start
    dv.setUint16(p, 0,            true); p += 2; // internal attributes
    dv.setUint32(p, 0,            true); p += 4; // external attributes
    dv.setUint32(p, lfOffsets[i], true); p += 4; // offset of local header
    u8.set(m.nb, p); p += m.nb.length;
  }

  // ── End-of-central-directory record ──────────────────────────────
  const cdSize = p - cdStart;
  dv.setUint32(p, 0x06054b50,    true); p += 4; // PK\5\6 signature
  dv.setUint16(p, 0,             true); p += 2; // disk number
  dv.setUint16(p, 0,             true); p += 2; // disk with cd start
  dv.setUint16(p, meta.length,   true); p += 2; // entries on this disk
  dv.setUint16(p, meta.length,   true); p += 2; // total entries
  dv.setUint32(p, cdSize,        true); p += 4; // size of central dir
  dv.setUint32(p, cdStart,       true); p += 4; // offset of central dir
  dv.setUint16(p, 0,             true); p += 2; // comment length

  return u8;
}

/* ================================================================== */
/* Public Excel API                                                    */
/* ================================================================== */

export interface ExcelBundle {
  threatModel?: ThreatModelResult;
  mitigations?: MitigationResult;
  dreadScores?: DreadScore[];
  dfd?: DfdResult;
  gherkin?: GherkinResult;
}

/**
 * Build a multi-sheet .xlsx workbook.
 *
 * SHEET LAYOUT
 * ─────────────────────────────────────────────────────────────────────
 * "STRIDE Threats"      — ONE ROW per threat (so 2 Spoofing = 2 rows).
 *                         COLUMNS: Finding/Issue, Description, Risk,
 *                         MITRE ATT&CK Mapping, Recommendation, Priority,
 *                         OWASP Reference, + DREAD scores if available.
 *                         Mitigations and DREAD are joined by threat name.
 *
 * "Hardening Checklist" — if present
 * "Gherkin Tests"       — if present
 * "DFD Components"      — if present
 * "DFD Flows"           — if present
 *
 * The Summary/Executive Summary sheet is intentionally removed;
 * that context belongs on the web page, not the spreadsheet.
 */
export function buildExcelWorkbook(bundle: ExcelBundle): ArrayBuffer {
  const enc = new TextEncoder();
  const sheets: { name: string; rows: Record<string, unknown>[] }[] = [];

  // ── Build lookup: all mitigations grouped by threat title ───────
  const mitsByThreat = new Map<string, MitigationResult["mitigations"]>();
  if (bundle.mitigations) {
    for (const m of bundle.mitigations.mitigations) {
      const key = m.threat.toLowerCase().trim();
      if (!mitsByThreat.has(key)) mitsByThreat.set(key, []);
      mitsByThreat.get(key)!.push(m);
    }
  }

  // ── Build lookup: DREAD score by threat title ────────────────────
  const dreadByThreat = new Map<string, DreadScore>();
  const hasDread = (bundle.dreadScores?.length ?? 0) > 0;
  if (hasDread) {
    for (const d of bundle.dreadScores!) {
      dreadByThreat.set(d.threat.toLowerCase().trim(), d);
    }
  }

  // ── Sheet 1: flat unified threat table ──────────────────────────
  if (bundle.threatModel) {
    const rows: Record<string, unknown>[] = bundle.threatModel.threats.map((t) => {
      const key  = t.threat.toLowerCase().trim();
      const mits = mitsByThreat.get(key) ?? [];
      const dread = dreadByThreat.get(key);

      // Join multiple mitigations for the same threat with a separator
      const recommendation = mits.map((m) => m.mitigation).join(" | ");
      const priority       = [...new Set(mits.map((m) => m.priority).filter(Boolean))].join(", ");
      const owasp          = [...new Set(mits.map((m) => m.owaspReference ?? "").filter(Boolean))].join(", ");

      const row: Record<string, unknown> = {
        "ID":                      t.id,
        "STRIDE Category":         t.strideCategory,
        "Component":               t.component,
        "Finding / Issue":         t.threat,
        "Description":             t.description,
        "Risk":                    t.risk,
        "MITRE ATT\u0026CK Mapping": (t.mitreAttack ?? []).join("; "),
        "Recommendation":          recommendation,
        "Priority":                priority,
        "OWASP Reference":         owasp,
      };

      // Append DREAD columns only when scores were generated
      if (hasDread) {
        row["Damage"]          = dread?.damage          ?? "";
        row["Reproducibility"] = dread?.reproducibility ?? "";
        row["Exploitability"]  = dread?.exploitability  ?? "";
        row["Affected Users"]  = dread?.affectedUsers   ?? "";
        row["Discoverability"] = dread?.discoverability ?? "";
        row["DREAD Total"]     = dread?.total           ?? "";
        row["DREAD Severity"]  = dread?.severity        ?? "";
      }

      return row;
    });

    sheets.push({ name: "STRIDE Threats", rows });
  }

  // ── Sheet 2: Hardening Checklist ────────────────────────────────
  if (bundle.mitigations?.hardeningChecklist.length) {
    sheets.push({
      name: "Hardening Checklist",
      rows: bundle.mitigations.hardeningChecklist.map((c, i) => ({
        "#":                   i + 1,
        "Hardening Checklist": c,
      })),
    });
  }

  // ── Sheet 3: Gherkin Tests ───────────────────────────────────────
  if (bundle.gherkin) {
    sheets.push({
      name: "Gherkin Tests",
      rows: bundle.gherkin.scenarios.map((s) => ({
        "Scenario": s.title,
        "Given":    s.given,
        "When":     s.when,
        "Then":     s.then.join("\n"),
      })),
    });
  }

  // ── Sheets 4 & 5: DFD ───────────────────────────────────────────
  if (bundle.dfd) {
    sheets.push({
      name: "DFD Components",
      rows: bundle.dfd.components.map((c) => ({
        "Component":   c.name,
        "Type":        c.type,
        "Trust Level": c.trustLevel,
      })),
    });
    sheets.push({
      name: "DFD Flows",
      rows: bundle.dfd.flows.map((f) => ({
        "From":      f.from,
        "To":        f.to,
        "Data Flow": f.description,
      })),
    });
  }

  // ── Build SST and worksheet XMLs ─────────────────────────────────
  const sst: string[] = [];
  const sstMap = new Map<string, number>();
  const sheetXmls = sheets.map((s) => buildSheetXml(s.rows, sst, sstMap));

  // ── OOXML XML parts ──────────────────────────────────────────────
  const sheetCTs = sheets
    .map(
      (_, i) =>
        `<Override PartName="/xl/worksheets/sheet${i + 1}.xml"` +
        ` ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
    )
    .join("");

  const contentTypesXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
    `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
    `<Default Extension="xml"  ContentType="application/xml"/>` +
    `<Override PartName="/xl/workbook.xml"` +
    ` ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    `<Override PartName="/xl/sharedStrings.xml"` +
    ` ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>` +
    sheetCTs +
    `</Types>`;

  const rootRelsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1"` +
    ` Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"` +
    ` Target="xl/workbook.xml"/>` +
    `</Relationships>`;

  const sheetEls = sheets
    .map(
      (s, i) =>
        `<sheet name="${xmlEsc(s.name)}" sheetId="${i + 1}" r:id="rId${i + 2}"/>`
    )
    .join("");
  const workbookXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"` +
    ` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
    `<sheets>${sheetEls}</sheets>` +
    `</workbook>`;

  const sheetRels = sheets
    .map(
      (_, i) =>
        `<Relationship Id="rId${i + 2}"` +
        ` Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"` +
        ` Target="worksheets/sheet${i + 1}.xml"/>`
    )
    .join("");
  const workbookRelsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1"` +
    ` Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"` +
    ` Target="sharedStrings.xml"/>` +
    sheetRels +
    `</Relationships>`;

  const sstItems = sst
    .map((s) => `<si><t xml:space="preserve">${xmlEsc(s)}</t></si>`)
    .join("");
  const sharedStringsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"` +
    ` count="${sst.length}" uniqueCount="${sst.length}">` +
    sstItems +
    `</sst>`;

  const zipEntries: ZipEntry[] = [
    { name: "[Content_Types].xml",          data: enc.encode(contentTypesXml) },
    { name: "_rels/.rels",                   data: enc.encode(rootRelsXml) },
    { name: "xl/workbook.xml",              data: enc.encode(workbookXml) },
    { name: "xl/_rels/workbook.xml.rels",   data: enc.encode(workbookRelsXml) },
    { name: "xl/sharedStrings.xml",         data: enc.encode(sharedStringsXml) },
    ...sheetXmls.map((xml, i) => ({
      name: `xl/worksheets/sheet${i + 1}.xml`,
      data: enc.encode(xml),
    })),
  ];

  return buildZip(zipEntries).buffer as ArrayBuffer;
}

export function downloadExcel(filename: string, bundle: ExcelBundle) {
  const buf = buildExcelWorkbook(bundle);
  const blob = new Blob([buf], {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ------------------------------------------------------------------ */
/* Generic text / file download trigger                               */
/* ------------------------------------------------------------------ */

export function downloadText(
  filename: string,
  content: string,
  mime = "text/plain"
) {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
