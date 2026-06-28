/**
 * report.ts — render scan results as either calm human output or --json.
 *
 * Scoring (mirrors the hosted product so numbers feel consistent):
 *   start 100; high -25, medium -10, low -3; floor at 0.
 *
 * The human renderer is deliberately quiet and green-accented. Evidence is
 * already masked by the detectors — this file never sees a raw secret.
 */

import pc from "picocolors";
import type { CheckName, Finding, Severity } from "./scan.js";
// Single source of truth for the version: package.json. The bundler (tsup) and
// the test runner (vitest) both inline this JSON import, so `npm version <x>`
// is the only place a release number ever needs to change.
import { version } from "../package.json";

export const VERSION: string = version;

const REPO_URL = "github.com/eabhvee/kavaca-cli";

// Upgrade CTA. Standard UTM params let any analytics tool attribute CLI traffic
// with zero config; `v` carries the tool version so we can see which releases
// convert. `ref=cli` is kept for backward-compatibility with existing reports.
export const UPGRADE_URL =
  `https://kavaca.io?ref=cli&utm_source=cli&utm_medium=cli&utm_campaign=preflight&v=${VERSION}`;

const SEVERITY_WEIGHT: Record<Severity, number> = {
  high: 25,
  medium: 10,
  low: 3,
};

export function computeScore(findings: Finding[]): number {
  const deduction = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.max(0, 100 - deduction);
}

/** Issues that should fail CI (everything except low). */
export function hasBlockingIssues(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === "high" || f.severity === "medium");
}

export interface JsonReport {
  version: string;
  scannedFiles: number;
  score: number;
  issues: {
    severity: Severity;
    check: CheckName;
    title: string;
    file: string;
    line: number;
    evidence: string;
  }[];
}

export function renderJson(findings: Finding[], scannedFiles: number): string {
  const report: JsonReport = {
    version: VERSION,
    scannedFiles,
    score: computeScore(findings),
    issues: findings.map((f) => ({
      severity: f.severity,
      check: f.check,
      title: f.title,
      file: f.file,
      line: f.line,
      evidence: f.evidence,
    })),
  };
  return JSON.stringify(report, null, 2);
}

const DIVIDER = "──────────────────────────────────────────────";

const CHECK_LABELS: Record<CheckName, string> = {
  secrets: "Secrets in code",
  frontend: "Frontend exposure",
  supabase: "Supabase database",
};

/** Pad a label with dotted leaders to a fixed column, like the spec output. */
function leader(label: string, width = 28): string {
  const dots = Math.max(2, width - label.length);
  return `${label} ${".".repeat(dots)}`;
}

function severityTag(sev: Severity): string {
  const t = sev.toUpperCase().padEnd(5);
  if (sev === "high") return pc.bold(pc.red(t));
  if (sev === "medium") return pc.bold(pc.yellow(t));
  return pc.bold(pc.gray(t));
}

export interface RenderOptions {
  scanLabel: string; // e.g. "./my-app"
}

export function renderHuman(
  findings: Finding[],
  opts: RenderOptions,
): string {
  const score = computeScore(findings);
  const out: string[] = [];
  const g = pc.green;

  out.push("");
  out.push(`  ${g("◎")} ${pc.bold("Kavaca")} — pre-flight security check`);
  out.push(
    `  Scanning ${opts.scanLabel}  ${pc.dim("(local only — nothing leaves your machine)")}`,
  );
  out.push("");

  // Per-check summary lines.
  const checks: CheckName[] = ["secrets", "frontend", "supabase"];
  for (const check of checks) {
    const count = findings.filter((f) => f.check === check).length;
    const status =
      count === 0 ? pc.dim("clear") : `${count} issue${count === 1 ? "" : "s"}`;
    const mark = count === 0 ? g("✔") : pc.yellow("✔");
    out.push(`  ${mark} ${leader(CHECK_LABELS[check])} ${status}`);
  }

  out.push("");
  out.push(`  ${pc.dim(DIVIDER)}`);

  if (findings.length === 0) {
    // Friendly all-clear.
    out.push(`  ${g("✔")}  ${pc.bold("No issues found")} · score ${pc.bold("100/100")}`);
    out.push("");
    out.push(`  ${pc.dim(DIVIDER)}`);
    out.push("  Looking good on these 3 — the full scan checks 5 more.");
    out.push("");
    out.push("  → Full scan (auth, API, dependencies + more) with plain-English");
    out.push(`    fixes and ready-to-paste AI prompts:  ${pc.cyan(UPGRADE_URL)}`);
    out.push("");
    out.push(`  ${pc.yellow("★")} Like this? Star the repo: ${pc.cyan(REPO_URL)}`);
    out.push("");
    return out.join("\n");
  }

  const n = findings.length;
  const scoreStr = `${score}/100`;
  out.push(
    `  ${pc.yellow("⚠")}  ${n} issue${n === 1 ? "" : "s"} found · score ${pc.bold(scoreStr)}`,
  );
  out.push("");

  // Sort high → medium → low for display.
  const order: Severity[] = ["high", "medium", "low"];
  const sorted = [...findings].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );
  for (const f of sorted) {
    const where = f.file ? ` ${pc.dim(`(${f.file}:${f.line})`)}` : "";
    out.push(`  ${severityTag(f.severity)} ${stripLoc(f.title)}${where}`);
    out.push(`        ${pc.dim(f.evidence)}`);
    out.push("");
  }

  out.push(`  ${pc.dim(DIVIDER)}`);
  out.push("  This is a quick check of 3 of 8 risk areas.");
  out.push("");
  out.push("  → Full scan (auth, API, dependencies + more) with plain-English");
  out.push(`    fixes and ready-to-paste AI prompts:  ${pc.cyan(UPGRADE_URL)}`);
  out.push("");
  out.push(`  ${pc.yellow("★")} Like this? Star the repo: ${pc.cyan(REPO_URL)}`);
  out.push("");

  return out.join("\n");
}

/**
 * Some titles already embed `file:line` (e.g. secrets). When we also print the
 * location chip, strip the trailing "in path:line" so it isn't doubled up.
 */
function stripLoc(title: string): string {
  return title.replace(/\s+in\s+\S+:\d+$/, "");
}
