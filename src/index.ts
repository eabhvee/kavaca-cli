/**
 * index.ts — CLI entry: argument parsing, orchestration, exit codes.
 *
 * Pipeline: scan files → run the 3 detectors → render → (opt-in) telemetry.
 * Exit 0 when clean of high/medium issues, exit 1 otherwise (CI-friendly).
 */

import fs from "node:fs";
import path from "node:path";
import pc from "picocolors";
import { scan, makeGitignoreChecker, type Finding } from "./scan.js";
import { detectSecrets } from "./detectors/secrets.js";
import { detectFrontend } from "./detectors/frontend.js";
import { detectSupabase } from "./detectors/supabase.js";
import {
  renderHuman,
  renderJson,
  hasBlockingIssues,
  VERSION,
} from "./report.js";
import { maybeSendTelemetry } from "./telemetry.js";

export interface CliOptions {
  targetPath: string;
  json: boolean;
  shareStats: boolean;
  color: boolean;
}

export interface RunResult {
  findings: Finding[];
  scannedFiles: number;
}

const HELP = `
  ◎ Kavaca — free, local pre-flight security check for AI-built apps

  Usage:
    npx kavaca [path] [options]

  Finds the two mistakes that sink most AI-built apps — exposed secrets and
  open Supabase databases — in seconds. Everything runs locally; nothing is
  ever uploaded.

  Kavaca respects your .gitignore. To skip intentional fakes (test fixtures,
  sample apps, doc snippets), add gitignore-style globs to a .kavacaignore file.

  Arguments:
    path               Directory to scan (default: current directory)

  Options:
    --json             Machine-readable JSON output (for CI / the GitHub Action)
    --share-stats      Opt in to sending ANONYMOUS aggregate counts (off by default)
    --no-color         Disable colored output
    --version, -v      Print version
    --help, -h         Show this help

  Full scan (auth, API, dependencies + more): https://kavaca.com?ref=cli
`;

export function parseArgs(argv: string[]): {
  options: CliOptions;
  showHelp: boolean;
  showVersion: boolean;
} {
  const options: CliOptions = {
    targetPath: ".",
    json: false,
    shareStats: false,
    color: true,
  };
  let showHelp = false;
  let showVersion = false;
  let pathSet = false;

  for (const arg of argv) {
    switch (arg) {
      case "--json":
        options.json = true;
        break;
      case "--share-stats":
        options.shareStats = true;
        break;
      case "--no-color":
        options.color = false;
        break;
      case "--help":
      case "-h":
        showHelp = true;
        break;
      case "--version":
      case "-v":
        showVersion = true;
        break;
      default:
        if (arg.startsWith("-")) break; // ignore unknown flags gracefully
        if (!pathSet) {
          options.targetPath = arg;
          pathSet = true;
        }
    }
  }

  return { options, showHelp, showVersion };
}

/** Run all three detectors over a directory. Pure-ish: no process.exit, no print. */
export function runScan(targetPath: string): RunResult {
  const { files, scannedFileCount } = scan(targetPath);
  const isGitignored = makeGitignoreChecker(targetPath);

  const findings: Finding[] = [];

  // Check 1 — exposed secrets.
  findings.push(...detectSecrets(files, isGitignored));

  // Check 2 — frontend exposure (also surfaces service_role-in-client hits).
  const frontend = detectFrontend(files);
  findings.push(...frontend.findings);

  // Check 3 — open Supabase database (only runs if Supabase is detected).
  const packageJson = files.find((f) => f.relPath === "package.json")?.content;
  findings.push(
    ...detectSupabase({
      files,
      packageJson,
      serviceRoleClientHits: frontend.serviceRoleClientHits,
    }),
  );

  return { findings, scannedFiles: scannedFileCount };
}

export async function main(argv: string[]): Promise<number> {
  const { options, showHelp, showVersion } = parseArgs(argv);

  if (!options.color) pc.createColors(false);

  if (showVersion) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (showHelp) {
    process.stdout.write(HELP + "\n");
    return 0;
  }

  // Validate the target path up front, gracefully.
  const abs = path.resolve(options.targetPath);
  try {
    const stat = fs.statSync(abs);
    if (!stat.isDirectory()) {
      process.stderr.write(
        `kavaca: "${options.targetPath}" is not a directory.\n`,
      );
      return 1;
    }
  } catch {
    process.stderr.write(`kavaca: cannot access "${options.targetPath}".\n`);
    return 1;
  }

  const { findings, scannedFiles } = runScan(abs);

  if (options.json) {
    process.stdout.write(renderJson(findings, scannedFiles) + "\n");
  } else {
    const label = options.targetPath === "." ? "./" : options.targetPath;
    process.stdout.write(renderHuman(findings, { scanLabel: label }) + "\n");
  }

  // Opt-in telemetry: anonymous aggregate counts only, never on by default.
  await maybeSendTelemetry(options.shareStats, findings, scannedFiles);

  return hasBlockingIssues(findings) ? 1 : 0;
}

// Execute when run directly (not when imported by tests).
// Compare realpaths so symlinked bins (npx) still match.
const invokedDirectly = (() => {
  try {
    const argv1 = process.argv[1];
    if (!argv1) return false;
    return import.meta.url === `file://${fs.realpathSync(argv1)}`;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`kavaca: unexpected error: ${err?.message ?? err}\n`);
      process.exit(1);
    });
}
