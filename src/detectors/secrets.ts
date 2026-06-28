/**
 * detectors/secrets.ts — Check 1: EXPOSED SECRETS (high).
 *
 * Scans every collected text file line-by-line for committed live credentials,
 * decodes JWTs to catch Supabase service_role tokens, flags DB URLs that carry
 * a real password, and flags committed `.env*` files that aren't gitignored.
 *
 * Precision first: we suppress matches in example/sample files, on lines that
 * merely reference `process.env.*`, and obvious placeholder values.
 */

import path from "node:path";
import {
  SECRET_PATTERNS,
  isExampleFile,
  isPlaceholder,
  jwtIsServiceRole,
  mask,
} from "../patterns.js";
import type { Finding, ScannedFile } from "../scan.js";

/** Real env files (not examples) that should never be committed. */
const ENV_FILE_RE = /(^|\/)\.env(\.local|\.production|\.development|\.staging)?$/;

export function detectSecrets(
  files: ScannedFile[],
  isGitignored: (relPath: string) => boolean,
): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    // --- Committed .env that is NOT gitignored -------------------------------
    const base = file.relPath;
    if (ENV_FILE_RE.test(base) && !isExampleFile(base)) {
      if (!isGitignored(file.relPath)) {
        findings.push({
          severity: "high",
          check: "secrets",
          title: `Committed env file "${path.basename(base)}" is not gitignored`,
          file: file.relPath,
          line: 1,
          evidence: "env file is tracked — its secrets are visible in the repo",
        });
      }
    }

    // Example/sample files: skip pattern scanning to avoid fake-secret noise.
    if (isExampleFile(file.relPath)) continue;

    // --- Line-by-line credential patterns ------------------------------------
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Lines that read from the environment (`process.env.FOO`) are safe code,
      // not committed secrets — skip them to avoid false positives.
      if (line.includes("process.env.")) continue;

      for (const pat of SECRET_PATTERNS) {
        // Fresh regex state per line.
        pat.regex.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pat.regex.exec(line)) !== null) {
          const matched = m[0];

          if (isPlaceholder(matched)) continue;

          if (pat.kind === "jwt") {
            // Only flag JWTs that actually grant service_role.
            if (!jwtIsServiceRole(matched)) continue;
            findings.push({
              severity: "high",
              check: "secrets",
              title: "Supabase service_role JWT committed to the repo",
              file: file.relPath,
              line: i + 1,
              evidence: `${mask(matched)} — full database access, bypasses RLS`,
            });
            continue;
          }

          if (pat.kind === "dburl") {
            // m[1] is the password group; skip if empty or placeholder.
            const pass = m[1] ?? "";
            if (!pass || isPlaceholder(pass)) continue;
            findings.push({
              severity: "high",
              check: "secrets",
              title: "Database URL with embedded password committed",
              file: file.relPath,
              line: i + 1,
              evidence: `${mask(matched)} — credentials visible in the repo`,
            });
            continue;
          }

          findings.push({
            severity: "high",
            check: "secrets",
            title: `${pat.label} in ${file.relPath}:${i + 1}`,
            file: file.relPath,
            line: i + 1,
            evidence: `${mask(matched)} — visible to anyone with the repo`,
          });
        }
      }
    }
  }

  return findings;
}
