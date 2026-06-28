/**
 * detectors/frontend.ts — Check 2: FRONTEND EXPOSURE (high).
 *
 * Secrets that leak into the browser bundle:
 *   (a) Public-prefixed env vars (NEXT_PUBLIC_*, VITE_*, REACT_APP_*, EXPO_PUBLIC_*)
 *       whose NAME or VALUE contains a sensitive token or matches a secret pattern.
 *   (b) A Supabase service_role key referenced in client-side code (under app/,
 *       pages/, src/components/, or any file marked "use client").
 *
 * `serviceRoleClientHits` is returned separately so the Supabase detector can
 * reuse it without re-scanning (the two checks overlap by design).
 */

import {
  PUBLIC_ENV_PREFIXES,
  SECRET_PATTERNS,
  SENSITIVE_TOKENS,
  isExampleFile,
  isPlaceholder,
  jwtIsServiceRole,
  mask,
} from "../patterns.js";
import type { Finding, ScannedFile } from "../scan.js";

export interface FrontendResult {
  findings: Finding[];
  /** Files where a service_role key appears in client-side code. */
  serviceRoleClientHits: { file: string; line: number }[];
}

/** Is this file client-side (ships to the browser)? */
function isClientSide(file: ScannedFile): boolean {
  const p = file.relPath;
  const clientDir =
    p.startsWith("app/") ||
    p.includes("/app/") ||
    p.startsWith("pages/") ||
    p.includes("/pages/") ||
    p.includes("src/components/") ||
    p.startsWith("components/");
  if (clientDir) return true;
  // Next.js App Router: any file explicitly opting into client rendering.
  return /["']use client["']/.test(file.content);
}

/** Build one regex that finds a public-prefixed env var assignment. */
// Matches: NEXT_PUBLIC_FOO=value  or  VITE_FOO: "value"  or  REACT_APP_FOO = 'value'
// Group 1 = full var name (a public prefix + at least one trailing char).
// Group 2 = the assigned value, up to a quote/comma/semicolon/newline.
const PUBLIC_ENV_RE = new RegExp(
  `\\b((?:${PUBLIC_ENV_PREFIXES.join("|")})[A-Z0-9_]+)\\s*[:=]\\s*["'\`]?([^"'\`\\n,;]*)`,
  "g",
);

const SENSITIVE_RE = new RegExp(SENSITIVE_TOKENS.join("|"), "i");

/** Does a value contain a real secret per Check-1 patterns (or a service_role JWT)? */
function valueLooksSecret(value: string): boolean {
  for (const pat of SECRET_PATTERNS) {
    pat.regex.lastIndex = 0;
    const m = pat.regex.exec(value);
    if (!m) continue;
    if (isPlaceholder(m[0])) continue;
    if (pat.kind === "jwt") return jwtIsServiceRole(m[0]);
    if (pat.kind === "dburl") return Boolean(m[1]) && !isPlaceholder(m[1]);
    return true;
  }
  return false;
}

export function detectFrontend(files: ScannedFile[]): FrontendResult {
  const findings: Finding[] = [];
  const serviceRoleClientHits: { file: string; line: number }[] = [];

  for (const file of files) {
    // Example/sample files hold deliberately fake values — never flag them.
    if (isExampleFile(file.relPath)) continue;

    const lines = file.content.split(/\r?\n/);
    const clientSide = isClientSide(file);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // (a) Public env var carrying something sensitive.
      PUBLIC_ENV_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = PUBLIC_ENV_RE.exec(line)) !== null) {
        const name = m[1];
        const value = (m[2] ?? "").trim();
        const nameSensitive = SENSITIVE_RE.test(name);
        const valueSensitive =
          (value && SENSITIVE_RE.test(value)) || valueLooksSecret(value);
        // Don't flag placeholders like NEXT_PUBLIC_X=your_value_here.
        if ((nameSensitive || valueSensitive) && !isPlaceholder(value)) {
          findings.push({
            severity: "high",
            check: "frontend",
            title: `Public env var "${name}" exposes a sensitive value to the browser`,
            file: file.relPath,
            line: i + 1,
            evidence: value
              ? `${name}=${mask(value)} — bundled into client JS`
              : `${name} — name implies a secret shipped to the browser`,
          });
        }
      }

      // (b) service_role JWT in client-side code.
      if (clientSide) {
        for (const pat of SECRET_PATTERNS) {
          if (pat.kind !== "jwt") continue;
          pat.regex.lastIndex = 0;
          let jm: RegExpExecArray | null;
          while ((jm = pat.regex.exec(line)) !== null) {
            if (!jwtIsServiceRole(jm[0])) continue;
            serviceRoleClientHits.push({ file: file.relPath, line: i + 1 });
            findings.push({
              severity: "high",
              check: "frontend",
              title: "Supabase service_role key used in client-side code",
              file: file.relPath,
              line: i + 1,
              evidence: `${mask(jm[0])} — grants full DB access from the browser`,
            });
          }
        }
      }
    }
  }

  return { findings, serviceRoleClientHits };
}
