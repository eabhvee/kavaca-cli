/**
 * telemetry.ts — OPT-IN, anonymous, aggregate-only. OFF by default.
 *
 * THE TRUST CONTRACT (see TELEMETRY.md):
 *   - Nothing is sent unless the user passes `--share-stats`.
 *   - The ONLY payload ever sent is the shape below: a version string, three
 *     integer counts, and a total file count. No file contents, no paths, no
 *     secrets, no repo names, no IP-identifying extras we control.
 *   - This is the entire network surface of Kavaca. There are no other fetch()
 *     / http calls anywhere in the codebase. Audit grep: `fetch(` and `https`.
 *
 * If telemetry fails for any reason, we swallow it silently — a security tool
 * must never crash or hang because a stats endpoint is down.
 */

import type { CheckName, Finding } from "./scan.js";
import { VERSION } from "./report.js";

/** Override-able endpoint (env var) so self-hosters can point elsewhere. */
const DEFAULT_ENDPOINT = "https://kavaca.com/api/telemetry";

/** The complete, exhaustive payload schema. Nothing else is ever added. */
export interface TelemetryPayload {
  toolVersion: string;
  issueCountsByCheck: { secrets: number; frontend: number; supabase: number };
  totalFiles: number;
}

export function buildPayload(
  findings: Finding[],
  totalFiles: number,
): TelemetryPayload {
  const count = (check: CheckName) =>
    findings.filter((f) => f.check === check).length;
  return {
    toolVersion: VERSION,
    issueCountsByCheck: {
      secrets: count("secrets"),
      frontend: count("frontend"),
      supabase: count("supabase"),
    },
    totalFiles,
  };
}

/**
 * Send aggregate stats — ONLY when `enabled` (i.e. user passed --share-stats).
 * Returns true if a request was actually dispatched, false otherwise. Never
 * throws. Bounded so it can't hang the CLI.
 */
export async function maybeSendTelemetry(
  enabled: boolean,
  findings: Finding[],
  totalFiles: number,
  endpoint: string = process.env.KAVACA_TELEMETRY_URL || DEFAULT_ENDPOINT,
): Promise<boolean> {
  // The single, explicit gate. No opt-in → no network. Full stop.
  if (!enabled) return false;

  const payload = buildPayload(findings, totalFiles);

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return true;
  } catch {
    // Network down / offline / blocked — that's fine, stay silent.
    return false;
  }
}
