/**
 * detectors/supabase.ts — Check 3: OPEN SUPABASE DATABASE (high/medium).
 *
 * Only runs when Supabase is actually used in the project. Then:
 *   - For every `CREATE TABLE <name>` across the SQL migrations, confirm the
 *     same migration set also `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY`.
 *     Missing RLS → high ("table <name> has no RLS policy").
 *   - service_role key used client-side (passed in from the frontend check) → high.
 *   - Supabase used but no migrations/RLS found anywhere → one medium note.
 *
 * RLS heuristic, explained for contributors:
 *   Supabase tables are PUBLIC by default once an anon key is shared. RLS is the
 *   gate. We pair each created table name with an ENABLE ROW LEVEL SECURITY
 *   statement on the same name. We match on the bare table name (schema/quotes
 *   stripped) so `public."orders"` and `orders` reconcile. This is a heuristic:
 *   it can't see RLS enabled outside migrations (e.g. via the dashboard), hence
 *   the softer "couldn't verify" path rather than false high-confidence alarms.
 */

import type { Finding, ScannedFile } from "../scan.js";

export interface SupabaseInput {
  files: ScannedFile[];
  packageJson: string | undefined;
  serviceRoleClientHits: { file: string; line: number }[];
}

/** Detect whether the project uses Supabase at all. */
export function usesSupabase(input: SupabaseInput): boolean {
  if (input.packageJson && /@supabase\/supabase-js/.test(input.packageJson)) {
    return true;
  }
  for (const f of input.files) {
    if (f.relPath === "package.json" && /@supabase\/supabase-js/.test(f.content)) {
      return true;
    }
    // A supabase/ directory shows up as file paths under "supabase/".
    if (f.relPath === "supabase/config.toml" || f.relPath.startsWith("supabase/")) {
      return true;
    }
    // createClient imported from a supabase package.
    if (
      /from\s+["']@supabase\/supabase-js["']/.test(f.content) ||
      /createClient\s*\(/.test(f.content) && /supabase/i.test(f.content)
    ) {
      return true;
    }
  }
  return false;
}

/** Strip schema qualifier and quotes from a SQL identifier → bare lowercase name. */
function bareName(raw: string): string {
  let name = raw.trim();
  // Drop schema prefix: public.orders -> orders
  const dot = name.lastIndexOf(".");
  if (dot !== -1) name = name.slice(dot + 1);
  // Strip surrounding quotes/backticks/brackets.
  name = name.replace(/["'`\[\]]/g, "");
  return name.toLowerCase();
}

// CREATE TABLE [IF NOT EXISTS] <name> — capture the (possibly quoted/qualified) name.
const CREATE_TABLE_RE =
  /create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_."`\[\]]+)/gi;

// ALTER TABLE <name> ... ENABLE ROW LEVEL SECURITY
const ENABLE_RLS_RE =
  /alter\s+table\s+(?:if\s+exists\s+)?([a-zA-Z0-9_."`\[\]]+)[\s\S]*?enable\s+row\s+level\s+security/gi;

export function detectSupabase(input: SupabaseInput): Finding[] {
  if (!usesSupabase(input)) return [];

  const findings: Finding[] = [];

  // service_role used client-side overlaps with the frontend check; surface it
  // here too as a database exposure (high).
  for (const hit of input.serviceRoleClientHits) {
    findings.push({
      severity: "high",
      check: "supabase",
      title: "Supabase service_role key exposed in client-side code",
      file: hit.file,
      line: hit.line,
      evidence: "service_role bypasses RLS — anyone can read/write every table",
    });
  }

  // Gather SQL files (migrations preferred, but any *.sql counts).
  const sqlFiles = input.files.filter((f) => f.relPath.toLowerCase().endsWith(".sql"));

  // Collect created tables (with their source location) and RLS-enabled tables.
  const created = new Map<string, { file: string; line: number }>();
  const rlsEnabled = new Set<string>();

  for (const f of sqlFiles) {
    CREATE_TABLE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = CREATE_TABLE_RE.exec(f.content)) !== null) {
      const name = bareName(m[1]);
      if (!name) continue;
      const line = f.content.slice(0, m.index).split(/\r?\n/).length;
      if (!created.has(name)) created.set(name, { file: f.relPath, line });
    }

    ENABLE_RLS_RE.lastIndex = 0;
    let r: RegExpExecArray | null;
    while ((r = ENABLE_RLS_RE.exec(f.content)) !== null) {
      rlsEnabled.add(bareName(r[1]));
    }
  }

  // No migrations/RLS info anywhere → soft medium note (don't alarm per-table).
  const sawAnyRls = sqlFiles.some((f) => /enable\s+row\s+level\s+security/i.test(f.content));
  if (created.size === 0 && !sawAnyRls) {
    findings.push({
      severity: "medium",
      check: "supabase",
      title: "Couldn't verify Supabase RLS — review manually",
      file: "",
      line: 0,
      evidence:
        "Supabase is used but no migrations/RLS statements were found to confirm tables are protected",
    });
    return findings;
  }

  // Per-table: created but never RLS-enabled → high.
  for (const [name, loc] of created) {
    if (!rlsEnabled.has(name)) {
      findings.push({
        severity: "high",
        check: "supabase",
        title: `Supabase table "${name}" has no RLS policy`,
        file: loc.file,
        line: loc.line,
        evidence: "Anyone with your anon key may be able to read it",
      });
    }
  }

  return findings;
}
