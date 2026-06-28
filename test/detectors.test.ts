import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runScan } from "../src/index.js";
import type { CheckName, Severity, Finding } from "../src/scan.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => path.join(here, "fixtures", name);

function countBy(findings: Finding[], key: "check" | "severity") {
  const out: Record<string, number> = {};
  for (const f of findings) out[f[key]] = (out[f[key]] ?? 0) + 1;
  return out;
}

describe("vulnerable fixture", () => {
  const { findings } = runScan(fixture("vulnerable"));

  it("produces exactly the planted high findings", () => {
    // Every planted issue is HIGH severity; nothing medium/low slips in.
    const bySeverity = countBy(findings, "severity") as Record<Severity, number>;
    expect(bySeverity.high).toBe(5);
    expect(bySeverity.medium ?? 0).toBe(0);
    expect(bySeverity.low ?? 0).toBe(0);
  });

  it("attributes findings to the right checks", () => {
    const byCheck = countBy(findings, "check") as Record<CheckName, number>;
    // secrets: hard-coded sk_live, committed .env.local, service_role JWT
    expect(byCheck.secrets).toBe(3);
    // frontend: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY
    expect(byCheck.frontend).toBe(1);
    // supabase: orders table without RLS
    expect(byCheck.supabase).toBe(1);
  });

  it("flags the specific planted vulnerabilities", () => {
    const titles = findings.map((f) => f.title);
    expect(titles.some((t) => /Live Stripe key/i.test(t))).toBe(true);
    expect(titles.some((t) => /service_role JWT/i.test(t))).toBe(true);
    expect(titles.some((t) => /not gitignored/i.test(t))).toBe(true);
    expect(
      titles.some((t) => /Public env var .*SERVICE_ROLE/i.test(t)),
    ).toBe(true);
    expect(titles.some((t) => /table "orders" has no RLS/i.test(t))).toBe(true);
  });

  it("locates the Stripe key on the right file:line", () => {
    const stripe = findings.find((f) => /Live Stripe key/i.test(f.title));
    expect(stripe?.file).toBe("lib/payments.ts");
    expect(stripe?.line).toBeGreaterThan(0);
  });
});

describe("clean fixture (false-positive guard — matters most)", () => {
  const { findings } = runScan(fixture("clean"));

  it("produces ZERO findings", () => {
    // If this fails, print what leaked so the regression is obvious.
    expect(findings, JSON.stringify(findings, null, 2)).toHaveLength(0);
  });
});
