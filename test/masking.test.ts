import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runScan } from "../src/index.js";
import { renderHuman, renderJson } from "../src/report.js";
import { mask } from "../src/patterns.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => path.join(here, "fixtures", name);

// The full secrets that are physically present in the vulnerable fixture.
const FULL_SECRETS = [
  "sk_live_FAKEfixturekey1234",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3MDAwMDAwMDB9.fakesignature_AbCdEf123456",
];

describe("masking", () => {
  const { findings, scannedFiles } = runScan(fixture("vulnerable"));

  it("never prints a full secret in human output", () => {
    const out = renderHuman(findings, { scanLabel: "./vulnerable" });
    for (const secret of FULL_SECRETS) {
      expect(out.includes(secret)).toBe(false);
    }
    // And it should clearly show masking dots.
    expect(out).toContain("•");
  });

  it("never prints a full secret in JSON output", () => {
    const out = renderJson(findings, scannedFiles);
    for (const secret of FULL_SECRETS) {
      expect(out.includes(secret)).toBe(false);
    }
  });

  it("mask() keeps only a recognizable prefix and last 4 chars", () => {
    const masked = mask("sk_live_FAKEmiddlepart1234");
    expect(masked.startsWith("sk_live_")).toBe(true);
    expect(masked.endsWith("1234")).toBe(true);
    expect(masked).toContain("•");
    // The entropy-bearing middle must be gone.
    expect(masked).not.toContain("FAKEmiddlepart");
  });
});
