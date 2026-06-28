import { describe, it, expect, vi, afterEach } from "vitest";
import { maybeSendTelemetry, buildPayload } from "../src/telemetry.js";
import type { Finding } from "../src/scan.js";

const sampleFindings: Finding[] = [
  { severity: "high", check: "secrets", title: "x", file: "a", line: 1, evidence: "•" },
  { severity: "high", check: "supabase", title: "y", file: "b", line: 2, evidence: "•" },
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("telemetry is opt-in", () => {
  it("sends NOTHING when --share-stats is not passed", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 200 }),
    );
    const sent = await maybeSendTelemetry(false, sampleFindings, 42);
    expect(sent).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("sends ONLY anonymous aggregate counts when opted in", async () => {
    let capturedBody: any = null;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (_url, init) => {
        capturedBody = JSON.parse(String(init?.body));
        return new Response(null, { status: 200 });
      },
    );

    const sent = await maybeSendTelemetry(true, sampleFindings, 42);
    expect(sent).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // The payload must contain ONLY the allowed, non-identifying keys.
    expect(Object.keys(capturedBody).sort()).toEqual(
      ["issueCountsByCheck", "toolVersion", "totalFiles"].sort(),
    );
    expect(capturedBody.issueCountsByCheck).toEqual({
      secrets: 1,
      frontend: 0,
      supabase: 1,
    });
    expect(capturedBody.totalFiles).toBe(42);

    // Defense in depth: nothing path-like or secret-like is present anywhere.
    const serialized = JSON.stringify(capturedBody);
    expect(serialized).not.toMatch(/\.(ts|tsx|js|sql|env)/);
    expect(serialized).not.toContain("/");
  });

  it("buildPayload exposes no file paths or contents", () => {
    const payload = buildPayload(sampleFindings, 10);
    expect(JSON.stringify(payload)).not.toContain("title");
    expect(JSON.stringify(payload)).not.toContain("file");
    expect(JSON.stringify(payload)).not.toContain("evidence");
  });
});
