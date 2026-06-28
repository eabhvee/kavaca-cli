import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runScan } from "../src/index.js";

// Build a tiny throwaway project on disk so we can prove .kavacaignore behavior
// end-to-end (the walk only excludes real paths, so an in-memory fake won't do).
let root: string;

const PLANTED_KEY = 'const k = "sk_live_FAKEignoretest1234";\n';

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "kavaca-ign-"));
  fs.mkdirSync(path.join(root, "fixtures"), { recursive: true });
  // Same planted secret in two places: one we'll ignore, one we won't.
  fs.writeFileSync(path.join(root, "fixtures", "planted.ts"), PLANTED_KEY);
  fs.writeFileSync(path.join(root, "real.ts"), PLANTED_KEY);
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe(".kavacaignore", () => {
  it("flags both planted secrets when there is no .kavacaignore", () => {
    const { findings } = runScan(root);
    const secretFiles = findings
      .filter((f) => /Stripe/i.test(f.title))
      .map((f) => f.file)
      .sort();
    expect(secretFiles).toEqual(["fixtures/planted.ts", "real.ts"]);
  });

  it("suppresses only the ignored path, never the rest", () => {
    fs.writeFileSync(path.join(root, ".kavacaignore"), "fixtures/\n");
    const { findings } = runScan(root);
    const secretFiles = findings
      .filter((f) => /Stripe/i.test(f.title))
      .map((f) => f.file);
    // The ignored fixture is gone; the real file is still flagged.
    expect(secretFiles).toEqual(["real.ts"]);
  });
});
