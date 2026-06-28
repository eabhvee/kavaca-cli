import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  platform: "node",
  clean: true,
  minify: false,
  // Prepend the shebang so the built file is directly executable via `npx kavaca`.
  banner: {
    js: "#!/usr/bin/env node",
  },
});
