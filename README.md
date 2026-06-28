# ◎ Kavaca

**A free, local pre-flight security check for apps built with AI tools** — Claude
Code, Cursor, Lovable, Bolt, Replit, and friends. Run one command and, in seconds,
catch the two mistakes that sink most AI-built apps: **exposed secrets** and **open
Supabase databases**.

```bash
npx kavaca
```

That's it. No install, no account, no config. The scan runs **entirely on your
machine** — your code and secrets never leave it.

[![Security: Kavaca](https://img.shields.io/badge/security-kavaca-2ea44f)](https://kavaca.com?ref=cli)

---

## Why this exists

AI coding tools are incredible at shipping features fast — and just as fast at
committing a live Stripe key or spinning up a Supabase table with **no row-level
security**, leaving your entire database readable by anyone with the public anon
key. These two mistakes are behind a huge share of "my AI-built app got hacked"
stories.

Kavaca is the 10-second check you run before you deploy.

## Quick start

```bash
# scan the current directory
npx kavaca

# scan a specific path
npx kavaca ./my-app

# machine-readable output (for CI)
npx kavaca --json
```

Exit code is `0` when clean and `1` when any high/medium issue is found, so it
drops straight into CI.

## What it checks

Kavaca runs three deterministic, local detectors:

1. **🔑 Exposed secrets** *(high)* — committed live credentials: Stripe
   (`sk_live_…`, `rk_live_…`), OpenAI / Anthropic keys, AWS access key IDs,
   Supabase **service_role** JWTs (decoded and verified, not just pattern-matched),
   database URLs with embedded passwords, and `.env` files that aren't gitignored.

2. **🌐 Frontend exposure** *(high)* — secrets that leak into the browser bundle:
   sensitive values behind a public env prefix (`NEXT_PUBLIC_*`, `VITE_*`,
   `REACT_APP_*`, `EXPO_PUBLIC_*`) and `service_role` keys referenced in
   client-side code.

3. **🛡️ Open Supabase database** *(high / medium)* — when Supabase is detected,
   Kavaca parses your SQL migrations and flags every `CREATE TABLE` that never gets
   `ENABLE ROW LEVEL SECURITY`. No RLS = your data is public.

It's deliberately quiet about false positives: example/sample files, `process.env`
references, and placeholder values (`your_key_here`, `changeme`, …) are ignored. A
noisy security tool gets uninstalled — so Kavaca biases toward precision.

### What you'll see

```
  ◎ Kavaca — pre-flight security check
  Scanning ./my-app  (local only — nothing leaves your machine)

  ✔ Secrets in code .............. 1 issue
  ✔ Frontend exposure ............ clear
  ✔ Supabase database ............ 1 issue

  ──────────────────────────────────────────────
  ⚠  2 issues found · score 50/100

  HIGH  Live Stripe key (lib/payments.ts:14)
        sk_live_••••••••1234 — visible to anyone with the repo

  HIGH  Supabase table "orders" has no RLS policy
        Anyone with your anon key may be able to read it
```

Evidence is always **masked** — Kavaca never prints (or uploads) a full secret.

## Score

Every scan gets a score out of 100, mirroring the hosted product so the numbers
feel consistent: start at 100, then **high −25, medium −10, low −3** (floored at 0).

## Use it in CI (GitHub Action)

Drop this into `.github/workflows/kavaca.yml` to scan every push and PR, fail the
build on findings, and comment the results on the pull request. A complete,
copy-pasteable version lives in
[`.github/workflows/example-action.yml`](.github/workflows/example-action.yml):

```yaml
name: Kavaca security check
on: [push, pull_request]
jobs:
  kavaca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes kavaca . --json
```

### Badge

Show your repo is checked:

```markdown
[![Security: Kavaca](https://img.shields.io/badge/security-kavaca-2ea44f)](https://kavaca.com?ref=cli)
```

## Privacy & telemetry

**Kavaca is local-first and offline by default. It never uploads your code,
files, paths, or secrets.** The plain default run makes zero network requests.

Optional, opt-in telemetry (`--share-stats`) sends only anonymous **aggregate
counts** — `{ toolVersion, issueCountsByCheck, totalFiles }` — and nothing else.
The full, auditable details are in [TELEMETRY.md](TELEMETRY.md). The entire
network surface is a single, clearly-gated function in `src/telemetry.ts`.

## → Want the full picture?

This free CLI checks **3 of 8** risk areas. The hosted scan at
**[kavaca.com](https://kavaca.com?ref=cli)** adds auth, API, and dependency
checks — with **plain-English fixes and ready-to-paste prompts** you can hand
straight back to your AI tool.

## Flags

| Flag | Description |
|---|---|
| `[path]` | Directory to scan (default: current directory) |
| `--json` | Machine-readable JSON output |
| `--share-stats` | Opt in to anonymous aggregate telemetry (off by default) |
| `--no-color` | Disable colored output |
| `--version`, `-v` | Print version |
| `--help`, `-h` | Show help |

## Contributing

Detectors live in [`src/detectors/`](src/detectors) and every regex is documented
in [`src/patterns.ts`](src/patterns.ts) — the place to add a new secret type. Run
the tests with `npm test`. PRs that add detectors (with fixtures!) are very
welcome.

## Development

```bash
npm install
npm run build      # bundle to dist/ with tsup
npm test           # run the vitest suite
npm run typecheck  # tsc --noEmit
node dist/index.js ./some/project
```

## License

[MIT](LICENSE) — free and open source.

⭐ If Kavaca saved you from a leak, **star the repo**: github.com/kavaca/kavaca
