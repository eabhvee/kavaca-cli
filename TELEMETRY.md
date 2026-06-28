# Telemetry in Kavaca

**Short version: telemetry is OFF by default. Kavaca sends nothing anywhere unless
you explicitly pass `--share-stats`. It never uploads your code, files, paths, or
secrets — ever, under any flag.**

This document describes exactly what happens, so you can verify it yourself.

## Default behavior: completely offline

Running `npx kavaca` (or any invocation without `--share-stats`) makes **zero
network requests**. The scan reads files from your disk, runs three local
detectors, prints a report, and exits. Nothing leaves your machine.

You can confirm this with a network monitor, or by reading the code — the single
gate lives at the top of `maybeSendTelemetry()` in
[`src/telemetry.ts`](src/telemetry.ts):

```ts
// The single, explicit gate. No opt-in → no network. Full stop.
if (!enabled) return false;
```

There is **no other network code anywhere in Kavaca**. To audit this, grep the
source:

```bash
grep -rn "fetch(\|http\|https\|net\.\|dns\." src/
```

The only `fetch(` in the entire codebase is the one inside `maybeSendTelemetry`.

## When you opt in with `--share-stats`

If — and only if — you pass `--share-stats`, Kavaca sends a single, anonymous,
aggregate payload. This is the **complete and exhaustive** shape of what is sent:

```json
{
  "toolVersion": "0.1.0",
  "issueCountsByCheck": { "secrets": 2, "frontend": 0, "supabase": 1 },
  "totalFiles": 184
}
```

That's it. Three integer counts, a version string, and a total file count.

### What is NEVER sent — even with `--share-stats`

- ❌ File contents
- ❌ File names or paths
- ❌ Any secret, key, token, or masked evidence string
- ❌ Repository name, remote URL, or git info
- ❌ Your username, hostname, IP-identifying data, or environment variables
- ❌ The specific titles, lines, or locations of findings

The payload is built by `buildPayload()` in `src/telemetry.ts`, which can only
ever read finding **counts** — it has no access to file paths or evidence by
construction. Our test suite asserts this
([`test/telemetry.test.ts`](test/telemetry.test.ts)):

- nothing is sent when `--share-stats` is absent;
- when opted in, the payload contains **only** the three allowed keys;
- the serialized payload contains no path-like or file-extension strings.

## Why we ask

Aggregate counts (e.g. "how often does the Supabase RLS check fire?") help us
tune detectors and prioritize new checks. It is genuinely optional and the tool
is fully functional — identical, in fact — without it.

## Configuration

- **Endpoint:** defaults to `https://kavaca.com/api/telemetry`. Override with the
  `KAVACA_TELEMETRY_URL` environment variable (useful for self-hosters or for
  pointing at a local sink to inspect the payload yourself).
- **Timeout:** the request is aborted after 2 seconds and any failure is silently
  ignored — telemetry can never slow down or crash a scan.

## TL;DR

| | Default | With `--share-stats` |
|---|---|---|
| Network requests | none | one POST of aggregate counts |
| Code / secrets / paths sent | never | never |
| Works fully | yes | yes |
