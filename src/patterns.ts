/**
 * patterns.ts — every regex Kavaca uses, plus masking helpers.
 *
 * Contributors: this is the file to extend when adding a new secret type.
 * Rules of the road:
 *   - Keep patterns specific. A noisy security tool gets uninstalled, so we
 *     bias toward precision (fewer false positives) over recall.
 *   - Each pattern below has a single capture intent. Where a sub-group matters
 *     (e.g. the password in a DB URL), it is documented inline.
 *   - Patterns are used with a fresh `RegExp` per line scan (no shared lastIndex).
 */

export type SecretKind =
  | "stripe"
  | "anthropic"
  | "openai"
  | "aws"
  | "jwt"
  | "dburl";

export interface SecretPattern {
  kind: SecretKind;
  /** Human label shown in the report title. */
  label: string;
  /** The matching regex (global so we can find all on a line). */
  regex: RegExp;
}

/**
 * Order matters: Anthropic (`sk-ant-...`) is listed before OpenAI (`sk-...`)
 * so the more specific key wins and we don't double-report the same token.
 * The OpenAI pattern additionally guards against `sk-ant-` at match time.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    kind: "stripe",
    label: "Live Stripe key",
    // Stripe live secret + restricted keys. We deliberately skip `sk_test_`.
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{10,}\b/g,
  },
  {
    kind: "anthropic",
    label: "Anthropic API key",
    // Anthropic keys: `sk-ant-` then base62 + dashes/underscores.
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    kind: "openai",
    label: "OpenAI API key",
    // Generic OpenAI-style key. Excludes the `sk-ant-` prefix via negative
    // lookahead so Anthropic keys are only reported once (as Anthropic).
    regex: /\bsk-(?!ant-)[A-Za-z0-9]{20,}\b/g,
  },
  {
    kind: "aws",
    label: "AWS access key id",
    // AWS access key IDs are exactly `AKIA` + 16 uppercase alphanumerics.
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    kind: "jwt",
    label: "JSON Web Token",
    // header.payload.signature — all base64url. The payload is decoded by the
    // detector to decide whether this is a dangerous `service_role` token.
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    kind: "dburl",
    label: "Database URL with embedded credentials",
    // Capture group 1 = the password between `user:` and `@host`.
    // We only flag when a non-empty password is present.
    regex:
      /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:/?#\s]+:([^@/\s"']+)@[^\s"'`]+/g,
  },
];

/** Public env-var prefixes that ship to the browser bundle (check 2). */
export const PUBLIC_ENV_PREFIXES = [
  "NEXT_PUBLIC_",
  "VITE_",
  "REACT_APP_",
  "EXPO_PUBLIC_",
];

/**
 * Sensitive tokens that should never appear in a public env var's NAME or VALUE.
 * Matched case-insensitively.
 */
export const SENSITIVE_TOKENS = [
  "SERVICE_ROLE",
  "SECRET",
  "SK_LIVE",
  "PRIVATE",
];

/**
 * Placeholder values we must NOT flag — these are the fake values people leave
 * in `.env.example` files and docs. Matched case-insensitively as a substring.
 */
const PLACEHOLDER_HINTS = [
  "your_",
  "_here",
  "changeme",
  "change-me",
  "placeholder",
  "example",
  "dummy",
  "xxxx",
  "<your",
  "...",
  "•",
];

/**
 * Files whose secrets are intentionally fake (`.env.example`, `config.sample`,
 * etc.). Both the secrets and frontend detectors skip these to avoid flagging
 * the placeholder values everyone commits on purpose.
 */
export function isExampleFile(relPath: string): boolean {
  const lower = relPath.toLowerCase();
  return (
    lower.includes(".example") ||
    lower.includes(".sample") ||
    lower.includes("example") ||
    lower.includes("sample")
  );
}

/** True if a value looks like a placeholder rather than a real secret. */
export function isPlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  if (/^x+$/i.test(value)) return true; // e.g. "xxxxxxxx"
  return PLACEHOLDER_HINTS.some((h) => v.includes(h));
}

/**
 * Mask a secret so the report proves a finding without ever leaking it.
 * Shows a short, recognizable prefix + dots + last 4 chars:
 *   sk_live_51H8...abcd  ->  sk_live_••••••••abcd
 * Anything shorter than 8 chars is fully masked.
 */
export function mask(secret: string): string {
  const s = secret.trim();
  if (s.length <= 8) return "•".repeat(Math.max(s.length, 4));

  // Keep a meaningful prefix for known shapes so the user recognizes the key
  // type, but never reveal the entropy-bearing middle.
  const prefixMatch = s.match(
    /^(sk_live_|rk_live_|sk-ant-|sk-|AKIA|eyJ|postgres(?:ql)?:\/\/|mysql:\/\/|mongodb(?:\+srv)?:\/\/)/,
  );
  const prefix = prefixMatch ? prefixMatch[0] : s.slice(0, 4);
  const last4 = s.slice(-4);
  return `${prefix}${"•".repeat(8)}${last4}`;
}

/**
 * Decode the payload (middle segment) of a JWT and return whether it grants
 * the Supabase `service_role`. Never throws — returns false on malformed input.
 */
export function jwtIsServiceRole(jwt: string): boolean {
  const parts = jwt.split(".");
  if (parts.length < 2) return false;
  try {
    // base64url -> base64
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    const payload = JSON.parse(json);
    return payload?.role === "service_role";
  } catch {
    return false;
  }
}
