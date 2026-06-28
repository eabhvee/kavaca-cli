/**
 * scan.ts — walk the target directory (gitignore-aware), read text files,
 * and hand them to the detectors.
 *
 * Performance & safety:
 *   - Always skips heavy/noise dirs (node_modules, .git, dist, ...).
 *   - Skips files > MAX_FILE_BYTES and anything that looks binary.
 *   - Respects the repo's .gitignore via the `ignore` package.
 *   - Never reads outside the target root. Never uploads anything.
 */

import fs from "node:fs";
import path from "node:path";
import ignore, { type Ignore } from "ignore";

export type Severity = "high" | "medium" | "low";
export type CheckName = "secrets" | "frontend" | "supabase";

export interface Finding {
  severity: Severity;
  check: CheckName;
  title: string;
  /** Path relative to the scan root (POSIX separators), or "" if not applicable. */
  file: string;
  /** 1-based line number, or 0 if not applicable. */
  line: number;
  /** Masked, safe-to-print evidence. NEVER a full secret. */
  evidence: string;
}

/** A text file collected during the walk, ready for detection. */
export interface ScannedFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path relative to root, POSIX-normalized (e.g. "src/app/page.tsx"). */
  relPath: string;
  /** File contents (decoded utf8). */
  content: string;
}

export interface ScanResult {
  root: string;
  files: ScannedFile[];
  scannedFileCount: number;
}

/** Directories we never descend into — pure noise / build output. */
const ALWAYS_SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  ".turbo",
  ".cache",
  ".vercel",
  "out",
]);

/** Files larger than this are skipped (1.5 MB). */
const MAX_FILE_BYTES = 1.5 * 1024 * 1024;

/** Extensions we treat as binary and skip outright. */
const BINARY_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif",
  ".mp4", ".mov", ".avi", ".webm", ".mp3", ".wav", ".ogg", ".flac",
  ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar", ".7z", ".bz2",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".wasm", ".node", ".so", ".dll", ".dylib", ".exe", ".bin",
  ".lockb", ".pyc", ".class", ".jar",
]);

/** Heuristic: a NUL byte in the first chunk means binary. */
function looksBinary(buf: Buffer): boolean {
  const len = Math.min(buf.length, 4096);
  for (let i = 0; i < len; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/** Load the root .gitignore (if any) into an `ignore` matcher. */
function loadGitignore(root: string): Ignore {
  const ig = ignore();
  // Always ignore the VCS dir itself for matching purposes.
  ig.add([".git"]);
  const gitignorePath = path.join(root, ".gitignore");
  try {
    const txt = fs.readFileSync(gitignorePath, "utf8");
    ig.add(txt);
  } catch {
    // No .gitignore is fine.
  }
  return ig;
}

/**
 * Recursively collect scannable text files under `root`.
 * Errors on individual files/dirs are swallowed so one bad file can't crash a scan.
 */
export function scan(root: string): ScanResult {
  const absRoot = path.resolve(root);
  const ig = loadGitignore(absRoot);
  const files: ScannedFile[] = [];

  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory — skip gracefully
    }

    for (const entry of entries) {
      const absPath = path.join(dir, entry.name);
      const relPath = toPosix(path.relative(absRoot, absPath));
      if (!relPath || relPath.startsWith("..")) continue;

      if (entry.isDirectory()) {
        if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
        // `ignore` matches directories when the path ends with "/".
        if (ig.ignores(relPath + "/")) continue;
        walk(absPath);
        continue;
      }

      if (!entry.isFile()) continue; // symlinks, sockets, etc.
      if (ig.ignores(relPath)) continue;
      if (BINARY_EXTS.has(path.extname(entry.name).toLowerCase())) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(absPath);
      } catch {
        continue;
      }
      if (stat.size > MAX_FILE_BYTES) continue;

      let buf: Buffer;
      try {
        buf = fs.readFileSync(absPath);
      } catch {
        continue; // unreadable file — skip gracefully
      }
      if (looksBinary(buf)) continue;

      files.push({ absPath, relPath, content: buf.toString("utf8") });
    }
  };

  try {
    walk(absRoot);
  } catch {
    // Defensive: any unexpected walk error leaves us with whatever we collected.
  }

  return { root: absRoot, files, scannedFileCount: files.length };
}

/** Normalize a path to forward slashes for stable, cross-platform output. */
export function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

/**
 * Does the repo's .gitignore cover this relative path? Exposed so the secrets
 * detector can tell whether a committed `.env` would actually be ignored.
 */
export function makeGitignoreChecker(root: string): (relPath: string) => boolean {
  const ig = loadGitignore(path.resolve(root));
  return (relPath: string) => ig.ignores(toPosix(relPath));
}
