import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getSourcePath } from "./metadata.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let projectRoot: string | null = null;

export function getProjectRoot(): string {
  if (projectRoot) {
    return projectRoot;
  }

  let current = __dirname;
  while (current !== path.dirname(current)) {
    if (fs.existsSync(path.join(current, "package.json"))) {
      projectRoot = current;
      return projectRoot;
    }
    current = path.dirname(current);
  }

  projectRoot = path.resolve(__dirname, "../../..");
  return projectRoot;
}

/** True when `target` is `root` itself or lies below it. */
export function isPathInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Resolve symlinks and make sure the real file stays inside `root` (by default
 * the project's `sources/` directory). External documentation repositories are
 * untrusted: a symlink such as `docs/x.md -> ~/.ssh/id_rsa` or a `relFile`
 * with `../` must never make the server read files outside the corpus.
 * Throws when the path escapes; returns the real path otherwise.
 */
export function assertInsideRoot(absPath: string, root: string = path.join(getProjectRoot(), "sources")): string {
  const lexical = path.resolve(absPath);
  const realRoot = fs.realpathSync.native(path.resolve(root));
  if (!isPathInside(path.resolve(root), lexical) && !isPathInside(realRoot, lexical)) {
    throw new Error(`Refusing to read outside of ${root}: ${absPath}`);
  }
  const real = fs.realpathSync.native(lexical);
  if (!isPathInside(realRoot, real)) {
    throw new Error(`Refusing to follow a link outside of ${root}: ${absPath}`);
  }
  return real;
}

/** Absolute path of a corpus file, verified to stay inside `sources/`. */
export function resolveSourceFile(sourcePath: string, relFile: string): string {
  return assertInsideRoot(path.join(getProjectRoot(), "sources", sourcePath, relFile));
}

export function readSourceContentSync(libraryId: string, relFile: string): string | null {
  if (!relFile) {
    return null;
  }

  const sourcePath = getSourcePath(libraryId);
  if (!sourcePath) {
    return null;
  }

  try {
    return fs.readFileSync(resolveSourceFile(sourcePath, relFile), "utf8");
  } catch {
    return null;
  }
}

export function extractSourceUrlFromText(text: string): string | null {
  const match = text.match(/\*\*URL:?\*\*:?\s*(https?:\/\/[^\s)]+)/i);
  if (match) {
    return normalizeExtractedUrl(match[1]);
  }

  const plainMatch = text.match(/^URL:\s*(https?:\/\/[^\s)]+)/m);
  return plainMatch ? normalizeExtractedUrl(plainMatch[1]) : null;
}

function normalizeExtractedUrl(url: string): string | null {
  const candidate = url.replace(/[>,.;]+$/, "");
  try {
    // Documentation may contain "URL: https://<tenant ...>" examples. Those
    // must not replace the citation to the actual documentation file.
    const parsed = new URL(candidate);
    return ['https:', 'http:'].includes(parsed.protocol) ? candidate : null;
  } catch {
    return null;
  }
}

function isAbsoluteHttpUrl(url?: string | null): boolean {
  return !!url && /^https?:\/\//i.test(url);
}

export function chooseSourceAwareUrl(
  sourceContent: string | null | undefined,
  docUrl: string | null | undefined,
  pathUrl: string | undefined,
  fallbackId: string
): string {
  const extractedSourceUrl = sourceContent ? extractSourceUrlFromText(sourceContent) : null;
  if (isAbsoluteHttpUrl(extractedSourceUrl)) {
    return extractedSourceUrl!;
  }

  if (isAbsoluteHttpUrl(docUrl)) {
    return docUrl!;
  }

  if (isAbsoluteHttpUrl(pathUrl)) {
    return pathUrl!;
  }

  return `#${fallbackId}`;
}
