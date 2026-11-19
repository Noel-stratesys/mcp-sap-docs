/**
 * HTTP surface hardening shared by the Streamable HTTP server and the legacy
 * HTTP server.
 *
 * - Host header allow-list and Origin validation (DNS-rebinding protection,
 *   required by the MCP Streamable HTTP specification for local servers).
 * - Restrictive CORS: only allowed origins are reflected.
 * - Request body size limit.
 *
 * Defaults are for a local server bound to 127.0.0.1. Deployments behind a
 * public hostname open them up with environment variables:
 *
 *   MCP_ALLOWED_HOSTS    comma-separated Host names (port ignored), or "*"
 *   MCP_ALLOWED_ORIGINS  comma-separated origins (scheme://host[:port]), or "*"
 *   MCP_MAX_BODY_BYTES   maximum request body size in bytes (default 262144)
 */
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

export interface HttpSecurityConfig {
  allowedHosts: Set<string> | "*";
  allowedOrigins: Set<string> | "*";
  maxBodyBytes: number;
}

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];
const WILDCARD_BINDS = new Set(["0.0.0.0", "::", "[::]", ""]);
export const DEFAULT_MAX_BODY_BYTES = 256 * 1024;

function splitList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Lower-cased host name without port; IPv6 literals keep their brackets. */
export function hostnameOf(hostHeader: string): string {
  const h = hostHeader.trim().toLowerCase();
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    return end === -1 ? h : h.slice(0, end + 1);
  }
  // A bare IPv6 address without brackets (only in config values).
  if ((h.match(/:/g) ?? []).length > 1) return `[${h}]`;
  return h.split(":")[0];
}

function normalizeOrigin(origin: string): string | null {
  try {
    const u = new URL(origin);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return null;
  }
}

export function loadHttpSecurityConfig(
  env: NodeJS.ProcessEnv = process.env,
  bindHost: string = env.MCP_HOST || "127.0.0.1"
): HttpSecurityConfig {
  const hostsRaw = splitList(env.MCP_ALLOWED_HOSTS);
  let allowedHosts: Set<string> | "*";
  if (hostsRaw.includes("*")) {
    allowedHosts = "*";
  } else {
    allowedHosts = new Set([...LOOPBACK_HOSTS, ...hostsRaw.map(hostnameOf)]);
    // A server bound to a specific address is reachable by that address.
    if (!WILDCARD_BINDS.has(bindHost.trim())) allowedHosts.add(hostnameOf(bindHost));
  }

  const originsRaw = splitList(env.MCP_ALLOWED_ORIGINS);
  let allowedOrigins: Set<string> | "*";
  if (originsRaw.includes("*")) {
    allowedOrigins = "*";
  } else {
    allowedOrigins = new Set(originsRaw.map(normalizeOrigin).filter((o): o is string => !!o));
  }

  const maxBody = Number.parseInt(env.MCP_MAX_BODY_BYTES ?? "", 10);
  return {
    allowedHosts,
    allowedOrigins,
    maxBodyBytes: Number.isSafeInteger(maxBody) && maxBody > 0 ? maxBody : DEFAULT_MAX_BODY_BYTES,
  };
}

export function isHostAllowed(hostHeader: string | undefined, cfg: HttpSecurityConfig): boolean {
  if (cfg.allowedHosts === "*") return true;
  if (!hostHeader) return false;
  return cfg.allowedHosts.has(hostnameOf(hostHeader));
}

/**
 * Requests without an Origin header (CLI / Node / IDE clients) are allowed.
 * Browser requests are allowed from loopback origins and from the configured
 * list only.
 */
export function isOriginAllowed(origin: string | undefined, cfg: HttpSecurityConfig): boolean {
  if (origin === undefined) return true;
  if (cfg.allowedOrigins === "*") return true;
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false; // "null", file:, chrome-extension:, garbage
  if (cfg.allowedOrigins.has(normalized)) return true;
  const host = hostnameOf(new URL(normalized).host);
  return LOOPBACK_HOSTS.includes(host);
}

export type RequestCheck = { ok: true } | { ok: false; status: number; message: string };

export function checkRequestHeaders(headers: IncomingHttpHeaders, cfg: HttpSecurityConfig): RequestCheck {
  if (!isHostAllowed(headers.host, cfg)) {
    return { ok: false, status: 403, message: "Forbidden: Host header not allowed (set MCP_ALLOWED_HOSTS)." };
  }
  const origin = headers.origin;
  if (!isOriginAllowed(Array.isArray(origin) ? origin[0] : origin, cfg)) {
    return { ok: false, status: 403, message: "Forbidden: Origin not allowed (set MCP_ALLOWED_ORIGINS)." };
  }
  return { ok: true };
}

const CORS_ALLOW_HEADERS = "Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID";

/** Set CORS headers only for allowed browser origins (never a blanket "*"). */
export function applyCorsHeaders(req: IncomingMessage, res: ServerResponse, cfg: HttpSecurityConfig, methods: string): void {
  const origin = req.headers.origin;
  if (typeof origin !== "string" || !isOriginAllowed(origin, cfg)) return;
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", methods);
  res.setHeader("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
  res.setHeader("Access-Control-Max-Age", "600");
}

/**
 * Express/Connect middleware: rejects disallowed Host/Origin, applies CORS and
 * answers preflight requests.
 */
export function httpSecurityMiddleware(cfg: HttpSecurityConfig, methods = "GET, POST, DELETE, OPTIONS") {
  return (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    const check = checkRequestHeaders(req.headers, cfg);
    if (!check.ok) {
      res.statusCode = check.status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: check.message }, id: null }));
      return;
    }
    applyCorsHeaders(req, res, cfg, methods);
    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      res.end();
      return;
    }
    next();
  };
}

/** Read a request body as UTF-8, rejecting bodies larger than maxBytes. */
export function readBodyLimited(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(Object.assign(new Error("Request body too large"), { status: 413 }));
      req.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    req.on("data", (chunk: Buffer) => {
      if (failed) return;
      size += chunk.length;
      if (size > maxBytes) {
        failed = true;
        reject(Object.assign(new Error("Request body too large"), { status: 413 }));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!failed) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", (err) => {
      if (!failed) reject(err);
    });
  });
}
