import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import {
  loadHttpSecurityConfig,
  isHostAllowed,
  isOriginAllowed,
  hostnameOf,
  checkRequestHeaders,
} from "../src/lib/httpSecurity.js";
import { validateToolArguments, INPUT_LIMITS } from "../src/lib/inputLimits.js";

describe("httpSecurity config", () => {
  const local = loadHttpSecurityConfig({}, "127.0.0.1");

  it("allows only loopback Host names by default", () => {
    for (const host of ["localhost", "localhost:3122", "127.0.0.1:3122", "[::1]:3122", "LOCALHOST:1"]) {
      expect(isHostAllowed(host, local)).toBe(true);
    }
    for (const host of [undefined, "", "evil.example", "evil.example:3122", "127.0.0.1.evil.example", "localhost.evil.example"]) {
      expect(isHostAllowed(host, local)).toBe(false);
    }
  });

  it("allows requests without Origin and loopback origins only", () => {
    expect(isOriginAllowed(undefined, local)).toBe(true);
    expect(isOriginAllowed("http://localhost:6274", local)).toBe(true);
    expect(isOriginAllowed("http://127.0.0.1:5173", local)).toBe(true);
    for (const origin of ["null", "http://evil.example", "http://evil.example:3122", "file://", "chrome-extension://abc", "http://localhost.evil.example"]) {
      expect(isOriginAllowed(origin, local)).toBe(false);
    }
  });

  it("can be opened with environment variables", () => {
    const cfg = loadHttpSecurityConfig(
      { MCP_ALLOWED_HOSTS: "docs.example.com, other.example:443", MCP_ALLOWED_ORIGINS: "https://app.example.com/", MCP_MAX_BODY_BYTES: "1000" },
      "0.0.0.0"
    );
    expect(isHostAllowed("docs.example.com", cfg)).toBe(true);
    expect(isHostAllowed("other.example", cfg)).toBe(true);
    expect(isHostAllowed("0.0.0.0", cfg)).toBe(false);
    expect(isOriginAllowed("https://app.example.com", cfg)).toBe(true);
    expect(isOriginAllowed("https://evil.example.com", cfg)).toBe(false);
    expect(cfg.maxBodyBytes).toBe(1000);

    const open = loadHttpSecurityConfig({ MCP_ALLOWED_HOSTS: "*", MCP_ALLOWED_ORIGINS: "*" });
    expect(isHostAllowed("anything", open)).toBe(true);
    expect(isOriginAllowed("https://anything", open)).toBe(true);
  });

  it("allows the specific bind address", () => {
    const cfg = loadHttpSecurityConfig({}, "192.168.1.20");
    expect(isHostAllowed("192.168.1.20:3122", cfg)).toBe(true);
    expect(hostnameOf("::1")).toBe("[::1]");
  });

  it("checkRequestHeaders reports 403 for DNS-rebinding style requests", () => {
    expect(checkRequestHeaders({ host: "attacker.example:3122", origin: "http://attacker.example:3122" }, local)).toMatchObject({ ok: false, status: 403 });
    expect(checkRequestHeaders({ host: "127.0.0.1:3122" }, local)).toEqual({ ok: true });
  });
});

describe("tool argument limits", () => {
  it("accepts normal arguments", () => {
    expect(validateToolArguments({ query: "RAP behavior definition", k: 10, sources: ["cap", "wdi5"], includeOnline: false })).toBeNull();
    expect(validateToolArguments(undefined)).toBeNull();
  });

  it("rejects oversized or malformed arguments", () => {
    expect(validateToolArguments({ query: "a".repeat(INPUT_LIMITS.query + 1) })).toMatch(/query/);
    expect(validateToolArguments({ id: "/x/" + "a".repeat(INPUT_LIMITS.id) })).toMatch(/id/);
    expect(validateToolArguments({ version: "1".repeat(INPUT_LIMITS.string + 1) })).toMatch(/version/);
    expect(validateToolArguments({ sources: new Array(INPUT_LIMITS.arrayItems + 1).fill("x") })).toMatch(/too many/);
    expect(validateToolArguments({ sources: [{ a: 1 }] })).toMatch(/scalar/);
    expect(validateToolArguments({ query: { $ne: 1 } })).toMatch(/object/);
    expect(validateToolArguments("query")).toMatch(/object/);
  });
});

// ---------------------------------------------------------------------------
// End-to-end against the compiled servers (npm run build:tsc runs first in the
// package scripts). No index or network access is needed for these checks.
// ---------------------------------------------------------------------------

const STREAMABLE = "dist/src/streamable-http-server.js";
const LEGACY = "dist/src/http-server.js";
const haveBuild = existsSync(STREAMABLE) && existsSync(LEGACY);

async function waitFor(url: string, timeoutMs = 20_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.status > 0) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`server did not start: ${url}`);
}

const INIT = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "t", version: "1" } },
});
const MCP_HEADERS = { "content-type": "application/json", accept: "application/json, text/event-stream" };

describe.skipIf(!haveBuild)("streamable HTTP server hardening (e2e)", () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const base = `http://127.0.0.1:${port}`;
  let child: ChildProcess;

  beforeAll(async () => {
    child = spawn(process.execPath, [STREAMABLE], {
      env: { ...process.env, PORT: String(port), MCP_HOST: "127.0.0.1", MCP_MAX_BODY_BYTES: "20000" },
      stdio: "ignore",
    });
    await waitFor(`${base}/health`);
  }, 30_000);

  afterAll(() => {
    child?.kill("SIGTERM");
  });

  it("accepts a local initialize request", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: MCP_HEADERS, body: INIT });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("rejects a foreign Origin (DNS rebinding) and does not reflect CORS", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, origin: "http://attacker.example" }, body: INIT });
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("reflects CORS only for loopback origins", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: { ...MCP_HEADERS, origin: "http://localhost:6274" }, body: INIT });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:6274");
  });

  it("rejects oversized bodies with 413 and no stack trace", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: MCP_HEADERS, body: JSON.stringify({ x: "a".repeat(30_000) }) });
    expect(res.status).toBe(413);
    const text = await res.text();
    expect(text).not.toMatch(/at .*\.js:\d+/);
  });

  it("rejects oversized tool arguments", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fetch", arguments: { id: "/" + "a".repeat(5000) } } });
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: MCP_HEADERS, body });
    const text = await res.text();
    expect(text).toContain("too long");
    expect(text).toContain("isError");
  });
});

describe.skipIf(!haveBuild)("legacy HTTP server hardening (e2e)", () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const base = `http://127.0.0.1:${port}`;
  let child: ChildProcess;

  beforeAll(async () => {
    child = spawn(process.execPath, [LEGACY], {
      env: { ...process.env, PORT: String(port), MCP_MAX_BODY_BYTES: "1000" },
      stdio: "ignore",
    });
    await waitFor(`${base}/healthz`);
  }, 30_000);

  afterAll(() => {
    child?.kill("SIGINT");
  });

  it("does not send a wildcard CORS header", async () => {
    const res = await fetch(`${base}/healthz`, { headers: { origin: "http://localhost:3000" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:3000");
    const foreign = await fetch(`${base}/healthz`, { headers: { origin: "http://attacker.example" } });
    expect(foreign.status).toBe(403);
  });

  it("limits the request body", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ content: "a".repeat(5000) }) });
    expect(res.status).toBe(413);
  });
});
