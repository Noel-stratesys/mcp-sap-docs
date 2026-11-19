import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { assertInsideRoot, isPathInside } from "../src/lib/sourceContent.js";
import { getCommunityPostsByIds } from "../src/lib/communityBestMatch.js";

describe("corpus path containment", () => {
  const base = mkdtempSync(path.join(tmpdir(), "mcp-path-safety-"));
  const root = path.join(base, "sources");
  mkdirSync(path.join(root, "repo", "docs"), { recursive: true });
  mkdirSync(path.join(base, "private"), { recursive: true });
  writeFileSync(path.join(root, "repo", "docs", "ok.md"), "# ok");
  writeFileSync(path.join(root, "repo", "README.md"), "# readme");
  writeFileSync(path.join(base, "private", "id_rsa"), "SECRET");
  symlinkSync(path.join(base, "private", "id_rsa"), path.join(root, "repo", "docs", "leak.md"));
  symlinkSync(path.join(base, "private"), path.join(root, "repo", "docs", "linkdir"));
  symlinkSync(path.join(root, "repo", "README.md"), path.join(root, "repo", "docs", "internal.md"));

  afterEach(() => vi.unstubAllGlobals());

  it("allows regular files and symlinks that stay inside the root", () => {
    expect(assertInsideRoot(path.join(root, "repo", "docs", "ok.md"), root)).toContain("ok.md");
    expect(assertInsideRoot(path.join(root, "repo", "docs", "internal.md"), root)).toContain("README.md");
  });

  it("rejects ../ traversal and symlinks that escape the root", () => {
    expect(() => assertInsideRoot(path.join(root, "repo", "docs", "..", "..", "..", "private", "id_rsa"), root)).toThrow(/outside/);
    expect(() => assertInsideRoot(path.join(root, "repo", "docs", "leak.md"), root)).toThrow(/outside/);
    expect(() => assertInsideRoot(path.join(root, "repo", "docs", "linkdir", "id_rsa"), root)).toThrow(/outside/);
  });

  it("isPathInside handles prefixes correctly", () => {
    expect(isPathInside("/a/sources", "/a/sources/x")).toBe(true);
    expect(isPathInside("/a/sources", "/a/sources-evil/x")).toBe(false);
    expect(isPathInside("/a/sources", "/a")).toBe(false);
  });

  it("cleanup", () => {
    rmSync(base, { recursive: true, force: true });
  });
});

describe("SAP Community post ids", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("never pastes non-numeric ids into the LiQL query", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await getCommunityPostsByIds(["1') OR id > ('0", "abc"]);
    expect(result).toEqual({});
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still queries numeric ids", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(decodeURIComponent(url)).toContain("where id in ('123')");
      return new Response(JSON.stringify({ status: "success", data: { items: [] } }), { headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);
    await getCommunityPostsByIds(["123", "x'y"]);
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
