// Build pipeline step 4 (optional): passage-level index of the FULL text of every document.
//
// The document-level FTS index (build-fts.ts) only covers title, description and keywords, so text
// that appears further down a page (a property default, a parameter, a restriction) cannot be found.
// This step reads the same file that `fetch` returns, splits it into heading-aware passages of about
// PASSAGE_CHARS characters (long documents are NOT truncated) and stores them in
// dist/data/passages.sqlite with an FTS5 (BM25, Porter stemming) index.
//
// Dense vectors for the passages are built separately by build-passage-embeddings.ts and kept in
// another file so rebuilding passages never throws away embedding work.
import fs from "fs";
import path from "path";
import crypto from "crypto";
import Database from "better-sqlite3";
import { getAllowedSources, getVariantName } from "../src/lib/variant.js";
import { getSourcePath } from "../src/lib/metadata.js";
import { PASSAGES_SCHEMA, PASSAGE_CHARS, passageEmbedText } from "../src/lib/passages.js";

type Doc = { id: string; title?: string; relFile: string; type?: string };
type LibraryBundle = { id: string; docs: Doc[] };

const DATA_DIR = path.join(process.cwd(), "dist", "data");
const SRC = path.join(DATA_DIR, "index.json");
const DST = path.join(DATA_DIR, "passages.sqlite");

/** Remove a leading YAML front matter block and markdown link targets; keep the readable text. */
export function cleanText(raw: string, isCode: boolean): string {
  let t = raw.replace(/\r\n/g, "\n");
  t = t.replace(/^---\n[\s\S]*?\n---\n/, "");
  if (isCode) {
    // JSDoc: drop the leading " * " of comment lines so the prose reads normally.
    t = t.replace(/^\s*\/?\*+\/?\s?/gm, "");
  }
  t = t.replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1");     // images → alt text
  t = t.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");       // links → link text
  t = t.replace(/<[^>\n]{1,200}>/g, " ");                // inline html tags
  t = t.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n");
  return t.trim();
}

type Passage = { heading: string; text: string };

/** Split on markdown headings, then pack paragraphs into windows of at most PASSAGE_CHARS characters. */
export function splitPassages(text: string, maxChars = PASSAGE_CHARS): Passage[] {
  const out: Passage[] = [];
  const lines = text.split("\n");
  let heading = "";
  let buf: string[] = [];
  let inFence = false;

  const flushSection = () => {
    const body = buf.join("\n").trim();
    buf = [];
    if (!body) return;
    const paras = body.split(/\n\s*\n/);
    let cur = "";
    const push = () => { if (cur.trim()) out.push({ heading, text: cur.trim() }); cur = ""; };
    for (let p of paras) {
      // Hard-split paragraphs that alone exceed the window (code blocks, tables, long lists).
      while (p.length > maxChars) {
        let cut = p.lastIndexOf("\n", maxChars);
        if (cut < maxChars * 0.5) cut = p.lastIndexOf(" ", maxChars);
        if (cut < maxChars * 0.5) cut = maxChars;
        if (cur) push();
        out.push({ heading, text: p.slice(0, cut).trim() });
        p = p.slice(cut);
      }
      if (cur.length + p.length + 2 > maxChars) push();
      cur += (cur ? "\n\n" : "") + p;
    }
    push();
  };

  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    const m = !inFence && line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (m) {
      flushSection();
      heading = m[2].trim();
      continue;
    }
    buf.push(line);
  }
  flushSection();
  return out;
}

function main() {
  if (!fs.existsSync(SRC)) throw new Error(`Missing ${SRC}. Run npm run build:index first.`);
  const raw = JSON.parse(fs.readFileSync(SRC, "utf8")) as Record<string, LibraryBundle>;
  const allowed = new Set(getAllowedSources());
  console.log(`Using MCP variant ${getVariantName()} with ${allowed.size} allowed library IDs.`);

  for (const suffix of ["", "-shm", "-wal"]) {
    if (fs.existsSync(DST + suffix)) fs.unlinkSync(DST + suffix);
  }
  const db = new Database(DST);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.exec(PASSAGES_SCHEMA);

  const ins = db.prepare(
    "INSERT INTO passages (pid, doc_id, library_id, title, heading, body, hash, tier) VALUES (?,?,?,?,?,?,?,?)"
  );
  const insFts = db.prepare("INSERT INTO passages_fts (rowid, title, heading, body) VALUES (?,?,?,?)");

  let pid = 0, docs = 0, chars = 0, missing = 0;
  const tx = db.transaction(() => {
    for (const lib of Object.values(raw)) {
      if (!allowed.has(lib.id)) continue;
      const sourcePath = getSourcePath(lib.id);
      if (!sourcePath) continue;
      for (const d of lib.docs) {
        // Sections share their parent's file; index each file once under the parent id.
        if (d.type === "markdown-section") continue;
        const abs = path.join(process.cwd(), "sources", sourcePath, d.relFile);
        let content: string;
        try {
          content = fs.readFileSync(abs, "utf8");
        } catch {
          missing++;
          continue;
        }
        const isCode = /\.(js|ts|json|xml|cds|abap|txt)$/i.test(d.relFile) && !/\.md$/i.test(d.relFile);
        const text = cleanText(content, isCode);
        const title = d.title || d.id;
        docs++;
        const seenHeadings = new Set<string>();
        let first = true;
        for (const p of splitPassages(text)) {
          pid++;
          chars += p.text.length;
          const hash = crypto.createHash("sha1").update(passageEmbedText(title, p.heading, p.text)).digest("hex");
          // Code samples are embedded last (tier 3): natural-language embedders do little for them.
          const tier = d.type === "sample" ? 3 : first ? 1 : seenHeadings.has(p.heading) ? 3 : 2;
          first = false;
          seenHeadings.add(p.heading);
          ins.run(pid, d.id, lib.id, title, p.heading, p.text, hash, tier);
          insFts.run(pid, title, p.heading, p.text);
        }
      }
    }
  });
  tx();
  db.exec("INSERT INTO passages_fts(passages_fts) VALUES('optimize')");
  db.close();
  console.log(`✅ Passages: ${pid} from ${docs} documents (${(chars / 1e6).toFixed(1)} MB of text, ${missing} missing files)`);
  console.log(`   💾 ${DST} (${(fs.statSync(DST).size / 1024 / 1024).toFixed(1)} MB)`);
}

import { pathToFileURL } from "url";
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
