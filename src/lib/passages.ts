// Passage-level retrieval over the full text of every offline document.
//
// Built by scripts/build-passages.ts (BM25/FTS5 over heading-aware passages) and, optionally,
// scripts/build-passage-embeddings.ts (dense vectors from any OpenAI-compatible /v1/embeddings or
// Ollama /api/embed endpoint, e.g. a multilingual model, so Spanish or German questions also match
// English documentation). search.ts fuses both legs with the existing document-level ranking.
import fs from "fs";
import path from "path";
import Database from "better-sqlite3";

export const PASSAGE_CHARS = 1000;
/** Characters of a passage body that are embedded (with title and heading); keeps embedding cheap on CPU. */
export const DENSE_CHARS = 600;

export const PASSAGES_DB = path.join(process.cwd(), "dist", "data", "passages.sqlite");
export const PASSAGE_VECTORS_DB = path.join(process.cwd(), "dist", "data", "passage-vectors.sqlite");

export const PASSAGES_SCHEMA = `
  CREATE TABLE passages (
    pid        INTEGER PRIMARY KEY,
    doc_id     TEXT NOT NULL,
    library_id TEXT NOT NULL,
    title      TEXT,
    heading    TEXT,
    body       TEXT NOT NULL,
    hash       TEXT NOT NULL,   -- sha1 of denseText(): key into passage-vectors.sqlite
    tier       INTEGER NOT NULL -- embedding priority: 1 first passage of a document, 2 first of a section, 3 rest
  );
  CREATE INDEX passages_doc ON passages(doc_id);
  CREATE VIRTUAL TABLE passages_fts USING fts5(
    title, heading, body,
    content='',
    tokenize = 'porter unicode61'
  );
`;

/** Text that is embedded for a passage (the model-specific prefix is added by the embedder). */
export function passageEmbedText(title: string, heading: string, body: string): string {
  const head = heading && heading !== title ? `${title} — ${heading}` : title;
  return `${head}\n${body.slice(0, DENSE_CHARS)}`;
}

// ---------------------------------------------------------------------------------------------
// Configuration (environment)
// ---------------------------------------------------------------------------------------------

export const PASSAGE_CONFIG = {
  /** "off" disables the passage legs entirely (original ranking only). */
  ENABLED: (process.env.PASSAGE_SEARCH || "on").toLowerCase() !== "off",
  /** Embedding endpoint for queries; must be the same model that built the vectors. */
  EMBED_URL: process.env.PASSAGE_EMBED_URL || "http://127.0.0.1:8099/v1/embeddings",
  EMBED_MODEL: process.env.PASSAGE_EMBED_MODEL || "multilingual-e5-small",
  QUERY_PREFIX: process.env.PASSAGE_EMBED_QUERY_PREFIX ?? "query: ",
  DOC_PREFIX: process.env.PASSAGE_EMBED_DOC_PREFIX ?? "passage: ",
  EMBED_TIMEOUT_MS: Number(process.env.PASSAGE_EMBED_TIMEOUT_MS || 8000),
  /** RRF weights of the three offline legs. */
  W_DOC: Number(process.env.PASSAGE_W_DOC ?? 1.0),
  W_LEX: Number(process.env.PASSAGE_W_LEX ?? 1.0),
  W_DENSE: Number(process.env.PASSAGE_W_DENSE ?? 1.0),
  /** Identifier-only BM25 leg (technical names of the query, ignoring natural-language words). */
  W_ID: Number(process.env.PASSAGE_W_ID ?? 1.0),
  LEX_LIMIT: Number(process.env.PASSAGE_LEX_LIMIT || 600),
  /** Use vectors of passages up to this tier only (1 = first passage of each document, 2 = + sections, 3 = all). */
  DENSE_MAX_TIER: Number(process.env.PASSAGE_DENSE_MAX_TIER || 3),
  DENSE_LIMIT: Number(process.env.PASSAGE_DENSE_LIMIT || 600),
};

// ---------------------------------------------------------------------------------------------
// Lexical leg
// ---------------------------------------------------------------------------------------------

// English + Spanish function words (questions arrive in both languages). Technical words stay.
const STOPWORDS = new Set(`
a an the to in on for and or of with from by at as is are was were be been being it its this that these those
how what why when where which who whom does do did can could should would will shall may might must not no
i you he she we they me my your our their there here than then so if but also into about over under via
use using used get set make want need example examples way ways between without within more most other
cuál cuáles qué que cómo como cuándo cuando dónde donde quién quiénes por para con sin sobre entre desde hasta
el la los las un una unos unas lo al del de y o u e ni pero sino si no sí ya es son ser está están estar
hay hace hacer puede pueden debo debe deben se le les su sus mi mis tu tus nos este esta estos estas ese esa
esos esas eso esto aquello cual cada todo todos toda todas muy más menos tiene tienen tener usar uso usa
cuál otra otro otros otras mismo misma algún alguna alguno ningún ninguna también solo sólo según quiero
necesito existe existen hay forma manera modo debería deberían habría sería
`.split(/\s+/).filter(Boolean));

const words = (s: string) => s.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
const stripPunct = (t: string) => t.replace(/^[^\p{L}\p{N}@]+/u, "").replace(/[^\p{L}\p{N}]+$/u, "");
const isUpperKeyword = (t: string) => /^[A-Z][A-Z0-9_-]*$/.test(t) && t.length >= 2;

/**
 * Technical identifiers of a query, as FTS5 phrases. Language-independent, so they carry Spanish or
 * German questions as well: runs of upper-case keywords ("FOR ALL ENTRIES", "WITH AUTO COMMIT"),
 * dotted/underscored/hyphenated names (sap.m.Table, CX_STATIC_CHECK, MOVE-CORRESPONDING, json_parse),
 * camelCase names (growingThreshold), annotations (@UI.lineItem) and upper-case acronyms (RAP, CDS).
 */
export function identifierClauses(query: string): string[] {
  // Punctuation-only tokens ("...", "/") end a keyword run but are not identifiers themselves.
  const toks = query.split(/\s+/).map(stripPunct);
  const out = new Set<string>();
  let run: string[] = [];
  const flush = () => {
    if (run.length >= 2) out.add(`"${run.flatMap(words).join(" ")}"`);
    run = [];
  };
  for (const t of toks) {
    if (isUpperKeyword(t)) run.push(t); else flush();
    if (!t) continue;
    const parts = words(t);
    if (!parts.length) continue;
    const isIdent = /[a-z][A-Z]/.test(t) || /[._\-@/]/.test(t.slice(1)) || t.startsWith("@") ||
      (isUpperKeyword(t) && !STOPWORDS.has(parts.join(""))) || (/\d/.test(t) && /\p{L}/u.test(t));
    if (isIdent) out.add(`"${parts.join(" ")}"`);
  }
  flush();
  return [...out];
}

/** FTS5 MATCH expression: OR of content words, plus the identifier phrases above. */
export function toPassageMatch(query: string): string {
  const clauses = new Set<string>(identifierClauses(query));
  for (const tok of query.split(/\s+/)) {
    for (const p of words(tok)) {
      if (STOPWORDS.has(p)) continue;
      if (p.length < 2 && !/\d/.test(p)) continue;
      clauses.add(`"${p}"`);
    }
  }
  return [...clauses].slice(0, 64).join(" OR ");
}

let pdb: Database.Database | null = null;
let pdbChecked = false;

export function openPassagesDb(): Database.Database | null {
  if (pdbChecked) return pdb;
  pdbChecked = true;
  if (!PASSAGE_CONFIG.ENABLED || !fs.existsSync(PASSAGES_DB)) return null;
  pdb = new Database(PASSAGES_DB, { readonly: true, fileMustExist: true });
  pdb.pragma("query_only = ON");
  pdb.pragma("cache_size = -64000");
  return pdb;
}

export type PassageHit = {
  pid: number;
  docId: string;
  libraryId: string;
  title: string;
  heading: string;
  body: string;
  score: number;
};

const passageRowStmtCache = new Map<string, Database.Statement>();
function stmt(db: Database.Database, sql: string): Database.Statement {
  let s = passageRowStmtCache.get(sql);
  if (!s) { s = db.prepare(sql); passageRowStmtCache.set(sql, s); }
  return s;
}

export function searchPassagesLexical(query: string, limit = PASSAGE_CONFIG.LEX_LIMIT, match = toPassageMatch(query)): PassageHit[] {
  const db = openPassagesDb();
  if (!db) return [];
  if (!match) return [];
  try {
    const rows = stmt(db, `
      SELECT p.pid, p.doc_id, p.library_id, p.title, p.heading, p.body, f.score
      FROM (SELECT rowid, bm25(passages_fts, 2.0, 3.0, 1.0) AS score
            FROM passages_fts WHERE passages_fts MATCH ? ORDER BY score LIMIT ?) f
      JOIN passages p ON p.pid = f.rowid
      ORDER BY f.score`).all(match, limit) as any[];
    return rows.map(r => ({
      pid: r.pid, docId: r.doc_id, libraryId: r.library_id, title: r.title,
      heading: r.heading, body: r.body, score: -Number(r.score),
    }));
  } catch (error) {
    console.warn("Passage FTS query failed:", error);
    return [];
  }
}

export function getPassages(pids: number[]): Map<number, PassageHit> {
  const db = openPassagesDb();
  const out = new Map<number, PassageHit>();
  if (!db || !pids.length) return out;
  const s = stmt(db, "SELECT pid, doc_id, library_id, title, heading, body FROM passages WHERE pid = ?");
  for (const pid of pids) {
    const r = s.get(pid) as any;
    if (r) out.set(pid, { pid: r.pid, docId: r.doc_id, libraryId: r.library_id, title: r.title, heading: r.heading, body: r.body, score: 0 });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Dense leg
// ---------------------------------------------------------------------------------------------

type VectorIndex = { pids: Int32Array; mat: Float32Array; dim: number; model: string };
let vindex: VectorIndex | null = null;
let vindexChecked = false;

/** Load every passage vector of the configured model into memory (L2-normalised, cosine = dot). */
export function loadPassageVectors(): VectorIndex | null {
  if (vindexChecked) return vindex;
  vindexChecked = true;
  const db = openPassagesDb();
  if (!db || !fs.existsSync(PASSAGE_VECTORS_DB)) return null;
  const t0 = Date.now();
  const vdb = new Database(PASSAGE_VECTORS_DB, { readonly: true, fileMustExist: true });
  const vec = vdb.prepare("SELECT vec FROM vectors WHERE hash = ? AND model = ?");
  const rows = db.prepare("SELECT pid, hash FROM passages WHERE tier <= ? ORDER BY pid").all(PASSAGE_CONFIG.DENSE_MAX_TIER) as { pid: number; hash: string }[];
  const pids: number[] = [];
  const chunks: Float32Array[] = [];
  let dim = 0;
  for (const r of rows) {
    const v = vec.get(r.hash, PASSAGE_CONFIG.EMBED_MODEL) as { vec: Buffer } | undefined;
    if (!v) continue;
    const f = new Float32Array(v.vec.buffer.slice(v.vec.byteOffset, v.vec.byteOffset + v.vec.byteLength));
    dim = f.length;
    pids.push(r.pid);
    chunks.push(f);
  }
  vdb.close();
  if (!pids.length) {
    console.warn(`🧠 [PASSAGES] No vectors for model ${PASSAGE_CONFIG.EMBED_MODEL}; dense leg disabled.`);
    return null;
  }
  const mat = new Float32Array(pids.length * dim);
  chunks.forEach((c, i) => mat.set(c, i * dim));
  vindex = { pids: Int32Array.from(pids), mat, dim, model: PASSAGE_CONFIG.EMBED_MODEL };
  console.log(`🧠 [PASSAGES] Loaded ${pids.length}/${rows.length} passage vectors (dim ${dim}) in ${Date.now() - t0}ms`);
  return vindex;
}

function l2(v: Float32Array): Float32Array {
  let n = 0;
  for (const x of v) n += x * x;
  n = Math.sqrt(n) || 1;
  for (let i = 0; i < v.length; i++) v[i] /= n;
  return v;
}

/** Embed texts with the configured endpoint (OpenAI-compatible /v1/embeddings or Ollama /api/embed). */
export async function embedTexts(texts: string[], timeoutMs = PASSAGE_CONFIG.EMBED_TIMEOUT_MS): Promise<Float32Array[]> {
  const url = PASSAGE_CONFIG.EMBED_URL;
  const ollama = /\/api\/embed\/?$/.test(url);
  const body = { model: PASSAGE_CONFIG.EMBED_MODEL, input: texts };
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`embedding endpoint ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const json = await res.json() as any;
  const vecs: number[][] = ollama ? json.embeddings : json.data.map((d: any) => d.embedding);
  return vecs.map(v => l2(Float32Array.from(v)));
}

export type DenseHit = { pid: number; score: number };

export async function searchPassagesDense(query: string, limit = PASSAGE_CONFIG.DENSE_LIMIT): Promise<DenseHit[]> {
  const idx = loadPassageVectors();
  if (!idx) return [];
  let q: Float32Array;
  try {
    [q] = await embedTexts([PASSAGE_CONFIG.QUERY_PREFIX + query]);
  } catch (error: any) {
    console.warn(`🧠 [PASSAGES] Query embedding failed (${error?.message || error}); dense leg skipped.`);
    return [];
  }
  if (q.length !== idx.dim) {
    console.warn(`🧠 [PASSAGES] Query dim ${q.length} != index dim ${idx.dim}; dense leg skipped.`);
    return [];
  }
  const { mat, dim, pids } = idx;
  const n = pids.length;
  // Keep the top `limit` scores with a simple threshold heap (n ~ 1e5, fast enough in JS).
  const scores = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    let s = 0;
    const off = i * dim;
    for (let j = 0; j < dim; j++) s += mat[off + j] * q[j];
    scores[i] = s;
  }
  const order = Array.from({ length: n }, (_, i) => i);
  order.sort((a, b) => scores[b] - scores[a]);
  return order.slice(0, limit).map(i => ({ pid: pids[i], score: scores[i] }));
}
