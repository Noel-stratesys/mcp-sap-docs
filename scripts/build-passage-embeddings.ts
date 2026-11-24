// Build pipeline step 5 (optional): dense vectors for passages (see src/lib/passages.ts).
//
// Calls an embedding endpoint (OpenAI-compatible /v1/embeddings, e.g. llama.cpp's llama-server, or
// Ollama's /api/embed) configured with PASSAGE_EMBED_URL / PASSAGE_EMBED_MODEL and the model's
// document prefix (PASSAGE_EMBED_DOC_PREFIX, "passage: " for e5 models).
//
// Vectors are stored in dist/data/passage-vectors.sqlite keyed by (sha1 of the embedded text, model),
// so the job is resumable and rebuilding the passage index reuses every unchanged vector.
// Passages are embedded by tier (1 = first passage of each document, 2 = first passage of each
// section, 3 = the rest); pass --max-tier N to stop after a tier. The server uses whatever vectors
// exist for the configured model.
//
// Usage: node dist/scripts/build-passage-embeddings.js [--max-tier 2] [--batch 32] [--parallel 2]
import Database from "better-sqlite3";
import fs from "fs";
import { PASSAGES_DB, PASSAGE_VECTORS_DB, PASSAGE_CONFIG, embedTexts, passageEmbedText } from "../src/lib/passages.js";

function arg(name: string, def: number): number {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? Number(process.argv[i + 1]) : def;
}

async function main() {
  const maxTier = arg("max-tier", 3);
  const batch = arg("batch", 32);
  const parallel = arg("parallel", 2);
  if (!fs.existsSync(PASSAGES_DB)) throw new Error(`Missing ${PASSAGES_DB}. Run build-passages first.`);

  const pdb = new Database(PASSAGES_DB, { readonly: true });
  const vdb = new Database(PASSAGE_VECTORS_DB);
  vdb.pragma("journal_mode = WAL");
  vdb.exec(`CREATE TABLE IF NOT EXISTS vectors (hash TEXT NOT NULL, model TEXT NOT NULL, vec BLOB NOT NULL, PRIMARY KEY (hash, model))`);
  const have = new Set((vdb.prepare("SELECT hash FROM vectors WHERE model = ?").all(PASSAGE_CONFIG.EMBED_MODEL) as { hash: string }[]).map(r => r.hash));

  const rows = pdb.prepare("SELECT pid, title, heading, body, hash, tier FROM passages WHERE tier <= ? ORDER BY tier, pid").all(maxTier) as any[];
  const todo: { hash: string; text: string }[] = [];
  const queued = new Set<string>();
  for (const r of rows) {
    if (have.has(r.hash) || queued.has(r.hash)) continue;
    queued.add(r.hash);
    todo.push({ hash: r.hash, text: PASSAGE_CONFIG.DOC_PREFIX + passageEmbedText(r.title, r.heading, r.body) });
  }
  console.log(`🧠 Model ${PASSAGE_CONFIG.EMBED_MODEL} at ${PASSAGE_CONFIG.EMBED_URL}: ${have.size} vectors cached, ${todo.length} to embed (tiers ≤ ${maxTier})`);

  const ins = vdb.prepare("INSERT OR REPLACE INTO vectors (hash, model, vec) VALUES (?, ?, ?)");
  const t0 = Date.now();
  let done = 0;
  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const items = todo.slice(next, next + batch);
      next += batch;
      let vecs: Float32Array[] | null = null;
      for (let attempt = 0; attempt < 5 && !vecs; attempt++) {
        try {
          vecs = await embedTexts(items.map(i => i.text), 600_000);
        } catch (error: any) {
          if (/ 400:/.test(String(error?.message))) {
            // An input longer than the model context: embed one by one, shortening the offender.
            vecs = [];
            for (const it of items) {
              let text = it.text;
              for (;;) {
                try { vecs.push((await embedTexts([text], 600_000))[0]); break; } catch (e: any) {
                  if (!/ 400:/.test(String(e?.message)) || text.length < 50) throw e;
                  text = text.slice(0, Math.floor(text.length * 0.7));
                }
              }
            }
            break;
          }
          console.warn(`retry ${attempt + 1}: ${error?.message || error}`);
          await new Promise(r => setTimeout(r, 5000 * (attempt + 1)));
        }
      }
      if (!vecs) throw new Error("embedding endpoint keeps failing");
      vdb.transaction(() => {
        items.forEach((it, i) => ins.run(it.hash, PASSAGE_CONFIG.EMBED_MODEL, Buffer.from(vecs![i].buffer)));
      })();
      done += items.length;
      if (done % (batch * 20) < batch || done === todo.length) {
        const rate = done / ((Date.now() - t0) / 1000);
        console.log(`  ${done}/${todo.length} (${rate.toFixed(1)}/s, ~${((todo.length - done) / rate / 60).toFixed(0)} min left)`);
      }
    }
  };
  await Promise.all(Array.from({ length: parallel }, worker));
  vdb.close();
  console.log(`✅ Embedded ${done} passages in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
}

main().catch(error => { console.error(error); process.exit(1); });
