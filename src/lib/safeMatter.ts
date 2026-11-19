/**
 * Safe wrapper around gray-matter.
 *
 * gray-matter selects the front-matter engine from the text right after the
 * opening delimiter. `---js` / `---javascript` front matter is evaluated with
 * eval(), so parsing an untrusted Markdown file (external git repositories,
 * downloaded pages) could execute arbitrary code. This wrapper only allows the
 * data-only engines (YAML and JSON) and throws for anything else.
 */
import matter from 'gray-matter';

const ALLOWED_LANGUAGES = new Set(['', 'yaml', 'yml', 'json']);

function rejectEngine(name: string) {
  return () => {
    throw new Error(`Front matter engine "${name}" is not allowed`);
  };
}

const SAFE_OPTIONS = {
  // Defence in depth: even if detection below were bypassed, the code engines
  // are replaced by functions that throw instead of evaluating.
  engines: {
    javascript: rejectEngine('javascript'),
    js: rejectEngine('js'),
    coffee: rejectEngine('coffee'),
    coffeescript: rejectEngine('coffeescript'),
    cson: rejectEngine('cson'),
  },
};

/** Returns the front-matter language declared after the opening `---`, as gray-matter sees it. */
export function frontMatterLanguage(input: string): string {
  const str = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  if (!str.startsWith('---') || str.charAt(3) === '-') return '';
  const rest = str.slice(3);
  return rest.slice(0, rest.search(/\r?\n/)).trim().toLowerCase();
}

/** Parse front matter, throwing for any engine other than YAML/JSON. */
export function safeMatter(input: string): matter.GrayMatterFile<string> {
  const text = String(input);
  const language = frontMatterLanguage(text);
  if (!ALLOWED_LANGUAGES.has(language)) {
    throw new Error(`Front matter engine "${language}" is not allowed`);
  }
  // Passing options also bypasses gray-matter's global cache.
  return matter(text, SAFE_OPTIONS as any);
}

/** Serialise front matter (YAML, js-yaml safeDump). */
safeMatter.stringify = (content: string, data: object): string => matter.stringify(content, data);

export default safeMatter;
