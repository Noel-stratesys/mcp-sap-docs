import { describe, it, expect, afterEach } from 'vitest';
import safeMatter, { frontMatterLanguage } from '../scripts/safe-matter.js';
import runtimeMatter from '../src/lib/safeMatter.js';
import { parseFrontmatter } from '../src/lib/url-generation/utils.js';

const g = globalThis as any;

describe('safe-matter', () => {
  afterEach(() => { delete g.__pwned; });

  it('parses YAML front matter normally', () => {
    const parsed = safeMatter('---\ntitle: Hello\ntags: [a, b]\n---\n# Body\n');
    expect(parsed.data).toEqual({ title: 'Hello', tags: ['a', 'b'] });
    expect(parsed.content).toBe('# Body\n');
  });

  it('parses JSON front matter and documents without front matter', () => {
    expect(safeMatter('---json\n{"title": "J"}\n---\nx').data).toEqual({ title: 'J' });
    expect(safeMatter('# Just markdown').content).toBe('# Just markdown');
    expect(safeMatter('').data).toEqual({});
  });

  for (const lang of ['js', 'javascript', 'JavaScript', ' js ', 'coffee', 'cson', 'toString', '__proto__']) {
    it(`rejects ---${lang} front matter without executing it`, () => {
      const doc = `---${lang}\n{ title: (globalThis.__pwned = true, "x") }\n---\nbody`;
      expect(() => safeMatter(doc)).toThrow(/not allowed/);
      expect(() => runtimeMatter(doc)).toThrow(/not allowed/);
      expect(g.__pwned).toBeUndefined();
    });
  }

  it('rejects executable front matter behind a BOM and with CRLF line endings', () => {
    const doc = '﻿---js\r\n{ title: (globalThis.__pwned = true, "x") }\r\n---\r\nbody';
    expect(frontMatterLanguage(doc)).toBe('js');
    expect(() => safeMatter(doc)).toThrow(/not allowed/);
    expect(g.__pwned).toBeUndefined();
  });

  it('runtime URL helper returns empty front matter instead of evaluating', () => {
    const doc = '---javascript\n{ id: (globalThis.__pwned = true, "x") }\n---\nbody';
    expect(parseFrontmatter(doc)).toEqual({});
    expect(g.__pwned).toBeUndefined();
  });

  it('stringify still produces YAML front matter', () => {
    const out = safeMatter.stringify('Body', { title: 'T' });
    expect(safeMatter(out).data).toEqual({ title: 'T' });
  });
});
