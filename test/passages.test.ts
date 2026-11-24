import { describe, expect, it } from 'vitest';
import { identifierClauses, toPassageMatch, passageEmbedText, DENSE_CHARS } from '../src/lib/passages.js';
import { splitPassages, cleanText } from '../scripts/build-passages.js';

describe('passage index helpers', () => {
  it('extracts language-independent technical identifiers as phrases', () => {
    const ids = identifierClauses('¿Qué precauciones hay con SELECT ... FOR ALL ENTRIES y json_parse( ) en sap.m.Table con growingThreshold?');
    expect(ids).toContain('"for all entries"');
    expect(ids).toContain('"json parse"');
    expect(ids).toContain('"sap m table"');
    expect(ids).toContain('"growingthreshold"');
  });

  it('drops English and Spanish stopwords from the OR query', () => {
    const match = toPassageMatch('¿Cómo se usa la tabla de usuarios?');
    expect(match).not.toMatch(/"cómo"|"se"|"la"|"de"/);
    expect(match).toContain('"tabla"');
  });

  it('splits on headings and never truncates long documents', () => {
    const body = Array.from({ length: 30 }, (_, i) => `Paragraph ${i} ` + 'x'.repeat(200)).join('\n\n');
    const passages = splitPassages(`# Title\n\nIntro\n\n## Part\n\n${body}`, 1000);
    expect(passages[0]).toEqual({ heading: 'Title', text: 'Intro' });
    expect(passages.every(p => p.text.length <= 1000)).toBe(true);
    expect(passages.map(p => p.text).join(' ')).toContain('Paragraph 29');
  });

  it('removes front matter and link targets', () => {
    expect(cleanText('---\ntitle: x\n---\nSee [the docs](ABEN.html) here', false)).toBe('See the docs here');
  });

  it('embeds title, heading and the start of the body', () => {
    const text = passageEmbedText('Doc', 'Section', 'y'.repeat(5000));
    expect(text.startsWith('Doc — Section\n')).toBe(true);
    expect(text.length).toBe('Doc — Section\n'.length + DENSE_CHARS);
  });
});
