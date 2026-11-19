/**
 * Front-matter parsing for the build scripts. Rejects executable front-matter
 * engines (`---js`, `---javascript`, coffee) so indexing third-party Markdown
 * cannot run code. Implementation shared with the runtime in src/lib/safeMatter.ts.
 */
export { safeMatter, frontMatterLanguage } from '../src/lib/safeMatter.js';
export { default } from '../src/lib/safeMatter.js';
