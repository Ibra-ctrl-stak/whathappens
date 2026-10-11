// Print the unified timeline of a recorded session.
// Usage: node timeline.mjs [session.json]   (default: out/session.json)
import { readFile } from 'node:fs/promises';
import { loadSession } from './src/session.js';
import { buildTimeline } from './src/timeline.js';

const path = process.argv[2] ?? new URL('./out/session.json', import.meta.url);
const ARROW = { out: '->', in: '<-' };

const { events } = buildTimeline(loadSession(JSON.parse(await readFile(path, 'utf8'))));
console.log(`${'t, ms'.padStart(9)}  layer  ${'kind'.padEnd(13)} dir  ${'bytes'.padEnd(26)} summary`);
for (const e of events) {
  const range = e.buffer ? `${e.buffer} [${e.offset}, ${e.length}]` : '-';
  console.log(
    `${e.t.toFixed(3).padStart(9)}  ${e.layer.padEnd(5)}  ${e.kind.padEnd(13)} ${(ARROW[e.dir] ?? '  ').padEnd(3)}  ${range.padEnd(26)} ${e.summary}`,
  );
}
