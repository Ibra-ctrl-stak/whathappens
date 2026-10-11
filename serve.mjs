// Show a recorded session's timeline on a local page.
// Usage: node serve.mjs [session.json]   (default: out/session.json). Stop with Ctrl+C.
import { readFile } from 'node:fs/promises';
import { loadSession } from './src/session.js';
import { buildTimeline } from './src/timeline.js';
import { timelineView } from './src/server/view-model.js';
import { startServer } from './src/server/server.js';

const path = process.argv[2] ?? new URL('./out/session.json', import.meta.url);
const timeline = buildTimeline(loadSession(JSON.parse(await readFile(path, 'utf8'))));
const server = await startServer({ view: timelineView(timeline) });

console.log(`whathappens: ${timeline.events.length} events`);
console.log(`open ${server.url}`);
console.log('(local only; the address contains a one-time token — Ctrl+C to stop)');

process.once('SIGINT', () => {
  server.close();
  process.exit(0);
});
