// Timeline page: event list (slice 1) + hex panel of the selected event (slice 2).
// All text from the session goes through textContent; no HTML strings.
import { hexRows, BYTES_PER_ROW } from './hex.js';

const LAYERS = ['dns', 'tcp', 'tls', 'http'];
const HALF_ROW = BYTES_PER_ROW / 2;
const ARROWS = { out: '→', in: '←' };
const LAYER_TITLES = { dns: 'DNS', tcp: 'TCP', tls: 'TLS', http: 'HTTP' };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const formatMs = (t) => `${t.toFixed(1)} мс`;
const formatRange = (e) => (e.buffer ? `${e.buffer} [${e.offset}, ${e.length}]` : 'байтов нет');

function renderStats(view) {
  const damaged = view.events.filter((e) => e.damaged).length;
  const parts = [`${view.events.length} событий`, `${formatMs(view.durationMs)} от первого DNS-запроса`];
  if (damaged > 0) parts.push(`повреждено: ${damaged}`);
  document.getElementById('stats').textContent = parts.join(' · ');
}

function renderFilters(list) {
  const box = document.getElementById('filters');
  for (const layer of LAYERS) {
    const label = el('label', `chip layer-${layer}`);
    const input = el('input');
    input.type = 'checkbox';
    input.checked = true;
    input.addEventListener('change', () => list.classList.toggle(`hide-${layer}`, !input.checked));
    label.append(input, ` ${LAYER_TITLES[layer]}`);
    box.append(label);
  }
}

function timeBar(e, durationMs) {
  const track = el('span', 'track');
  const dot = el('span', 'dot');
  dot.style.left = `${durationMs > 0 ? (e.t / durationMs) * 100 : 0}%`; // CSSOM, allowed by the CSP
  track.append(dot);
  return track;
}

function row(e, durationMs) {
  const item = el('li', `event layer-${e.layer}${e.damaged ? ' damaged' : ''}`);
  item.dataset.layer = e.layer;
  const what = el('span', 'what');
  what.append(el('span', 'summary', e.summary));
  if (e.damaged) what.append(el('span', 'problem', `повреждено: ${e.problem}`));
  item.append(
    el('span', 'time', formatMs(e.t)),
    timeBar(e, durationMs),
    el('span', 'chip', LAYER_TITLES[e.layer]),
    el('span', 'dir', ARROWS[e.dir] ?? '·'),
    el('span', 'kind', e.kind),
    what,
    el('span', 'range', formatRange(e)),
  );
  return item;
}

// ---- hex panel -------------------------------------------------------------------------------

const hexLine = (r) => {
  const line = el('div', 'hex-row');
  const bytes = [r.hex.slice(0, HALF_ROW).join(' '), r.hex.slice(HALF_ROW).join(' ')].filter(Boolean).join('  ');
  line.append(el('span', 'hex-offset', r.offset), el('span', 'hex-bytes', bytes), el('span', 'hex-ascii', r.ascii));
  return line;
};

function showHex(e, bytes) {
  const panel = document.getElementById('hex');
  const title = el('h2', 'hex-title', e.summary);
  const meta = el('p', 'hex-meta', `${formatRange(e)} · ${e.layer.toUpperCase()} ${e.kind}`);
  if (!bytes) {
    panel.replaceChildren(title, meta, el('p', 'hex-hint', 'У этого события нет записанных байтов (например, SYN/ACK делает ОС, Node их не видит).'));
    return;
  }
  const dump = el('div', 'hex-dump');
  dump.append(...hexRows(bytes, e.offset).map(hexLine));
  panel.replaceChildren(title, meta, dump);
}

let latestRequest = 0;

async function select(index, e, item) {
  document.querySelector('.event[aria-current="true"]')?.removeAttribute('aria-current');
  item.setAttribute('aria-current', 'true');
  const request = ++latestRequest;
  let bytes = null;
  if (e.buffer !== null) {
    const response = await fetch(`events/${index}/bytes`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`bytes of event ${index}: HTTP ${response.status}`);
    bytes = new Uint8Array(await response.arrayBuffer());
  }
  if (request === latestRequest) showHex(e, bytes); // a later click won: drop this stale answer
}

function selectable(item, index, e) {
  item.tabIndex = 0;
  const go = () => select(index, e, item).catch(showError);
  item.addEventListener('click', go);
  item.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      go();
    }
  });
  return item;
}

function showError(err) {
  const box = document.getElementById('error');
  box.textContent = `Ошибка: ${err.message}`;
  box.hidden = false;
}

async function main() {
  const response = await fetch('timeline.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`timeline.json: HTTP ${response.status}`);
  const view = await response.json();
  const list = document.getElementById('events');
  renderStats(view);
  renderFilters(list);
  list.append(...view.events.map((e, i) => selectable(row(e, view.durationMs), i, e)));
}

main().catch(showError);
