// Timeline page, slice 1. All text from the session goes through textContent; no HTML strings.
const LAYERS = ['dns', 'tcp', 'tls', 'http'];
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

async function main() {
  const response = await fetch('timeline.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`timeline.json: HTTP ${response.status}`);
  const view = await response.json();
  const list = document.getElementById('events');
  renderStats(view);
  renderFilters(list);
  list.append(...view.events.map((e) => row(e, view.durationMs)));
}

main().catch((err) => {
  const box = document.getElementById('error');
  box.textContent = `Не удалось загрузить шкалу: ${err.message}`;
  box.hidden = false;
});
