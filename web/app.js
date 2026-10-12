// Timeline page: event list (slice 1), hex panel of the selected event (slice 2),
// field tree linked to the hex bytes (slice 3).
// All text from the session goes through textContent; no HTML strings.
import { hexRows, BYTES_PER_ROW } from './hex.js';
import { indexTree, ownerOf, ancestors, describe } from './fields.js';

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

// ---- event list ------------------------------------------------------------------------------

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
  what.title = e.summary;
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

// ---- hex dump: one span per byte, in both columns ---------------------------------------------

function hexDump(bytes, baseOffset) {
  const dump = el('div', 'hex-dump');
  const cells = []; // cells[i] = [hexSpan, asciiSpan] for byte i of the event
  for (const r of hexRows(bytes, baseOffset)) {
    const line = el('div', 'hex-row');
    const hexCol = el('span', 'hex-bytes');
    const asciiCol = el('span', 'hex-ascii');
    r.hex.forEach((h, k) => {
      const i = cells.length;
      const hexCell = el('span', 'byte', h);
      const asciiCell = el('span', 'byte', r.ascii[k]);
      hexCell.dataset.i = String(i);
      asciiCell.dataset.i = String(i);
      if (k > 0) hexCol.append(k === HALF_ROW ? '  ' : ' ');
      hexCol.append(hexCell);
      asciiCol.append(asciiCell);
      cells.push([hexCell, asciiCell]);
    });
    line.append(el('span', 'hex-offset', r.offset), hexCol, asciiCol);
    dump.append(line);
  }
  return { dump, cells };
}

// ---- field tree --------------------------------------------------------------------------------

function fieldRow(entry, onSelect) {
  const { node } = entry;
  const line = el('div', `field-row${node.problem ? ' damaged' : ''}`);
  line.tabIndex = 0;
  line.setAttribute('role', 'treeitem');
  const toggle = el('span', 'field-toggle', node.children.length > 0 ? '▾' : ' ');
  line.append(
    toggle,
    el('span', 'field-name', node.name),
    el('span', 'field-value', describe(node)),
    el('span', 'field-range', `[${node.offset}, ${node.length}]`),
  );
  if (node.problem) line.append(el('span', 'problem', `повреждено: ${node.problem}`));
  line.addEventListener('click', (ev) => (ev.target === toggle ? null : onSelect(entry.id)));
  line.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      onSelect(entry.id);
    }
  });
  return { line, toggle };
}

/** Builds the tree; returns { root, rows } where rows[id] = { line, childList }. */
function fieldTree(index, onSelect) {
  const rows = [];
  const childIdsOf = index.nodes.map(() => []);
  for (const n of index.nodes) if (n.parent !== null) childIdsOf[n.parent].push(n.id);
  const build = (id) => {
    const entry = index.nodes[id];
    const item = el('li');
    const { line, toggle } = fieldRow(entry, onSelect);
    item.append(line);
    let childList = null;
    if (entry.node.children.length > 0) {
      childList = el('ul', 'field-children');
      item.append(childList);
      toggle.addEventListener('click', () => {
        childList.hidden = !childList.hidden;
        toggle.textContent = childList.hidden ? '▸' : '▾';
      });
    }
    rows[id] = { line, childList, toggle };
    if (childList) childList.append(...childIdsOf[id].map(build));
    return item;
  };
  const root = el('ul', 'field-tree');
  root.setAttribute('role', 'tree');
  root.append(build(0));
  return { root, rows };
}

// ---- selection: field <-> bytes ---------------------------------------------------------------

// Reveal an item inside one scroller, without moving the page or a sibling pane.
function revealWithin(scroller, node) {
  if (!node) return;
  const box = scroller.getBoundingClientRect();
  const target = node.getBoundingClientRect();
  const top = box.top + scroller.clientTop;
  const left = box.left + scroller.clientLeft;
  if (target.top < top) scroller.scrollTop -= top - target.top;
  else if (target.bottom > top + scroller.clientHeight) scroller.scrollTop += target.bottom - top - scroller.clientHeight;
  if (target.left < left) scroller.scrollLeft -= left - target.left;
  else if (target.right > left + scroller.clientWidth) scroller.scrollLeft += target.right - left - scroller.clientWidth;
}

/**
 * If `node`'s top edge is outside `scroller`'s visible area, scroll once so it sits `margin` px
 * below the top. No-op when already visible, so later manual scrolling is never fought.
 */
function revealTop(scroller, node, margin) {
  if (!node) return;
  const box = scroller.getBoundingClientRect();
  const target = node.getBoundingClientRect();
  const top = box.top + scroller.clientTop;
  const visible = target.top >= top && target.bottom <= top + scroller.clientHeight;
  if (!visible) scroller.scrollTop += target.top - top - margin;
  const left = box.left + scroller.clientLeft;
  if (target.left < left) scroller.scrollLeft -= left - target.left;
  else if (target.right > left + scroller.clientWidth) scroller.scrollLeft += target.right - left - scroller.clientWidth;
}

function linkTreeAndBytes(e, index, tree, cells, dump, viewport) {
  let lit = [];
  let current = null;
  const select = (id, { fromBytes = false } = {}) => {
    lit.forEach((c) => c.classList.remove('hl'));
    current?.classList.remove('selected');
    const { node } = index.nodes[id];
    const start = node.offset - e.offset;
    lit = cells.slice(start, start + node.length).flat();
    lit.forEach((c) => c.classList.add('hl'));
    for (const a of ancestors(index, id).slice(0, -1)) {
      const { childList, toggle } = tree.rows[a.id];
      childList.hidden = false; // reveal the path to the selected field
      toggle.textContent = '▾';
    }
    current = tree.rows[id].line;
    current.classList.add('selected');
    if (fromBytes) {
      revealWithin(tree.root, current.querySelector('.field-name'));
    } else if (lit[0]) {
      // Show where the selection starts: bring the byte viewport into the panel if it is out of
      // sight, then put the first selected byte one row below the viewport's top edge.
      const panel = viewport.closest('.hex-panel');
      if (panel) revealTop(panel, viewport, 8);
      revealTop(viewport, lit[0], lit[0].getBoundingClientRect().height);
    }
  };
  dump.addEventListener('click', (ev) => {
    const cell = ev.target.closest('[data-i]');
    const id = cell ? ownerOf(index, e.offset + Number(cell.dataset.i)) : null;
    if (id !== null) select(id, { fromBytes: true });
  });
  return select;
}

// ---- our own checks (computed results, not network events) ------------------------------------

const CHECK_STATUS = {
  passed: ['✓', 'пройдена'],
  failed: ['✗', 'не пройдена'],
  unavailable: ['?', 'проверить невозможно'],
};
const statusOf = (status) => CHECK_STATUS[status] ?? ['?', 'неизвестный результат'];

function checkItem(c) {
  const [mark, word] = statusOf(c.status);
  const item = el('div', `check check-${c.status}`);
  item.append(el('h3', 'check-title', `${mark} ${c.title}: ${word}`));
  if (c.explanation) item.append(el('p', 'check-text', `Что проверено: ${c.explanation}`));
  if (c.reason) item.append(el('p', 'check-reason', `Причина: ${c.reason}`));
  if (c.steps.length > 0) {
    const list = el('ul', 'check-steps');
    for (const s of c.steps) {
      const step = el('li', `check-${s.status}`, `${statusOf(s.status)[0]} ${s.label}`);
      if (s.reason && s.status !== 'passed') step.append(el('span', 'check-reason', ` — ${s.reason}`));
      list.append(step);
    }
    item.append(list);
  }
  if (c.notCovered.length > 0) item.append(el('p', 'check-text', `Не входит в эту проверку: ${c.notCovered.join('; ')}.`));
  return item;
}

function checksBlock(checks) {
  const box = el('details', 'checks'); // collapsed: the status line is enough until asked for more
  const marks = checks.map((c) => `${statusOf(c.status)[0]} ${c.title} — ${statusOf(c.status)[1]}`).join(' · ');
  box.append(
    el('summary', 'checks-summary', `Проверки: ${marks}`),
    el('p', 'check-note', 'Вычислено по записанным байтам этой сессии. Это не сетевое событие и не результат проверки сертификата, которую Node выполнил при соединении.'),
    ...checks.map(checkItem),
  );
  return box;
}

function showDetail(e, bytes, fields) {
  const panel = document.getElementById('hex');
  const header = el('div', 'detail-header');
  const toolbar = el('div', 'detail-toolbar');
  const space = e.buffer?.startsWith('http-decoded/') ? 'Декодированное тело HTTP · отдельные смещения'
    : e.buffer?.startsWith('tls-hs/') ? 'Собранные сообщения TLS'
    : e.buffer?.startsWith('http/') ? 'Расшифрованный HTTP'
      : e.buffer ? 'Сетевые байты' : 'Событие соединения';
  const expand = el('button', 'detail-expand');
  expand.type = 'button';
  const main = document.querySelector('main');
  const updateExpand = () => {
    const wide = main.classList.contains('detail-wide');
    expand.textContent = wide ? 'Вернуть список' : 'На всю ширину';
    expand.setAttribute('aria-pressed', String(wide));
  };
  expand.addEventListener('click', () => { main.classList.toggle('detail-wide'); updateExpand(); });
  updateExpand();
  toolbar.append(el('span', 'byte-space', space), expand);
  const title = el('h2', 'hex-title', e.summary);
  title.title = e.summary;
  const meta = el('p', 'hex-meta', `${formatRange(e)} · ${e.layer.toUpperCase()} ${e.kind}`);
  header.append(toolbar, title, meta);
  if (e.checks?.length) header.append(checksBlock(e.checks));
  if (!bytes) {
    panel.replaceChildren(header, el('p', 'hex-hint', 'У этого события нет записанных байтов (например, SYN/ACK делает ОС, Node их не видит).'));
    return;
  }
  const { dump, cells } = hexDump(bytes, e.offset);
  const content = el('div', 'detail-content');
  const viewport = el('div', 'hex-viewport');
  viewport.tabIndex = 0;
  viewport.setAttribute('role', 'region');
  viewport.setAttribute('aria-label', 'Байты события: hex и ASCII');
  viewport.append(dump);
  if (!fields) {
    content.append(el('p', 'hex-hint', 'Поля этого события не разобраны.'), viewport);
    panel.replaceChildren(header, content);
    return;
  }
  const index = indexTree(fields);
  let select = () => {};
  const tree = fieldTree(index, (id) => select(id));
  select = linkTreeAndBytes(e, index, tree, cells, dump, viewport);
  header.append(el('p', 'hex-hint', 'Клик по полю подсвечивает его байты; клик по байту — его поле.'));
  content.append(tree.root, viewport); // two blocks only, so they can sit side by side in full-width mode
  panel.replaceChildren(header, content);
}

// ---- loading ----------------------------------------------------------------------------------

let latestRequest = 0;

async function fetchOk(url, read) {
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return read(response);
}

async function select(index, e, item) {
  document.querySelector('.event[aria-current="true"]')?.removeAttribute('aria-current');
  item.setAttribute('aria-current', 'true');
  const request = ++latestRequest;
  const [bytes, view] = e.buffer === null
    ? [null, { fields: null }]
    : await Promise.all([
      fetchOk(`events/${index}/bytes`, async (r) => new Uint8Array(await r.arrayBuffer())),
      fetchOk(`events/${index}/fields`, (r) => r.json()),
    ]);
  if (request === latestRequest) showDetail(e, bytes, view.fields); // a later click won: drop this stale answer
}

function showError(err) {
  const box = document.getElementById('error');
  box.textContent = `Ошибка: ${err.message}`;
  box.hidden = false;
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

async function main() {
  const view = await fetchOk('timeline.json', (r) => r.json());
  const list = document.getElementById('events');
  renderStats(view);
  renderFilters(list);
  list.append(...view.events.map((e, i) => selectable(row(e, view.durationMs), i, e)));
}

main().catch(showError);
