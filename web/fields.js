// Page-side helpers over a field tree (from events/<i>/fields). Pure; used by the page and tests.
const MAX_VALUE_CHARS = 64;

/** Pre-order index: nodes[id] = { id, node, parent, depth }; leaves sorted by offset for lookups. */
export function indexTree(tree) {
  const nodes = [];
  const visit = (node, parent, depth) => {
    const id = nodes.length;
    nodes.push({ id, node, parent, depth });
    for (const child of node.children) visit(child, id, depth + 1);
  };
  visit(tree, null, 0);
  const leaves = nodes.filter((n) => n.node.children.length === 0 && n.node.length > 0); // already in offset order
  return { nodes, leaves };
}

/** Id of the leaf that owns buffer position `pos`, or null outside the tree. Binary search. */
export function ownerOf(index, pos) {
  let lo = 0;
  let hi = index.leaves.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const { node } = index.leaves[mid];
    if (pos < node.offset) hi = mid - 1;
    else if (pos >= node.offset + node.length) lo = mid + 1;
    else return index.leaves[mid].id;
  }
  return null;
}

/** Root ... node, as index entries. */
export function ancestors(index, id) {
  const path = [];
  for (let at = id; at !== null; at = index.nodes[at].parent) path.unshift(index.nodes[at]);
  return path;
}

const shorten = (text) => (text.length > MAX_VALUE_CHARS ? `${text.slice(0, MAX_VALUE_CHARS - 1)}…` : text);

/** Short display text for a field: certificate CN + expiry, else "label (value)", else value. */
export function describe(node) {
  if (node.x509) {
    const cn = node.x509.subject.split('\n').find((l) => l.startsWith('CN=')) ?? node.x509.subject;
    return shorten(`${cn}, до ${node.x509.validTo.slice(0, 10)}`);
  }
  if (node.label !== null && node.label !== undefined) return shorten(`${node.label} (${node.value})`);
  return node.value === null || node.value === undefined ? '' : shorten(String(node.value));
}
