// Safe DOM construction. Every string child becomes a Text node, so untrusted
// telemetry (journal messages, host IDs, unit names, summaries) can never be
// interpreted as markup. This module never touches innerHTML/outerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';
const SAFE_URL = /^(#|\/(?!\/))/; // in-app fragments and same-origin absolute paths only

/**
 * el('div', { class: 'card', on: { click }, attrs: { role: 'button' } }, 'text', node, [more])
 */
export function el(tag, props = null, ...children) {
  const node = document.createElement(tag);
  if (props) applyProps(node, props);
  append(node, children);
  return node;
}

function applyProps(node, props) {
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    switch (key) {
      case 'class':
        node.className = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
        break;
      case 'text':
        node.textContent = String(value);
        break;
      case 'on':
        for (const [evt, fn] of Object.entries(value)) node.addEventListener(evt, fn);
        break;
      case 'dataset':
        for (const [k, v] of Object.entries(value)) if (v !== undefined && v !== null) node.dataset[k] = String(v);
        break;
      case 'attrs':
        for (const [k, v] of Object.entries(value)) {
          if (v === undefined || v === null || v === false) continue;
          if (/^on/i.test(k) || k === 'style') throw new Error(`refusing unsafe attribute ${k}`);
          node.setAttribute(k, v === true ? '' : String(v));
        }
        break;
      case 'href':
        if (!SAFE_URL.test(String(value))) throw new Error('refusing non-local href');
        node.setAttribute('href', String(value));
        break;
      case 'value':
      case 'checked':
      case 'disabled':
      case 'type':
      case 'name':
      case 'id':
      case 'title':
      case 'placeholder':
      case 'min':
      case 'max':
      case 'step':
      case 'rows':
      case 'htmlFor':
      case 'open':
      case 'selected':
      case 'tabIndex':
      case 'hidden':
        node[key] = value;
        break;
      default:
        throw new Error(`unknown prop ${key}`);
    }
  }
}

export function append(node, children) {
  const list = Array.isArray(children) ? children.flat(Infinity) : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false || child === '') continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.firstChild.remove();
  return node;
}

export function replace(node, ...children) {
  clear(node);
  return append(node, children);
}

// Static icon geometry (trusted constants only).
const ICONS = {
  fleet: ['M3 5h18v6H3z', 'M3 13h18v6H3z', 'M7 8h.01', 'M7 16h.01'],
  incident: ['M12 3 2.5 20h19L12 3Z', 'M12 10v4', 'M12 17h.01'],
  baseline: ['M4 19V5', 'M4 19h16', 'M8 15l3-4 3 2 5-6'],
  audit: ['M7 3h7l5 5v13H7z', 'M14 3v5h5', 'M10 13h6', 'M10 17h6'],
  refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 5v6h-6'],
  lock: ['M6 11h12v9H6z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  shield: ['M12 3 4.5 6v6c0 4.6 3.2 8.2 7.5 9.3 4.3-1.1 7.5-4.7 7.5-9.3V6L12 3Z', 'M8.8 12.2l2.3 2.3 4.2-4.7'],
  alert: ['M12 3 2.5 20h19L12 3Z', 'M12 10v4', 'M12 17h.01'],
  chevron: ['M9 6l6 6-6 6'],
  copy: ['M9 9h11v11H9z', 'M5 15H4V4h11v1'],
  close: ['M6 6l12 12', 'M18 6 6 18'],
  clock: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', 'M12 7v5l3 2'],
  plus: ['M12 5v14', 'M5 12h14'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  eye: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z'],
  flask: ['M9 3h6', 'M10 3v6L4.5 19a1.5 1.5 0 0 0 1.3 2h12.4a1.5 1.5 0 0 0 1.3-2L14 9V3'],
  bolt: ['M13 2.5 4.5 13.5H12l-1 8 8.5-11H12l1-8Z'],
  key: ['M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M12 12h9', 'M18 12v3', 'M21 12v2'],
  user: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M4.5 20.5a7.5 7.5 0 0 1 15 0'],
  logout: ['M14 4h5v16h-5', 'M10 8l-4 4 4 4', 'M6 12h10'],
  terminal: ['M3.5 5h17v14h-17z', 'M7.5 10l3 2-3 2', 'M12.5 15h4'],
  check: ['M5 12.5l4.2 4.2L19 7'],
};

export function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name] ?? []) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return el('span', { dataset: { icon: name } }, svg);
}

/** Hydrate static `<span data-icon="x">` placeholders shipped in index.html. */
export function hydrateIcons(root = document) {
  for (const node of root.querySelectorAll('[data-icon]')) {
    if (!node.firstChild) node.append(icon(node.dataset.icon).firstChild);
  }
}
