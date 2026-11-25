// ui.js: the few helpers the shell's modules and an app's pages share on top
// of Z-Dash (window.DS, from /z-dash/ds.min.js, which every page loads
// before its modules).
//
// Markup is built with the html`` tagged template: every value is escaped
// unless it is itself html`` or raw(), so a string from the server can never
// become markup. It is drawn with morph() (DS.dom.morphHtml), which patches
// in place, so a field keeps what is typed into it and its focus while the
// state around it changes, and a status chip glides to its new colour.
// Everything else is a thin name for the documented DS call: busy faces of a
// button (DS.motion.busy), snackbars (DS.overlay.toast), the confirm dialog
// (DS.overlay.confirm), icons (DS.icons).

export const DS = window.DS;
if (!DS) throw new Error('Load /z-dash/ds.min.js before the shell\'s modules.');

/* ------------------------------------------------------------ markup */

class Raw {
  constructor(markup) {
    this.markup = String(markup);
  }
  toString() {
    return this.markup;
  }
}

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** esc escapes text for markup, in text and in quoted attributes. */
export function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

/** raw marks trusted markup (an icon, a fragment built here) so html`` keeps it. */
export function raw(markup) {
  return markup instanceof Raw ? markup : new Raw(markup);
}

// One value of a template: escaped text, kept markup, or a list of either.
// null, undefined and false render nothing, so a condition can stand in it.
function part(value) {
  if (value === null || value === undefined || value === false) return '';
  if (value instanceof Raw) return value.markup;
  if (Array.isArray(value)) return value.map(part).join('');
  return esc(value);
}

/** html is the tagged template every markup string is built with; templates nest. */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((value, i) => {
    out += part(value) + strings[i + 1];
  });
  return new Raw(out);
}

/** morph patches `target` to the markup, touching only what changed. */
export function morph(target, markup, options) {
  return DS.dom.morphHtml(target, String(markup), options);
}

/** icon is a glyph of DS.icons by name ("check", "alertCircle"), as markup for html``. */
export function icon(name, size = 20, className) {
  const body = DS.icons[name];
  if (typeof body !== 'string') throw new Error(`Unknown icon "${name}"`);
  return raw(DS.icons.icon(body, size, className));
}

/* ------------------------------------------------------------ buttons */

/**
 * faces is the inside of a button that shows it works: the label, a busy
 * face and, when given, a done face (Button, "faces"). busy() rolls them.
 */
export function faces(label, busyLabel, doneLabel) {
  return html`<span class="ds-btn__faces"><span class="ds-btn__face">${label}</span><span class="ds-btn__face ds-btn__face--busy" aria-hidden="true"><span class="ds-spinner ds-spinner--ink ds-sm"></span>${busyLabel}</span>${
    doneLabel ? html`<span class="ds-btn__face ds-btn__face--done" aria-hidden="true">${icon('check', 16)}${doneLabel}</span>` : ''
  }</span>`;
}

/** busy runs `work` (a promise or a function) with the button's busy face; see DS.motion.busy. */
export function busy(button, work, options) {
  return DS.motion.busy(button, work, options);
}

/* ------------------------------------------------------- messages */

/** toast shows a snackbar in the page's region: `kind` is "success", "error" or "info". */
export function toast(text, kind = 'success', options = {}) {
  return DS.overlay.toast(null, text, { kind, ...options });
}

/** confirm asks a question in the built dialog of DS.overlay; resolves true or false. */
export function confirm(options) {
  return DS.overlay.confirm(options);
}

/** sentence makes a server's "enter at least one address" read as one. */
export function sentence(text) {
  const s = String(text || '').trim();
  if (!s) return '';
  const head = s.charAt(0).toUpperCase() + s.slice(1);
  return /[.!?…]$/.test(head) ? head : head + '.';
}

const ALERTS = {
  error: ['ds-alert ds-tone-error', 'alert', 'alertCircle'],
  warning: ['ds-alert ds-tone-warning', 'status', 'alert'],
  success: ['ds-alert ds-tone-success', 'status', 'checkCircle'],
  info: ['ds-alert', 'status', 'info'],
};

/**
 * alertHtml is an alert (Alert): `kind` error, warning, success or info,
 * `text` a string or html``; `title` above it, `actions` (html``) after it,
 * `key` its data-ds-key, so a redraw keeps the same element.
 */
export function alertHtml(kind, text, { title = '', actions = '', key = '' } = {}) {
  const [cls, role, glyph] = ALERTS[kind] || ALERTS.info;
  const body = title
    ? html`<div class="ds-alert__text"><p class="ds-alert__title">${title}</p><p>${text}</p></div>`
    : html`<span class="ds-alert__text">${text}</span>`;
  return html`<div class="${cls}" role="${role}"${key ? raw(` data-ds-key="${esc(key)}"`) : ''}>${icon(glyph, 20)}${body}${
    actions ? html`<div class="ds-alert__actions">${actions}</div>` : ''}</div>`;
}

/* --------------------------------------------------------- fields */

/**
 * setFieldError shows `text` as the error of a field (Form: aria-invalid
 * and a .ds-field__hint--error with its icon, named by aria-describedby),
 * or takes it away when `text` is empty. It works on the live DOM, so a
 * field that a behaviour such as DS.password holds keeps its state.
 */
export function setFieldError(input, text) {
  if (!input) return;
  const id = (input.id || 'field') + '-error';
  let hint = document.getElementById(id);
  const described = (input.getAttribute('aria-describedby') || '').split(/\s+/).filter((x) => x && x !== id);
  if (!text) {
    input.removeAttribute('aria-invalid');
    if (hint) hint.remove();
    if (described.length) input.setAttribute('aria-describedby', described.join(' '));
    else input.removeAttribute('aria-describedby');
    return;
  }
  if (!hint) {
    hint = document.createElement('small');
    hint.className = 'ds-field__hint ds-field__hint--error';
    hint.id = id;
    (input.closest('.ds-input-group, .ds-field__row') || input).after(hint);
  }
  hint.replaceChildren(DS.icons.iconElement(DS.icons.alertCircle, 16), document.createTextNode(sentence(text)));
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', [id, ...described].join(' '));
}

/**
 * passwordField is a password field of Password (data-ds-password): the
 * reveal button and the caps-lock hint, and with `meter` the strength meter
 * for choosing one. `id` names the input, `name` its form name.
 */
export function passwordField({ id, name = id, label, autocomplete = 'current-password', meter = false, minlength = 0, hint = '' }) {
  const describe = [meter ? id + '-strength' : '', id + '-caps', hint ? id + '-hint' : ''].filter(Boolean).join(' ');
  return html`<div class="ds-field" data-ds-password>
    <label class="ds-field__label" for="${id}">${label}</label>
    <div class="ds-input-group">
      <input class="ds-input" id="${id}" name="${name}" type="password" autocomplete="${autocomplete}"${minlength ? raw(` minlength="${Number(minlength)}"`) : ''} aria-describedby="${describe}">
      <span class="ds-input-group__trailing"><button class="ds-btn ds-btn--quiet ds-btn--icon ds-sm" type="button" aria-label="Show password" aria-pressed="false"><span class="ds-icon-swap"><span class="ds-icon-swap__a">${icon('eye', 18)}</span><span class="ds-icon-swap__b">${icon('eyeOff', 18)}</span></span></button></span>
    </div>
    ${meter ? html`<div class="ds-password__meter" id="${id + '-strength'}"><span class="ds-password__bars" aria-hidden="true"><span></span><span></span><span></span><span></span></span><span class="ds-password__strength"></span></div>` : ''}
    <small class="ds-field__hint ds-field__hint--warning ds-password__caps" id="${id + '-caps'}" hidden>${icon('alert', 16)}Caps Lock is on.</small>
    ${hint ? html`<small class="ds-field__hint" id="${id + '-hint'}">${hint}</small>` : ''}
  </div>`;
}

/** fieldErrors shows the `fields` of an ApiError on the inputs `byField` maps them to; true when one matched. */
export function fieldErrors(err, byField) {
  let first = null;
  for (const [name, input] of Object.entries(byField)) {
    const text = err && err.fields ? err.fields[name] : '';
    setFieldError(input, text || '');
    if (text && !first) first = input;
  }
  if (first) first.focus();
  return !!first;
}
