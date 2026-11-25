// tunnel.js: reaching the app from anywhere through a Cloudflare tunnel,
// drawn into a container (the "Remote access" card of the server settings,
// or a card of an app's own settings page).
//
// The person creates a Cloudflare API token through a link with the
// permissions filled in (the table lists them too: the dashboard drops a
// permission it does not know without a word), pastes it and checks it
// (POST /api/cloudflare/check lists the domains it may use, and the
// Cloudflare user when it may read it), then picks a domain, a subdomain and
// the e-mail addresses that may sign in. POST /api/cloudflare/setup creates
// the tunnel, the DNS record and Cloudflare Access in the background; the
// page follows GET /api/cloudflare (polled while the job runs, and on the
// "cloudflare" change notice) and shows the steps as a task list. A name
// that is already taken on Cloudflare stops the setup with its conflicts,
// and Replace runs it again with replace: true once the person agreed.
//
// Once it runs, the card shows the tunnel's state, its address, who may
// sign in (PUT /api/cloudflare/emails), Repair (the setup again, with the
// token the server keeps) and Remove (DELETE /api/cloudflare, in the
// background too). A setup that stopped half way offers both. Everything is
// drawn with morph(), so the fields keep what is typed into them while the
// status changes under them.

import { get, post, put, del, errorMessage, isOffline } from './api.js';
import { html, raw, icon, morph, faces, busy, toast, confirm, sentence, alertHtml } from './ui.js';
import { on } from './shell.js';

// How often the page asks while something moves: a job, a tunnel that is
// still connecting, an open log.
const POLL_JOB = 1500;
const POLL_LIVE = 4000;

// The status chip: always an icon (or the spinner) and a word.
const CHIP = {
  ok: ['ds-status ds-tone-success', 'check'],
  warning: ['ds-status ds-tone-warning', 'alert'],
  error: ['ds-status ds-tone-error', 'alertCircle'],
  running: ['ds-status ds-status--running', null],
  off: ['ds-status', 'ban'],
};

function chip(kind, label, state) {
  const [cls, glyph] = CHIP[kind];
  const mark = glyph ? icon(glyph, 16) : html`<span class="ds-spinner ds-status__spinner" aria-hidden="true"></span>`;
  return html`<span class="${cls}" data-zs-state="${state}">${mark}<span>${label}</span></span>`;
}

// stateOf is the tunnel's state as a chip: [kind, label, machine word].
function stateOf(st) {
  const job = st.job || {};
  if (job.running) return job.kind === 'remove' ? ['running', 'Removing', 'removing'] : ['running', 'Setting up', 'setting-up'];
  if (!st.configured) return st.partial ? ['warning', 'Half set up', 'partial'] : ['off', 'Not set up', 'off'];
  if (st.error) return ['error', 'Problem', 'error'];
  if (st.downloading) return ['running', 'Downloading cloudflared', 'downloading'];
  if (!st.running || !st.connected) return ['running', 'Connecting', 'connecting'];
  if (!st.verified) return ['running', 'Checking from outside', 'checking'];
  return ['ok', 'Up', 'up'];
}

// emailsOf is the addresses in a textarea: one per line, commas and spaces tolerated.
function emailsOf(text) {
  return String(text || '').split(/[\s,;]+/).map((e) => e.trim()).filter(Boolean);
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : many);
}

// slug is a subdomain to start from: the app's name in DNS letters.
function slug(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63) || 'app';
}

/**
 * mountTunnel draws the tunnel settings into `host` and keeps them current.
 * Options: `name` (the app's name, from the session; it names the app in
 * the texts and gives the first subdomain), `level` (the heading level of
 * the steps: 3 in a card, 2 under a page title), `log` (false hides the
 * cloudflared log), `onChange(payload)` (every GET /api/cloudflare answer).
 * Returns `{ refresh, destroy }`.
 */
export function mountTunnel(host, { name = 'The app', level = 3, log = true, onChange = () => {} } = {}) {
  let data = null;          // GET /api/cloudflare
  let loadError = '';
  let timer = 0;
  let watching = false;     // a job this page saw running: its end is shown
  let editing = false;      // the form is open over a tunnel that exists (Repair)
  let logOpen = false;
  let checking = false;     // the stored token is being checked (Repair)
  let checked = null;       // POST /api/cloudflare/check's answer
  let notice = '';          // an API error of the last action
  let errors = {};          // field id -> what is wrong with it
  let focusField = '';
  let addresses = null;     // the "who may sign in" text while edited
  let gone = false;
  const form = { token: '', zoneId: '', sub: slug(name), emails: '' };
  const h = raw('h' + Math.min(6, Math.max(2, Number(level) || 3)));
  const local = location.origin;

  /* ------------------------------------------------------------ fetching */

  async function refresh() {
    clearTimeout(timer);
    if (gone) return;
    try {
      take(await get('/api/cloudflare'));
      loadError = '';
    } catch (err) {
      if (isOffline(err)) {
        // The shell says the server is away; keep asking.
        timer = setTimeout(refresh, POLL_LIVE);
        return;
      }
      loadError = errorMessage(err);
    }
    render();
  }

  // take keeps a payload and notices a job that ended while the page watched.
  function take(next) {
    const before = data && data.status && data.status.job;
    data = next;
    const st = data.status || {};
    const job = st.job || {};
    if (job.running) watching = true;
    if (before && before.running && !job.running) ended(job);
    if (!form.emails && data.via === 'tunnel' && data.email) form.emails = data.email;
    try {
      onChange(data);
    } catch (err) {
      reportError(err);
    }
  }

  function ended(job) {
    if (job.kind === 'remove') {
      if (job.ok) {
        toast('Remote access is removed.', 'success');
        watching = false;
        editing = false;
        checked = null;
        form.token = '';
      }
      return;
    }
    if (job.ok) {
      // The alert under the steps says where it is now.
      editing = false;
      form.token = '';
      addresses = null;
    }
  }

  function schedule() {
    clearTimeout(timer);
    const st = data && data.status;
    if (!st || gone) return;
    let wait = 0;
    if (st.job && st.job.running) wait = POLL_JOB;
    else if (logOpen || (st.configured && (!st.connected || !st.verified || st.downloading || st.error))) wait = POLL_LIVE;
    if (wait) timer = setTimeout(refresh, wait);
  }

  /* ------------------------------------------------------------- drawing */

  function render() {
    if (!host.isConnected || gone) return;
    if (!data) {
      morph(host, html`<div class="ds-stack" data-ds-key="zs-tunnel">
        <div class="ds-cluster" role="status" data-ds-key="state">${loadError ? chip('error', 'Unknown', 'unknown') : chip('running', 'Loading', 'loading')}</div>
        ${loadError ? alertHtml('error', sentence(loadError), { key: 'load' }) : ''}
      </div>`);
      return;
    }
    const st = data.status || {};
    const job = st.job || {};
    const conflicts = job.conflicts || [];
    const showForm = !job.running && (editing || (!st.configured && !st.partial));
    morph(host, html`<div class="ds-stack" data-ds-key="zs-tunnel">
      ${stateHtml(st)}
      ${loadError ? alertHtml('error', sentence(loadError), { key: 'load' }) : ''}
      ${st.error && !job.running && !(watching && job.error) && !conflicts.length ? alertHtml('error', sentence(st.error), { key: 'status-error' }) : ''}
      ${!job.running && st.configured && !editing ? configuredHtml(st) : ''}
      ${!job.running && !st.configured && st.partial && !editing ? partialHtml() : ''}
      ${showForm ? formHtml(st) : ''}
      ${watching || job.running ? jobHtml(st, job) : ''}
      ${!job.running && conflicts.length ? conflictsHtml(job) : ''}
      ${notice ? alertHtml('error', sentence(notice), { key: 'notice' }) : ''}
      ${log ? logHtml(st) : ''}
    </div>`);
    if (focusField) {
      const field = host.querySelector('#' + focusField);
      focusField = '';
      if (field) field.focus();
    }
    schedule();
  }

  function link(url) {
    return html`<a href="${url}" target="_blank" rel="noopener" class="zs-break">${url}</a>`;
  }

  function stateHtml(st) {
    const [kind, label, word] = stateOf(st);
    return html`<div class="ds-cluster" role="status" data-ds-key="state">${chip(kind, label, word)}${
      st.configured && st.publicUrl ? html`<span class="ds-parts"><span class="ds-parts__list"><span>${link(st.publicUrl)}</span></span></span>` : ''}</div>`;
  }

  // jobHtml is the steps of the setup or removal: done, running, failed.
  function jobHtml(st, job) {
    const done = job.done || [];
    const items = done.map((text) => ({ text, status: 'done' }));
    if (job.step) items.push({ text: job.step, status: job.running ? 'running' : job.error ? 'failed' : 'done' });
    if (!items.length && job.running) items.push({ text: 'Starting', status: 'running' });
    const title = job.kind === 'remove' ? 'Removing remote access' : 'Setting up remote access';
    let tail = '';
    if (!job.running && job.ok) {
      tail = job.kind === 'remove'
        ? alertHtml('success', `Removed. ${name} is on its local address only now.`, { key: 'job-ok' })
        : html`<div class="ds-alert ds-tone-success" role="status" data-ds-key="job-ok">${icon('checkCircle', 20)}<span class="ds-alert__text">${name} is at ${link(st.publicUrl)}. Opening it asks for a Cloudflare login: a one-time code goes by e-mail to the addresses that may sign in.</span></div>`;
    } else if (!job.running && job.error && !(job.conflicts || []).length) {
      tail = alertHtml('error', sentence(job.error), { key: 'job-error' });
    }
    const count = done.length + (job.ok && job.step ? 1 : 0);
    return html`<div class="ds-stack" data-ds-key="${'job-' + (job.kind || 'none')}">
      <div class="ds-tasks__head"><${h} class="ds-card__subtitle">${title}</${h}><p class="ds-meta">${plural(count, 'step', 'steps')} done</p></div>
      <ol class="ds-tasks" aria-label="${title}">${items.map((item, i) => html`<li class="ds-tasks__item" data-ds-key="${'s' + i}" data-status="${item.status}"><span class="ds-tasks__mark" aria-hidden="true">${
        item.status === 'running' ? html`<span class="ds-spinner ds-spinner--ink ds-sm"></span>`
          : item.status === 'done' ? icon('checkCircle', 20) : icon('alertCircle', 20)
      }</span><span class="ds-tasks__text">${item.text}<span class="ds-sr">${': ' + (item.status === 'running' ? 'running' : item.status)}</span></span></li>`)}</ol>
      ${tail}
    </div>`;
  }

  function conflictsHtml(job) {
    return html`<div class="ds-alert ds-tone-warning" role="status" data-ds-key="conflicts">${icon('alert', 20)}<div class="ds-alert__text">
      <p class="ds-alert__title">This address is already taken on Cloudflare</p>
      <ul class="ds-plain-list">${job.conflicts.map((c) => html`<li class="zs-break">${c.detail || c.name}</li>`)}</ul>
      <p>Choose another subdomain, or let ${name} replace what is there.</p>
    </div><div class="ds-alert__actions"><button class="ds-btn ds-sm" type="button" data-zs-cf="replace">${faces('Replace', 'Starting')}</button></div></div>`;
  }

  function configuredHtml(st) {
    const bin = st.cloudflared || {};
    const binary = bin.installed
      ? [bin.version || 'installed', bin.managed ? `downloaded by ${name}` : bin.path].filter(Boolean).join(' · ')
      : (bin.canInstall ? `not installed; ${name} downloads it` : 'not installed');
    const facts = [
      ['Cloudflare account', st.account || '—'],
      ['Domain', st.zone || '—'],
      data.via === 'local' ? ['Local address', local] : null,
      ['cloudflared', binary],
    ].filter(Boolean);
    const text = addresses !== null ? addresses : (st.emails || []).join('\n');
    return html`<div class="ds-stack" data-ds-key="configured">
      <dl class="ds-facts">${facts.map(([label, value]) => html`<div><dt>${label}</dt><dd class="zs-break">${value}</dd></div>`)}</dl>
      <p class="ds-meta">Opening the address asks for a Cloudflare login: a one-time code goes by e-mail to the addresses below. The password is only needed on the local address.</p>
      <div class="ds-field">
        <label class="ds-field__label" for="zs-cf-addresses">Who may sign in</label>
        <textarea class="ds-input" id="zs-cf-addresses" rows="3" spellcheck="false" autocomplete="off" autocapitalize="off" aria-describedby="${described('zs-cf-addresses', 'zs-cf-addresses-hint')}"${invalid('zs-cf-addresses')}>${text}</textarea>
        ${errorHtml('zs-cf-addresses')}
        <small class="ds-field__hint" id="zs-cf-addresses-hint">One e-mail address per line.</small>
      </div>
      <div class="ds-form-actions">
        <button class="ds-btn" type="button" data-zs-cf="save-emails">${faces('Save addresses', 'Saving', 'Saved')}</button>
        <button class="ds-btn ds-btn--text" type="button" data-zs-cf="repair">${icon('refresh', 16)}<span>Repair</span></button>
        <button class="ds-btn ds-btn--text" type="button" data-zs-cf="remove">${faces('Remove remote access', 'Starting')}</button>
      </div>
    </div>`;
  }

  function partialHtml() {
    return html`<div class="ds-alert ds-tone-warning" role="status" data-ds-key="partial">${icon('alert', 20)}<div class="ds-alert__text"><p>A setup stopped half way: some of it exists on Cloudflare, but no tunnel runs. Run the setup again to finish it, or remove what was made.</p></div><div class="ds-alert__actions">
      <button class="ds-btn ds-btn--text ds-sm" type="button" data-zs-cf="remove">${faces('Remove', 'Starting')}</button>
      <button class="ds-btn ds-sm" type="button" data-zs-cf="repair">Set up again</button>
    </div></div>`;
  }

  function errorHtml(id) {
    return errors[id]
      ? html`<small class="ds-field__hint ds-field__hint--error" id="${id + '-error'}">${icon('alertCircle', 16)}${errors[id]}</small>`
      : '';
  }

  function described(id, hint) {
    return [errors[id] ? id + '-error' : '', hint].filter(Boolean).join(' ');
  }

  function invalid(id) {
    return raw(errors[id] ? ' aria-invalid="true"' : '');
  }

  function zoneOf(id) {
    return ((checked && checked.zones) || []).find((z) => z.id === id) || null;
  }

  function hostname() {
    const zone = zoneOf(form.zoneId);
    const sub = form.sub.trim().toLowerCase();
    return zone && sub ? sub + '.' + zone.name : '';
  }

  function hostHint() {
    const full = hostname();
    return full ? `${name} will be at https://${full}.` : `Enter the name ${name} gets under the domain.`;
  }

  function formHtml(st) {
    const perms = data.permissions || [];
    const stored = !!st.hasToken;
    const zones = (checked && checked.zones) || [];
    const accounts = [...new Set(zones.map((z) => z.accountName).filter(Boolean))];
    const zone = zoneOf(form.zoneId);
    return html`<div class="ds-stack" data-ds-key="form">
      <section class="ds-card__section" aria-labelledby="zs-cf-step1" data-ds-key="step1">
        <${h} class="ds-card__subtitle" id="zs-cf-step1">1. Create an API token</${h}>
        <p>The link opens Cloudflare with the permissions filled in. Choose the account and the domain there, then create the token and copy it.</p>
        <div class="ds-cluster"><a class="ds-btn" href="${data.tokenUrl}" target="_blank" rel="noopener">${icon('external', 16)}<span>Create the token at Cloudflare</span></a></div>
        <div class="ds-table-wrap">
          <table class="ds-table ds-density-tight">
            <caption class="ds-sr">Permissions of the API token</caption>
            <thead><tr><th scope="col" class="ds-nowrap">Scope</th><th scope="col">Permission</th><th scope="col" class="ds-nowrap">Access</th></tr></thead>
            <tbody>${perms.map((p) => html`<tr><td class="ds-nowrap">${p.scope}</td><td>${p.name}${p.optional ? html` <span class="ds-tag ds-tone-neutral">Optional</span>` : ''}</td><td class="ds-nowrap">${p.level}</td></tr>`)}</tbody>
          </table>
        </div>
        <p class="ds-meta">Cloudflare Zero Trust's free plan is enough. ${name} keeps the token encrypted on this machine and needs it again only to change the addresses, to repair or to remove the tunnel.</p>
      </section>

      <section class="ds-card__section" aria-labelledby="zs-cf-step2" data-ds-key="step2">
        <${h} class="ds-card__subtitle" id="zs-cf-step2">2. Paste and check the token</${h}>
        <div class="ds-field">
          <label class="ds-field__label" for="zs-cf-token">API token${stored ? html` <span class="ds-field__optional">· optional</span>` : ''}</label>
          <div class="ds-field__row">
            <input class="ds-input" type="password" id="zs-cf-token" value="${form.token}" autocomplete="off" spellcheck="false" autocapitalize="off" enterkeyhint="go" aria-describedby="${described('zs-cf-token', stored ? 'zs-cf-token-hint' : '')}"${invalid('zs-cf-token')}>
            <button class="ds-btn" type="button" data-zs-cf="check">${faces('Check token', 'Checking')}</button>
          </div>
          ${errorHtml('zs-cf-token')}
          ${stored ? html`<small class="ds-field__hint" id="zs-cf-token-hint">Empty uses the token ${name} keeps.</small>` : ''}
        </div>
        ${checking ? html`<div class="ds-loading" role="status" data-ds-key="checking"><span class="ds-loader ds-sm" aria-hidden="true"></span>Asking Cloudflare which domains the token may use</div>` : ''}
        ${checked ? html`<div class="ds-alert ds-tone-success" role="status" data-ds-key="checked">${icon('checkCircle', 20)}<div class="ds-alert__text">
          <p>Valid: may use ${plural(zones.length, 'domain', 'domains')}.</p>
          ${checked.user ? html`<p>Cloudflare user: ${checked.user}</p>` : ''}
          ${accounts.length ? html`<p>${accounts.length === 1 ? 'Account' : 'Accounts'}: ${accounts.join(', ')}</p>` : ''}
        </div></div>` : ''}
      </section>

      <section class="ds-card__section" aria-labelledby="zs-cf-step3" data-ds-key="step3">
        <${h} class="ds-card__subtitle" id="zs-cf-step3">3. Address and who may sign in</${h}>
        ${!checked ? html`<p class="ds-meta" data-ds-key="wait">Check the token first: then the domains it may use are listed here.</p>` : html`<div class="ds-form" data-ds-key="fields">
          <div class="ds-field">
            <label class="ds-field__label" for="zs-cf-zone">Domain</label>
            <select class="ds-input" id="zs-cf-zone" aria-describedby="${described('zs-cf-zone', '')}"${invalid('zs-cf-zone')}>
              ${zone ? '' : html`<option value="" selected>Choose a domain</option>`}
              ${zones.map((z) => html`<option value="${z.id}"${raw(z.id === form.zoneId ? ' selected' : '')}>${z.name}</option>`)}
            </select>
            ${errorHtml('zs-cf-zone')}
          </div>
          <div class="ds-field">
            <label class="ds-field__label" for="zs-cf-sub">Subdomain</label>
            <div class="ds-input-group">
              <input class="ds-input" type="text" id="zs-cf-sub" value="${form.sub}" spellcheck="false" autocomplete="off" autocapitalize="off" enterkeyhint="next" aria-describedby="${described('zs-cf-sub', 'zs-cf-sub-hint')}"${invalid('zs-cf-sub')}>
              <span class="ds-input-group__suffix" aria-hidden="true">${zone ? '.' + zone.name : ''}</span>
            </div>
            ${errorHtml('zs-cf-sub')}
            <small class="ds-field__hint" id="zs-cf-sub-hint">${hostHint()}</small>
          </div>
          <div class="ds-field">
            <label class="ds-field__label" for="zs-cf-emails">Who may sign in</label>
            <textarea class="ds-input" id="zs-cf-emails" rows="3" spellcheck="false" autocomplete="off" autocapitalize="off" aria-describedby="${described('zs-cf-emails', 'zs-cf-emails-hint')}"${invalid('zs-cf-emails')}>${form.emails}</textarea>
            ${errorHtml('zs-cf-emails')}
            <small class="ds-field__hint" id="zs-cf-emails-hint">One e-mail address per line. Cloudflare sends each a one-time code to sign in with.</small>
          </div>
          <div class="ds-form-actions">
            <button class="ds-btn ds-btn--filled" type="button" data-zs-cf="setup">${faces('Set up the tunnel', 'Starting')}</button>
            ${editing ? html`<button class="ds-btn ds-btn--text" type="button" data-zs-cf="cancel">Cancel</button>` : ''}
          </div>
        </div>`}
        ${!checked && editing ? html`<div class="ds-form-actions" data-ds-key="cancel-only"><button class="ds-btn ds-btn--text" type="button" data-zs-cf="cancel">Cancel</button></div>` : ''}
      </section>
    </div>`;
  }

  // logHtml is cloudflared's and the setup's last lines, in a Log viewer
  // while it is open.
  function logHtml(st) {
    const lines = (st.logs || []).join('\n');
    return html`<div class="ds-stack" data-ds-key="log">
      <div class="ds-cluster"><button class="ds-btn ds-btn--text ds-sm" type="button" data-zs-cf="log" aria-expanded="${logOpen ? 'true' : 'false'}" aria-controls="zs-cf-log">${logOpen ? 'Hide log' : 'Show log'}</button></div>
      <div id="zs-cf-log"${raw(logOpen ? '' : ' hidden')}>${logOpen ? html`<div class="ds-logview" data-ds-logview data-ds-logview-wrap aria-label="Tunnel log" data-ds-key="logview"><pre class="ds-logview__source">${lines}</pre></div>` : ''}</div>
    </div>`;
  }

  /* ------------------------------------------------------------- actions */

  function setError(id, text) {
    errors = { ...errors, [id]: text };
    focusField = id;
    render();
  }

  async function check(button, { quiet = false } = {}) {
    const token = form.token.trim();
    const st = data.status || {};
    errors = {};
    notice = '';
    if (!token && !st.hasToken) {
      setError('zs-cf-token', 'Paste the API token first.');
      return;
    }
    const work = post('/api/cloudflare/check', { apiToken: token });
    if (!button) {
      checking = true;
      render();
    }
    try {
      const res = button ? await busy(button, work, { done: false }) : await work;
      checked = { zones: res.zones || [], user: res.user || '', stored: !!res.stored };
      if (!zoneOf(form.zoneId)) form.zoneId = checked.zones.length === 1 ? checked.zones[0].id : '';
      if (!form.emails.trim() && checked.user) form.emails = checked.user;
      if (!checked.zones.length) errors = { 'zs-cf-token': 'The token may use no domain. Give it the domain under Zone Resources.' };
      else if (!quiet) focusField = form.zoneId ? 'zs-cf-sub' : 'zs-cf-zone';
    } catch (err) {
      checked = null;
      if (isOffline(err)) notice = errorMessage(err);
      else {
        errors = { 'zs-cf-token': sentence((err.fields && err.fields.apiToken) || errorMessage(err)) };
        if (!quiet) focusField = 'zs-cf-token';
      }
    } finally {
      checking = false;
    }
    render();
  }

  // validated is the setup's request, or null after marking what is wrong.
  function validated() {
    errors = {};
    if (!checked) { setError('zs-cf-token', 'Check the token first.'); return null; }
    const zone = zoneOf(form.zoneId);
    if (!zone) { setError('zs-cf-zone', 'Choose a domain.'); return null; }
    const sub = form.sub.trim().toLowerCase();
    if (!sub) { setError('zs-cf-sub', `Enter a subdomain, like ${slug(name)}.`); return null; }
    if (!sub.split('.').every((p) => LABEL.test(p))) {
      setError('zs-cf-sub', `Use letters, digits and hyphens, like ${slug(name)}.`);
      return null;
    }
    const emails = emailsOf(form.emails);
    if (!emails.length) { setError('zs-cf-emails', 'Enter at least one e-mail address.'); return null; }
    const bad = emails.find((e) => !EMAIL.test(e));
    if (bad) { setError('zs-cf-emails', '“' + bad + '” is not an e-mail address.'); return null; }
    if (data.via === 'tunnel' && data.email && !emails.some((e) => e.toLowerCase() === data.email.toLowerCase())) {
      setError('zs-cf-emails', 'Keep your own address (' + data.email + ') on the list, or you lock yourself out.');
      return null;
    }
    return { apiToken: form.token.trim(), zoneId: zone.id, hostname: sub + '.' + zone.name, emails };
  }

  async function setup(button, replace = false) {
    const body = validated();
    if (!body) return;
    if (replace) {
      const yes = await confirm({
        title: 'Replace what is on Cloudflare?',
        text: `${name} deletes the existing DNS record or Access application for ${body.hostname} and creates its own. `
          + 'Whatever it pointed to is no longer reachable under that name.',
        confirmLabel: 'Delete and replace', destructive: true, opener: button,
      });
      if (!yes) return;
    }
    notice = '';
    try {
      const res = await busy(button, post('/api/cloudflare/setup', { ...body, replace }), { done: false });
      watching = true;
      take(res);
    } catch (err) {
      if (err.fields && err.fields.emails) errors = { 'zs-cf-emails': sentence(err.fields.emails) };
      else notice = errorMessage(err);
    }
    render();
  }

  async function saveEmails(button) {
    const text = addresses !== null ? addresses : ((data.status || {}).emails || []).join('\n');
    const emails = emailsOf(text);
    errors = {};
    if (!emails.length) { setError('zs-cf-addresses', 'Enter at least one e-mail address.'); return; }
    const bad = emails.find((e) => !EMAIL.test(e));
    if (bad) { setError('zs-cf-addresses', '“' + bad + '” is not an e-mail address.'); return; }
    notice = '';
    try {
      const res = await busy(button, put('/api/cloudflare/emails', { emails }));
      addresses = null;
      take(res);
      toast('Saved: ' + plural(emails.length, 'address', 'addresses') + ' may sign in.', 'success');
    } catch (err) {
      if (isOffline(err)) notice = errorMessage(err);
      else errors = { 'zs-cf-addresses': sentence((err.fields && err.fields.emails) || errorMessage(err)) };
    }
    render();
  }

  async function remove(button) {
    const st = data.status || {};
    const away = data.via === 'tunnel';
    const yes = await confirm({
      title: 'Remove remote access?',
      text: `${name} stops the tunnel and deletes it on Cloudflare, with its DNS record and its Access applications. `
        + `${name} stays reachable on its local address with the password.`
        + (away ? ' You came through the tunnel: this page loses its connection once the tunnel is gone.' : ''),
      confirmLabel: 'Remove' + (st.hostname ? ' ' + st.hostname : ' remote access'), destructive: true, opener: button,
    });
    if (!yes) return;
    notice = '';
    try {
      const res = await busy(button, del('/api/cloudflare'), { done: false });
      watching = true;
      editing = false;
      take(res);
    } catch (err) {
      notice = errorMessage(err);
    }
    render();
  }

  function repair() {
    const st = data.status || {};
    editing = true;
    errors = {};
    notice = '';
    form.token = '';
    if (st.zoneId) form.zoneId = st.zoneId;
    if (st.hostname && st.zone && st.hostname.endsWith('.' + st.zone)) form.sub = st.hostname.slice(0, -st.zone.length - 1);
    if ((st.emails || []).length) form.emails = st.emails.join('\n');
    checked = null;
    watching = false;
    if (!st.hasToken) focusField = 'zs-cf-token';
    render();
    if (st.hasToken) check(null, { quiet: true });
  }

  function onClick(event) {
    const button = event.target.closest('[data-zs-cf]');
    if (!button || !data) return;
    const what = button.dataset.zsCf;
    if (what === 'check') check(button);
    else if (what === 'setup') setup(button);
    else if (what === 'replace') setup(button, true);
    else if (what === 'save-emails') saveEmails(button);
    else if (what === 'remove') remove(button);
    else if (what === 'repair') repair();
    else if (what === 'cancel') {
      editing = false;
      errors = {};
      notice = '';
      render();
    } else if (what === 'log') {
      logOpen = !logOpen;
      if (logOpen) refresh();
      else render();
    }
  }

  // What is typed is kept in `form`, so that a redraw puts it back.
  function onInput(event) {
    const t = event.target;
    const clear = (id) => {
      if (!errors[id]) return false;
      const { [id]: _gone, ...rest } = errors;
      errors = rest;
      return true;
    };
    if (t.id === 'zs-cf-token') {
      form.token = t.value;
      // Another token is another set of domains: check it again.
      const had = !!checked;
      checked = null;
      if (clear('zs-cf-token') || had) render();
    } else if (t.id === 'zs-cf-sub') {
      form.sub = t.value;
      const hint = host.querySelector('#zs-cf-sub-hint');
      if (hint) hint.textContent = hostHint();
      if (clear('zs-cf-sub')) render();
    } else if (t.id === 'zs-cf-emails') {
      form.emails = t.value;
      if (clear('zs-cf-emails')) render();
    } else if (t.id === 'zs-cf-addresses') {
      addresses = t.value;
      if (clear('zs-cf-addresses')) render();
    }
  }

  function onChangeField(event) {
    if (event.target.id !== 'zs-cf-zone') return;
    form.zoneId = event.target.value;
    const { 'zs-cf-zone': _gone, ...rest } = errors;
    errors = rest;
    render();
  }

  // Enter in the token checks it; in the subdomain it sets up.
  function onKey(event) {
    if (event.key !== 'Enter' || event.isComposing) return;
    const id = event.target.id;
    const act = id === 'zs-cf-token' ? 'check' : id === 'zs-cf-sub' ? 'setup' : '';
    if (!act) return;
    event.preventDefault();
    const button = host.querySelector(`[data-zs-cf="${act}"]`);
    if (button) (act === 'check' ? check : setup)(button);
  }

  host.addEventListener('click', onClick);
  host.addEventListener('input', onInput);
  host.addEventListener('change', onChangeField);
  host.addEventListener('keydown', onKey);
  // The change notice, and every topic after the stream was away or the
  // tab slept (shell.js), bring the state again.
  const stop = on('cloudflare', refresh);

  render();
  refresh();

  return {
    refresh,
    destroy() {
      gone = true;
      clearTimeout(timer);
      stop();
      host.removeEventListener('click', onClick);
      host.removeEventListener('input', onInput);
      host.removeEventListener('change', onChangeField);
      host.removeEventListener('keydown', onKey);
    },
  };
}
