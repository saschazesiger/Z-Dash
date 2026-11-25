// shell.js: the start of every page of an app on the server.
//
// A page holds its own documented app layout (a .ds-app with the top bar,
// the drawer and the view), marked `hidden`, and one module that does
//
//   import { start, on } from '/z-dash/server/shell.js';
//   const session = await start();
//   on('devices', loadDevices);
//
// start() wires Z-Dash once for the page (DS.ripple.attach, the tooltips,
// the icons of the static markup, DS.init for the data-ds-* behaviours),
// asks the server who is there (GET /api/session) and, until someone is
// signed in, shows the sign-in card instead of the app: the first-password
// card on the very first visit (needsPassword), else the password sign-in.
// The app's layout stays hidden meanwhile, so nothing of it shows to a
// stranger, and the app's script does not run on until start() resolves
// (with the session; `onReady(session)` hears it too).
//
// Once signed in it fills what the layout leaves to it: every
// [data-zs-name] with the app's name, every [data-zs-version] with its
// version, and the account capsule `.ds-account[data-zs-account]` (who,
// how they signed in, Sign out). Signing out ends the password session, or
// through the tunnel goes to Cloudflare Access's logout. A request that
// answers 401 later (the session ended elsewhere) brings the sign-in card
// back; signing in again shows the same page and tells every live topic,
// so it fetches again.
//
// on(topic, fn) is the page's side of the live change notices: one event
// stream for the page while someone is signed in, `fn(topics)` for every
// notice that names the topic, and for every topic after the stream was
// away (the server restarted, the network dropped), since a notice may
// have been missed.

import * as api from './api.js';
import { DS, html, morph, faces, busy, alertHtml, passwordField, setFieldError, fieldErrors, toast } from './ui.js';

let session = null;
let started = null;     // the promise start() returns
let readyFns = [];      // start()'s resolve and onReady, until the first sign-in
let entered = false;    // the app was shown once
let auth = null;        // the sign-in card's <main>
let stream = null;
let offlineTimer = 0;
const listeners = new Map(); // topic -> Set of functions

/** current is the session of GET /api/session, or null before start() has it. */
export function current() {
  return session;
}

/**
 * on calls `fn(topics)` whenever a change notice names `topic` (and after a
 * reconnect, when anything may have changed). Returns a function that stops
 * it.
 */
export function on(topic, fn) {
  if (!listeners.has(topic)) listeners.set(topic, new Set());
  listeners.get(topic).add(fn);
  return () => listeners.get(topic)?.delete(fn);
}

function emit(topics, all = false) {
  for (const [topic, fns] of listeners) {
    if (!all && !topics.has(topic)) continue;
    for (const fn of [...fns]) {
      try {
        fn(topics);
      } catch (err) {
        reportError(err);
      }
    }
  }
}

/**
 * start shows the sign-in until someone is signed in, then the page.
 * Resolves with the session (`onReady(session)` is called first). A second
 * call returns the same promise.
 */
export function start({ onReady } = {}) {
  if (started) return started;
  started = new Promise((resolve) => {
    readyFns = [(s) => { if (onReady) onReady(s); }, resolve];
  });
  wire();
  api.whenSignedOut(() => signedOut('Your session ended. Sign in again.'));
  boot();
  return started;
}

/** signOut ends the session: the password session here, or Cloudflare Access's through the tunnel. */
export async function signOut() {
  let next = '';
  try {
    next = (await api.post('/api/logout')).next || '';
  } catch {
    // Signed out on this side either way; through the tunnel Access still has to end its own.
    next = session && session.logout ? session.logout : '';
  }
  if (next) {
    location.assign(next);
    return;
  }
  signedOut('You are signed out.');
}

/* ----------------------------------------------------------- wiring */

function wire() {
  DS.ripple.attach(document);
  DS.overlay.tooltips(document);
  DS.icons.fill(document);
  DS.init(document);
  DS.dom.followViewport();
  for (const view of document.querySelectorAll('.ds-app .ds-view')) DS.dom.watchScrolled(view);
  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-zs-signout]');
    if (button) busy(button, signOut(), { done: false }).catch(() => {});
  });
  // Coming back to a tab that slept: the stream may have missed notices.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && stream) emit(new Set(), true);
  });
}

function apps() {
  return [...document.querySelectorAll('body > .ds-app, [data-zs-app]')];
}

async function boot() {
  const loading = document.createElement('div');
  loading.className = 'ds-boot';
  loading.setAttribute('role', 'status');
  const loader = document.createElement('span');
  loader.className = 'ds-loader';
  loader.setAttribute('aria-hidden', 'true');
  loading.append(loader, 'Starting');
  document.body.prepend(loading);
  try {
    session = await api.get('/api/session');
  } catch (err) {
    loading.remove();
    showAuth({ error: api.errorMessage(err), retry: true });
    return;
  }
  loading.remove();
  if (session.signedIn) enter();
  else showAuth();
}

/* ------------------------------------------------------------ the app */

function enter() {
  if (auth) {
    auth.remove();
    auth = null;
  }
  for (const node of document.querySelectorAll('[data-zs-name]')) node.textContent = session.name;
  // An app without pages of its own has nothing to go back to: its links
  // to / (which leads here) go.
  if (!session.pages) for (const node of document.querySelectorAll('[data-zs-app-link]')) node.hidden = true;
  for (const node of document.querySelectorAll('[data-zs-version]')) node.textContent = session.version;
  if (!document.title) document.title = session.name;
  for (const node of document.querySelectorAll('.ds-account[data-zs-account]')) morph(node, accountHtml(session));
  for (const app of apps()) app.hidden = false;
  connect();
  if (!entered) {
    entered = true;
    const fns = readyFns;
    readyFns = [];
    for (const fn of fns) fn(session);
  } else {
    emit(new Set(), true);
  }
}

function accountHtml(s) {
  const tunnel = s.via === 'tunnel' && s.email;
  const name = tunnel ? s.email : 'Admin';
  const how = s.open ? 'Sign-in is off' : tunnel ? 'Signed in with Cloudflare Access' : 'Signed in with the password';
  const label = `${name}, ${how}`;
  return html`<div class="ds-account__text" aria-hidden="true"><div class="ds-account__name">${name}</div><div class="ds-account__email">${how}</div></div>
    <span class="ds-account__avatar" role="img" aria-label="${label}" tabindex="0" data-tip="${label}">${name.charAt(0).toUpperCase()}</span>
    ${s.open ? '' : html`<span class="ds-account__divider"></span><button class="ds-btn ds-btn--text" type="button" data-zs-signout>${faces('Sign out', 'Signing out')}</button>`}`;
}

function signedOut(message) {
  if (auth && auth.isConnected && !session?.signedIn) return;
  disconnect();
  // What the app said belongs to the app, not over the sign-in card.
  DS.overlay.closeToasts(null);
  if (session) session = { ...session, signedIn: false, needsPassword: false };
  showAuth({ notice: message });
}

/* --------------------------------------------------------- live updates */

function connect() {
  if (stream) return;
  let away = false;
  stream = api.live((topics) => emit(topics), (up, source) => {
    clearTimeout(offlineTimer);
    if (up) {
      if (away) {
        DS.overlay.closeToasts(null, { key: 'zs-offline' });
        emit(new Set(), true);
      }
      away = false;
      return;
    }
    away = true;
    if (source.readyState === EventSource.CLOSED) {
      // Refused, not lost: the session may have ended.
      stream = null;
      recheck();
      return;
    }
    offlineTimer = setTimeout(offline, 5000);
  });
}

function disconnect() {
  clearTimeout(offlineTimer);
  if (stream) stream.close();
  stream = null;
}

function offline() {
  toast(`${session ? session.name : 'The server'} does not answer. What you see stays until it is back; the page reconnects by itself.`,
    'error', { key: 'zs-offline' });
}

async function recheck() {
  try {
    const next = await api.get('/api/session');
    if (!next.signedIn) {
      session = next;
      signedOut('Your session ended. Sign in again.');
      return;
    }
    setTimeout(() => {
      if (session && session.signedIn && !auth) connect();
    }, 3000);
  } catch {
    offline();
    setTimeout(recheck, 5000);
  }
}

/* ------------------------------------------------------------ sign-in */

function showAuth({ notice = '', error = '', retry = false } = {}) {
  for (const app of apps()) app.hidden = true;
  if (!auth) {
    auth = document.createElement('main');
    auth.className = 'ds-auth';
    auth.id = 'zs-auth';
    auth.addEventListener('submit', onSubmit);
    auth.addEventListener('click', onAuthClick);
    auth.addEventListener('input', (event) => {
      if (event.target.getAttribute('aria-invalid') === 'true') setFieldError(event.target, '');
    });
    document.body.prepend(auth);
  }
  const s = session || {};
  const name = s.name || 'The app';
  let card;
  if (retry) card = unreachableHtml(name);
  else if (s.via === 'tunnel') card = accessHtml(s);
  else if (s.needsPassword) card = firstPasswordHtml(s);
  else card = signInHtml(s);
  morph(auth, html`<div class="ds-auth__alert" id="zs-auth-alert">${error ? alertHtml('error', error) : notice ? alertHtml('info', notice) : ''}</div>${card}`);
  const first = auth.querySelector('input');
  if (first) first.focus();
  else auth.querySelector('h1')?.focus();
}

function cardHtml(title, body) {
  return html`<section class="ds-card ds-card--elevated ds-auth__card" aria-labelledby="zs-auth-title">
    <h1 class="ds-card__title" id="zs-auth-title" tabindex="-1">${title}</h1>
    ${body}
  </section>`;
}

function signInHtml(s) {
  return cardHtml(`Sign in to ${s.name}`, html`<form class="ds-form" data-zs-form="login" novalidate>
    ${passwordField({ id: 'zs-login-password', name: 'password', label: 'Admin password', autocomplete: 'current-password',
      hint: `Lost it? Start the app again with a new password in its ${s.env ? s.env + '_' : ''}ADMIN_PASSWORD environment variable: that signs everybody out.` })}
    <div class="ds-form-actions"><button class="ds-btn ds-btn--filled" type="submit">${faces('Sign in', 'Signing in')}</button></div>
  </form>`);
}

function firstPasswordHtml(s) {
  return cardHtml('Set the admin password', html`<p class="ds-muted">${s.name} runs for the first time. Choose the password that signs in on this address: whoever sets it first owns it. Through a Cloudflare tunnel, Cloudflare Access signs people in instead.</p>
  <form class="ds-form" data-zs-form="first" novalidate>
    ${passwordField({ id: 'zs-first-password', name: 'password', label: 'New password', autocomplete: 'new-password', meter: true, minlength: 10 })}
    ${passwordField({ id: 'zs-first-repeat', name: 'repeat', label: 'Repeat it', autocomplete: 'new-password',
      hint: 'At least 10 characters. A sentence of a few words is easy to remember and hard to guess.' })}
    <div class="ds-form-actions"><button class="ds-btn ds-btn--filled" type="submit">${faces('Set password and sign in', 'Saving')}</button></div>
  </form>`);
}

function accessHtml(s) {
  return cardHtml(`Sign in to ${s.name}`, html`<p class="ds-muted">Through the tunnel, Cloudflare Access signs you in. Load the page again to sign in, or sign in with another address.</p>
  <div class="ds-form-actions">
    <button class="ds-btn ds-btn--filled" type="button" data-zs-act="reload">Load again</button>
    <a class="ds-btn ds-btn--text" href="${s.logout || '/cdn-cgi/access/logout'}">Use another address</a>
  </div>`);
}

function unreachableHtml(name) {
  return cardHtml(name, html`<p class="ds-muted">The page could not reach the server.</p>
  <div class="ds-form-actions"><button class="ds-btn ds-btn--filled" type="button" data-zs-act="retry">${faces('Try again', 'Trying')}</button></div>`);
}

function authAlert(kind, text) {
  const slot = document.getElementById('zs-auth-alert');
  if (slot) morph(slot, text ? alertHtml(kind, text) : '');
}

function onAuthClick(event) {
  const button = event.target.closest('[data-zs-act]');
  if (!button) return;
  if (button.dataset.zsAct === 'reload') location.reload();
  else if (button.dataset.zsAct === 'retry') {
    busy(button, api.get('/api/session'), { done: false }).then((next) => {
      session = next;
      if (session.signedIn) enter();
      else showAuth();
    }, (err) => authAlert('error', api.errorMessage(err)));
  }
}

async function onSubmit(event) {
  const form = event.target.closest('[data-zs-form]');
  if (!form) return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]');
  const password = form.elements.password;
  authAlert('', '');
  if (form.dataset.zsForm === 'login') {
    if (!password.value) {
      setFieldError(password, 'Enter the admin password.');
      password.focus();
      return;
    }
    try {
      await busy(button, api.post('/api/login', { password: password.value }), { done: false });
    } catch (err) {
      failed(err, { password });
      return;
    }
  } else {
    const repeat = form.elements.repeat;
    if (password.value.length < 10) {
      setFieldError(password, 'Use at least 10 characters.');
      password.focus();
      return;
    }
    if (repeat.value !== password.value) {
      setFieldError(repeat, 'The two passwords differ.');
      repeat.focus();
      return;
    }
    try {
      await busy(button, api.post('/api/setup/password', { password: password.value }), { done: false });
    } catch (err) {
      if (err.status === 409) {
        // Somebody else set it first: sign in with theirs.
        session = { ...session, needsPassword: false };
        showAuth({ error: err.message });
        return;
      }
      failed(err, { password });
      return;
    }
  }
  try {
    session = await api.get('/api/session');
  } catch (err) {
    authAlert('error', api.errorMessage(err));
    return;
  }
  if (session.signedIn) enter();
  else showAuth({ error: 'The server did not keep the session. Check that the browser allows cookies for this address.' });
}

function failed(err, byField) {
  if (!fieldErrors(err, byField)) {
    authAlert('error', api.errorMessage(err));
    const input = Object.values(byField)[0];
    if (input) input.focus();
  }
}
