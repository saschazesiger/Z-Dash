// api.js: the server's JSON API and its live change notices, for the shell
// and for the app's own pages.
//
// Every request that changes something carries the header X-Z-Dash: 1. The
// server refuses one without it (a form or a script on another site cannot
// send it), so the app's own POST, PUT and DELETE go through here too. A
// failed request rejects with an ApiError whose message is the server's
// sentence for the person, with the field errors of a checked form. A 401
// means the session ended: whenSignedOut() hears it, and the shell shows
// the sign-in card again.
//
// live() is the server-sent event stream (GET /api/events): the server
// names the topics that changed ("devices", "cloudflare"), and the page
// fetches again what it shows. Notices carry no data on purpose: there is
// one way to read the state, the API.

/** The header the server's CSRF guard asks for on every request that changes something. */
export const CSRF_HEADER = 'X-Z-Dash';

/** A failed request: `status` (0 when the server did not answer), `message` for the person, `fields` by name. */
export class ApiError extends Error {
  constructor(status, message, fields = {}, body = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fields = fields || {};
    this.body = body || {};
  }
}

let onSignedOut = () => {};

/** Calls `fn(error)` when the server answers 401: the session ended or was never there. */
export function whenSignedOut(fn) {
  onSignedOut = typeof fn === 'function' ? fn : () => {};
}

// A 401 from these is a wrong password, not an ended session.
const SIGN_IN = new Set(['/api/login', '/api/setup/password']);

/**
 * request sends one JSON request. `body` is sent as JSON (any value but
 * undefined); GET and HEAD send none. Resolves with the parsed answer
 * (an empty object when there is none).
 */
export async function request(method, path, body) {
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (method !== 'GET' && method !== 'HEAD') {
    init.headers[CSRF_HEADER] = '1';
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError(0, 'The server does not answer. Check that it runs and that this device can reach it.');
  }
  let data = {};
  const text = await response.text().catch(() => '');
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = {};
    }
  }
  if (!response.ok) {
    const error = new ApiError(response.status, (data && data.error) || `The server answered ${response.status}. Try again.`,
      data && data.fields, data);
    if (response.status === 401 && !SIGN_IN.has(path)) {
      try {
        onSignedOut(error);
      } catch (err) {
        reportError(err);
      }
    }
    throw error;
  }
  return data;
}

export const get = (path) => request('GET', path);
export const post = (path, body = {}) => request('POST', path, body);
export const put = (path, body = {}) => request('PUT', path, body);
export const del = (path) => request('DELETE', path);

/** isOffline says whether a request failed because the server did not answer. */
export function isOffline(err) {
  return err instanceof ApiError && err.status === 0;
}

/** errorMessage is one sentence for the person, whatever failed. */
export function errorMessage(err) {
  if (!err) return 'Something went wrong.';
  return err.message || String(err);
}

/**
 * live opens the event stream. `onTopics(topics)` gets a Set of the topics
 * that changed; `onStatus(up, source)` hears the stream come up and go
 * down (EventSource reconnects by itself while the server is away; a
 * refused stream, such as after a sign-out, stays closed:
 * `source.readyState === EventSource.CLOSED`). Returns `{ close() }`.
 */
export function live(onTopics, onStatus = () => {}) {
  const source = new EventSource('/api/events');
  source.addEventListener('open', () => onStatus(true, source));
  source.addEventListener('error', () => onStatus(source.readyState === EventSource.OPEN, source));
  source.addEventListener('change', (event) => {
    let topics;
    try {
      topics = new Set(JSON.parse(event.data).topics || []);
    } catch {
      topics = new Set();
    }
    if (topics.size) onTopics(topics);
  });
  return { close: () => source.close(), source };
}
