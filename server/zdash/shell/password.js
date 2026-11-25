// password.js: changing the admin password, drawn into a container (the
// "Password" card of the server settings, or one of an app's own pages).
//
// POST /api/password { current, password }. On the local address the
// current password is asked for; through the tunnel Cloudflare Access
// vouched for the person, so the server does not need it and the form does
// not ask. Changing it signs every other browser out; this one stays signed
// in. The form is drawn once and then only its errors change (setFieldError),
// so the strength meter and the reveal of DS.password keep their state.

import { post, errorMessage } from './api.js';
import { html, morph, faces, busy, toast, alertHtml, passwordField, setFieldError, fieldErrors } from './ui.js';

const MIN = 10;

/**
 * mountPassword draws the form into `host`. `session` is GET /api/session's
 * answer (start() of shell.js resolves with it). Returns `{ destroy }`.
 */
export function mountPassword(host, session) {
  const tunnel = session && session.via === 'tunnel';
  morph(host, html`<form class="ds-form" novalidate data-zs-password>
    <p class="ds-muted">The password signs in on the local address. Changing it signs out every other browser.</p>
    ${tunnel ? alertHtml('info', `You came through Cloudflare Access as ${session.email}: the current password is not needed.`) : ''}
    <div class="ds-form-grid ds-form-grid--2">
      ${tunnel ? '' : passwordField({ id: 'zs-pw-current', name: 'current', label: 'Current password', autocomplete: 'current-password' })}
      ${passwordField({ id: 'zs-pw-new', name: 'password', label: 'New password', autocomplete: 'new-password', meter: true, minlength: MIN })}
    </div>
    <div class="ds-form-actions"><button class="ds-btn" type="submit">${faces('Change password', 'Changing', 'Changed')}</button></div>
    <div data-zs-password-alert hidden></div>
  </form>`);
  const form = host.querySelector('[data-zs-password]');
  const current = form.elements.current || null;
  const next = form.elements.password;
  const button = form.querySelector('[type="submit"]');
  const slot = form.querySelector('[data-zs-password-alert]');

  async function onSubmit(event) {
    event.preventDefault();
    showAlert('');
    if (current && !current.value) {
      setFieldError(current, 'Enter the current password.');
      current.focus();
      return;
    }
    if (next.value.length < MIN) {
      setFieldError(next, `Use at least ${MIN} characters.`);
      next.focus();
      return;
    }
    try {
      const res = await busy(button, post('/api/password', { current: current ? current.value : '', password: next.value }));
      form.reset();
      next.dispatchEvent(new Event('input', { bubbles: true }));
      toast(res.message || 'Password changed.', 'success');
    } catch (err) {
      const fields = { password: next };
      if (current) fields.current = current;
      if (!fieldErrors(err, fields)) showAlert(errorMessage(err));
    }
  }

  // The slot takes no room in the form's rhythm while it is empty.
  function showAlert(text) {
    morph(slot, text ? alertHtml('error', text) : '');
    slot.hidden = !text;
  }

  function onInput(event) {
    if (event.target.getAttribute('aria-invalid') === 'true') setFieldError(event.target, '');
  }

  form.addEventListener('submit', onSubmit);
  form.addEventListener('input', onInput);
  return {
    destroy() {
      form.removeEventListener('submit', onSubmit);
      form.removeEventListener('input', onInput);
    },
  };
}
