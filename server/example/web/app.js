// app.js: the example app's page, the template for a new app on the server.
//
// The shell (sign-in, account, live notices) comes from /z-dash/server/;
// this file only loads, shows and changes the app's own data: a list of
// devices (GET, POST /api/devices, DELETE /api/devices/{id}). The server
// sends the change notice "devices" after every change, from any browser,
// and the list fetches again.

import { start, on } from '/z-dash/server/shell.js';
import { get, post, del, errorMessage } from '/z-dash/server/api.js';
import { html, icon, morph, busy, toast, confirm, alertHtml, setFieldError, fieldErrors } from '/z-dash/server/ui.js';

const list = document.getElementById('devices');
const form = document.getElementById('add-device');

await start();

async function load() {
  try {
    render(await get('/api/devices'));
  } catch (err) {
    morph(list, alertHtml('error', errorMessage(err), {
      actions: html`<button class="ds-btn ds-btn--text ds-sm" type="button" data-act="retry">Try again</button>`,
    }));
  }
}

function render(devices) {
  if (!devices.length) {
    morph(list, html`<div class="ds-empty">
      <span class="ds-empty__disc" aria-hidden="true">${icon('laptop', 24)}</span>
      <p class="ds-empty__title">No devices yet</p>
      <p class="ds-empty__text">Add the first one above.</p>
    </div>`);
    return;
  }
  morph(list, html`<div class="ds-table-wrap">
    <table class="ds-table">
      <caption class="ds-sr">Devices</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">Room</th><th scope="col" class="ds-num"><span class="ds-sr">Actions</span></th></tr></thead>
      <tbody>${devices.map((d) => html`<tr data-ds-key="${'d' + d.id}">
        <td class="ds-col--text">${d.name}</td>
        <td>${d.room || '—'}</td>
        <td class="ds-num"><button class="ds-btn ds-btn--quiet ds-btn--icon ds-sm" type="button" data-remove="${d.id}" data-name="${d.name}" aria-label="${'Remove ' + d.name}" data-tip="${'Remove ' + d.name}">${icon('trash', 18)}</button></td>
      </tr>`)}</tbody>
    </table>
  </div>`);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = form.elements.name;
  if (!name.value.trim()) {
    setFieldError(name, 'Enter a name.');
    name.focus();
    return;
  }
  try {
    await busy(form.querySelector('[type="submit"]'), post('/api/devices', { name: name.value, room: form.elements.room.value }));
  } catch (err) {
    if (!fieldErrors(err, { name })) toast(errorMessage(err), 'error');
    return;
  }
  toast(`Added ${name.value.trim()}.`);
  form.reset();
  name.focus();
  load();
});

form.addEventListener('input', (event) => {
  if (event.target.getAttribute('aria-invalid') === 'true') setFieldError(event.target, '');
});

list.addEventListener('click', async (event) => {
  if (event.target.closest('[data-act="retry"]')) {
    load();
    return;
  }
  const button = event.target.closest('[data-remove]');
  if (!button) return;
  const removed = await confirm({
    title: `Remove ${button.dataset.name}?`,
    text: 'It disappears from the list in every browser.',
    confirmLabel: 'Remove device',
    destructive: true,
    opener: button,
    onConfirm: () => del(`/api/devices/${encodeURIComponent(button.dataset.remove)}`),
    errorText: 'The device could not be removed.',
  });
  if (removed) {
    toast(`Removed ${button.dataset.name}.`);
    load();
  }
});

on('devices', load);
load();
