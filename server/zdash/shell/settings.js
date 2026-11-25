// settings.js: the shell's own page at /z-dash/server/, the server settings
// every app on the server has: remote access through a Cloudflare tunnel
// (tunnel.js) and the admin password (password.js). An app without settings
// of its own links its drawer here; one with its own settings page may
// mount the same two parts there instead.

import { start } from './shell.js';
import { mountTunnel } from './tunnel.js';
import { mountPassword } from './password.js';

const session = await start();
document.title = `Server settings · ${session.name}`;
mountTunnel(document.getElementById('zs-tunnel'), { name: session.name });
mountPassword(document.getElementById('zs-password'), session);
