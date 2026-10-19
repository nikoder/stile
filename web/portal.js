'use strict';

const $ = id => document.getElementById(id);
const rd = new URLSearchParams(location.search).get('rd') || '';

// A fresh tap of an enrolled key, unlocking exactly one operation of the
// declared kind.
async function stepUp(op) {
  showMsg($('msg'), 'Tap your key to confirm…');
  const options = await postJSON('/api/stepup/begin', { op });
  const result = await assertKey(options);
  const done = await sendResult('/api/stepup/finish', result);
  return done.action_token;
}

async function loadKeys() {
  const { keys } = await (await fetch('/api/keys')).json();
  const ul = $('keys');
  ul.textContent = '';
  const lastKey = keys.length === 1;
  for (const k of keys) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = k.name;
    name.title = 'last used ' + new Date(k.last_used_at).toLocaleString();
    const rename = document.createElement('button');
    rename.type = 'button';
    rename.className = 'mini';
    rename.textContent = 'rename';
    rename.addEventListener('click', async () => {
      const newName = prompt('New name for "' + k.name + '":', k.name);
      if (!newName) return;
      try {
        await postJSON('/api/keys/rename', { id: k.id, name: newName });
        await loadKeys();
      } catch (err) { showMsg($('msg'), err.message, 'error'); }
    });
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'mini danger';
    del.textContent = 'delete';
    del.addEventListener('click', async () => {
      // All warnings come BEFORE any key tap — nobody should authenticate
      // their way into a refusal or a surprise.
      const warning = lastKey
        ? '⚠️ "' + k.name + '" is your ONLY key.\n\nDeleting it LOCKS THIS ACCOUNT COMPLETELY: every session ends now, sign-in becomes impossible, and the only way back in is a fresh invite from an admin.\n\nDo this if the key is lost or stolen. Delete it?'
        : 'Delete key "' + k.name + '"?\n\nThis also signs you out everywhere else (the key might be lost or stolen — all existing sessions are revoked). This browser stays signed in.';
      if (!confirm(warning)) return;
      try {
        const action = await stepUp('delete-key');
        await postJSON('/api/keys/delete', { id: k.id, action_token: action, confirm_lockout: lastKey });
        if (lastKey) {
          alert('Key deleted. The account is locked until an admin re-invites it.');
          location.replace('/');
          return;
        }
        showMsg($('msg'), 'Key deleted; all other sessions revoked.', 'ok');
        await loadKeys();
      } catch (err) { showMsg($('msg'), err.message, 'error'); }
    });
    li.append(name, rename, del);
    ul.append(li);
  }
}

async function init() {
  const qs = rd ? '?rd=' + encodeURIComponent(rd) : '';
  let state = { authenticated: false };
  try {
    state = await (await fetch('/api/session' + qs)).json();
  } catch { /* fall through to the login form */ }

  if (state.authenticated) {
    $('who').textContent = state.username;
    $('authed').classList.remove('hidden');
    if (state.admin) $('adminBox').classList.remove('hidden');
    if (state.redirect) {
      // Already signed in with a destination pending: fetch a one-time
      // ticket and bounce straight on.
      try {
        const t = await postJSON('/api/ticket', { rd: state.redirect });
        location.replace(t.redirect);
        return;
      } catch { /* stay on the portal, show the manage view */ }
    }
    loadKeys().catch(() => {});
  } else {
    $('login').classList.remove('hidden');
    const last = localStorage.getItem('stile_username');
    if (last) $('username').value = last;
    $('username').focus();
    if (state.bootstrap) $('enrollHint').classList.remove('hidden');
  }
}

$('login').addEventListener('submit', async ev => {
  ev.preventDefault();
  const button = $('go');
  const username = $('username').value.trim().toLowerCase();
  if (!username) return;
  button.disabled = true;
  showMsg($('msg'), 'Tap your key…');
  try {
    const options = await postJSON('/api/login/begin', { username });
    const result = await assertKey(options);
    const qs = rd ? '?rd=' + encodeURIComponent(rd) : '';
    const done = await sendResult('/api/login/finish' + qs, result);
    localStorage.setItem('stile_username', username);
    showMsg($('msg'), 'Welcome!', 'ok');
    location.replace(done.redirect || '/');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
    button.disabled = false;
  }
});

$('addKey').addEventListener('click', async () => {
  const name = prompt('Name for the new key:');
  if (!name) return;
  try {
    const action = await stepUp('add-key');
    showMsg($('msg'), 'Now tap the NEW key…');
    const options = await postJSON('/api/keys/add/begin', { action_token: action, key_name: name });
    const result = await createKey(options);
    await sendResult('/api/enroll/finish', result);
    showMsg($('msg'), 'Key added.', 'ok');
    await loadKeys();
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  }
});

$('inviteForm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const username = $('inviteUser').value.trim().toLowerCase();
  if (!username) return;
  try {
    const action = await stepUp('invite');
    const inv = await postJSON('/api/invite', { username, action_token: action });
    $('inviteLink').value = inv.link;
    $('inviteOut').classList.remove('hidden');
    $('inviteNote').textContent = 'Single use, expires in ' + inv.expires_in_minutes + ' minutes.';
    showMsg($('msg'), 'Invite minted.', 'ok');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  }
});

$('inviteCopy').addEventListener('click', async () => {
  const link = $('inviteLink').value;
  if (!link) return;
  try {
    await navigator.clipboard.writeText(link);
    $('inviteCopy').textContent = 'Copied!';
  } catch {
    // Clipboard API can be denied; fall back to select-for-manual-copy.
    $('inviteLink').select();
    $('inviteCopy').textContent = 'Press Ctrl+C';
  }
  setTimeout(() => { $('inviteCopy').textContent = 'Copy'; }, 2000);
});

$('logout').addEventListener('click', async () => {
  try { await postJSON('/api/logout', {}); } catch { /* cookie clear is best-effort */ }
  location.replace('/');
});

$('logoutAll').addEventListener('click', async () => {
  if (!confirm('Sign out everywhere? Every session on every device and app dies immediately.')) return;
  try { await postJSON('/api/logout-all', {}); } catch (err) { showMsg($('msg'), err.message, 'error'); return; }
  location.replace('/');
});

init();
