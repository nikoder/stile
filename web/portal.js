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

let freeze = { armed: false };

async function init() {
  const qs = rd ? '?rd=' + encodeURIComponent(rd) : '';
  let state = { authenticated: false };
  try {
    [state, freeze] = await Promise.all([
      fetch('/api/session' + qs).then(r => r.json()),
      fetch('/api/freeze/status').then(r => r.json()),
    ]);
  } catch { /* fall through to the login form */ }

  // The freeze button works with a device token OR a live session —
  // visible whenever either exists.
  if (freeze.armed || state.authenticated) {
    $('freezeWho').textContent = freeze.armed ? '"' + freeze.username + '"' : '';
    $('freezeBox').classList.remove('hidden');
  }

  if (state.authenticated) {
    $('who').textContent = state.username;
    $('authed').classList.remove('hidden');
    if (state.admin) $('adminBox').classList.remove('hidden');
    if (freeze.armed) {
      $('armedRow').classList.remove('hidden');
      if (freeze.username === state.username) {
        // Slide the token's lifetime on authenticated visits — own token,
        // non-public session only (the server enforces both).
        if (!state.public) postJSON('/api/freeze/arm', {}).catch(() => {});
      } else {
        // Someone else's token: never silently clobber it. Arming for
        // this user is an explicit login-time choice after a Forget.
        $('armedWho').textContent = ' for "' + freeze.username + '"';
      }
    } else if (!state.public) {
      $('armRow').classList.remove('hidden');
    }
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
    // One-time per-device trust decision: only asked when the device
    // carries no freeze token, with no silent default.
    if (!freeze.armed) $('trustChoice').classList.remove('hidden');
  }
}

$('login').addEventListener('submit', async ev => {
  ev.preventDefault();
  const button = $('go');
  const username = $('username').value.trim().toLowerCase();
  if (!username) return;
  // On a token-less device the trust decision is mandatory and explicit.
  let trust = 'returning';
  if (!freeze.armed) {
    const picked = document.querySelector('input[name="trust"]:checked');
    if (!picked) {
      showMsg($('msg'), 'Choose whether this is your own device first.', 'error');
      return;
    }
    trust = picked.value;
  }
  const isPublic = trust === 'public';
  button.disabled = true;
  showMsg($('msg'), 'Tap your key…');
  try {
    const options = await postJSON('/api/login/begin', { username });
    const result = await assertKey(options);
    const params = new URLSearchParams();
    if (rd) params.set('rd', rd);
    if (isPublic) params.set('public', '1');
    // Arming rides the login tap itself (the server mints the freeze
    // token on the finish response) — a bare session can't arm devices.
    if (trust === 'trust') params.set('trust', '1');
    const qs = params.toString() ? '?' + params.toString() : '';
    const done = await sendResult('/api/login/finish' + qs, result);
    if (!isPublic) localStorage.setItem('stile_username', username);
    showMsg($('msg'), 'Welcome!', 'ok');
    location.replace(done.redirect || '/');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
    button.disabled = false;
  }
});

$('freezeBtn').addEventListener('click', async () => {
  if (!confirm('Freeze this account?\n\nEvery session on every device and app ends immediately and sign-in is blocked until an admin clears the dispute. Do this if a key is lost or stolen.')) return;
  try {
    await postJSON('/api/freeze', {});
    showMsg($('msg'), 'Account frozen. All sessions revoked; sign-in is blocked until an admin clears the dispute.', 'ok');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  }
});

$('forgetBtn').addEventListener('click', async () => {
  if (!confirm('Remove the emergency freeze token from this device?\n\nThis device will no longer be able to freeze the account without signing in.')) return;
  try { await postJSON('/api/freeze/forget', {}); } catch { /* best-effort */ }
  location.reload();
});

$('disarmForm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const username = $('disarmUser').value.trim().toLowerCase();
  if (!username) return;
  try {
    const action = await stepUp('disarm-freeze');
    await postJSON('/api/freeze/disarm', { username, action_token: action });
    showMsg($('msg'), 'All freeze tokens for "' + username + '" disarmed.', 'ok');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  }
});

$('disputeForm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const username = $('disputeUser').value.trim().toLowerCase();
  if (!username) return;
  try {
    const action = await stepUp('clear-dispute');
    await postJSON('/api/dispute/clear', { username, action_token: action });
    showMsg($('msg'), 'Dispute cleared for "' + username + '" — they can sign in again.', 'ok');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
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
