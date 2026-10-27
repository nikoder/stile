'use strict';

const $ = id => document.getElementById(id);
const rd = new URLSearchParams(location.search).get('rd') || '';

// A fresh tap of an enrolled key, unlocking exactly one operation of the
// declared kind.
async function stepUp(op, msg) {
  showMsg($('msg'), msg || 'Tap your key to confirm…');
  const options = await postJSON('/api/stepup/begin', { op });
  const result = await assertKey(options);
  const done = await sendResult('/api/stepup/finish', result);
  return done.action_token;
}

let keyNames = [];

async function loadKeys() {
  const { keys } = await (await fetch('/api/keys')).json();
  keyNames = keys.map(k => k.name);
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
        ? '⚠️ "' + k.name + '" is your ONLY key.\n\nDeleting it LOCKS THIS ACCOUNT COMPLETELY: every session ends now, sign-in becomes impossible, and the only way back in is a fresh invite from an admin.\n\nThis is for RETIRING a key you still hold (the next step asks you to tap it). If the key is lost or stolen, use the Freeze button instead. Delete it?'
        : 'Delete key "' + k.name + '"?\n\nThis also signs you out everywhere else (the key might be lost or distrusted — all existing sessions are revoked). This browser stays signed in.';
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
let sessionState = { authenticated: false };

// renderFreezeBox paints the freeze capabilities from current state —
// called at load and again whenever fresher state arrives (e.g. after a
// failed freeze reveals the token was disarmed behind this page's back).
function renderFreezeBox() {
  const show = freeze.armed || sessionState.authenticated;
  $('freezeBox').classList.toggle('hidden', !show);
  $('freezeWho').textContent = freeze.armed
    ? '"' + freeze.username + '"'
    : (sessionState.authenticated ? '"' + sessionState.username + '"' : '');
  const self = sessionState.authenticated && freeze.armed && freeze.username !== sessionState.username;
  $('freezeSelfBtn').classList.toggle('hidden', !self);
  if (!$('login').classList.contains('hidden')) evaluateTrustChoice();
}

async function init() {
  const qs = rd ? '?rd=' + encodeURIComponent(rd) : '';
  let state = { authenticated: false };
  // Deliberately NOT coupled: if the session endpoint hiccups, the
  // freeze button on an armed device must still appear — it's the
  // panic path.
  const [sRes, fRes] = await Promise.allSettled([
    fetch('/api/session' + qs).then(r => r.json()),
    fetch('/api/freeze/status').then(r => r.json()),
  ]);
  if (sRes.status === 'fulfilled') state = sRes.value;
  if (fRes.status === 'fulfilled') freeze = fRes.value;
  sessionState = state;

  // Freeze buttons mirror the device's REAL capabilities, one per
  // distinct account it can freeze: the device token's user (shown even
  // to other logged-in users — the capability is the device's, and
  // hiding it would be theater: anyone here could log out and press it)
  // and the signed-in user when they differ.
  $('freezeSelfWho').textContent = state.authenticated ? '"' + state.username + '"' : '';
  renderFreezeBox();

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
        // Someone else's token: never touch it from this session — no
        // slide, and no one-click Forget either (destroying another
        // user's panic button shouldn't be a casual affordance; the
        // owner gets Forget when THEY sign in). Arming for this user
        // is an explicit login-time choice.
        $('armedWho').textContent = ' for "' + freeze.username + '"';
        $('forgetBtn').classList.add('hidden');
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
    // The trust choice is device-AND-account scoped: it's only needed
    // when this device holds no freeze token for the username being
    // entered. Re-evaluated as the username changes.
    $('username').addEventListener('input', evaluateTrustChoice);
    evaluateTrustChoice();
  }
}

// deviceReturningFor reports whether this device already holds a freeze
// token for the given username (so no trust choice is needed).
function deviceReturningFor(username) {
  return freeze.armed && freeze.username === username;
}

function evaluateTrustChoice() {
  const username = $('username').value.trim().toLowerCase();
  const show = !deviceReturningFor(username);
  $('trustChoice').classList.toggle('hidden', !show);
}

$('login').addEventListener('submit', async ev => {
  ev.preventDefault();
  const button = $('go');
  const username = $('username').value.trim().toLowerCase();
  if (!username) return;
  // Press-time freshness: the page-load status may be stale (the token
  // can be disarmed behind an open tab), and a wrong "returning" call
  // here would silently skip minting. Re-check before deciding.
  try {
    freeze = await (await fetch('/api/freeze/status')).json();
  } catch { /* keep last known state */ }
  evaluateTrustChoice();
  // The trust decision is mandatory and explicit UNLESS this device is
  // already a trusted device for this exact account (returning device).
  let trust = 'returning';
  if (!deviceReturningFor(username)) {
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

async function doFreeze(scope) {
  if (!confirm('Freeze this account?\n\nEvery session on every device and app ends immediately and sign-in is blocked until an admin clears the dispute. Do this if a key is lost or stolen.')) return;
  try {
    // Fresh pre-check at press time (not page-load state): a session that
    // expired while the tab idled must not let "session died" later read
    // as proof the freeze landed.
    const pre = await fetch('/api/session').then(r => r.json()).catch(() => ({ authenticated: false }));
    const wasAuthenticated = !!pre.authenticated;
    await postJSON('/api/freeze', scope ? { scope } : {});
    // The server's answer is deliberately uniform (no oracle for
    // outsiders), so verify truthfully with information this DEVICE is
    // already entitled to: its own token validity and session state.
    // False "success" to a panicking owner whose token was disarmed
    // would be the worst possible failure mode here.
    let stOK = true, sessOK = true;
    const [st, sess] = await Promise.all([
      fetch('/api/freeze/status').then(r => r.json()).catch(() => { stOK = false; return { armed: false }; }),
      fetch('/api/session').then(r => r.json()).catch(() => { sessOK = false; return { authenticated: true }; }),
    ]);
    // The verification fetches are also the freshest state this page
    // has — adopt them, so a disarmed-behind-our-back token updates the
    // buttons and the login form's trust logic instead of going stale.
    // But adopt only FULFILLED fetches: the catch values above are
    // conservative defaults for the landed-verdict, not real state.
    if (stOK) freeze = st;
    if (sessOK) sessionState = sess;
    renderFreezeBox();
    // Token path proof: a still-valid token means the freeze landed on
    // its account (tokens survive their own freeze). Session path proof:
    // our session just died (the freeze bumps the epoch).
    const landed = (!scope && st.armed) || (wasAuthenticated && !sess.authenticated);
    if (landed) {
      showMsg($('msg'), 'Account frozen. All sessions revoked; sign-in is blocked until an admin clears the dispute.', 'ok');
      // The freeze killed OUR session too when it targeted our account —
      // deliberately: a (possibly stolen) session must never survive by
      // pressing freeze, and the disputed seal refuses it anyway. Swap
      // the view to match instead of showing a dead signed-in state.
      if (wasAuthenticated && !sess.authenticated) {
        $('authed').classList.add('hidden');
        $('adminBox').classList.add('hidden');
        $('login').classList.remove('hidden');
        renderFreezeBox();
      }
    } else {
      showMsg($('msg'), 'FREEZE DID NOT TAKE EFFECT: this device holds no valid freeze token and no active session. Sign in to freeze, use another trusted device, or contact your admin.', 'error');
    }
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  }
}

$('freezeBtn').addEventListener('click', () => doFreeze(''));
$('freezeSelfBtn').addEventListener('click', () => doFreeze('session'));

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
  const name = prompt('Name for the NEW key:');
  if (!name) return;
  // The browser's own WebAuthn sheet can't be relabeled, and presenting
  // the new key during step-up earns an opaque "key not recognized"
  // from the authenticator layer — so set expectations BEFORE any sheet
  // appears, naming the keys that step 1 will actually accept.
  const existing = keyNames.length ? '"' + keyNames.join('", "') + '"' : 'an already-enrolled key';
  if (!confirm('Adding a key takes TWO taps:\n\n'
      + 'Step 1 — AUTHORIZE: tap a key that is ALREADY enrolled (' + existing + ').\n'
      + 'Step 2 — ENROLL: when prompted again, tap the NEW key.\n\n'
      + 'Ready? The next tap is Step 1 — the EXISTING key, not the new one.')) return;
  let action;
  try {
    action = await stepUp('add-key', 'Step 1 of 2: tap your EXISTING key (' + existing + ')…');
  } catch (err) {
    showMsg($('msg'), (err.message || String(err))
      + ' — Step 1 needs a key that is already enrolled; the NEW key only comes in Step 2.', 'error');
    return;
  }
  try {
    showMsg($('msg'), 'Step 2 of 2: now insert & tap the NEW key…');
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
