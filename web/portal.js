'use strict';

const $ = id => document.getElementById(id);
const rd = new URLSearchParams(location.search).get('rd') || '';

async function init() {
  const qs = rd ? '?rd=' + encodeURIComponent(rd) : '';
  let state = { authenticated: false };
  try {
    state = await (await fetch('/api/session' + qs)).json();
  } catch { /* fall through to the login form */ }

  if (state.authenticated) {
    $('who').textContent = state.username;
    $('authed').classList.remove('hidden');
    if (state.redirect) {
      // Mid-flow bounce: already signed in (e.g. another tab), go straight on.
      location.replace(state.redirect);
      return;
    }
  } else {
    $('login').classList.remove('hidden');
    const last = localStorage.getItem('stile_username');
    if (last) $('username').value = last;
    $('username').focus();
  }
  if (state.enrollment) $('enrollHint').classList.remove('hidden');
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

$('logout').addEventListener('click', async () => {
  try { await postJSON('/api/logout', {}); } catch { /* cookie clear is best-effort */ }
  location.replace('/');
});

init();
