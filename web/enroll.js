'use strict';

const $ = id => document.getElementById(id);

// Invite links carry a single-use, expiring, username-bound code — safe to
// prefill from the URL (unlike a standing shared secret, which never
// belongs in one).
const params = new URLSearchParams(location.search);
if (params.get('invite')) $('token').value = params.get('invite');
if (params.get('username')) $('username').value = params.get('username');

// First run (no users yet): the field takes the bootstrap token instead.
fetch('/api/session').then(r => r.json()).then(state => {
  if (state.bootstrap) {
    $('tokenLabel').textContent = 'Bootstrap token';
    $('blurb').textContent = 'First-time setup: enter the bootstrap token from '
      + 'the server config. This first account becomes the admin.';
  }
}).catch(() => { /* the begin call will report any real problem */ });

$('enroll').addEventListener('submit', async ev => {
  ev.preventDefault();
  const button = $('go');
  button.disabled = true;
  showMsg($('msg'), 'Tap your key…');
  try {
    const options = await postJSON('/api/enroll/begin', {
      token: $('token').value.trim(),
      username: $('username').value.trim().toLowerCase(),
      key_name: $('keyname').value.trim(),
    });
    const result = await createKey(options);
    await sendResult('/api/enroll/finish', result);
    showMsg($('msg'), 'Key enrolled. You can sign in now.', 'ok');
  } catch (err) {
    showMsg($('msg'), err.message || String(err), 'error');
  } finally {
    button.disabled = false;
  }
});
