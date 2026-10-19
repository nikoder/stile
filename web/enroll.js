'use strict';

const $ = id => document.getElementById(id);

const presetToken = new URLSearchParams(location.search).get('token');
if (presetToken) $('token').value = presetToken;

// Surface the server-side state up front; /api/enroll/begin enforces it.
fetch('/api/session').then(r => r.json()).then(state => {
  if (!state.enrollment) {
    $('go').disabled = true;
    showMsg($('msg'), 'Enrollment is disabled on this server (no enrollment token set).', 'error');
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
