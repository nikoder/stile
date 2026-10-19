// Shared helpers: base64url <-> ArrayBuffer and ceremony plumbing.
'use strict';

const b64u = {
  dec(s) {
    return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  },
  enc(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('request failed (' + res.status + ')'));
  return data;
}

// navigator.credentials.get with options freshly fetched from the server.
async function assertKey(options) {
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map(c => ({ ...c, id: b64u.dec(c.id) }));
  const cred = await navigator.credentials.get({ publicKey: pk });
  return {
    id: cred.id,
    rawId: b64u.enc(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: b64u.enc(cred.response.authenticatorData),
      clientDataJSON: b64u.enc(cred.response.clientDataJSON),
      signature: b64u.enc(cred.response.signature),
      userHandle: cred.response.userHandle ? b64u.enc(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

// navigator.credentials.create for enrollment.
async function createKey(options) {
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map(c => ({ ...c, id: b64u.dec(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: pk });
  const out = {
    id: cred.id,
    rawId: b64u.enc(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: b64u.enc(cred.response.attestationObject),
      clientDataJSON: b64u.enc(cred.response.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  if (cred.response.getTransports) out.response.transports = cred.response.getTransports();
  return out;
}

async function sendResult(url, result) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(result),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('request failed (' + res.status + ')'));
  return data;
}

function showMsg(el, text, cls) {
  el.textContent = text;
  el.className = 'msg' + (cls ? ' ' + cls : '');
}
