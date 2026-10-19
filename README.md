# stile

A minimal WebAuthn forward-auth gate: **type your username, tap your
hardware key, you're in**. No password. No PIN.

A [stile](https://en.wikipedia.org/wiki/Stile) is the arrangement of steps
that lets a person cross a fence effortlessly while remaining a fence to
everything else. That is the whole design.

stile exists because of a gap in the current IdP landscape: usernameless
"passkey" login needs discoverable credentials, and mainstream browsers
(Chromium in particular) refuse to create or enumerate discoverable
credentials on a security key that has no PIN set. Every polished SSO
solution therefore quietly taxes hardware-key users with either a PIN or a
password. stile instead runs the *username-first* WebAuthn flow: the
server already knows your credential IDs, sends them in `allowCredentials`,
and the browser performs a presence-only (`userVerification: discouraged`)
assertion — which every major browser happily does on a PIN-less key.

## How sessions work (two tiers, no domain-wide cookie)

Nothing stile mints is ever a domain-wide bearer token:

1. Logging in at the portal sets a **host-only portal cookie** on the
   portal origin. Long-lived, renewed sliding while you keep using it. No
   backend ever sees it.
2. Visiting a protected app without a session bounces you to the portal,
   which mints a **one-time ticket** (single use, ~30 s, bound to your
   user and that app's hostname) and redirects back with
   `?stile_ticket=CODE`. The forward-auth endpoint redeems it — before the
   backend sees the request — into a **host-only service cookie** for that
   app alone (short-lived; when it expires the re-bounce through the
   portal is silent). A compromised backend can replay its own cookie
   against itself until expiry, and nothing else.
3. **Revocation**: every user record in `users.json` has a
   `session_epoch`, embedded in every cookie at mint time and compared on
   every check. Bump the number (just edit the file — it is re-read on
   change, no restart) and every outstanding session for that user dies
   within one request. Deleting the user works too.

## Threat model — read this before using it

The key tap defends against **remote** attacks: credential stuffing,
phishing (assertions are origin-bound), keylogging, database leaks (only
public keys are stored). It deliberately does **not** defend against
someone who physically steals your key and knows your username — if that
is in your threat model, you want a PIN and should use a mainstream IdP
instead. stile is built for the operator who judged that trade honestly.

Other sharp edges, stated plainly:

- Cookies are stateless HMAC tokens: logout clears the portal cookie but
  cannot invalidate a stolen copy. The epoch bump above is the real
  revocation lever (rotating `STILE_SESSION_SECRET` logs everyone out).
- forward_auth only protects the proxy's path. A service with a
  LAN-reachable port is **not** behind stile until that port is closed,
  and `Remote-User` is forgeable by anything that can reach the backend
  directly — keep per-app trust secrets if the backend is reachable at all.
- SameSite is computed on the registrable domain: XSS in (or compromise
  of) *any* site on it can fire blind authenticated requests at protected
  services from a logged-in browser. Backend CSRF protections remain
  load-bearing.
- The portal remembers the last username in localStorage, so on a
  previously-used machine a borrowed key alone signs in — coherent with
  the accepted physical-theft trade-off, but know it's there.

## Deployment

stile is a single static binary / scratch container listening on `:9092`.
It must only be reachable through your TLS-terminating reverse proxy.

### Caddy

```caddyfile
# the login portal
@tap host tap.example.com
reverse_proxy @tap stile:9092

# a protected service
@app host app.example.com
route @app {
  forward_auth stile:9092 {
    uri /verify
    copy_headers Remote-User
  }
  # hygiene: the backend never needs stile's cookie
  request_header Cookie "(;\s*)?stile_svc=[^;]*" ""
  reverse_proxy app:8080
}
```

### Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `STILE_PORTAL_URL` | *(required)* | Public https URL of the portal, e.g. `https://tap.example.com` |
| `STILE_SESSION_SECRET` | *(required)* | ≥32 chars; HMAC key for all tokens (`openssl rand -hex 32`) |
| `STILE_RP_ID` | portal host | WebAuthn RP ID, and the domain zone protected apps may live under. Does **not** scope any cookie |
| `STILE_BOOTSTRAP_TOKEN` | *(unset)* | Enrolls the **first** user only (who becomes admin); inert once any user exists |
| `STILE_ADMIN_USERS` | *(unset)* | Comma-separated extra admin usernames |
| `STILE_SESSION_TTL` | `720h` | Portal session lifetime (sliding) |
| `STILE_SVC_TTL` | `8h` | Per-app service cookie lifetime |
| `STILE_LISTEN` | `:9092` | Bind address |
| `STILE_DATA` | `/data` | Directory for `users.json` |
| `STILE_EXTRA_ORIGINS` | *(unset)* | Comma-separated additional WebAuthn origins |
| `STILE_COOKIE_NAME` | `stile_session` | Portal cookie name |
| `STILE_DISPLAY_NAME` | `stile` | RP name shown in authenticator UIs |

### Enrollment and key management

- **First run**: set `STILE_BOOTSTRAP_TOKEN`, open `/enroll`, enter it
  with your username — this account becomes the admin. The token is inert
  from then on.
- **Further users/keys**: an admin mints a single-use, 15-minute,
  username-bound invite from the portal (this costs a fresh key tap).
  Invite links are safe to send — they are nothing like a standing shared
  secret.
- **Self-service**: the portal lists your keys; rename freely. Adding or
  deleting a key requires a **fresh tap of an existing key** (step-up),
  never just the session cookie — a stolen session cannot convert itself
  into a permanent credential. The last key cannot be deleted.

Credentials are non-discoverable: they consume **no** storage slots on the
key, and the key never needs a PIN set at any point.

### Endpoints

| Path | Purpose |
|---|---|
| `GET /verify` | forward-auth check: redeems tickets, validates service cookies; 200 + `Remote-User`, or 302 (browsers) / 401 (API clients). Honors `X-Forwarded-*` only on real forward_auth subrequests |
| `GET /` | login portal + key management (`?rd=` = validated post-login redirect) |
| `GET /enroll` | enrollment page (bootstrap token or invite code) |
| `GET /healthz` | liveness |
| `POST /api/...` | ceremony, ticket, step-up, key and invite endpoints used by the two pages |

## Building

```sh
go build .          # or:
docker build -t stile .
```

## License

MIT — see [LICENSE](LICENSE).
