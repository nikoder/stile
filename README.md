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

## Threat model — read this before using it

The key tap defends against **remote** attacks: credential stuffing,
phishing (assertions are origin-bound), keylogging, database leaks (only
public keys are stored). It deliberately does **not** defend against
someone who physically steals your key and knows your username — if that
is in your threat model, you want a PIN and should use a mainstream IdP
instead. stile is built for the homelab operator who judged that trade
honestly.

Other sharp edges, stated plainly:

- Sessions are stateless HMAC cookies: logout clears the cookie but cannot
  invalidate a stolen copy before it expires. Revoke by deleting the user
  from `users.json` (checked on every request) or rotating
  `STILE_SESSION_SECRET` (logs everyone out).
- The session cookie is scoped to the whole `STILE_RP_ID` domain, so
  every service behind the proxy sees it. That is what makes it SSO — and
  it means a hostile/compromised service under the same domain could
  replay the cookie. Same model as Authelia/forward-auth generally.
- Enrollment is gated by one shared token. Leave `STILE_ENROLL_TOKEN`
  unset to disable enrollment entirely once your keys are registered.

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
  reverse_proxy app:8080
}
```

### Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `STILE_PORTAL_URL` | *(required)* | Public https URL of the portal, e.g. `https://tap.example.com` |
| `STILE_SESSION_SECRET` | *(required)* | ≥32 chars; HMAC key for session cookies (`openssl rand -hex 32`) |
| `STILE_RP_ID` | portal host | WebAuthn RP ID *and* cookie domain. Set to the parent domain (`example.com`) to cover sibling services |
| `STILE_ENROLL_TOKEN` | *(unset)* | Shared secret for `/enroll`; unset = enrollment disabled |
| `STILE_SESSION_TTL` | `720h` | Session lifetime (sliding: renewed when half-spent) |
| `STILE_LISTEN` | `:9092` | Bind address |
| `STILE_DATA` | `/data` | Directory for `users.json` |
| `STILE_EXTRA_ORIGINS` | *(unset)* | Comma-separated additional WebAuthn origins |
| `STILE_COOKIE_NAME` | `stile_session` | Session cookie name |
| `STILE_DISPLAY_NAME` | `stile` | RP name shown in authenticator UIs |

### Enrolling a key

1. Set `STILE_ENROLL_TOKEN` (e.g. `openssl rand -hex 16`) and restart.
2. Open `https://tap.example.com/enroll`, enter the token, a username and
   a key name, tap the key.
3. Optionally unset the token and restart to freeze enrollment.

Credentials are non-discoverable: they consume **no** storage slots on the
key, and the key never needs a PIN set at any point.

### Endpoints

| Path | Purpose |
|---|---|
| `GET /verify` | forward-auth check: 200 + `Remote-User` header, or 302 (browsers) / 401 (API clients) |
| `GET /` | login portal (`?rd=` = validated post-login redirect) |
| `GET /enroll` | enrollment page |
| `GET /healthz` | liveness |
| `POST /api/...` | ceremony endpoints used by the two pages |

## Building

```sh
go build .          # or:
docker build -t stile .
```

## License

MIT — see [LICENSE](LICENSE).
