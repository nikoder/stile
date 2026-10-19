package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type App struct {
	cfg     *Config
	store   *Store
	wa      *webauthn.WebAuthn
	pending *pendingStore
	limiter *limiter
}

const ceremonyCookie = "stile_ceremony"

var usernameRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

func (a *App) Routes(static fs.FS) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", a.servePage(static, "portal.html"))
	mux.HandleFunc("GET /enroll", a.servePage(static, "enroll.html"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /verify", a.handleVerify)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /api/session", a.handleSession)
	mux.HandleFunc("POST /api/login/begin", a.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", a.handleLoginFinish)
	mux.HandleFunc("POST /api/enroll/begin", a.handleEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", a.handleEnrollFinish)
	mux.HandleFunc("POST /api/logout", a.handleLogout)

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *App) servePage(static fs.FS, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := fs.ReadFile(static, name)
		if err != nil {
			http.Error(w, "missing page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(raw)
	}
}

// ---- forward auth -------------------------------------------------------

// handleVerify is the Caddy forward_auth endpoint: 200 + Remote-User when
// the session cookie is valid; otherwise 302 to the portal for browser
// navigations (Accept: text/html) and plain 401 for API clients.
func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	if sess, ok := a.checkSession(r); ok {
		a.maybeRenew(w, sess)
		w.Header().Set("Remote-User", sess.Username)
		w.WriteHeader(http.StatusOK)
		return
	}

	host := r.Header.Get("X-Forwarded-Host")
	if strings.Contains(r.Header.Get("Accept"), "text/html") && host != "" {
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		rd := proto + "://" + host + r.Header.Get("X-Forwarded-Uri")
		http.Redirect(w, r, a.cfg.PortalURL.String()+"/?rd="+url.QueryEscape(rd), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (a *App) checkSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(a.cfg.CookieName)
	if err != nil {
		return Session{}, false
	}
	sess, err := verifySession(a.cfg.SessionSecret, c.Value, time.Now())
	if err != nil {
		return Session{}, false
	}
	// The user must still exist and still own at least one credential —
	// deleting a user from users.json revokes their sessions.
	rec := a.store.Get(sess.Username)
	if rec == nil || len(rec.Credentials) == 0 {
		return Session{}, false
	}
	return sess, true
}

// maybeRenew re-issues the cookie once less than half the TTL remains, so
// an actively used session never expires mid-use.
func (a *App) maybeRenew(w http.ResponseWriter, sess Session) {
	remaining := time.Until(time.Unix(sess.Expiry, 0))
	if remaining > a.cfg.SessionTTL/2 {
		return
	}
	a.setSessionCookie(w, sess.Username)
}

func (a *App) setSessionCookie(w http.ResponseWriter, username string) {
	exp := time.Now().Add(a.cfg.SessionTTL)
	tok, err := signSession(a.cfg.SessionSecret, Session{
		Username: username,
		IssuedAt: time.Now().Unix(),
		Expiry:   exp.Unix(),
	})
	if err != nil {
		log.Printf("sign session: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    tok,
		Domain:   a.cfg.RPID,
		Path:     "/",
		Expires:  exp,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---- portal API ---------------------------------------------------------

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"authenticated": false,
		// Lets the pages show/hide the enrollment UI; the begin endpoint
		// is what actually enforces it.
		"enrollment": a.cfg.EnrollToken != "",
	}
	if sess, ok := a.checkSession(r); ok {
		resp["authenticated"] = true
		resp["username"] = sess.Username
	}
	// The portal echoes ?rd= back through the server so redirect targets
	// are validated in exactly one place.
	if rd := a.safeRedirect(r.URL.Query().Get("rd")); rd != "" {
		resp["redirect"] = rd
	}
	writeJSON(w, resp)
}

func (a *App) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !a.guardCeremony(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))

	rec := a.store.Get(req.Username)
	if !usernameRe.MatchString(req.Username) || rec == nil || len(rec.Credentials) == 0 {
		// Uniform failure: don't leak which usernames exist.
		a.limiter.Allow("fail:"+clientIP(r), 10)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}

	opts, sess, err := a.wa.BeginLogin(waUser{rec.ID, rec.Username, credentials(rec)},
		webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		log.Printf("begin login %s: %v", req.Username, err)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}

	id := a.pending.Put(pendingCeremony{Kind: "login", Username: req.Username, Session: *sess})
	a.setCeremonyCookie(w, id)
	writeJSON(w, opts)
}

func (a *App) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	p, ok := a.takeCeremony(r, "login")
	if !ok {
		jsonError(w, "no ceremony in progress", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	rec := a.store.Get(p.Username)
	if rec == nil {
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}

	cred, err := a.wa.FinishLogin(waUser{rec.ID, rec.Username, credentials(rec)}, p.Session, r)
	if err != nil {
		a.limiter.Allow("fail:"+clientIP(r), 10)
		log.Printf("finish login %s: %v", p.Username, err)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	if cred.Authenticator.CloneWarning {
		log.Printf("REFUSED login %s: sign counter regression (cloned credential?)", p.Username)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	if err := a.store.TouchCredential(p.Username, cred); err != nil {
		log.Printf("touch credential %s: %v", p.Username, err)
	}

	a.setSessionCookie(w, p.Username)
	a.clearCeremonyCookie(w)
	redirect := a.safeRedirect(r.URL.Query().Get("rd"))
	if redirect == "" {
		redirect = a.cfg.PortalURL.String() + "/"
	}
	log.Printf("login ok: %s (key %q, ip %s)", p.Username, credentialName(rec, cred), clientIP(r))
	writeJSON(w, map[string]string{"redirect": redirect})
}

func (a *App) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if !a.guardCeremony(w, r) {
		return
	}
	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		KeyName  string `json:"key_name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if a.cfg.EnrollToken == "" ||
		subtle.ConstantTimeCompare([]byte(req.Token), []byte(a.cfg.EnrollToken)) != 1 {
		a.limiter.Allow("fail:"+clientIP(r), 10)
		jsonError(w, "enrollment refused", http.StatusForbidden)
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRe.MatchString(req.Username) {
		jsonError(w, "username must match [a-z0-9._-]{1,32}", http.StatusBadRequest)
		return
	}
	if req.KeyName == "" || len(req.KeyName) > 64 {
		jsonError(w, "key name must be 1-64 characters", http.StatusBadRequest)
		return
	}

	// Reuse the stored user handle, or mint one for a brand-new user; the
	// record itself is only created when the ceremony finishes.
	var userID []byte
	var exclusions []protocol.CredentialDescriptor
	if rec := a.store.Get(req.Username); rec != nil {
		userID = rec.ID
		for _, c := range rec.Credentials {
			exclusions = append(exclusions, protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: c.Credential.ID,
				Transport:    c.Credential.Transport,
			})
		}
	} else {
		userID = make([]byte, 16)
		if _, err := rand.Read(userID); err != nil {
			panic(err)
		}
	}

	// The whole point of stile: non-discoverable credential, presence
	// only. Browsers honour both on PIN-less security keys.
	opts, sess, err := a.wa.BeginRegistration(waUser{userID, req.Username, nil},
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.CrossPlatform,
			ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
			RequireResidentKey:      protocol.ResidentKeyNotRequired(),
			UserVerification:        protocol.VerificationDiscouraged,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		log.Printf("begin registration %s: %v", req.Username, err)
		jsonError(w, "enrollment failed", http.StatusBadRequest)
		return
	}

	id := a.pending.Put(pendingCeremony{
		Kind:     "register",
		Username: req.Username,
		UserID:   userID,
		CredName: req.KeyName,
		Session:  *sess,
	})
	a.setCeremonyCookie(w, id)
	writeJSON(w, opts)
}

func (a *App) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	p, ok := a.takeCeremony(r, "register")
	if !ok {
		jsonError(w, "no ceremony in progress", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	cred, err := a.wa.FinishRegistration(waUser{p.UserID, p.Username, nil}, p.Session, r)
	if err != nil {
		log.Printf("finish registration %s: %v", p.Username, err)
		jsonError(w, "enrollment failed", http.StatusBadRequest)
		return
	}
	if err := a.store.AddCredential(p.Username, p.UserID, p.CredName, *cred); err != nil {
		log.Printf("store credential %s: %v", p.Username, err)
		jsonError(w, "enrollment failed", http.StatusInternalServerError)
		return
	}
	a.clearCeremonyCookie(w)
	log.Printf("enrolled: %s key %q (ip %s)", p.Username, p.CredName, clientIP(r))
	writeJSON(w, map[string]string{"status": "enrolled"})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    "",
		Domain:   a.cfg.RPID,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]string{"status": "logged out"})
}

// ---- helpers ------------------------------------------------------------

// guardCeremony applies the origin check and rate limits to ceremony
// starts: per-IP volume plus recent-failure lockout.
func (a *App) guardCeremony(w http.ResponseWriter, r *http.Request) bool {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return false
	}
	ip := clientIP(r)
	if !a.limiter.Peek("fail:"+ip, 10) {
		jsonError(w, "too many failures, wait a few minutes", http.StatusTooManyRequests)
		return false
	}
	if !a.limiter.Allow("begin:"+ip, 30) {
		jsonError(w, "slow down", http.StatusTooManyRequests)
		return false
	}
	return true
}

// checkOrigin requires state-changing requests to come from the portal's
// own origin. The WebAuthn ceremonies additionally verify the origin
// embedded in the signed clientDataJSON.
func (a *App) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	for _, allowed := range a.cfg.Origins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// safeRedirect allows only https URLs on the RP ID domain or below it —
// anything else collapses to "" (portal home).
func (a *App) safeRedirect(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	if h == a.cfg.RPID || strings.HasSuffix(h, "."+a.cfg.RPID) {
		return u.String()
	}
	return ""
}

func (a *App) setCeremonyCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ceremonyCookie,
		Value:    id,
		Path:     "/api/",
		MaxAge:   300,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) clearCeremonyCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookie, Value: "", Path: "/api/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) takeCeremony(r *http.Request, kind string) (pendingCeremony, bool) {
	c, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return pendingCeremony{}, false
	}
	p, ok := a.pending.Take(c.Value)
	if !ok || p.Kind != kind {
		return pendingCeremony{}, false
	}
	return p, true
}

// waUser adapts a user record to the library's interface.
type waUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.id }
func (u waUser) WebAuthnName() string                       { return u.name }
func (u waUser) WebAuthnDisplayName() string                { return u.name }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func credentials(rec *UserRecord) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(rec.Credentials))
	for _, c := range rec.Credentials {
		out = append(out, c.Credential)
	}
	return out
}

func credentialName(rec *UserRecord, cred *webauthn.Credential) string {
	for _, c := range rec.Credentials {
		if string(c.Credential.ID) == string(cred.ID) {
			return c.Name
		}
	}
	return "?"
}

// clientIP trusts X-Forwarded-For because the listener is only reachable
// from the reverse proxy's docker network.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}
