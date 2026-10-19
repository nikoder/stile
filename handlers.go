package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
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
	codes   *codeStore
	limiter *limiter
}

const (
	svcCookieName  = "stile_svc"
	ceremonyCookie = "stile_ceremony"
	ticketParam    = "stile_ticket"

	ticketTTL = 30 * time.Second // portal → app bounce
	actionTTL = 2 * time.Minute  // step-up tap → sensitive operation
	inviteTTL = 15 * time.Minute // admin invite → enrollment

	// maxPortalLineage caps how long a portal session can keep renewing
	// itself since the original key tap. Past this, sign in again.
	maxPortalLineage = 90 * 24 * time.Hour
)

// stepUpOps are the operations a step-up tap can authorize; the client
// declares one up front and the minted action token spends only on it.
var stepUpOps = map[string]bool{"delete-key": true, "add-key": true, "invite": true}

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
	mux.HandleFunc("POST /api/ticket", a.handleTicket)
	mux.HandleFunc("POST /api/login/begin", a.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", a.handleLoginFinish)
	mux.HandleFunc("POST /api/enroll/begin", a.handleEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", a.handleEnrollFinish)
	mux.HandleFunc("POST /api/stepup/begin", a.handleStepupBegin)
	mux.HandleFunc("POST /api/stepup/finish", a.handleStepupFinish)
	mux.HandleFunc("GET /api/keys", a.handleKeysList)
	mux.HandleFunc("POST /api/keys/rename", a.handleKeyRename)
	mux.HandleFunc("POST /api/keys/delete", a.handleKeyDelete)
	mux.HandleFunc("POST /api/keys/add/begin", a.handleKeyAddBegin)
	mux.HandleFunc("POST /api/invite", a.handleInvite)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("POST /api/logout-all", a.handleLogoutAll)

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

// ---- forward auth ---------------------------------------------------------

// handleVerify is the Caddy forward_auth endpoint. Order of business:
// redeem a one-time ticket into a host-bound service cookie, else accept a
// valid service cookie, else bounce browsers to the portal (401 for API
// clients). The portal session cookie is deliberately NOT accepted here —
// it never leaves the portal origin.
func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	fwdHost := r.Header.Get("X-Forwarded-Host")
	// Only trust the X-Forwarded-* bundle on a real forward_auth
	// subrequest. Two independent tells, either sufficient: forward_auth
	// subrequests carry the protected app's original Host header (the
	// portal route's proxied requests carry the portal's own Host, so
	// those are refused without trusting any X-Forwarded-* header), and
	// X-Forwarded-Method is set by Caddy's forward_auth and additionally
	// stripped from client requests on the portal route.
	isFwd := r.Header.Get("X-Forwarded-Method") != "" && fwdHost != "" &&
		!strings.EqualFold(requestHostname(r), a.cfg.PortalURL.Hostname())

	if isFwd {
		if a.redeemTicket(w, r, fwdHost) {
			return
		}
		if tok, ok := a.checkServiceToken(r, fwdHost); ok {
			w.Header().Set("Remote-User", tok.Username)
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			rd := fwdProto(r) + "://" + fwdHost + r.Header.Get("X-Forwarded-Uri")
			http.Redirect(w, r, a.cfg.PortalURL.String()+"/?rd="+url.QueryEscape(rd), http.StatusFound)
			return
		}
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// redeemTicket converts ?stile_ticket=CODE on the forwarded URI into a
// host-bound service cookie and 302s to the clean URL. This works because
// Caddy copies a non-2xx forward_auth response to the browser in the app
// host's own context — the backend never sees the code or the Set-Cookie.
func (a *App) redeemTicket(w http.ResponseWriter, r *http.Request, fwdHost string) bool {
	u, err := url.ParseRequestURI(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		return false
	}
	q := u.Query()
	code := q.Get(ticketParam)
	if code == "" {
		return false
	}
	e, ok := a.codes.Take("ticket", code)
	if !ok || e.Host != fwdHost {
		// Stale, replayed or cross-host ticket: fall through — the portal
		// bounce will mint a fresh one if the browser holds a session.
		log.Printf("refused ticket on %s (ip %s)", fwdHost, clientIP(r))
		return false
	}
	rec := a.store.Get(e.Username)
	if rec == nil || len(rec.Credentials) == 0 {
		return false
	}
	a.setServiceCookie(w, e.Username, fwdHost, rec.SessionEpoch)
	q.Del(ticketParam)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, fwdProto(r)+"://"+fwdHost+u.String(), http.StatusFound)
	log.Printf("service session: %s on %s (ip %s)", e.Username, fwdHost, clientIP(r))
	return true
}

func (a *App) checkServiceToken(r *http.Request, fwdHost string) (Token, bool) {
	c, err := r.Cookie(svcCookieName)
	if err != nil {
		return Token{}, false
	}
	tok, err := verifyToken(a.cfg.SessionSecret, tokenSvc, c.Value, time.Now())
	if err != nil || tok.Host == "" || tok.Host != fwdHost {
		return Token{}, false
	}
	rec := a.store.Get(tok.Username)
	if rec == nil || len(rec.Credentials) == 0 || rec.SessionEpoch != tok.Epoch {
		return Token{}, false
	}
	return tok, true
}

// checkPortalSession validates the portal cookie: user still exists, still
// owns a credential, and the cookie's epoch matches users.json.
func (a *App) checkPortalSession(r *http.Request) (Token, *UserRecord, bool) {
	c, err := r.Cookie(a.cfg.CookieName)
	if err != nil {
		return Token{}, nil, false
	}
	tok, err := verifyToken(a.cfg.SessionSecret, tokenPortal, c.Value, time.Now())
	if err != nil {
		return Token{}, nil, false
	}
	rec := a.store.Get(tok.Username)
	if rec == nil || len(rec.Credentials) == 0 || rec.SessionEpoch != tok.Epoch {
		return Token{}, nil, false
	}
	return tok, rec, true
}

// setPortalCookie mints the portal session cookie. first is the original
// login time carried across renewals; pass 0 for a fresh login.
func (a *App) setPortalCookie(w http.ResponseWriter, username string, epoch, first int64) {
	now := time.Now()
	if first == 0 {
		first = now.Unix()
	}
	exp := now.Add(a.cfg.SessionTTL)
	a.setCookie(w, a.cfg.CookieName, Token{
		Type: tokenPortal, Username: username,
		IssuedAt: now.Unix(), First: first, Expiry: exp.Unix(), Epoch: epoch,
	}, exp)
}

func (a *App) setServiceCookie(w http.ResponseWriter, username, host string, epoch int64) {
	exp := time.Now().Add(a.cfg.SvcTTL)
	a.setCookie(w, svcCookieName, Token{
		Type: tokenSvc, Username: username, Host: host,
		IssuedAt: time.Now().Unix(), Expiry: exp.Unix(), Epoch: epoch,
	}, exp)
}

// setCookie emits a HOST-ONLY cookie (no Domain attribute): the portal
// cookie stays on the portal origin and each service cookie on its own
// app host. Nothing stile mints is ever a domain-wide bearer token.
func (a *App) setCookie(w http.ResponseWriter, name string, tok Token, exp time.Time) {
	raw, err := signToken(a.cfg.SessionSecret, tok)
	if err != nil {
		log.Printf("sign %s token: %v", tok.Type, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    raw,
		Path:     "/",
		Expires:  exp,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---- portal API -----------------------------------------------------------

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"authenticated": false,
		// bootstrap: true only while the store is empty and a bootstrap
		// token is configured — i.e. first-run. Afterwards enrollment
		// happens via admin-minted invites.
		"bootstrap": a.store.UserCount() == 0 && a.cfg.BootstrapToken != "",
	}
	if tok, rec, ok := a.checkPortalSession(r); ok {
		resp["authenticated"] = true
		resp["username"] = tok.Username
		resp["admin"] = a.isAdmin(rec)
		// Sliding renewal belongs here: the browser talks to the portal
		// origin directly, so Set-Cookie actually lands (on forward_auth
		// 2xx responses Caddy discards it). Renewal stops once the session
		// lineage is older than maxPortalLineage — a stolen cookie can't
		// renew itself forever.
		first := tok.First
		if first == 0 {
			first = tok.IssuedAt
		}
		if time.Until(time.Unix(tok.Expiry, 0)) < a.cfg.SessionTTL/2 &&
			time.Since(time.Unix(first, 0)) < maxPortalLineage {
			a.setPortalCookie(w, tok.Username, rec.SessionEpoch, first)
		}
	}
	// The portal echoes ?rd= back through the server so redirect targets
	// are validated in exactly one place.
	if rd := a.safeRedirect(r.URL.Query().Get("rd")); rd != "" {
		resp["redirect"] = rd
	}
	writeJSON(w, resp)
}

// handleTicket mints a one-time service ticket for an already-signed-in
// browser (the fresh-login path gets its ticket from login/finish).
func (a *App) handleTicket(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	tok, _, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		Rd string `json:"rd"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := a.safeRedirect(req.Rd)
	if target == "" {
		jsonError(w, "bad redirect target", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"redirect": a.ticketRedirect(tok.Username, target)})
}

// ticketRedirect appends a one-time ticket to an app-host target; targets
// on the portal host itself pass through untouched.
func (a *App) ticketRedirect(username, target string) string {
	u, err := url.Parse(target)
	// Hostname comparison on purpose: an explicit default port in the rd
	// (tap.example.com:443) must not slip past the portal exclusion and
	// mint an unredeemable port-suffixed ticket.
	if err != nil || strings.EqualFold(u.Hostname(), a.cfg.PortalURL.Hostname()) {
		return target
	}
	code := a.codes.Put(codeEntry{Kind: "ticket", Username: username, Host: u.Host}, ticketTTL)
	q := u.Query()
	q.Set(ticketParam, code)
	u.RawQuery = q.Encode()
	return u.String()
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
	a.beginAssertion(w, r, rec, "login")
}

// beginAssertion starts a presence-only assertion ceremony against the
// user's enrolled credentials (shared by login and step-up).
func (a *App) beginAssertion(w http.ResponseWriter, r *http.Request, rec *UserRecord, kind string) {
	opts, sess, err := a.wa.BeginLogin(waUser{rec.ID, rec.Username, credentials(rec)},
		webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		log.Printf("begin %s %s: %v", kind, rec.Username, err)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	id := a.pending.Put(pendingCeremony{Kind: kind, Username: rec.Username, Session: *sess})
	a.setCeremonyCookie(w, id)
	writeJSON(w, opts)
}

// finishAssertion completes an assertion ceremony and returns the record
// and credential on success (nil on failure, with the response written).
func (a *App) finishAssertion(w http.ResponseWriter, r *http.Request, kind string) (*UserRecord, *webauthn.Credential) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return nil, nil
	}
	p, ok := a.takeCeremony(r, kind)
	if !ok {
		jsonError(w, "no ceremony in progress", http.StatusBadRequest)
		return nil, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	rec := a.store.Get(p.Username)
	if rec == nil || len(rec.Credentials) == 0 {
		jsonError(w, "login failed", http.StatusBadRequest)
		return nil, nil
	}
	cred, err := a.wa.FinishLogin(waUser{rec.ID, rec.Username, credentials(rec)}, p.Session, r)
	if err != nil {
		a.limiter.Allow("fail:"+clientIP(r), 10)
		log.Printf("finish %s %s: %v", kind, p.Username, err)
		jsonError(w, "login failed", http.StatusBadRequest)
		return nil, nil
	}
	if cred.Authenticator.CloneWarning {
		log.Printf("REFUSED %s %s: sign counter regression (cloned credential?)", kind, p.Username)
		jsonError(w, "login failed", http.StatusBadRequest)
		return nil, nil
	}
	if err := a.store.TouchCredential(p.Username, cred); err != nil {
		log.Printf("touch credential %s: %v", p.Username, err)
	}
	a.clearCeremonyCookie(w)
	return rec, cred
}

func (a *App) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	rec, cred := a.finishAssertion(w, r, "login")
	if rec == nil {
		return
	}
	a.setPortalCookie(w, rec.Username, rec.SessionEpoch, 0)
	redirect := a.safeRedirect(r.URL.Query().Get("rd"))
	if redirect == "" {
		redirect = a.cfg.PortalURL.String() + "/"
	} else {
		redirect = a.ticketRedirect(rec.Username, redirect)
	}
	log.Printf("login ok: %s (key %q, ip %s)", rec.Username, credentialName(rec, cred), clientIP(r))
	writeJSON(w, map[string]string{"redirect": redirect})
}

// ---- step-up: a fresh tap unlocks one sensitive operation -----------------

func (a *App) handleStepupBegin(w http.ResponseWriter, r *http.Request) {
	if !a.guardCeremony(w, r) {
		return
	}
	_, rec, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		Op string `json:"op"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	// The intended operation is declared up front and rides the ceremony:
	// the resulting action token spends on that operation only, so a tap
	// meant for "delete key" can't be redirected into "mint invite".
	if !stepUpOps[req.Op] {
		jsonError(w, "unknown step-up operation", http.StatusBadRequest)
		return
	}
	opts, sess, err := a.wa.BeginLogin(waUser{rec.ID, rec.Username, credentials(rec)},
		webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		log.Printf("begin stepup %s: %v", rec.Username, err)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	id := a.pending.Put(pendingCeremony{Kind: "stepup", Username: rec.Username, Op: req.Op, Session: *sess})
	a.setCeremonyCookie(w, id)
	writeJSON(w, opts)
}

func (a *App) handleStepupFinish(w http.ResponseWriter, r *http.Request) {
	tok, _, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	p, pok := a.takeCeremony(r, "stepup")
	if !pok {
		jsonError(w, "no ceremony in progress", http.StatusBadRequest)
		return
	}
	if p.Username != tok.Username {
		jsonError(w, "session mismatch", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	rec := a.store.Get(p.Username)
	if rec == nil || len(rec.Credentials) == 0 {
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	cred, err := a.wa.FinishLogin(waUser{rec.ID, rec.Username, credentials(rec)}, p.Session, r)
	if err != nil || cred.Authenticator.CloneWarning {
		a.limiter.Allow("fail:"+clientIP(r), 10)
		log.Printf("finish stepup %s refused: %v (clone=%v)", p.Username, err, cred != nil && cred.Authenticator.CloneWarning)
		jsonError(w, "login failed", http.StatusBadRequest)
		return
	}
	if err := a.store.TouchCredential(p.Username, cred); err != nil {
		log.Printf("touch credential %s: %v", p.Username, err)
	}
	a.clearCeremonyCookie(w)
	action := a.codes.Put(codeEntry{Kind: "action", Username: rec.Username, Op: p.Op}, actionTTL)
	writeJSON(w, map[string]string{"action_token": action})
}

// consumeAction redeems a step-up action token for the given user and
// operation.
func (a *App) consumeAction(username, token, op string) bool {
	e, ok := a.codes.Take("action", token)
	return ok && e.Username == username && e.Op == op
}

// ---- key management (self-service, step-up gated where it matters) --------

func (a *App) handleKeysList(w http.ResponseWriter, r *http.Request) {
	_, rec, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	type key struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		AddedAt    time.Time `json:"added_at"`
		LastUsedAt time.Time `json:"last_used_at"`
	}
	keys := make([]key, 0, len(rec.Credentials))
	for _, c := range rec.Credentials {
		keys = append(keys, key{
			ID:         base64.RawURLEncoding.EncodeToString(c.Credential.ID),
			Name:       c.Name,
			AddedAt:    c.AddedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}
	writeJSON(w, map[string]any{"keys": keys})
}

// Renaming is cosmetic: session-gated only.
func (a *App) handleKeyRename(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	tok, _, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(req.ID)
	if err != nil || req.Name == "" || len(req.Name) > 64 {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := a.store.RenameCredential(tok.Username, credID, req.Name); err != nil {
		jsonError(w, "rename failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "renamed"})
}

// Deleting a credential needs a FRESH tap (action token), not just the
// session cookie — otherwise a stolen session could strip the account.
func (a *App) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	tok, _, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		ID          string `json:"id"`
		ActionToken string `json:"action_token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !a.consumeAction(tok.Username, req.ActionToken, "delete-key") {
		jsonError(w, "step-up required", http.StatusForbidden)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(req.ID)
	if err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := a.store.DeleteCredential(tok.Username, credID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The delete bumped the epoch (revocation event), which also killed
	// the session this request rode in on. The human is present and just
	// step-upped, so hand them a fresh cookie under the new epoch.
	if rec2 := a.store.Get(tok.Username); rec2 != nil {
		a.setPortalCookie(w, tok.Username, rec2.SessionEpoch, 0)
	}
	log.Printf("key deleted: %s — epoch bumped, outstanding sessions revoked (ip %s)", tok.Username, clientIP(r))
	writeJSON(w, map[string]string{"status": "deleted"})
}

// Adding a key also needs a fresh tap — a stolen session must not be able
// to convert itself into a permanent credential. The flow is two taps:
// step-up with an existing key, then the registration tap on the new one.
func (a *App) handleKeyAddBegin(w http.ResponseWriter, r *http.Request) {
	if !a.guardCeremony(w, r) {
		return
	}
	tok, rec, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req struct {
		ActionToken string `json:"action_token"`
		KeyName     string `json:"key_name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !a.consumeAction(tok.Username, req.ActionToken, "add-key") {
		jsonError(w, "step-up required", http.StatusForbidden)
		return
	}
	if req.KeyName == "" || len(req.KeyName) > 64 {
		jsonError(w, "key name must be 1-64 characters", http.StatusBadRequest)
		return
	}
	a.beginRegistration(w, rec.Username, rec.ID, req.KeyName, false, credentialDescriptors(rec))
}

// ---- enrollment (bootstrap or invite) --------------------------------------

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
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRe.MatchString(req.Username) {
		jsonError(w, "username must match [a-z0-9._-]{1,32}", http.StatusBadRequest)
		return
	}
	if req.KeyName == "" || len(req.KeyName) > 64 {
		jsonError(w, "key name must be 1-64 characters", http.StatusBadRequest)
		return
	}

	// The env token only bootstraps the FIRST user (who becomes admin).
	// After that, enrollment runs on single-use, username-bound, expiring
	// invite codes minted by an admin — a standing shared secret that can
	// silently add keys to existing accounts is not a thing here.
	admin := false
	if a.store.UserCount() == 0 {
		if a.cfg.BootstrapToken == "" ||
			subtle.ConstantTimeCompare([]byte(req.Token), []byte(a.cfg.BootstrapToken)) != 1 {
			a.limiter.Allow("fail:"+clientIP(r), 10)
			log.Printf("enrollment refused for %q: bad bootstrap token (ip %s)", req.Username, clientIP(r))
			jsonError(w, "enrollment refused", http.StatusForbidden)
			return
		}
		admin = true
	} else {
		e, ok := a.codes.Take("invite", req.Token)
		if !ok || e.Username != req.Username {
			a.limiter.Allow("fail:"+clientIP(r), 10)
			log.Printf("enrollment refused for %q: invalid invite (ip %s)", req.Username, clientIP(r))
			jsonError(w, "enrollment refused", http.StatusForbidden)
			return
		}
	}

	var userID []byte
	var exclusions []protocol.CredentialDescriptor
	if rec := a.store.Get(req.Username); rec != nil {
		userID = rec.ID
		exclusions = credentialDescriptors(rec)
	} else {
		userID = make([]byte, 16)
		if _, err := rand.Read(userID); err != nil {
			panic(err)
		}
	}
	a.beginRegistration(w, req.Username, userID, req.KeyName, admin, exclusions)
}

// beginRegistration starts the registration ceremony shared by enrollment
// and self-service key addition. The whole point of stile: non-discoverable
// credential, presence only. Browsers honour both on PIN-less keys.
func (a *App) beginRegistration(w http.ResponseWriter, username string, userID []byte, keyName string, admin bool, exclusions []protocol.CredentialDescriptor) {
	opts, sess, err := a.wa.BeginRegistration(waUser{userID, username, nil},
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
		log.Printf("begin registration %s: %v", username, err)
		jsonError(w, "enrollment failed", http.StatusBadRequest)
		return
	}
	id := a.pending.Put(pendingCeremony{
		Kind:     "register",
		Username: username,
		UserID:   userID,
		CredName: keyName,
		Admin:    admin,
		Session:  *sess,
	})
	a.setCeremonyCookie(w, id)
	writeJSON(w, opts)
}

// handleEnrollFinish completes registration for both the enroll page and
// the portal's add-key flow (they share the pending "register" kind).
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
	if err := a.store.AddCredential(p.Username, p.UserID, p.CredName, *cred, p.Admin); err != nil {
		log.Printf("store credential %s: %v", p.Username, err)
		jsonError(w, "enrollment failed", http.StatusInternalServerError)
		return
	}
	a.clearCeremonyCookie(w)
	log.Printf("enrolled: %s key %q (ip %s)", p.Username, p.CredName, clientIP(r))
	writeJSON(w, map[string]string{"status": "enrolled"})
}

// ---- invites (admin, step-up gated) ----------------------------------------

func (a *App) handleInvite(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	tok, rec, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if !a.isAdmin(rec) {
		jsonError(w, "admin only", http.StatusForbidden)
		return
	}
	var req struct {
		Username    string `json:"username"`
		ActionToken string `json:"action_token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	// An invite adds a key to (or creates) the named account — that's as
	// sensitive as adding a key directly, so it costs a fresh tap too.
	if !a.consumeAction(tok.Username, req.ActionToken, "invite") {
		jsonError(w, "step-up required", http.StatusForbidden)
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRe.MatchString(req.Username) {
		jsonError(w, "username must match [a-z0-9._-]{1,32}", http.StatusBadRequest)
		return
	}
	code := a.codes.Put(codeEntry{Kind: "invite", Username: req.Username}, inviteTTL)
	link := a.cfg.PortalURL.String() + "/enroll?invite=" + url.QueryEscape(code) +
		"&username=" + url.QueryEscape(req.Username)
	log.Printf("invite minted for %q by %s (ip %s)", req.Username, tok.Username, clientIP(r))
	writeJSON(w, map[string]any{"code": code, "link": link, "expires_in_minutes": int(inviteTTL.Minutes())})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.cfg.CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]string{"status": "logged out"})
}

// handleLogoutAll bumps the user's epoch: every portal and service cookie
// everywhere dies on its next check. Session-gated on purpose — the worst
// a stolen session can do here is log its victim out, and this doubles as
// the UI panic button (the alternative is editing users.json by hand).
func (a *App) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if !a.checkOrigin(r) {
		jsonError(w, "bad origin", http.StatusForbidden)
		return
	}
	tok, _, ok := a.checkPortalSession(r)
	if !ok {
		jsonError(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if _, err := a.store.BumpEpoch(tok.Username); err != nil {
		jsonError(w, "failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.cfg.CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	log.Printf("logout-all: %s — epoch bumped, all sessions revoked (ip %s)", tok.Username, clientIP(r))
	writeJSON(w, map[string]string{"status": "logged out everywhere"})
}

// ---- helpers ----------------------------------------------------------------

func (a *App) isAdmin(rec *UserRecord) bool {
	return rec.Admin || slices.Contains(a.cfg.AdminUsers, rec.Username)
}

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
// anything else collapses to "" (portal home). The RP ID doubles as the
// zone of protectable apps; it no longer scopes any cookie.
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

func credentialDescriptors(rec *UserRecord) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(rec.Credentials))
	for _, c := range rec.Credentials {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.Credential.ID,
			Transport:    c.Credential.Transport,
		})
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

// requestHostname is the Host header without any port.
func requestHostname(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return r.Host
}

func fwdProto(r *http.Request) string {
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		return p
	}
	return "https"
}

// clientIP takes the LAST X-Forwarded-For entry: that one was appended by
// our own Caddy. Leftmost entries are client-supplied and become
// attacker-controlled the moment any hop is added in front of Caddy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
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
