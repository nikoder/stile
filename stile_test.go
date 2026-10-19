package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testApp(t *testing.T) (*App, http.Handler) {
	t.Helper()
	portal, _ := url.Parse("https://tap.example.com")
	cfg := &Config{
		Listen:         ":0",
		PortalURL:      portal,
		RPID:           "example.com",
		Origins:        []string{"https://tap.example.com"},
		CookieName:     "stile_session",
		SessionSecret:  []byte(strings.Repeat("s", 32)),
		SessionTTL:     time.Hour,
		SvcTTL:         10 * time.Minute,
		FreezeTTL:      24 * time.Hour,
		BootstrapToken: "sekrit-bootstrap",
		DataDir:        t.TempDir(),
		DisplayName:    "stile-test",
	}
	store, err := OpenStore(filepath.Join(cfg.DataDir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := newApp(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	static, _ := fs.Sub(webFS, "web")
	return app, app.Routes(static)
}

func addFakeUser(t *testing.T, app *App, username string) {
	t.Helper()
	cred := webauthn.Credential{ID: []byte("cred-" + username), PublicKey: []byte("pk")}
	if err := app.store.AddCredential(username, []byte("handle-"+username), "test key", cred, false); err != nil {
		t.Fatal(err)
	}
}

func cookieOf(t *testing.T, app *App, typ, name, username, host string, epoch int64) *http.Cookie {
	t.Helper()
	raw, err := signToken(app.cfg.SessionSecret, Token{
		Type: typ, Username: username, Host: host,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Hour).Unix(),
		Epoch:    epoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: name, Value: raw}
}

func portalCookie(t *testing.T, app *App, username string) *http.Cookie {
	return cookieOf(t, app, tokenPortal, app.cfg.CookieName, username, "", 0)
}

func svcCookie(t *testing.T, app *App, username, host string) *http.Cookie {
	return cookieOf(t, app, tokenSvc, svcCookieName, username, host, 0)
}

func fwdReq(path, host, uri string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	// A real forward_auth subrequest carries the protected app's original
	// Host header, never the portal's.
	r.Host = host
	r.Header.Set("X-Forwarded-Method", "GET")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", uri)
	return r
}

// ---- tokens -----------------------------------------------------------------

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	raw, err := signToken(secret, Token{Type: tokenPortal, Username: "nick", Expiry: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := verifyToken(secret, tokenPortal, raw, time.Now())
	if err != nil || tok.Username != "nick" {
		t.Fatalf("round trip failed: %v %+v", err, tok)
	}
}

func TestTokenTamperedOrExpired(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	raw, _ := signToken(secret, Token{Type: tokenPortal, Username: "nick", Expiry: time.Now().Add(time.Hour).Unix()})

	if _, err := verifyToken([]byte(strings.Repeat("x", 32)), tokenPortal, raw, time.Now()); err == nil {
		t.Fatal("accepted token signed with a different key")
	}
	if _, err := verifyToken(secret, tokenPortal, "A"+raw[1:], time.Now()); err == nil {
		t.Fatal("accepted mangled token")
	}
	if _, err := verifyToken(secret, tokenPortal, "garbage", time.Now()); err == nil {
		t.Fatal("accepted garbage token")
	}
	if _, err := verifyToken(secret, tokenPortal, raw, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("accepted expired token")
	}
}

// A portal token must never pass as a service token or vice versa.
func TestTokenTypeConfusion(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	portal, _ := signToken(secret, Token{Type: tokenPortal, Username: "nick", Expiry: time.Now().Add(time.Hour).Unix()})
	svc, _ := signToken(secret, Token{Type: tokenSvc, Username: "nick", Host: "app.example.com", Expiry: time.Now().Add(time.Hour).Unix()})

	if _, err := verifyToken(secret, tokenSvc, portal, time.Now()); err == nil {
		t.Fatal("portal token accepted as service token")
	}
	if _, err := verifyToken(secret, tokenPortal, svc, time.Now()); err == nil {
		t.Fatal("service token accepted as portal token")
	}
}

// ---- store ------------------------------------------------------------------

func TestStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cred := webauthn.Credential{ID: []byte("id1"), PublicKey: []byte("pk1")}
	if err := s1.AddCredential("nick", []byte("handle"), "main", cred, true); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := s2.Get("nick")
	if rec == nil || len(rec.Credentials) != 1 || rec.Credentials[0].Name != "main" {
		t.Fatalf("reload lost data: %+v", rec)
	}
	if string(rec.Credentials[0].Credential.ID) != "id1" || string(rec.ID) != "handle" || !rec.Admin {
		t.Fatal("fields did not survive the JSON round trip")
	}
}

func TestStoreHandleMismatch(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "users.json"))
	cred := webauthn.Credential{ID: []byte("id1")}
	if err := s.AddCredential("nick", []byte("handle"), "a", cred, false); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCredential("nick", []byte("other"), "b", cred, false); err == nil {
		t.Fatal("accepted a second credential under a different user handle")
	}
}

// External edits to users.json must take effect without a restart and must
// not be clobbered by the next save — this is the revocation story.
func TestStoreExternalEditReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, _ := OpenStore(path)
	if err := s.AddCredential("nick", []byte("handle"), "main", webauthn.Credential{ID: []byte("id1")}, false); err != nil {
		t.Fatal(err)
	}

	// Simulate the operator bumping the epoch by hand.
	raw, _ := os.ReadFile(path)
	edited := bytes.Replace(raw, []byte(`"session_epoch": 0`), []byte(`"session_epoch": 7`), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("test setup: epoch field not found in users.json")
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	// mtime granularity can swallow fast successive writes; force it.
	past := time.Now().Add(2 * time.Second)
	os.Chtimes(path, past, past)

	if rec := s.Get("nick"); rec == nil || rec.SessionEpoch != 7 {
		t.Fatalf("external edit not picked up: %+v", rec)
	}
	// A subsequent save must build on the reloaded state, not resurrect it.
	if err := s.TouchCredential("nick", &webauthn.Credential{ID: []byte("id1")}); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenStore(path)
	if rec := s2.Get("nick"); rec.SessionEpoch != 7 {
		t.Fatal("save clobbered the external epoch edit")
	}
}

func TestStoreDeleteAndRename(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "users.json"))
	s.AddCredential("nick", []byte("h"), "a", webauthn.Credential{ID: []byte("id1")}, false)
	s.AddCredential("nick", []byte("h"), "b", webauthn.Credential{ID: []byte("id2")}, false)
	if err := s.DeleteCredential("nick", []byte("id1")); err != nil {
		t.Fatalf("delete with a spare failed: %v", err)
	}
	if err := s.RenameCredential("nick", []byte("id2"), "renamed"); err != nil {
		t.Fatalf("rename failed: %v", err)
	}
	if rec := s.Get("nick"); len(rec.Credentials) != 1 || rec.Credentials[0].Name != "renamed" {
		t.Fatalf("unexpected state: %+v", rec)
	}
}

// ---- /verify ------------------------------------------------------------------

// Without X-Forwarded-Method the X-Forwarded-* bundle is client-controlled
// (the portal host routes /verify publicly) — no redirect may be built.
func TestVerifyRequiresForwardAuthContext(t *testing.T) {
	_, h := testApp(t)
	r := httptest.NewRequest("GET", "/verify", nil)
	r.Host = "other.example.com"
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Host", "evil-controlled.example.com")
	r.Header.Set("X-Forwarded-Uri", "/x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without forward_auth context, got %d", w.Code)
	}
}

// Requests reaching /verify through the portal route carry the portal's
// Host header — those must be refused even with a fully forged
// X-Forwarded-* bundle (X-Forwarded-Method included).
func TestVerifyRefusedOnPortalHost(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	code := app.codes.Put(codeEntry{Kind: "ticket", Username: "nick", Host: "app.example.com"}, time.Minute)

	r := fwdReq("/verify", "app.example.com", "/?"+ticketParam+"="+code)
	r.Host = "tap.example.com" // arrived via the portal route
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("forged forward_auth context on portal host accepted: %d", w.Code)
	}
}

func TestVerifyUnauthenticatedBrowser(t *testing.T) {
	_, h := testApp(t)
	r := fwdReq("/verify", "app.example.com", "/dash?x=1")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	want := "https://tap.example.com/?rd=" + url.QueryEscape("https://app.example.com/dash?x=1")
	if got := w.Header().Get("Location"); got != want {
		t.Fatalf("redirect = %q, want %q", got, want)
	}
}

func TestVerifyUnauthenticatedAPI(t *testing.T) {
	_, h := testApp(t)
	r := fwdReq("/verify", "app.example.com", "/api/x")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestVerifyServiceCookie(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	r := fwdReq("/verify", "app.example.com", "/")
	r.AddCookie(svcCookie(t, app, "nick", "app.example.com"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Remote-User") != "nick" {
		t.Fatalf("want 200/nick, got %d/%q", w.Code, w.Header().Get("Remote-User"))
	}
}

// The host binding is the point of service cookies: a cookie replayed by a
// compromised backend must not open any other host.
func TestVerifyServiceCookieWrongHost(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	r := fwdReq("/verify", "other.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svcCookie(t, app, "nick", "app.example.com"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-host service cookie accepted: %d", w.Code)
	}
}

// The portal cookie must never work at /verify.
func TestVerifyRejectsPortalCookie(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	c := portalCookie(t, app, "nick")
	c.Name = svcCookieName // even smuggled under the right name
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("portal token accepted at /verify: %d", w.Code)
	}
}

// Epoch bump revokes outstanding cookies.
func TestVerifyEpochRevocation(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	// Cookie minted at epoch 0; bump the stored epoch to 1.
	path := filepath.Join(app.cfg.DataDir, "users.json")
	raw, _ := os.ReadFile(path)
	edited := bytes.Replace(raw, []byte(`"session_epoch": 0`), []byte(`"session_epoch": 1`), 1)
	os.WriteFile(path, edited, 0o600)
	past := time.Now().Add(2 * time.Second)
	os.Chtimes(path, past, past)

	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svcCookie(t, app, "nick", "app.example.com"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("epoch-0 cookie accepted after bump to 1: %d", w.Code)
	}
}

func TestVerifyDeletedUser(t *testing.T) {
	app, h := testApp(t)
	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svcCookie(t, app, "ghost", "app.example.com"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for deleted user, got %d", w.Code)
	}
}

// ---- ticket flow ---------------------------------------------------------------

func TestTicketMintAndRedeem(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	// Mint via the API, as the portal JS does.
	body, _ := json.Marshal(map[string]string{"rd": "https://app.example.com/dash?x=1"})
	r := httptest.NewRequest("POST", "/api/ticket", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tap.example.com")
	r.AddCookie(portalCookie(t, app, "nick"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mint: want 200, got %d: %s", w.Code, w.Body)
	}
	var mint struct{ Redirect string }
	json.Unmarshal(w.Body.Bytes(), &mint)
	u, err := url.Parse(mint.Redirect)
	if err != nil || u.Query().Get(ticketParam) == "" {
		t.Fatalf("no ticket in redirect: %q", mint.Redirect)
	}

	// Redeem at /verify in the app host's forward_auth context.
	r2 := fwdReq("/verify", "app.example.com", u.RequestURI())
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusFound {
		t.Fatalf("redeem: want 302, got %d", w2.Code)
	}
	if got := w2.Header().Get("Location"); got != "https://app.example.com/dash?x=1" {
		t.Fatalf("clean-url redirect = %q", got)
	}
	var sc *http.Cookie
	for _, c := range w2.Result().Cookies() {
		if c.Name == svcCookieName {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("no service cookie set on redemption")
	}
	if sc.Domain != "" {
		t.Fatalf("service cookie must be host-only, got Domain=%q", sc.Domain)
	}
	tok, err := verifyToken(app.cfg.SessionSecret, tokenSvc, sc.Value, time.Now())
	if err != nil || tok.Host != "app.example.com" || tok.Username != "nick" {
		t.Fatalf("bad service token: %v %+v", err, tok)
	}

	// Replay: the code is single-use.
	r3 := fwdReq("/verify", "app.example.com", u.RequestURI())
	r3.Header.Set("Accept", "application/json")
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, r3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("replayed ticket accepted: %d", w3.Code)
	}
}

func TestTicketHostBinding(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	code := app.codes.Put(codeEntry{Kind: "ticket", Username: "nick", Host: "app.example.com"}, time.Minute)

	r := fwdReq("/verify", "other.example.com", "/?"+ticketParam+"="+code)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-host ticket redeemed: %d", w.Code)
	}
}

func TestTicketMintRequiresSessionAndSafeTarget(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	post := func(cookie *http.Cookie, rd string) int {
		body, _ := json.Marshal(map[string]string{"rd": rd})
		r := httptest.NewRequest("POST", "/api/ticket", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://tap.example.com")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := post(nil, "https://app.example.com/"); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated mint: want 401, got %d", code)
	}
	if code := post(portalCookie(t, app, "nick"), "https://evil.com/"); code != http.StatusBadRequest {
		t.Fatalf("off-zone mint: want 400, got %d", code)
	}
}

// ---- redirect validation --------------------------------------------------------

func TestSafeRedirect(t *testing.T) {
	app, _ := testApp(t)
	cases := map[string]string{
		"https://app.example.com/x":   "https://app.example.com/x",
		"https://example.com/":        "https://example.com/",
		"https://evil.com/":           "",
		"https://example.com.evil.io": "",
		"http://app.example.com/":     "", // https only
		"//evil.com/x":                "",
		"javascript:alert(1)":         "",
		"":                            "",
	}
	for in, want := range cases {
		if got := app.safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- ceremony endpoints ----------------------------------------------------------

func postAs(h http.Handler, path, origin string, cookies []*http.Cookie, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoginBeginUnknownUserIsGeneric(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	known := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nobody"})
	invalid := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "NO SUCH !!"})
	if known.Code != http.StatusBadRequest || invalid.Code != http.StatusBadRequest {
		t.Fatalf("want uniform 400s, got %d / %d", known.Code, invalid.Code)
	}
	if known.Body.String() != invalid.Body.String() {
		t.Fatal("unknown-user and invalid-user responses differ (username oracle)")
	}
}

func TestLoginBeginKnownUser(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	w := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nick"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var opts struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &opts); err != nil {
		t.Fatal(err)
	}
	if opts.PublicKey.Challenge == "" {
		t.Fatal("no challenge")
	}
	if opts.PublicKey.UserVerification != "discouraged" {
		t.Fatalf("userVerification = %q, want discouraged", opts.PublicKey.UserVerification)
	}
	if len(opts.PublicKey.AllowCredentials) != 1 {
		t.Fatalf("allowCredentials = %+v, want exactly the enrolled key", opts.PublicKey.AllowCredentials)
	}
}

func TestLoginBeginRejectsBadOrigin(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	if w := postAs(h, "/api/login/begin", "https://evil.com", nil, map[string]string{"username": "nick"}); w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if w := postAs(h, "/api/login/begin", "", nil, map[string]string{"username": "nick"}); w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for missing origin, got %d", w.Code)
	}
}

func TestFinishWithoutCeremony(t *testing.T) {
	_, h := testApp(t)
	w := postAs(h, "/api/login/finish", "https://tap.example.com", nil, map[string]string{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestFailureLockout(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	for i := 0; i < 10; i++ {
		postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nobody"})
	}
	w := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nick"})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after repeated failures, got %d", w.Code)
	}
}

// ---- enrollment: bootstrap + invites ----------------------------------------------

func TestBootstrapOnlyWhileEmpty(t *testing.T) {
	app, h := testApp(t)

	enroll := map[string]string{"token": "sekrit-bootstrap", "username": "nick", "key_name": "k"}
	w := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil, enroll)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap on empty store: want 200, got %d: %s", w.Code, w.Body)
	}
	var opts struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &opts); err != nil {
		t.Fatal(err)
	}
	if opts.PublicKey.AuthenticatorSelection.ResidentKey != "discouraged" ||
		opts.PublicKey.AuthenticatorSelection.UserVerification != "discouraged" {
		t.Fatalf("ceremony not presence-only/non-discoverable: %+v", opts.PublicKey.AuthenticatorSelection)
	}

	// Once a user exists, the bootstrap token is inert — even the right one.
	addFakeUser(t, app, "someone")
	w2 := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil, enroll)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("bootstrap token accepted with existing users: %d", w2.Code)
	}
}

func TestInviteFlow(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "someone")

	code := app.codes.Put(codeEntry{Kind: "invite", Username: "newbie"}, time.Minute)

	// Username-bound: using it for another account fails (and burns it).
	w := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil,
		map[string]string{"token": code, "username": "attacker", "key_name": "k"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("invite accepted for wrong username: %d", w.Code)
	}

	code2 := app.codes.Put(codeEntry{Kind: "invite", Username: "newbie"}, time.Minute)
	w2 := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil,
		map[string]string{"token": code2, "username": "newbie", "key_name": "k"})
	if w2.Code != http.StatusOK {
		t.Fatalf("valid invite refused: %d: %s", w2.Code, w2.Body)
	}

	// Single use.
	w3 := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil,
		map[string]string{"token": code2, "username": "newbie", "key_name": "k"})
	if w3.Code != http.StatusForbidden {
		t.Fatalf("invite reused: %d", w3.Code)
	}
}

func TestInviteMintingGates(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")  // not admin
	addFakeUser(t, app, "admin") // promoted below
	app.cfg.AdminUsers = []string{"admin"}

	// Non-admin refused outright.
	w := postAs(h, "/api/invite", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"username": "newbie", "action_token": "x"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin minted an invite: %d", w.Code)
	}

	// Admin without a fresh step-up refused.
	w2 := postAs(h, "/api/invite", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "newbie", "action_token": "stale"})
	if w2.Code != http.StatusForbidden {
		t.Fatalf("invite minted without step-up: %d", w2.Code)
	}

	// Admin with a fresh action token succeeds.
	action := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "invite"}, time.Minute)
	w3 := postAs(h, "/api/invite", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "newbie", "action_token": action})
	if w3.Code != http.StatusOK {
		t.Fatalf("admin + step-up refused: %d: %s", w3.Code, w3.Body)
	}
	var inv struct{ Code, Link string }
	json.Unmarshal(w3.Body.Bytes(), &inv)
	if inv.Code == "" || !strings.Contains(inv.Link, "invite="+inv.Code) {
		t.Fatalf("bad invite response: %+v", inv)
	}
}

// ---- key management ----------------------------------------------------------------

func TestKeyDeleteRequiresStepUp(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	app.store.AddCredential("nick", []byte("handle-nick"), "spare", webauthn.Credential{ID: []byte("id2")}, false)

	// List to get ids.
	r := httptest.NewRequest("GET", "/api/keys", nil)
	r.AddCookie(portalCookie(t, app, "nick"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var list struct {
		Keys []struct{ ID, Name string } `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Keys) != 2 {
		t.Fatalf("keys list: %v %s", err, w.Body)
	}

	// Without an action token: refused.
	w2 := postAs(h, "/api/keys/delete", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"id": list.Keys[0].ID, "action_token": "nope"})
	if w2.Code != http.StatusForbidden {
		t.Fatalf("delete without step-up: %d", w2.Code)
	}

	// With one: works.
	action := app.codes.Put(codeEntry{Kind: "action", Username: "nick", Op: "delete-key"}, time.Minute)
	w3 := postAs(h, "/api/keys/delete", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"id": list.Keys[0].ID, "action_token": action})
	if w3.Code != http.StatusOK {
		t.Fatalf("delete with step-up failed: %d: %s", w3.Code, w3.Body)
	}

	// Deleting the last one without the explicit lockout confirmation:
	// refused even with step-up, and BEFORE the action token is spent.
	// (The first delete bumped the epoch, so cookies are minted at 1.)
	action2 := app.codes.Put(codeEntry{Kind: "action", Username: "nick", Op: "delete-key"}, time.Minute)
	epoch1 := cookieOf(t, app, tokenPortal, app.cfg.CookieName, "nick", "", 1)
	w4 := postAs(h, "/api/keys/delete", "https://tap.example.com",
		[]*http.Cookie{epoch1},
		map[string]any{"id": list.Keys[1].ID, "action_token": action2})
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("last key deleted without confirm_lockout: %d", w4.Code)
	}

	// With confirmation: allowed, account goes credential-less and locked.
	w5 := postAs(h, "/api/keys/delete", "https://tap.example.com",
		[]*http.Cookie{epoch1},
		map[string]any{"id": list.Keys[1].ID, "action_token": action2, "confirm_lockout": true})
	if w5.Code != http.StatusOK {
		t.Fatalf("confirmed last-key delete refused: %d: %s", w5.Code, w5.Body)
	}
	rec := app.store.Get("nick")
	if len(rec.Credentials) != 0 || rec.SessionEpoch != 2 {
		t.Fatalf("unexpected post-lockout state: %+v", rec)
	}
	// Nothing signs in anymore — portal cookies at any epoch are dead.
	r2 := httptest.NewRequest("GET", "/api/keys", nil)
	r2.AddCookie(cookieOf(t, app, tokenPortal, app.cfg.CookieName, "nick", "", 2))
	w6 := httptest.NewRecorder()
	h.ServeHTTP(w6, r2)
	if w6.Code != http.StatusUnauthorized {
		t.Fatalf("credential-less account still has a working session: %d", w6.Code)
	}
	// ...but an invite can re-enroll the existing (empty) account.
	code := app.codes.Put(codeEntry{Kind: "invite", Username: "nick"}, time.Minute)
	w7 := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil,
		map[string]string{"token": code, "username": "nick", "key_name": "fresh"})
	if w7.Code != http.StatusOK {
		t.Fatalf("re-enrollment of locked account refused: %d: %s", w7.Code, w7.Body)
	}
}

func TestKeyAddRequiresStepUp(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	w := postAs(h, "/api/keys/add/begin", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"action_token": "nope", "key_name": "new"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("add-key ceremony started without step-up: %d", w.Code)
	}

	action := app.codes.Put(codeEntry{Kind: "action", Username: "nick", Op: "add-key"}, time.Minute)
	w2 := postAs(h, "/api/keys/add/begin", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"action_token": action, "key_name": "new"})
	if w2.Code != http.StatusOK {
		t.Fatalf("add-key with step-up refused: %d: %s", w2.Code, w2.Body)
	}
}

// Action tokens belong to one user: another user's session can't spend them.
func TestActionTokenUserBinding(t *testing.T) {
	app, _ := testApp(t)
	action := app.codes.Put(codeEntry{Kind: "action", Username: "alice", Op: "delete-key"}, time.Minute)
	if app.consumeAction("bob", action, "delete-key") {
		t.Fatal("bob spent alice's action token")
	}
	// And the attempt burned it.
	if app.consumeAction("alice", action, "delete-key") {
		t.Fatal("burned token redeemed")
	}
}

// ---- misc ---------------------------------------------------------------------------

func TestSessionReportsBootstrap(t *testing.T) {
	app, h := testApp(t)
	get := func() map[string]any {
		r := httptest.NewRequest("GET", "/api/session", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := get(); resp["bootstrap"] != true {
		t.Fatalf("bootstrap = %v, want true on empty store", resp["bootstrap"])
	}
	addFakeUser(t, app, "nick")
	if resp := get(); resp["bootstrap"] != false {
		t.Fatalf("bootstrap = %v, want false once users exist", resp["bootstrap"])
	}
}

func TestClientIPTakesLastXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 10.0.0.9, 192.168.1.50")
	if ip := clientIP(r); ip != "192.168.1.50" {
		t.Fatalf("clientIP = %q, want the proxy-appended last entry", ip)
	}
}

// A tap authorized for one operation must not spend on another.
func TestActionTokenOpBinding(t *testing.T) {
	app, _ := testApp(t)
	action := app.codes.Put(codeEntry{Kind: "action", Username: "nick", Op: "delete-key"}, time.Minute)
	if app.consumeAction("nick", action, "add-key") {
		t.Fatal("delete-key tap spent on add-key")
	}
}

func TestLogoutAllBumpsEpoch(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	svc := svcCookie(t, app, "nick", "app.example.com") // minted at epoch 0

	w := postAs(h, "/api/logout-all", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")}, map[string]string{})
	if w.Code != http.StatusOK {
		t.Fatalf("logout-all: %d: %s", w.Code, w.Body)
	}
	if app.store.Get("nick").SessionEpoch != 1 {
		t.Fatal("epoch not bumped")
	}
	// The old service cookie must now be dead everywhere.
	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svc)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("service cookie survived logout-all: %d", w2.Code)
	}
}

// Deleting a key is a revocation event: the epoch bumps (killing all
// outstanding sessions) and the deleting browser gets a fresh cookie.
func TestKeyDeleteBumpsEpochAndReissues(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	app.store.AddCredential("nick", []byte("handle-nick"), "spare", webauthn.Credential{ID: []byte("id2")}, false)
	svc := svcCookie(t, app, "nick", "app.example.com")

	action := app.codes.Put(codeEntry{Kind: "action", Username: "nick", Op: "delete-key"}, time.Minute)
	id := base64.RawURLEncoding.EncodeToString([]byte("id2"))
	w := postAs(h, "/api/keys/delete", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")},
		map[string]string{"id": id, "action_token": action})
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d: %s", w.Code, w.Body)
	}
	if app.store.Get("nick").SessionEpoch != 1 {
		t.Fatal("delete did not bump the epoch")
	}
	var fresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == app.cfg.CookieName && c.Value != "" {
			fresh = c
		}
	}
	if fresh == nil {
		t.Fatal("no fresh portal cookie after delete")
	}
	tok, err := verifyToken(app.cfg.SessionSecret, tokenPortal, fresh.Value, time.Now())
	if err != nil || tok.Epoch != 1 {
		t.Fatalf("fresh cookie not on the new epoch: %v %+v", err, tok)
	}
	// Old service cookie: dead.
	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svc)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("service cookie survived key deletion: %d", w2.Code)
	}
}

// Sliding renewal stops once the session lineage exceeds the absolute cap.
func TestRenewalLineageCap(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	mk := func(first time.Time) *http.Cookie {
		raw, err := signToken(app.cfg.SessionSecret, Token{
			Type: tokenPortal, Username: "nick",
			IssuedAt: time.Now().Unix(),
			First:    first.Unix(),
			// Within the renewal window (remaining < TTL/2).
			Expiry: time.Now().Add(time.Minute).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: app.cfg.CookieName, Value: raw}
	}
	renewed := func(c *http.Cookie) bool {
		r := httptest.NewRequest("GET", "/api/session", nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		for _, sc := range w.Result().Cookies() {
			if sc.Name == app.cfg.CookieName && sc.Value != "" {
				return true
			}
		}
		return false
	}

	if !renewed(mk(time.Now().Add(-24 * time.Hour))) {
		t.Fatal("young session not renewed")
	}
	if renewed(mk(time.Now().Add(-maxPortalLineage - time.Hour))) {
		t.Fatal("over-age lineage still renewing")
	}
}

// An explicit default port must not dodge the portal-host exclusion.
func TestTicketRedirectPortalPortInsensitive(t *testing.T) {
	app, _ := testApp(t)
	target := "https://tap.example.com:443/x"
	if got := app.ticketRedirect("nick", target, time.Time{}); got != target {
		t.Fatalf("portal target with explicit port got ticketed: %q", got)
	}
	if got := app.ticketRedirect("nick", "https://app.example.com/x", time.Time{}); !strings.Contains(got, ticketParam+"=") {
		t.Fatalf("app target not ticketed: %q", got)
	}
}

// ---- emergency freeze --------------------------------------------------------

func freezeCookie(t *testing.T, app *App, username string) *http.Cookie {
	t.Helper()
	raw, err := signToken(app.cfg.SessionSecret, Token{
		Type: tokenFreeze, Username: username,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: freezeCookieName, Value: raw}
}

func TestFreezeViaDeviceToken(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	svc := svcCookie(t, app, "nick", "app.example.com")

	w := postAs(h, "/api/freeze", "https://tap.example.com",
		[]*http.Cookie{freezeCookie(t, app, "nick")}, map[string]string{})
	if w.Code != http.StatusOK {
		t.Fatalf("freeze: %d: %s", w.Code, w.Body)
	}
	rec := app.store.Get("nick")
	if !rec.Disputed || rec.SessionEpoch != 1 {
		t.Fatalf("not frozen: %+v", rec)
	}

	// Everything is sealed: service cookie, portal session, login begin.
	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(svc)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("service cookie survived freeze: %d", w2.Code)
	}
	frozen := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nick"})
	unknown := postAs(h, "/api/login/begin", "https://tap.example.com", nil, map[string]string{"username": "nobody"})
	if frozen.Code != http.StatusBadRequest || frozen.Body.String() != unknown.Body.String() {
		t.Fatalf("frozen login not uniform with unknown user: %d %q vs %q", frozen.Code, frozen.Body, unknown.Body)
	}
}

// The freeze token must survive the attacker's "sign out everywhere".
func TestFreezeTokenSurvivesEpochBump(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	app.store.BumpEpoch("nick") // attacker ran logout-all

	fc := freezeCookie(t, app, "nick")
	r := httptest.NewRequest("GET", "/api/freeze/status", nil)
	r.AddCookie(fc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var st struct{ Armed bool }
	json.Unmarshal(w.Body.Bytes(), &st)
	if !st.Armed {
		t.Fatal("epoch bump disarmed the device")
	}
	w2 := postAs(h, "/api/freeze", "https://tap.example.com", []*http.Cookie{fc}, map[string]string{})
	if w2.Code != http.StatusOK || !app.store.Get("nick").Disputed {
		t.Fatal("freeze after epoch bump failed")
	}
}

func TestFreezeUniformWithoutCredential(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	w := postAs(h, "/api/freeze", "https://tap.example.com", nil, map[string]string{})
	if w.Code != http.StatusOK {
		t.Fatalf("want uniform 200, got %d", w.Code)
	}
	if app.store.Get("nick").Disputed {
		t.Fatal("credential-less request froze an account")
	}
}

func TestFreezeTokenIsDenyOnly(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	fc := freezeCookie(t, app, "nick")

	// Not a session: keys listing refuses it even smuggled under the
	// portal cookie name.
	smuggled := &http.Cookie{Name: app.cfg.CookieName, Value: fc.Value}
	r := httptest.NewRequest("GET", "/api/keys", nil)
	r.AddCookie(smuggled)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("freeze token granted access: %d", w.Code)
	}
	// Not a service cookie either.
	r2 := fwdReq("/verify", "app.example.com", "/")
	r2.Header.Set("Accept", "application/json")
	r2.AddCookie(&http.Cookie{Name: svcCookieName, Value: fc.Value})
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("freeze token passed /verify: %d", w2.Code)
	}
}

func TestFreezeArmGates(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	if w := postAs(h, "/api/freeze/arm", "https://tap.example.com", nil, map[string]string{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("arm without session: %d", w.Code)
	}

	// Public sessions never arm.
	pub := func() *http.Cookie {
		raw, _ := signToken(app.cfg.SessionSecret, Token{
			Type: tokenPortal, Username: "nick", NoRenew: true,
			IssuedAt: time.Now().Unix(), Expiry: time.Now().Add(time.Hour).Unix(),
		})
		return &http.Cookie{Name: app.cfg.CookieName, Value: raw}
	}()
	if w := postAs(h, "/api/freeze/arm", "https://tap.example.com", []*http.Cookie{pub}, map[string]string{}); w.Code != http.StatusBadRequest {
		t.Fatalf("public session armed a device: %d", w.Code)
	}

	// A bare session never mints: arming rides the login tap. The arm
	// endpoint only SLIDES an existing, matching token.
	if w := postAs(h, "/api/freeze/arm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick")}, map[string]string{}); w.Code != http.StatusForbidden {
		t.Fatalf("bare session armed a device: %d", w.Code)
	}
	// Another user's token can't be clobbered via the session either.
	addFakeUser(t, app, "other")
	if w := postAs(h, "/api/freeze/arm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick"), freezeCookie(t, app, "other")}, map[string]string{}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user token slide allowed: %d", w.Code)
	}

	w := postAs(h, "/api/freeze/arm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "nick"), freezeCookie(t, app, "nick")}, map[string]string{})
	if w.Code != http.StatusOK {
		t.Fatalf("slide of own token refused: %d: %s", w.Code, w.Body)
	}
	var fc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == freezeCookieName {
			fc = c
		}
	}
	if fc == nil || fc.Path != freezePath {
		t.Fatalf("freeze cookie missing or not path-scoped: %+v", fc)
	}
	if tok, err := verifyToken(app.cfg.SessionSecret, tokenFreeze, fc.Value, time.Now()); err != nil || tok.Username != "nick" {
		t.Fatalf("bad freeze token: %v %+v", err, tok)
	}
}

func TestDisputeClear(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "admin")
	addFakeUser(t, app, "victim")
	app.cfg.AdminUsers = []string{"admin"}
	app.store.Freeze("victim")

	// Invites for a disputed account are refused.
	action := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "invite"}, time.Minute)
	if w := postAs(h, "/api/invite", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "victim", "action_token": action}); w.Code != http.StatusConflict {
		t.Fatalf("invite minted for disputed account: %d", w.Code)
	}
	// Invite redemption for a disputed account is refused too.
	code := app.codes.Put(codeEntry{Kind: "invite", Username: "victim"}, time.Minute)
	if w := postAs(h, "/api/enroll/begin", "https://tap.example.com", nil,
		map[string]string{"token": code, "username": "victim", "key_name": "k"}); w.Code != http.StatusForbidden {
		t.Fatalf("disputed account enrolled: %d", w.Code)
	}

	// Clearing needs admin + the right op.
	wrong := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "invite"}, time.Minute)
	if w := postAs(h, "/api/dispute/clear", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "victim", "action_token": wrong}); w.Code != http.StatusForbidden {
		t.Fatalf("cleared with wrong-op token: %d", w.Code)
	}
	right := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "clear-dispute"}, time.Minute)
	if w := postAs(h, "/api/dispute/clear", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "victim", "action_token": right}); w.Code != http.StatusOK {
		t.Fatalf("clear refused: %d: %s", w.Code, w.Body)
	}
	if app.store.Get("victim").Disputed {
		t.Fatal("still disputed after clear")
	}
	// Login works again (epoch from the freeze keeps old cookies dead).
	if w := postAs(h, "/api/login/begin", "https://tap.example.com", nil,
		map[string]string{"username": "victim"}); w.Code != http.StatusOK {
		t.Fatalf("login still blocked after clear: %d", w.Code)
	}
}

func TestPublicSessionNoRenewAndCappedTickets(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	// Public portal token inside the renewal window: must NOT renew.
	raw, _ := signToken(app.cfg.SessionSecret, Token{
		Type: tokenPortal, Username: "nick", NoRenew: true,
		IssuedAt: time.Now().Unix(), First: time.Now().Unix(),
		Expiry: time.Now().Add(time.Minute).Unix(),
	})
	pub := &http.Cookie{Name: app.cfg.CookieName, Value: raw}
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.AddCookie(pub)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for _, sc := range w.Result().Cookies() {
		if sc.Name == app.cfg.CookieName && sc.Value != "" {
			t.Fatal("public session renewed")
		}
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["public"] != true {
		t.Fatalf("session not reported public: %v", resp)
	}

	// Tickets minted under it cap the service cookie to the session expiry.
	body, _ := json.Marshal(map[string]string{"rd": "https://app.example.com/x"})
	r2 := httptest.NewRequest("POST", "/api/ticket", bytes.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Origin", "https://tap.example.com")
	r2.AddCookie(pub)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	var mint struct{ Redirect string }
	json.Unmarshal(w2.Body.Bytes(), &mint)
	u, _ := url.Parse(mint.Redirect)

	r3 := fwdReq("/verify", "app.example.com", u.RequestURI())
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, r3)
	var sc *http.Cookie
	for _, c := range w3.Result().Cookies() {
		if c.Name == svcCookieName {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("no service cookie on redemption")
	}
	tok, err := verifyToken(app.cfg.SessionSecret, tokenSvc, sc.Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if time.Unix(tok.Expiry, 0).After(time.Now().Add(2 * time.Minute)) {
		t.Fatalf("service cookie outlives the public session: expires %v", time.Unix(tok.Expiry, 0))
	}
}

// A cookie minted DURING the dispute (the thief finishing a pre-freeze
// ceremony) must die when the dispute is cleared: clear bumps the epoch.
func TestClearDisputeKillsMidDisputeCookies(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "victim")
	app.store.Freeze("victim") // epoch 1

	midDispute := cookieOf(t, app, tokenSvc, svcCookieName, "victim", "app.example.com", 1)
	if err := app.store.ClearDispute("victim"); err != nil { // epoch 2
		t.Fatal(err)
	}
	r := fwdReq("/verify", "app.example.com", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(midDispute)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mid-dispute cookie survived the clear: %d", w.Code)
	}
}

// The finish-time gate: a disputed account is not assertable, so any
// in-flight login/step-up ceremony aborts at finish.
func TestAssertableUserRefusesDisputed(t *testing.T) {
	app, _ := testApp(t)
	addFakeUser(t, app, "nick")
	if app.assertableUser("nick") == nil {
		t.Fatal("healthy user not assertable")
	}
	app.store.Freeze("nick")
	if app.assertableUser("nick") != nil {
		t.Fatal("disputed user still assertable")
	}
	if app.assertableUser("ghost") != nil {
		t.Fatal("unknown user assertable")
	}
}

// Enrollment finishing after a freeze must abort before storing anything.
func TestEnrollFinishRefusesDisputed(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "victim")
	id := app.pending.Put(pendingCeremony{Kind: "register", Username: "victim", UserID: []byte("handle-victim"), CredName: "thief"})
	app.store.Freeze("victim")

	raw, _ := json.Marshal(map[string]string{})
	r := httptest.NewRequest("POST", "/api/enroll/finish", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tap.example.com")
	r.AddCookie(&http.Cookie{Name: ceremonyCookie, Value: id})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if n := len(app.store.Get("victim").Credentials); n != 1 {
		t.Fatalf("credential count changed on disputed account: %d", n)
	}
}

// A bumped freeze epoch kills outstanding freeze tokens (leaked-token
// remediation) without touching sessions.
func TestFreezeEpochDisarm(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	fc := freezeCookie(t, app, "nick") // minted at freeze_epoch 0

	if err := app.store.DisarmFreezeTokens("nick"); err != nil {
		t.Fatal(err)
	}
	// Status: disarmed.
	r := httptest.NewRequest("GET", "/api/freeze/status", nil)
	r.AddCookie(fc)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var st struct{ Armed bool }
	json.Unmarshal(w.Body.Bytes(), &st)
	if st.Armed {
		t.Fatal("stale freeze token still reports armed")
	}
	// Freeze attempt with the stale token: uniform response, no freeze.
	w2 := postAs(h, "/api/freeze", "https://tap.example.com", []*http.Cookie{fc}, map[string]string{})
	if w2.Code != http.StatusOK {
		t.Fatalf("want uniform 200, got %d", w2.Code)
	}
	if app.store.Get("nick").Disputed {
		t.Fatal("stale freeze token froze the account")
	}
	// Sessions were untouched: session epoch still 0.
	if app.store.Get("nick").SessionEpoch != 0 {
		t.Fatal("disarm touched the session epoch")
	}
}

func TestFreezeDisarmEndpointGates(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "admin")
	addFakeUser(t, app, "victim")
	app.cfg.AdminUsers = []string{"admin"}

	// Non-admin refused.
	act := app.codes.Put(codeEntry{Kind: "action", Username: "victim", Op: "disarm-freeze"}, time.Minute)
	if w := postAs(h, "/api/freeze/disarm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "victim")},
		map[string]string{"username": "victim", "action_token": act}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin disarmed: %d", w.Code)
	}
	// Admin without step-up refused.
	if w := postAs(h, "/api/freeze/disarm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "victim", "action_token": "stale"}); w.Code != http.StatusForbidden {
		t.Fatalf("disarm without step-up: %d", w.Code)
	}
	// Own account refused even for an admin with a fresh tap.
	self := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "disarm-freeze"}, time.Minute)
	if w := postAs(h, "/api/freeze/disarm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "admin", "action_token": self}); w.Code != http.StatusBadRequest {
		t.Fatalf("self-disarm allowed in-protocol: %d", w.Code)
	}
	// Admin + tap + other account: works.
	ok := app.codes.Put(codeEntry{Kind: "action", Username: "admin", Op: "disarm-freeze"}, time.Minute)
	if w := postAs(h, "/api/freeze/disarm", "https://tap.example.com",
		[]*http.Cookie{portalCookie(t, app, "admin")},
		map[string]string{"username": "victim", "action_token": ok}); w.Code != http.StatusOK {
		t.Fatalf("disarm refused: %d: %s", w.Code, w.Body)
	}
	if app.store.Get("victim").FreezeEpoch != 1 {
		t.Fatal("freeze epoch not bumped")
	}
}

// On a device carrying another user's freeze token, scope=session lets
// the signed-in user freeze THEMSELVES; the default still freezes the
// token's account. Neither path is shadowed by the other.
func TestFreezeScopeSession(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "alice") // token holder (device owner)
	addFakeUser(t, app, "bob")   // signed-in guest
	cookies := []*http.Cookie{freezeCookie(t, app, "alice"), portalCookie(t, app, "bob")}

	w := postAs(h, "/api/freeze", "https://tap.example.com", cookies, map[string]string{"scope": "session"})
	if w.Code != http.StatusOK {
		t.Fatalf("freeze: %d: %s", w.Code, w.Body)
	}
	if app.store.Get("alice").Disputed {
		t.Fatal("scope=session froze the token holder")
	}
	if !app.store.Get("bob").Disputed {
		t.Fatal("scope=session did not freeze the session user")
	}

	// Default scope: the token's account.
	w2 := postAs(h, "/api/freeze", "https://tap.example.com", cookies, map[string]string{})
	if w2.Code != http.StatusOK {
		t.Fatalf("freeze: %d: %s", w2.Code, w2.Body)
	}
	if !app.store.Get("alice").Disputed {
		t.Fatal("default scope did not freeze the token holder")
	}
}
