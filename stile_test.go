package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		Listen:        ":0",
		PortalURL:     portal,
		RPID:          "example.com",
		Origins:       []string{"https://tap.example.com"},
		CookieName:    "stile_session",
		SessionSecret: []byte(strings.Repeat("s", 32)),
		SessionTTL:    time.Hour,
		EnrollToken:   "sekrit-enroll",
		DataDir:       t.TempDir(),
		DisplayName:   "stile-test",
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
	if err := app.store.AddCredential(username, []byte("handle-"+username), "test key", cred); err != nil {
		t.Fatal(err)
	}
}

func sessionCookie(t *testing.T, app *App, username string) *http.Cookie {
	t.Helper()
	tok, err := signSession(app.cfg.SessionSecret, Session{
		Username: username,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: app.cfg.CookieName, Value: tok}
}

// ---- sessions -------------------------------------------------------------

func TestSessionRoundTrip(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	tok, err := signSession(secret, Session{Username: "nick", IssuedAt: 1, Expiry: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	s, err := verifySession(secret, tok, time.Now())
	if err != nil || s.Username != "nick" {
		t.Fatalf("round trip failed: %v %+v", err, s)
	}
}

func TestSessionTampered(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	tok, _ := signSession(secret, Session{Username: "nick", Expiry: time.Now().Add(time.Hour).Unix()})

	if _, err := verifySession([]byte(strings.Repeat("x", 32)), tok, time.Now()); err == nil {
		t.Fatal("accepted token signed with a different key")
	}
	mangled := "A" + tok[1:]
	if _, err := verifySession(secret, mangled, time.Now()); err == nil {
		t.Fatal("accepted mangled token")
	}
	if _, err := verifySession(secret, "garbage", time.Now()); err == nil {
		t.Fatal("accepted garbage token")
	}
}

func TestSessionExpiry(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	tok, _ := signSession(secret, Session{Username: "nick", Expiry: time.Now().Add(time.Hour).Unix()})
	if _, err := verifySession(secret, tok, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("accepted expired token")
	}
}

// ---- store ----------------------------------------------------------------

func TestStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cred := webauthn.Credential{ID: []byte("id1"), PublicKey: []byte("pk1")}
	if err := s1.AddCredential("nick", []byte("handle"), "main", cred); err != nil {
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
	if string(rec.Credentials[0].Credential.ID) != "id1" {
		t.Fatal("credential ID did not survive the JSON round trip")
	}
	if string(rec.ID) != "handle" {
		t.Fatal("user handle did not survive the JSON round trip")
	}
}

func TestStoreHandleMismatch(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "users.json"))
	cred := webauthn.Credential{ID: []byte("id1")}
	if err := s.AddCredential("nick", []byte("handle"), "a", cred); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCredential("nick", []byte("other"), "b", cred); err == nil {
		t.Fatal("accepted a second credential under a different user handle")
	}
}

// ---- /verify --------------------------------------------------------------

func TestVerifyUnauthenticatedBrowser(t *testing.T) {
	_, h := testApp(t)
	r := httptest.NewRequest("GET", "/verify", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Uri", "/dash?x=1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	want := "https://tap.example.com/?rd=" + url.QueryEscape("https://app.example.com/dash?x=1")
	if loc != want {
		t.Fatalf("redirect = %q, want %q", loc, want)
	}
}

func TestVerifyUnauthenticatedAPI(t *testing.T) {
	_, h := testApp(t)
	r := httptest.NewRequest("GET", "/verify", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestVerifyAuthenticated(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(sessionCookie(t, app, "nick"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if got := w.Header().Get("Remote-User"); got != "nick" {
		t.Fatalf("Remote-User = %q", got)
	}
}

// A valid cookie for a user that no longer exists must not pass: deleting
// the user from users.json is the revocation story.
func TestVerifyDeletedUser(t *testing.T) {
	app, h := testApp(t)
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(sessionCookie(t, app, "ghost"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for deleted user, got %d", w.Code)
	}
}

// ---- redirect validation ----------------------------------------------------

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

// ---- ceremony endpoints -----------------------------------------------------

func postAs(h http.Handler, path, origin string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoginBeginUnknownUserIsGeneric(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")

	known := postAs(h, "/api/login/begin", "https://tap.example.com", map[string]string{"username": "nobody"})
	invalid := postAs(h, "/api/login/begin", "https://tap.example.com", map[string]string{"username": "NO SUCH !!"})
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

	w := postAs(h, "/api/login/begin", "https://tap.example.com", map[string]string{"username": "nick"})
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
	w := postAs(h, "/api/login/begin", "https://evil.com", map[string]string{"username": "nick"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if w2 := postAs(h, "/api/login/begin", "", map[string]string{"username": "nick"}); w2.Code != http.StatusForbidden {
		t.Fatalf("want 403 for missing origin, got %d", w2.Code)
	}
}

func TestEnrollBeginToken(t *testing.T) {
	_, h := testApp(t)
	bad := postAs(h, "/api/enroll/begin", "https://tap.example.com",
		map[string]string{"token": "wrong", "username": "nick", "key_name": "k"})
	if bad.Code != http.StatusForbidden {
		t.Fatalf("want 403 for bad token, got %d", bad.Code)
	}
	good := postAs(h, "/api/enroll/begin", "https://tap.example.com",
		map[string]string{"token": "sekrit-enroll", "username": "nick", "key_name": "k"})
	if good.Code != http.StatusOK {
		t.Fatalf("want 200 for good token, got %d: %s", good.Code, good.Body)
	}
	var opts struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(good.Body.Bytes(), &opts); err != nil {
		t.Fatal(err)
	}
	if opts.PublicKey.AuthenticatorSelection.ResidentKey != "discouraged" {
		t.Fatalf("residentKey = %q, want discouraged", opts.PublicKey.AuthenticatorSelection.ResidentKey)
	}
	if opts.PublicKey.AuthenticatorSelection.UserVerification != "discouraged" {
		t.Fatalf("userVerification = %q, want discouraged", opts.PublicKey.AuthenticatorSelection.UserVerification)
	}
}

func TestEnrollDisabledWithoutToken(t *testing.T) {
	app, h := testApp(t)
	app.cfg.EnrollToken = ""
	w := postAs(h, "/api/enroll/begin", "https://tap.example.com",
		map[string]string{"token": "", "username": "nick", "key_name": "k"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 when enrollment disabled, got %d", w.Code)
	}
}

func TestFinishWithoutCeremony(t *testing.T) {
	_, h := testApp(t)
	w := postAs(h, "/api/login/finish", "https://tap.example.com", map[string]string{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestFailureLockout(t *testing.T) {
	app, h := testApp(t)
	addFakeUser(t, app, "nick")
	for i := 0; i < 10; i++ {
		postAs(h, "/api/login/begin", "https://tap.example.com", map[string]string{"username": "nobody"})
	}
	w := postAs(h, "/api/login/begin", "https://tap.example.com", map[string]string{"username": "nick"})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after repeated failures, got %d", w.Code)
	}
}

func TestSessionReportsEnrollmentState(t *testing.T) {
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
	if resp := get(); resp["enrollment"] != true {
		t.Fatalf("enrollment = %v, want true while a token is set", resp["enrollment"])
	}
	app.cfg.EnrollToken = ""
	if resp := get(); resp["enrollment"] != false {
		t.Fatalf("enrollment = %v, want false with no token", resp["enrollment"])
	}
}
