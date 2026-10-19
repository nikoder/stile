// stile — a minimal WebAuthn forward-auth gate.
//
// One job: put a "type username, tap hardware key" login in front of
// reverse-proxied services, with NO PIN and NO password. It deliberately
// uses non-discoverable (server-side) credentials and asks for
// userVerification=discouraged, because a username-first assertion with a
// populated allowCredentials list is the only WebAuthn flow that every
// major browser performs on a PIN-less security key. Usernameless
// "passkey" flows need discoverable credentials, which Chromium refuses
// to create or enumerate without a PIN.
//
// Threat model (explicit): the key's presence test defends against
// remote credential theft, phishing and keylogging. Physical theft of
// the key is accepted — a PIN would tax every legitimate login to cover
// that case.
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web
var webFS embed.FS

type Config struct {
	Listen         string        // bind address
	PortalURL      *url.URL      // public URL of this portal (login page)
	RPID           string        // WebAuthn RP ID; also the zone apps may live under
	Origins        []string      // allowed WebAuthn origins (exact scheme://host[:port])
	CookieName     string        // portal session cookie name (host-only on the portal)
	SessionSecret  []byte        // HMAC key for all tokens (>= 32 bytes)
	SessionTTL     time.Duration // portal session lifetime (sliding)
	SvcTTL         time.Duration // per-app service cookie lifetime (re-bounce is silent)
	BootstrapToken string        // enrolls the FIRST user only; invites after that
	AdminUsers     []string      // extra admins beside the bootstrap user
	DataDir        string        // where users.json lives
	DisplayName    string        // RP display name shown by authenticator UIs
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		Listen:         envDefault("STILE_LISTEN", ":9092"),
		CookieName:     envDefault("STILE_COOKIE_NAME", "stile_session"),
		DataDir:        envDefault("STILE_DATA", "/data"),
		DisplayName:    envDefault("STILE_DISPLAY_NAME", "stile"),
		BootstrapToken: os.Getenv("STILE_BOOTSTRAP_TOKEN"),
	}
	if admins := os.Getenv("STILE_ADMIN_USERS"); admins != "" {
		for _, u := range strings.Split(admins, ",") {
			if u = strings.ToLower(strings.TrimSpace(u)); u != "" {
				cfg.AdminUsers = append(cfg.AdminUsers, u)
			}
		}
	}

	rawPortal := os.Getenv("STILE_PORTAL_URL")
	if rawPortal == "" {
		return nil, fmt.Errorf("STILE_PORTAL_URL is required (e.g. https://tap.example.com)")
	}
	portal, err := url.Parse(rawPortal)
	if err != nil || portal.Scheme != "https" || portal.Host == "" {
		return nil, fmt.Errorf("STILE_PORTAL_URL must be an absolute https URL, got %q", rawPortal)
	}
	portal.Path = strings.TrimSuffix(portal.Path, "/")
	cfg.PortalURL = portal

	// RP ID defaults to the portal host; set it to a parent domain
	// (e.g. example.com for tap.example.com) so credentials survive a
	// portal rename and sibling apps fall inside the redirect zone. It
	// scopes no cookie — all cookies are host-only.
	cfg.RPID = envDefault("STILE_RP_ID", portal.Hostname())
	if cfg.RPID != portal.Hostname() && !strings.HasSuffix(portal.Hostname(), "."+cfg.RPID) {
		return nil, fmt.Errorf("STILE_RP_ID %q is not a registrable suffix of the portal host %q", cfg.RPID, portal.Hostname())
	}

	cfg.Origins = []string{portal.Scheme + "://" + portal.Host}
	if extra := os.Getenv("STILE_EXTRA_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.Origins = append(cfg.Origins, o)
			}
		}
	}

	secret := os.Getenv("STILE_SESSION_SECRET")
	if len(secret) < 32 {
		return nil, fmt.Errorf("STILE_SESSION_SECRET must be at least 32 characters (have %d)", len(secret))
	}
	cfg.SessionSecret = []byte(secret)

	ttl := envDefault("STILE_SESSION_TTL", "720h")
	cfg.SessionTTL, err = time.ParseDuration(ttl)
	if err != nil || cfg.SessionTTL <= 0 {
		return nil, fmt.Errorf("STILE_SESSION_TTL %q is not a positive Go duration", ttl)
	}

	svcTTL := envDefault("STILE_SVC_TTL", "8h")
	cfg.SvcTTL, err = time.ParseDuration(svcTTL)
	if err != nil || cfg.SvcTTL <= 0 {
		return nil, fmt.Errorf("STILE_SVC_TTL %q is not a positive Go duration", svcTTL)
	}

	return cfg, nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newApp(cfg *Config, store *Store) (*App, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.DisplayName,
		RPOrigins:     cfg.Origins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	return &App{
		cfg:     cfg,
		store:   store,
		wa:      wa,
		pending: newPendingStore(5 * time.Minute),
		codes:   newCodeStore(),
		limiter: newLimiter(5 * time.Minute),
	}, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := OpenStore(filepath.Join(cfg.DataDir, "users.json"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	app, err := newApp(cfg, store)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	static, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embedded assets: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Routes(static),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if store.UserCount() == 0 && cfg.BootstrapToken == "" {
		log.Printf("WARNING: no users and no STILE_BOOTSTRAP_TOKEN — nobody can enroll")
	}
	log.Printf("stile listening on %s (rp_id=%s portal=%s users=%d svc_ttl=%s)",
		cfg.Listen, cfg.RPID, cfg.PortalURL, store.UserCount(), cfg.SvcTTL)
	log.Fatal(srv.ListenAndServe())
}
