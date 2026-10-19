package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Two-tier sessions, so no backend ever sees a long-lived credential:
//
//   - "portal": host-only cookie on the portal origin. Long-lived, with
//     sliding renewal — renewal happens at the portal, where Set-Cookie
//     actually reaches the browser (Caddy's forward_auth discards
//     everything except copy_headers on a 2xx response).
//   - "svc": host-only cookie on ONE protected app host, short-lived and
//     bound to that host. Minted by redeeming a one-time ticket from the
//     portal. A compromised backend can replay it only against itself,
//     and only until it expires or the user's epoch is bumped.
const (
	tokenPortal = "portal"
	tokenSvc    = "svc"
)

// Token is the payload of a stateless HMAC-signed cookie.
type Token struct {
	Type     string `json:"t"`
	Username string `json:"u"`
	Host     string `json:"h,omitempty"` // svc only: the one host this is valid for
	IssuedAt int64  `json:"i"`
	// First is the original login time, carried across sliding renewals so
	// a stolen portal cookie can't renew itself forever: renewal is
	// refused once the lineage exceeds maxPortalLineage.
	First  int64 `json:"f,omitempty"`
	Expiry int64 `json:"e"`
	// Epoch must equal the user's current session_epoch in users.json.
	// Bumping that number (API-less: edit the file) is the panic button —
	// it invalidates every outstanding cookie for the user at once.
	Epoch int64 `json:"p"`
}

var errBadToken = errors.New("invalid session token")

func signToken(secret []byte, tok Token) (string, error) {
	payload, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// verifyToken checks signature, type, username and expiry. The epoch and
// host-binding checks are the caller's job (they need the user record and
// the request context).
func verifyToken(secret []byte, typ, raw string, now time.Time) (Token, error) {
	var tok Token
	dot := strings.IndexByte(raw, '.')
	if dot < 0 {
		return tok, errBadToken
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(raw[:dot])
	if err != nil {
		return tok, errBadToken
	}
	sig, err := enc.DecodeString(raw[dot+1:])
	if err != nil {
		return tok, errBadToken
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return tok, errBadToken
	}
	if err := json.Unmarshal(payload, &tok); err != nil {
		return tok, errBadToken
	}
	if tok.Type != typ || tok.Username == "" || now.Unix() >= tok.Expiry {
		return tok, errBadToken
	}
	return tok, nil
}
