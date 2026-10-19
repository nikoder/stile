package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Session is the payload of the stateless HMAC-signed cookie. There is no
// server-side session table: logout just clears the cookie, and a stolen
// cookie stays valid until expiry — same model as most forward-auth gates.
type Session struct {
	Username string `json:"u"`
	IssuedAt int64  `json:"i"`
	Expiry   int64  `json:"e"`
}

var errBadToken = errors.New("invalid session token")

func signSession(secret []byte, s Session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

func verifySession(secret []byte, token string, now time.Time) (Session, error) {
	var s Session
	dot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return s, errBadToken
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(token[:dot])
	if err != nil {
		return s, errBadToken
	}
	sig, err := enc.DecodeString(token[dot+1:])
	if err != nil {
		return s, errBadToken
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return s, errBadToken
	}
	if err := json.Unmarshal(payload, &s); err != nil {
		return s, errBadToken
	}
	if s.Username == "" || now.Unix() >= s.Expiry {
		return s, errBadToken
	}
	return s, nil
}
