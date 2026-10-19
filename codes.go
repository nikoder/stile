package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// codeStore holds short-lived single-use codes: service tickets (portal →
// app bounce), invite codes (admin → new enrollment) and action tokens
// (step-up tap → one sensitive operation). In-memory on purpose — a
// restart invalidates them all, and every flow just retries.
type codeEntry struct {
	Kind     string // "ticket", "invite", "action"
	Username string
	Host     string // ticket only: the app host the ticket is bound to
	Op       string // action only: the one operation the step-up tap authorizes
	// SvcCap (ticket only, zero = none) caps the minted service cookie's
	// expiry — tickets from a public-device session must not outlive it.
	SvcCap  time.Time
	Expires time.Time
}

type codeStore struct {
	mu sync.Mutex
	m  map[string]codeEntry
}

func newCodeStore() *codeStore {
	return &codeStore{m: map[string]codeEntry{}}
}

func (c *codeStore) Put(e codeEntry, ttl time.Duration) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand failure is not a recoverable state
	}
	code := hex.EncodeToString(buf)
	e.Expires = time.Now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m { // opportunistic sweep; the map stays tiny
		if time.Now().After(v.Expires) {
			delete(c.m, k)
		}
	}
	c.m[code] = e
	return code
}

// Take consumes the code: single use, wrong kind or expired entries fail.
// A code is burned even when the caller's follow-up checks (username,
// host binding) then fail — deliberately: a guessed-then-misused code
// must not remain redeemable.
func (c *codeStore) Take(kind, code string) (codeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[code]
	if !ok {
		return codeEntry{}, false
	}
	delete(c.m, code)
	if e.Kind != kind || time.Now().After(e.Expires) {
		return codeEntry{}, false
	}
	return e, true
}
