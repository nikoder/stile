package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// pendingCeremony holds the server half of an in-flight WebAuthn ceremony
// (challenge etc.), keyed by a random ID in a short-lived cookie. In-memory
// only: a restart mid-ceremony just means the human retries the tap.
type pendingCeremony struct {
	Kind     string // "login" or "register"
	Username string
	UserID   []byte // registration only: handle the ceremony ran with
	CredName string // registration only
	Admin    bool   // registration only: bootstrap user becomes admin
	Op       string // stepup only: the one operation the tap authorizes
	Session  webauthn.SessionData
	Expires  time.Time
}

type pendingStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]pendingCeremony
}

func newPendingStore(ttl time.Duration) *pendingStore {
	return &pendingStore{ttl: ttl, m: map[string]pendingCeremony{}}
}

func (p *pendingStore) Put(c pendingCeremony) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand failure is not a recoverable state
	}
	id := hex.EncodeToString(buf)
	c.Expires = time.Now().Add(p.ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.m { // opportunistic sweep; the map stays tiny
		if time.Now().After(v.Expires) {
			delete(p.m, k)
		}
	}
	p.m[id] = c
	return id
}

// Take consumes the ceremony: single use, expired entries don't count.
func (p *pendingStore) Take(id string) (pendingCeremony, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.m[id]
	if !ok {
		return pendingCeremony{}, false
	}
	delete(p.m, id)
	if time.Now().After(c.Expires) {
		return pendingCeremony{}, false
	}
	return c, true
}
