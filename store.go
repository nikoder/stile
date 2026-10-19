package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// StoredCredential wraps the library's credential with bookkeeping shown
// to the human (name, timestamps). The embedded webauthn.Credential holds
// the public key, credential ID and sign counter.
type StoredCredential struct {
	Name       string              `json:"name"`
	AddedAt    time.Time           `json:"added_at"`
	LastUsedAt time.Time           `json:"last_used_at"`
	Credential webauthn.Credential `json:"credential"`
}

type UserRecord struct {
	// ID is the WebAuthn user handle: random bytes fixed at creation,
	// never the username (the spec forbids PII in user handles).
	ID          []byte             `json:"id"`
	Username    string             `json:"username"`
	CreatedAt   time.Time          `json:"created_at"`
	Credentials []StoredCredential `json:"credentials"`
}

// Store is a mutex-guarded JSON file. The whole dataset is a handful of
// public keys for a handful of humans; a database would be ceremony.
type Store struct {
	mu   sync.Mutex
	path string
	data map[string]*UserRecord
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]*UserRecord{}}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

// Get returns a deep-enough copy: callers may read the record and its
// credential slice without racing later writes.
func (s *Store) Get(username string) *UserRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[username]
	if !ok {
		return nil
	}
	cp := *rec
	cp.Credentials = append([]StoredCredential(nil), rec.Credentials...)
	return &cp
}

func (s *Store) UserCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

// AddCredential creates the user record on first enrollment. userID is the
// handle the registration ceremony ran with; for an existing user it must
// match the stored handle.
func (s *Store) AddCredential(username string, userID []byte, name string, cred webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[username]
	if !ok {
		rec = &UserRecord{ID: userID, Username: username, CreatedAt: time.Now().UTC()}
		s.data[username] = rec
	} else if string(rec.ID) != string(userID) {
		return fmt.Errorf("user handle mismatch for %q", username)
	}
	rec.Credentials = append(rec.Credentials, StoredCredential{
		Name:       name,
		AddedAt:    time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		Credential: cred,
	})
	return s.saveLocked()
}

// TouchCredential persists the post-login credential state (sign counter)
// and bumps last_used_at.
func (s *Store) TouchCredential(username string, cred *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[username]
	if !ok {
		return fmt.Errorf("unknown user %q", username)
	}
	for i := range rec.Credentials {
		if string(rec.Credentials[i].Credential.ID) == string(cred.ID) {
			rec.Credentials[i].Credential = *cred
			rec.Credentials[i].LastUsedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("unknown credential for %q", username)
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
