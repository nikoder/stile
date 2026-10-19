package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
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
	ID       []byte `json:"id"`
	Username string `json:"username"`
	// Admin users can mint invite codes. Set automatically for the
	// bootstrap user; editable by hand in users.json or via
	// STILE_ADMIN_USERS.
	Admin bool `json:"admin"`
	// SessionEpoch is the revocation lever: every cookie embeds the epoch
	// it was minted under and is rejected on mismatch. Bump this number
	// (edit users.json — the file is re-read on change) to kill every
	// outstanding session for the user at once.
	SessionEpoch int64              `json:"session_epoch"`
	CreatedAt    time.Time          `json:"created_at"`
	Credentials  []StoredCredential `json:"credentials"`
}

// Store is a mutex-guarded JSON file. The whole dataset is a handful of
// public keys for a handful of humans; a database would be ceremony.
//
// The file is re-read whenever its mtime/size changes, so a hand edit
// (delete a user, bump an epoch) takes effect on the next request — no
// restart, and no risk of the next login's save clobbering the edit.
type Store struct {
	mu   sync.Mutex
	path string
	data map[string]*UserRecord

	loadedMod  time.Time
	loadedSize int64
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]*UserRecord{}}
	if err := s.reloadLocked(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) reloadLocked() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	data := map[string]*UserRecord{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	s.data = data
	if st, err := os.Stat(s.path); err == nil {
		s.loadedMod, s.loadedSize = st.ModTime(), st.Size()
	}
	return nil
}

// maybeReloadLocked picks up external edits to users.json. On a parse
// error the previous in-memory state is kept (and the error logged) so a
// half-finished edit can't lock everyone out.
func (s *Store) maybeReloadLocked() {
	st, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if st.ModTime().Equal(s.loadedMod) && st.Size() == s.loadedSize {
		return
	}
	if err := s.reloadLocked(); err != nil {
		log.Printf("users.json changed but failed to reload (keeping previous state): %v", err)
		// Remember the broken version so the error isn't logged per-request.
		s.loadedMod, s.loadedSize = st.ModTime(), st.Size()
	} else {
		log.Printf("users.json reloaded (external change)")
	}
}

// Get returns a deep-enough copy: callers may read the record and its
// credential slice without racing later writes.
func (s *Store) Get(username string) *UserRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeReloadLocked()
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
	s.maybeReloadLocked()
	return len(s.data)
}

// AddCredential creates the user record on first enrollment. userID is the
// handle the registration ceremony ran with; for an existing user it must
// match the stored handle. admin is only applied when creating the record.
func (s *Store) AddCredential(username string, userID []byte, name string, cred webauthn.Credential, admin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeReloadLocked()
	rec, ok := s.data[username]
	if !ok {
		rec = &UserRecord{ID: userID, Username: username, Admin: admin, CreatedAt: time.Now().UTC()}
		s.data[username] = rec
	} else if !bytes.Equal(rec.ID, userID) {
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
	s.maybeReloadLocked()
	rec, ok := s.data[username]
	if !ok {
		return fmt.Errorf("unknown user %q", username)
	}
	for i := range rec.Credentials {
		if bytes.Equal(rec.Credentials[i].Credential.ID, cred.ID) {
			rec.Credentials[i].Credential = *cred
			rec.Credentials[i].LastUsedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("unknown credential for %q", username)
}

// RenameCredential changes a credential's display name.
func (s *Store) RenameCredential(username string, credID []byte, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeReloadLocked()
	rec, ok := s.data[username]
	if !ok {
		return fmt.Errorf("unknown user %q", username)
	}
	for i := range rec.Credentials {
		if bytes.Equal(rec.Credentials[i].Credential.ID, credID) {
			rec.Credentials[i].Name = name
			return s.saveLocked()
		}
	}
	return fmt.Errorf("unknown credential for %q", username)
}

// DeleteCredential removes a credential — except the user's last one:
// locking yourself out should take a deliberate users.json edit, not a
// misclick.
func (s *Store) DeleteCredential(username string, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeReloadLocked()
	rec, ok := s.data[username]
	if !ok {
		return fmt.Errorf("unknown user %q", username)
	}
	if len(rec.Credentials) <= 1 {
		return fmt.Errorf("refusing to delete the last credential for %q", username)
	}
	for i := range rec.Credentials {
		if bytes.Equal(rec.Credentials[i].Credential.ID, credID) {
			rec.Credentials = append(rec.Credentials[:i], rec.Credentials[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("unknown credential for %q", username)
}

// saveLocked writes atomically (temp + rename) and fsyncs both the file
// and its directory: this box has lost power with dirty storage before,
// and a truncated users.json means total lockout.
func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: persist the rename itself
		d.Close()
	}
	if st, err := os.Stat(s.path); err == nil {
		s.loadedMod, s.loadedSize = st.ModTime(), st.Size()
	}
	return nil
}
