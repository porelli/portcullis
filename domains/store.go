package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// Everything the service keeps — credentials, the ACME account key,
// per-domain state and the issued certificates with their private keys —
// is one JSON document, age-encrypted to the X25519 identity in
// secrets/domains/age.key (contract §12.4 "Secrets at rest"). It is written
// to a temporary file and renamed, mode 0600. The volume (and so a backup
// of it) never holds a credential in clear.

const storeVersion = 1

// Domain is one enrolled domain. Credentials never leave the service: they
// are stripped from every API answer (View) and redacted from errors.
type Domain struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
	State       string            `json:"state"`
	RecordsOK   bool              `json:"records_ok"`
	LastError   string            `json:"last_error"`
	// CertPEM is the full chain, KeyPEM its private key (PKCS#8 / EC PEM).
	CertPEM      string     `json:"cert_pem,omitempty"`
	KeyPEM       string     `json:"key_pem,omitempty"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	// Records are the records the service set (A/AAAA, its CAA entries,
	// opted-in sets), per DNS zone (the
	// zone found for the domain may change over its life); DELETE removes
	// every one of them.
	Records map[string][]RecordRef `json:"records,omitempty"`
	// Failures counts consecutive failed attempts (backoff); NextAttempt
	// is when work may run again; RecordsCheckedAt is the last records check.
	Failures         int       `json:"failures"`
	NextAttempt      time.Time `json:"next_attempt"`
	RecordsCheckedAt time.Time `json:"records_checked_at"`
	// Generation is unique per enrollment and per credentials replacement
	// (from storeDoc.NextGeneration, never reused — also not after a
	// delete and re-enroll): work started for an older one never commits.
	Generation int `json:"generation"`
	// EnrollID is the generation the enrollment started with (unchanged by
	// a credentials replacement): records a running step created are
	// recorded against it, so they are never lost.
	EnrollID int `json:"enroll_id"`
	// AppliedIPv4 / AppliedIPv6: the addresses the records were last set
	// to; a different configured address makes the records due at start.
	AppliedIPv4 string `json:"applied_ipv4,omitempty"`
	AppliedIPv6 string `json:"applied_ipv6,omitempty"`
	// CAAAccountURI: the ACME account URI the live CAA pin was written
	// with ("" = none written); another current URI makes caa due.
	CAAAccountURI string `json:"caa_account_uri,omitempty"`
	// CAAOK: the last check found our CAA in place and the CA would issue
	// for <d> and *.<d> (false with CAA off or an unknown CA).
	CAAOK bool `json:"caa_ok"`
	// DNSSEC: the last chain check's state (dnssec.State).
	DNSSEC string `json:"dnssec"`
	// Sets: the optional record sets opted in (nomail); DueSets: sets to
	// apply on the next records step (POST /domains/{name}/dns/apply).
	Sets    []string `json:"sets,omitempty"`
	DueSets []string `json:"due_sets,omitempty"`
	// SignRequested: turn DNSSEC signing on in the next records step.
	SignRequested bool `json:"sign_requested,omitempty"`
	// Deleting: a DELETE is in progress (not persisted). No new work
	// starts and running work commits nothing but the records it set.
	Deleting bool `json:"-"`
}

// RecordRef is a record the service created (relative to Zone).
type RecordRef struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Account is the ACME account (one for all domains).
type Account struct {
	Email        string `json:"email"`
	CAServer     string `json:"ca_server"`
	KeyPEM       string `json:"key_pem"`
	Registration []byte `json:"registration,omitempty"` // lego's registration.Resource as JSON
}

type storeDoc struct {
	Version int `json:"version"`
	// NextGeneration: the last Domain.Generation handed out.
	NextGeneration int                `json:"next_generation"`
	Account        *Account           `json:"account,omitempty"`
	Domains        map[string]*Domain `json:"domains"`
}

// Store reads and writes the encrypted document. Not safe for concurrent
// use on its own: the Service serialises access.
type Store struct {
	path      string
	identity  *age.X25519Identity
	recipient *age.X25519Recipient
}

// loadIdentity reads an age X25519 identity file (comments allowed).
func loadIdentity(path string) (*age.X25519Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("age key %s unreadable: %w", path, err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("age key %s: %w", path, err)
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("age key %s: want exactly one identity, got %d", path, len(ids))
	}
	id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("age key %s: not an X25519 identity", path)
	}
	return id, nil
}

// OpenStore returns the store at dir/store.age with the given identity.
func OpenStore(dir string, id *age.X25519Identity) *Store {
	return &Store{path: filepath.Join(dir, "store.age"), identity: id, recipient: id.Recipient()}
}

// Load decrypts the document; a missing file is an empty store. A file
// that can't be decrypted (wrong key, corrupt) is an error: starting empty
// would forget every domain and its records.
func (s *Store) Load() (*storeDoc, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &storeDoc{Version: storeVersion, Domains: map[string]*Domain{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, s.identity)
	if err != nil {
		return nil, fmt.Errorf("%s: decrypt (wrong secrets/domains/age.key?): %w", s.path, err)
	}
	var doc storeDoc
	dec := json.NewDecoder(io.LimitReader(r, 64<<20))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if doc.Version != storeVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", s.path, doc.Version)
	}
	if doc.Domains == nil {
		doc.Domains = map[string]*Domain{}
	}
	for _, d := range doc.Domains {
		if d.Generation > doc.NextGeneration {
			doc.NextGeneration = d.Generation
		}
	}
	return &doc, nil
}

// Save encrypts and atomically replaces the document.
func (s *Store) Save(doc *storeDoc) error {
	doc.Version = storeVersion
	plain, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".store-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// redact replaces every credential value (and its common encodings) in
// msg. Every error message that may reach last_error, a log line or an API
// answer goes through it (contract §12.2: messages never contain
// credentials).
func redact(msg string, creds map[string]string) string {
	for _, v := range creds {
		if len(v) < 4 {
			continue
		}
		for _, form := range []string{v, fmt.Sprintf("%q", v), url.QueryEscape(v), url.PathEscape(v)} {
			msg = strings.ReplaceAll(msg, form, "[redacted]")
		}
		if len(v) >= 12 {
			// A provider might echo a truncated or partly masked token.
			msg = strings.ReplaceAll(msg, v[:len(v)/2], "[redacted]")
		}
	}
	return msg
}
