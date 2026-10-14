// Package blob seals and opens wake blobs (PUSH-GATEWAY §4): the gateway's
// only record of a registration, kept by the registering vault alone.
//
//	wake_blob = base64url-nopad( 0x01 || key_id(4) || nonce(24) || ct )
//	ct        = XChaCha20-Poly1305(blob_key[key_id], nonce,
//	                aad = "vettid/push/1/blob" || 0x00 || channel, pt = JSON record)
//
// It also seals the pending registration a registration answers with
// while the push token's challenge is outstanding (§5.1): the same
// format and keys, the record with the challenge code "c" added, under
// the associated data "vettid/push/1/pending" || 0x00 || channel, so a
// pending registration never opens as a wake blob, nor the reverse.
//
// Nothing in this package logs, and no error carries blob, key or record
// material.
package blob

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Version is the blob format's first byte.
	Version = 0x01
	// MaxLen bounds a blob's encoded form (§4: at most 6,144 bytes).
	MaxLen = 6144
	// KeyIDLen is the length of a key id inside a blob.
	KeyIDLen = 4
	// KeySize is the length of a blob key.
	KeySize = chacha20poly1305.KeySize

	aadLabel     = "vettid/push/1/blob"
	pendingLabel = "vettid/push/1/pending"
	headerLen    = 1 + KeyIDLen + chacha20poly1305.NonceSizeX
	minRawLen    = headerLen + chacha20poly1305.Overhead
)

var (
	// ErrInvalid is every blob that does not open: malformed, of another
	// channel, under an unknown or deleted key, or altered. Callers get no
	// finer reason (§5.2 step 2: no oracle).
	ErrInvalid = errors.New("blob: invalid")
	// ErrTooLarge is a record whose sealed blob would exceed MaxLen.
	ErrTooLarge = errors.New("blob: record too large")
	// ErrKeys is a malformed blob-keys secret.
	ErrKeys = errors.New("blob: malformed blob keys")
)

// Record is one registration (§4). Environment is empty for fcm.
type Record struct {
	Platform    string
	Environment string
	AppID       string
	Token       string
	// Key is the registration's wake public key.
	Key ed25519.PublicKey
	// Issued is the registration time, Unix seconds.
	Issued int64
}

// wire is the record's JSON (§4): {"p","e"?,"a","t","k","i"}, and in a
// pending registration also "c", the challenge code.
type wire struct {
	P string `json:"p"`
	E string `json:"e,omitempty"`
	A string `json:"a"`
	T string `json:"t"`
	K string `json:"k"`
	I int64  `json:"i"`
	C string `json:"c,omitempty"`
}

// Keyring holds a channel's blob keys in memory: one current key, which
// seals, and the retired keys that still open (§4).
type Keyring struct {
	channel string
	current [KeyIDLen]byte
	keys    map[[KeyIDLen]byte]cipher.AEAD
}

// secret is the blob-keys secret (§10.2): {current, keys: {<key_id>:
// <b64 32 bytes>}}. A key id is 8 lowercase hex digits (the blob's 4 key
// id bytes).
type secret struct {
	Current string            `json:"current"`
	Keys    map[string]string `json:"keys"`
}

func parseKeyID(s string) (id [KeyIDLen]byte, ok bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeyIDLen || hex.EncodeToString(b) != s {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// NewKeyring builds a keyring for channel from the blob-keys secret.
func NewKeyring(channel string, secretJSON []byte) (*Keyring, error) {
	if channel == "" {
		return nil, ErrKeys
	}
	var s secret
	dec := json.NewDecoder(bytes.NewReader(secretJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || dec.More() || len(s.Keys) == 0 {
		return nil, ErrKeys
	}
	k := &Keyring{channel: channel, keys: map[[KeyIDLen]byte]cipher.AEAD{}}
	for ids, b64 := range s.Keys {
		id, ok := parseKeyID(ids)
		if !ok {
			return nil, ErrKeys
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(b64)
		if err != nil || len(raw) != KeySize || allZero(raw) {
			return nil, ErrKeys
		}
		aead, err := chacha20poly1305.NewX(raw)
		clear(raw)
		if err != nil {
			return nil, ErrKeys
		}
		k.keys[id] = aead
	}
	cur, ok := parseKeyID(s.Current)
	if !ok {
		return nil, ErrKeys
	}
	if _, ok := k.keys[cur]; !ok {
		return nil, ErrKeys
	}
	k.current = cur
	return k, nil
}

func allZero(b []byte) bool {
	var z byte
	for _, x := range b {
		z |= x
	}
	return z == 0
}

// NewRandomKeyring returns a keyring with one fresh random key (the dev
// stand-in: its blobs do not survive a restart).
func NewRandomKeyring(channel string) (*Keyring, error) {
	sec, err := NewSecret()
	if err != nil {
		return nil, err
	}
	return NewKeyring(channel, sec)
}

// NewSecret returns a blob-keys secret with one fresh random key.
func NewSecret() ([]byte, error) { return RotateSecret(nil) }

// RotateSecret returns old with a fresh random key added and made current;
// the previous keys stay, so their blobs still open and are resealed
// (§4). A nil old yields a first secret.
func RotateSecret(old []byte) ([]byte, error) {
	s := secret{Keys: map[string]string{}}
	if old != nil {
		if _, err := NewKeyring("check", old); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(old, &s); err != nil {
			return nil, ErrKeys
		}
	}
	for {
		var id [KeyIDLen]byte
		key := make([]byte, KeySize)
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		ids := hex.EncodeToString(id[:])
		if _, taken := s.Keys[ids]; taken {
			continue
		}
		s.Keys[ids] = base64.StdEncoding.EncodeToString(key)
		s.Current = ids
		break
	}
	return json.Marshal(s)
}

// KeyIDs returns the key ids the ring opens, sorted, and the current one.
func (k *Keyring) KeyIDs() (all []string, current string) {
	for id := range k.keys {
		all = append(all, hex.EncodeToString(id[:]))
	}
	sort.Strings(all)
	return all, hex.EncodeToString(k.current[:])
}

func (k *Keyring) aad(label string) []byte {
	return append(append([]byte(label), 0x00), k.channel...)
}

// Seal makes a blob of r under the current key with a random nonce. The
// same record sealed twice yields two different blobs; both open.
func (k *Keyring) Seal(r Record) (string, error) { return k.seal(r, "", aadLabel) }

// SealPending seals r and the challenge code sent to its token as a
// pending registration (§5.1): it opens only with OpenPending.
func (k *Keyring) SealPending(r Record, code string) (string, error) {
	if code == "" {
		return "", ErrInvalid
	}
	return k.seal(r, code, pendingLabel)
}

func (k *Keyring) seal(r Record, code, label string) (string, error) {
	if len(r.Key) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	var pt bytes.Buffer
	enc := json.NewEncoder(&pt)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wire{P: r.Platform, E: r.Environment, A: r.AppID, T: r.Token,
		K: base64.StdEncoding.EncodeToString(r.Key), I: r.Issued, C: code}); err != nil {
		return "", ErrInvalid
	}
	body := bytes.TrimSuffix(pt.Bytes(), []byte("\n"))
	if base64.RawURLEncoding.EncodedLen(minRawLen+len(body)) > MaxLen {
		return "", ErrTooLarge
	}
	out := make([]byte, headerLen, minRawLen+len(body))
	out[0] = Version
	copy(out[1:], k.current[:])
	if _, err := rand.Read(out[1+KeyIDLen:]); err != nil {
		return "", err
	}
	out = k.keys[k.current].Seal(out, out[1+KeyIDLen:headerLen], body, k.aad(label))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open opens a blob. current reports whether it was sealed under the
// current key; if not, the caller answers the wake with a reseal (§4).
// Every failure is ErrInvalid.
func (k *Keyring) Open(blob string) (r Record, current bool, err error) {
	r, code, current, err := k.open(blob, aadLabel)
	if err != nil || code != "" {
		return Record{}, false, ErrInvalid
	}
	return r, current, nil
}

// OpenPending opens a pending registration and returns its record and
// challenge code. Every failure is ErrInvalid.
func (k *Keyring) OpenPending(pending string) (r Record, code string, err error) {
	r, code, _, err = k.open(pending, pendingLabel)
	if err != nil || code == "" {
		return Record{}, "", ErrInvalid
	}
	return r, code, nil
}

func (k *Keyring) open(blob, label string) (r Record, code string, current bool, err error) {
	if len(blob) == 0 || len(blob) > MaxLen {
		return Record{}, "", false, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(blob)
	if err != nil || len(raw) < minRawLen || raw[0] != Version {
		return Record{}, "", false, ErrInvalid
	}
	var id [KeyIDLen]byte
	copy(id[:], raw[1:])
	aead, ok := k.keys[id]
	if !ok {
		return Record{}, "", false, ErrInvalid
	}
	pt, err := aead.Open(nil, raw[1+KeyIDLen:headerLen], raw[headerLen:], k.aad(label))
	if err != nil {
		return Record{}, "", false, ErrInvalid
	}
	var w wire
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Record{}, "", false, ErrInvalid
	}
	key, err := base64.StdEncoding.Strict().DecodeString(w.K)
	if err != nil || len(key) != ed25519.PublicKeySize || w.I < 0 {
		return Record{}, "", false, ErrInvalid
	}
	return Record{Platform: w.P, Environment: w.E, AppID: w.A, Token: w.T, Key: key, Issued: w.I}, w.C,
		subtle.ConstantTimeCompare(id[:], k.current[:]) == 1, nil
}

// DropKey returns the secret without the retired key id (§4: a retired
// key is deleted after 400 days). The current key cannot be dropped.
func DropKey(old []byte, id string) ([]byte, error) {
	if _, err := NewKeyring("check", old); err != nil {
		return nil, err
	}
	var s secret
	if err := json.Unmarshal(old, &s); err != nil {
		return nil, ErrKeys
	}
	if _, ok := s.Keys[id]; !ok || id == s.Current {
		return nil, errors.New("blob: no such retired key")
	}
	delete(s.Keys, id)
	return json.Marshal(s)
}
