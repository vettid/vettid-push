package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/nsmtest"
)

// The PUSH-GATEWAY §15 test vector, byte for byte.
const (
	vecSeedB64   = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	vecPubB64    = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E="
	vecBody      = `{"platform":"apns","token":"740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad","environment":"production","app_id":"com.vettid.app"}`
	vecBodyHash  = "b7c8170d637df5d636f997d15ac1e16f5900c18f6271f838d7f9e6c8a722881b"
	vecTimestamp = "2026-06-10T12:00:00Z"
	vecCanonical = "POST\n/v1/register\n2026-06-10T12:00:00Z\nb7c8170d637df5d636f997d15ac1e16f5900c18f6271f838d7f9e6c8a722881b"
	vecSig       = "3K+q6jDs868+0XetrLQXlddh8iZtKYeu5GRq6RZajyxRPIdDVh0dCYlkX59qFgL/wEhxs+sSzsOyH02gpsBQDA=="
)

func TestSpecVector(t *testing.T) {
	seed, err := base64.StdEncoding.DecodeString(vecSeedB64)
	if err != nil || !bytes.Equal(seed, bytes.Repeat([]byte{3}, 32)) {
		t.Fatalf("seed: %v", err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	if got := base64.StdEncoding.EncodeToString(pub); got != vecPubB64 {
		t.Fatalf("wake pubkey %s", got)
	}
	bh := sha256.Sum256([]byte(vecBody))
	if hex.EncodeToString(bh[:]) != vecBodyHash {
		t.Fatalf("sha256(body) %x", bh)
	}
	if got := string(relayauth.Canonical("POST", "/v1/register", vecTimestamp, bh)); got != vecCanonical {
		t.Fatalf("canonical string %q", got)
	}
	digest := sha256.Sum256([]byte(vecCanonical))
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest[:])); got != vecSig {
		t.Fatalf("signature %s", got)
	}
	// The vault's client builds exactly this body for this registration.
	reg := pushwire.Registration{Platform: "apns", Token: "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad",
		Environment: "production", AppID: "com.vettid.app"}
	if string(reg.Body()) != vecBody {
		t.Fatalf("the vault client's body differs from the vector: %s", reg.Body())
	}

	// The gateway accepts exactly these headers at the vector's time,
	// with an attestation whose user_data is SHA-256(canonical string)
	// and whose public_key is the wake key.
	at, _ := time.Parse(time.RFC3339, vecTimestamp)
	g := newGWAt(t, at)
	doc, _ := g.nsm.Attest(digest[:], nil, pub)
	send := func(attestation string) answer {
		return g.do(rawReq{path: "/v1/register", body: []byte(vecBody), mangle: func(h http.Header) {
			h.Set("X-VettID-Key", vecPubB64)
			h.Set("X-VettID-Timestamp", vecTimestamp)
			h.Set("X-VettID-Sig", vecSig)
			h.Set("X-VettID-Attestation", attestation)
			h.Set("Content-Type", "application/json")
		}})
	}
	a := send(nsmtest.Header(doc))
	pending, ok := parsePending(a)
	if !ok {
		t.Fatalf("the vector's request: %d %s", a.status, a.body)
	}
	if rec, code, err := g.cfg.Keys.OpenPending(pending); err != nil || code != g.code(reg) || !bytes.Equal(rec.Key, pub) {
		t.Fatalf("pending registration: %v", err)
	}
	c := g.confirm(key, pending, g.code(reg))
	wb, err := pushwire.ParseRegistered([]byte(c.body))
	if c.status != 201 || err != nil {
		t.Fatalf("confirmation %d %s: %v", c.status, c.body, err)
	}
	rec, current, err := g.cfg.Keys.Open(wb)
	if err != nil || !current {
		t.Fatal(err)
	}
	if rec.Platform != "apns" || rec.Environment != "production" || rec.AppID != "com.vettid.app" ||
		rec.Token != reg.Token || !bytes.Equal(rec.Key, pub) || rec.Issued != at.Unix() {
		t.Fatalf("sealed record %+v", rec)
	}
	// The same signed request again is a replay.
	if a := send(nsmtest.Header(doc)); !a.is(401, "replay_detected") {
		t.Fatalf("replay: %d %s", a.status, a.body)
	}
	// An attestation over any other user_data is refused: the vector's
	// user_data is the digest of the canonical string, nothing else.
	g2 := newGWAt(t, at)
	other, _ := g2.nsm.Attest(bh[:], nil, pub) // sha256(body), not the digest
	if a := g2.do(rawReq{path: "/v1/register", body: []byte(vecBody), mangle: func(h http.Header) {
		h.Set("X-VettID-Key", vecPubB64)
		h.Set("X-VettID-Timestamp", vecTimestamp)
		h.Set("X-VettID-Sig", vecSig)
		h.Set("X-VettID-Attestation", nsmtest.Header(other))
	}}); !a.is(403, "attestation_invalid") {
		t.Fatalf("wrong user_data: %d %s", a.status, a.body)
	}
}
