package blob

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// secretOf builds a blob-keys secret from random keys; ids[0] is current.
func secretOf(t *testing.T, ids ...string) ([]byte, map[string][]byte) {
	t.Helper()
	raw := map[string][]byte{}
	keys := map[string]string{}
	for _, id := range ids {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		raw[id] = k
		keys[id] = base64.StdEncoding.EncodeToString(k)
	}
	b, _ := json.Marshal(map[string]any{"current": ids[0], "keys": keys})
	return b, raw
}

func ring(t *testing.T, channel string, sec []byte) *Keyring {
	t.Helper()
	k, err := NewKeyring(channel, sec)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// §4: the blob's exact layout, key id, associated data and JSON record.
func TestSealFormat(t *testing.T) {
	sec, raw := secretOf(t, "0a0b0c0d")
	k := ring(t, "staging", sec)
	pub := testKey(t)
	for _, rec := range []Record{
		{Platform: "apns", Environment: "production", AppID: "com.vettid.app", Token: strings.Repeat("ab", 32), Key: pub, Issued: 1781092800},
		{Platform: "fcm", AppID: "com.vettid.app", Token: "tok:<en>&\"x\\", Key: pub, Issued: 1},
	} {
		b, err := k.Seal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(b, "=+/") {
			t.Fatalf("not base64url without padding: %q", b)
		}
		rawBlob, err := base64.RawURLEncoding.DecodeString(b)
		if err != nil {
			t.Fatal(err)
		}
		if rawBlob[0] != 0x01 || !bytes.Equal(rawBlob[1:5], []byte{0x0a, 0x0b, 0x0c, 0x0d}) {
			t.Fatalf("header % x", rawBlob[:5])
		}
		aead, _ := chacha20poly1305.NewX(raw["0a0b0c0d"])
		pt, err := aead.Open(nil, rawBlob[5:29], rawBlob[29:], []byte("vettid/push/1/blob\x00staging"))
		if err != nil {
			t.Fatalf("the documented key, nonce and aad do not open the blob: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(pt, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"p": rec.Platform, "a": rec.AppID, "t": rec.Token,
			"k": base64.StdEncoding.EncodeToString(pub), "i": float64(rec.Issued)}
		if rec.Environment != "" {
			want["e"] = rec.Environment
		}
		if len(got) != len(want) {
			t.Fatalf("record members %v", got)
		}
		for n, v := range want {
			if got[n] != v {
				t.Fatalf("record %s = %v, want %v", n, got[n], v)
			}
		}
		back, current, err := k.Open(b)
		if err != nil || !current {
			t.Fatalf("open: %v current=%v", err, current)
		}
		if back.Platform != rec.Platform || back.Environment != rec.Environment || back.AppID != rec.AppID ||
			back.Token != rec.Token || !bytes.Equal(back.Key, rec.Key) || back.Issued != rec.Issued {
			t.Fatalf("round trip: %+v", back)
		}
	}
}

// §5.1: the same body registered twice yields two different blobs; both
// work. §4: the nonce is random.
func TestSealTwice(t *testing.T) {
	sec, _ := secretOf(t, "00000001")
	k := ring(t, "prod", sec)
	rec := Record{Platform: "fcm", AppID: "a", Token: "t", Key: testKey(t), Issued: 5}
	a, _ := k.Seal(rec)
	b, _ := k.Seal(rec)
	if a == b {
		t.Fatal("two seals of one record are identical")
	}
	for _, x := range []string{a, b} {
		if _, _, err := k.Open(x); err != nil {
			t.Fatal(err)
		}
	}
}

// §4: a blob of one channel never opens in the other, even under the same
// keys.
func TestChannelSeparation(t *testing.T) {
	sec, _ := secretOf(t, "00000001")
	rec := Record{Platform: "fcm", AppID: "a", Token: "t", Key: testKey(t)}
	b, _ := ring(t, "staging", sec).Seal(rec)
	if _, _, err := ring(t, "prod", sec).Open(b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a staging blob opened in prod: %v", err)
	}
	if _, _, err := ring(t, "staging", sec).Open(b); err != nil {
		t.Fatal(err)
	}
}

// §4: a retired key still opens (not current: the wake is answered with
// a reseal); a deleted key's blobs are invalid.
func TestRotation(t *testing.T) {
	first, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	old := ring(t, "prod", first)
	rec := Record{Platform: "fcm", AppID: "a", Token: "t", Key: testKey(t), Issued: 9}
	b, _ := old.Seal(rec)

	rotated, err := RotateSecret(first)
	if err != nil {
		t.Fatal(err)
	}
	k := ring(t, "prod", rotated)
	ids, cur := k.KeyIDs()
	_, oldCur := old.KeyIDs()
	if len(ids) != 2 || cur == oldCur {
		t.Fatalf("after rotation: ids %v current %s (was %s)", ids, cur, oldCur)
	}
	back, current, err := k.Open(b)
	if err != nil || current {
		t.Fatalf("retired key: err %v current %v", err, current)
	}
	nb, _ := k.Seal(back)
	if got, current, err := k.Open(nb); err != nil || !current || got.Issued != rec.Issued || got.Token != rec.Token {
		t.Fatalf("reseal: %+v current %v err %v", got, current, err)
	}
	if _, _, err := old.Open(nb); !errors.Is(err, ErrInvalid) {
		t.Fatal("a blob under a key the ring does not hold opened")
	}

	dropped, err := DropKey(rotated, oldCur)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ring(t, "prod", dropped).Open(b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a deleted key's blob: %v", err)
	}
	if _, err := DropKey(rotated, cur); err == nil {
		t.Fatal("the current key was dropped")
	}
	if _, err := DropKey(rotated, "ffffffff"); err == nil {
		t.Fatal("an unknown key was dropped")
	}
}

// §5.2 step 2: anything that does not open is the same ErrInvalid.
func TestOpenInvalid(t *testing.T) {
	sec, _ := secretOf(t, "00000001")
	k := ring(t, "prod", sec)
	good, _ := k.Seal(Record{Platform: "fcm", AppID: "a", Token: "t", Key: testKey(t)})
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	enc := base64.RawURLEncoding.EncodeToString
	cases := map[string]string{
		"empty":         "",
		"not base64url": good[:10] + "+" + good[11:],
		"padded":        good + "=",
		"short":         enc(raw[:44]),
		"too long":      strings.Repeat("A", MaxLen+1),
	}
	for i, name := range map[int]string{0: "version", 2: "key id", 10: "nonce", 40: "ciphertext", len(raw) - 1: "tag"} {
		m := append([]byte(nil), raw...)
		m[i] ^= 1
		cases["flipped "+name] = enc(m)
	}
	cases["truncated"] = enc(raw[:len(raw)-1])
	cases["extended"] = enc(append(append([]byte(nil), raw...), 0))
	for name, b := range cases {
		if _, _, err := k.Open(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §4: a blob is at most 6,144 bytes. The largest registration the spec
// allows in plain characters fits; a token that JSON must escape heavily
// does not, and is refused rather than sealed oversize.
func TestSizeLimit(t *testing.T) {
	sec, _ := secretOf(t, "00000001")
	k := ring(t, "staging", sec)
	pub := testKey(t)
	b, err := k.Seal(Record{Platform: "fcm", AppID: strings.Repeat("a", 255), Token: strings.Repeat("T", 4096), Key: pub, Issued: 1 << 40})
	if err != nil || len(b) > MaxLen {
		t.Fatalf("largest plain registration: len %d err %v", len(b), err)
	}
	// HTML-significant characters are not escaped (they would cost six
	// bytes each).
	if _, err := k.Seal(Record{Platform: "fcm", AppID: "a", Token: strings.Repeat("<", 4096), Key: pub}); err != nil {
		t.Fatalf("4096 '<': %v", err)
	}
	if _, err := k.Seal(Record{Platform: "fcm", AppID: "a", Token: strings.Repeat(`"`, 4096), Key: pub}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("4096 quotes: %v", err)
	}
}

func TestKeyringSecret(t *testing.T) {
	k32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	bad := []string{
		``, `{}`, `[]`, `{"current":"00000001","keys":{}}`,
		`{"current":"00000002","keys":{"00000001":"` + k32 + `"}}`,                                                 // current not listed
		`{"current":"0000001","keys":{"0000001":"` + k32 + `"}}`,                                                   // 7 hex digits
		`{"current":"0000000A","keys":{"0000000A":"` + k32 + `"}}`,                                                 // uppercase
		`{"current":"00000001","keys":{"00000001":"` + k32[:40] + `"}}`,                                            // short key
		`{"current":"00000001","keys":{"00000001":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}}`, // zero key
		`{"current":"00000001","keys":{"00000001":"` + k32 + `"},"extra":1}`,
	}
	for _, s := range bad {
		if _, err := NewKeyring("prod", []byte(s)); !errors.Is(err, ErrKeys) {
			t.Errorf("%s: %v", s, err)
		}
	}
	good := `{"current":"00000001","keys":{"00000001":"` + k32 + `"}}`
	if _, err := NewKeyring("prod", []byte(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyring("", []byte(good)); err == nil {
		t.Fatal("no channel accepted")
	}
	if _, err := RotateSecret([]byte(`{"current":"x"}`)); err == nil {
		t.Fatal("a malformed secret was rotated")
	}
	// No error text carries key material.
	_, err := NewKeyring("prod", []byte(`{"current":"00000001","keys":{"00000001":"`+k32[:40]+`"}}`))
	if strings.Contains(err.Error(), k32[:20]) {
		t.Fatal("error text carries key material")
	}
}

// A pending registration (§5.1) is sealed with the same keys under its
// own associated data: it opens only as a pending registration, with its
// code, and a wake blob never opens as one, nor a record with a code as
// a wake blob even under the blob's associated data.
func TestPending(t *testing.T) {
	sec, raw := secretOf(t, "0a0b0c0d")
	k := ring(t, "staging", sec)
	rec := Record{Platform: "fcm", AppID: "com.vettid.app", Token: "tok", Key: testKey(t), Issued: 1781092800}
	p, err := k.SealPending(rec, "q3Zl0-Yc_w7Tj2b1d9KfAA")
	if err != nil {
		t.Fatal(err)
	}
	got, code, err := k.OpenPending(p)
	if err != nil || code != "q3Zl0-Yc_w7Tj2b1d9KfAA" || got.Token != rec.Token || !bytes.Equal(got.Key, rec.Key) || got.Issued != rec.Issued {
		t.Fatalf("open pending: %+v %q %v", got, code, err)
	}
	if _, _, err := k.Open(p); !errors.Is(err, ErrInvalid) {
		t.Fatal("a pending registration opened as a wake blob")
	}
	wb, err := k.Seal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.OpenPending(wb); !errors.Is(err, ErrInvalid) {
		t.Fatal("a wake blob opened as a pending registration")
	}
	if _, err := k.SealPending(rec, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("a pending registration without a code")
	}
	if _, _, err := ring(t, "prod", sec).OpenPending(p); !errors.Is(err, ErrInvalid) {
		t.Fatal("a staging pending registration opened in production")
	}
	// A record carrying a code, sealed by hand under the blob's own
	// associated data, is still no wake blob.
	aead, _ := chacha20poly1305.NewX(raw["0a0b0c0d"])
	pt := []byte(`{"p":"fcm","a":"com.vettid.app","t":"tok","k":"` + base64.StdEncoding.EncodeToString(rec.Key) + `","i":1,"c":"x"}`)
	out := []byte{Version, 0x0a, 0x0b, 0x0c, 0x0d}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, pt, []byte("vettid/push/1/blob\x00staging"))
	if _, _, err := k.Open(base64.RawURLEncoding.EncodeToString(out)); !errors.Is(err, ErrInvalid) {
		t.Fatal("a record with a code opened as a wake blob")
	}
}
