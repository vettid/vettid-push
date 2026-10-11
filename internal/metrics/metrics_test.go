package metrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// §10.5: CloudWatch EMF, aggregated per flush, dimensions from closed
// sets.
func TestFlushEMF(t *testing.T) {
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	r := New("vettid-org/staging/push", func() time.Time { return at })
	for i := 0; i < 3; i++ {
		r.Count("wakes", Dim{"platform", "fcm"}, Dim{"environment", "none"}, Dim{"outcome", "sent"})
	}
	r.Count("blob_resealed")
	for i := 0; i < 250; i++ {
		r.Observe("provider_latency_ms", float64(i), Dim{"platform", "apns"})
	}
	if r.Value("wakes", Dim{"platform", "fcm"}, Dim{"environment", "none"}, Dim{"outcome", "sent"}) != 3 {
		t.Fatal("counter value")
	}
	var out bytes.Buffer
	if err := r.Flush(&out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines for three series (one line per series, not per event):\n%s", len(lines), out.String())
	}
	byName := map[string]map[string]any{}
	for _, l := range lines {
		var doc map[string]any
		if err := json.Unmarshal([]byte(l), &doc); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		aws := doc["_aws"].(map[string]any)
		if aws["Timestamp"].(float64) != float64(at.UnixMilli()) {
			t.Fatal("timestamp")
		}
		cw := aws["CloudWatchMetrics"].([]any)[0].(map[string]any)
		if cw["Namespace"] != "vettid-org/staging/push" {
			t.Fatal("namespace")
		}
		m := cw["Metrics"].([]any)[0].(map[string]any)
		name := m["Name"].(string)
		byName[name] = doc
		for _, d := range cw["Dimensions"].([]any)[0].([]any) {
			if _, ok := doc[d.(string)].(string); !ok {
				t.Fatalf("%s: dimension %v has no value member", name, d)
			}
		}
	}
	if byName["wakes"]["wakes"].(float64) != 3 || byName["wakes"]["outcome"] != "sent" {
		t.Fatalf("wakes: %v", byName["wakes"])
	}
	if byName["blob_resealed"]["blob_resealed"].(float64) != 1 {
		t.Fatal("blob_resealed")
	}
	if n := len(byName["provider_latency_ms"]["provider_latency_ms"].([]any)); n != 100 {
		t.Fatalf("%d latency values in one line, want at most 100", n)
	}
	// Flushed series reset; an idle interval writes nothing.
	out.Reset()
	if err := r.Flush(&out); err != nil || out.Len() != 0 {
		t.Fatalf("idle flush wrote %q", out.String())
	}
}
