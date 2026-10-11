// Package metrics aggregates the gateway's counters in memory and writes
// them periodically in the CloudWatch embedded metric format (EMF), one
// JSON line per metric and dimension set that changed (PUSH-GATEWAY
// §10.5).
//
// Nothing here is per request: a line carries the count of a whole flush
// interval. Dimension values come from closed sets fixed in the code
// (platform, environment, outcome, reason, scope); no dimension can hold a
// token, a key, a vault or an address.
package metrics

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxSamples bounds the values of one metric in one EMF line (the format
// allows at most 100 values per metric).
const maxSamples = 100

// Dim is one dimension.
type Dim struct{ Name, Value string }

type series struct {
	name  string
	unit  string
	dims  []Dim
	count float64
	// samples, for a distribution metric (provider_latency_ms).
	samples []float64
	seen    int
	dist    bool
}

// Registry aggregates metrics between flushes.
type Registry struct {
	namespace string
	now       func() time.Time

	mu     sync.Mutex
	series map[string]*series
	// rnd is a small deterministic generator for reservoir sampling.
	rnd uint64
}

// New returns a registry that reports in namespace.
func New(namespace string, now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{namespace: namespace, now: now, series: map[string]*series{}, rnd: 0x9e3779b97f4a7c15}
}

func key(name string, dims []Dim) string {
	var b strings.Builder
	b.WriteString(name)
	for _, d := range dims {
		b.WriteByte(0)
		b.WriteString(d.Name)
		b.WriteByte('=')
		b.WriteString(d.Value)
	}
	return b.String()
}

func (r *Registry) get(name, unit string, dist bool, dims []Dim) *series {
	k := key(name, dims)
	s, ok := r.series[k]
	if !ok {
		s = &series{name: name, unit: unit, dims: append([]Dim(nil), dims...), dist: dist}
		r.series[k] = s
	}
	return s
}

// Count adds one to the counter name with dims.
func (r *Registry) Count(name string, dims ...Dim) {
	r.mu.Lock()
	r.get(name, "Count", false, dims).count++
	r.mu.Unlock()
}

// Observe records one value (milliseconds) of the distribution name. At
// most 100 values per flush are kept, as a uniform sample.
func (r *Registry) Observe(name string, ms float64, dims ...Dim) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(name, "Milliseconds", true, dims)
	s.seen++
	if len(s.samples) < maxSamples {
		s.samples = append(s.samples, ms)
		return
	}
	r.rnd ^= r.rnd << 13
	r.rnd ^= r.rnd >> 7
	r.rnd ^= r.rnd << 17
	if i := int(r.rnd % uint64(s.seen)); i < maxSamples {
		s.samples[i] = ms
	}
}

// Value returns the counter's count since the last flush (tests).
func (r *Registry) Value(name string, dims ...Dim) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.series[key(name, dims)]; ok {
		return s.count
	}
	return 0
}

// Flush writes one EMF line per series that changed since the last flush
// and resets them.
func (r *Registry) Flush(w io.Writer) error {
	r.mu.Lock()
	cur := r.series
	r.series = map[string]*series{}
	ts := r.now().UnixMilli()
	r.mu.Unlock()

	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []byte
	for _, k := range keys {
		s := cur[k]
		names := make([]string, len(s.dims))
		doc := map[string]any{}
		for i, d := range s.dims {
			names[i] = d.Name
			doc[d.Name] = d.Value
		}
		doc["_aws"] = map[string]any{
			"Timestamp": ts,
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  r.namespace,
				"Dimensions": [][]string{names},
				"Metrics":    []any{map[string]string{"Name": s.name, "Unit": s.unit}},
			}},
		}
		if s.dist {
			doc[s.name] = s.samples
		} else {
			doc[s.name] = s.count
		}
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		out = append(append(out, b...), '\n')
	}
	if len(out) == 0 {
		return nil
	}
	_, err := w.Write(out)
	return err
}
