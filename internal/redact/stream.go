// Package redact hides secret values in a stream of output.
package redact

import (
	"bytes"
	"slices"
)

// Secret is a value to hide and the ID of the secret it belongs to.
type Secret struct {
	ID    string
	Value []byte
}

type replacement struct {
	id     string
	needle []byte
	marker []byte
	used   bool
}

// Redactor replaces exact secret values, even when they span chunk boundaries.
// Its retained input is bounded by the longest secret. Each stream owns one
// Redactor; callers may clear their input secrets after construction.
type Redactor struct {
	rules   []replacement
	byFirst [256][]int // rule indices by first needle byte
	maxLen  int
	tail    []byte
}

// New labels replacements with the ID of the matching secret.
func New(secrets ...Secret) *Redactor {
	r := &Redactor{}
	for _, secret := range secrets {
		if len(secret.Value) == 0 || slices.ContainsFunc(r.rules, func(rule replacement) bool { return bytes.Equal(rule.needle, secret.Value) }) {
			continue
		}
		r.byFirst[secret.Value[0]] = append(r.byFirst[secret.Value[0]], len(r.rules))
		r.rules = append(r.rules, replacement{id: secret.ID, needle: bytes.Clone(secret.Value), marker: []byte("[REDACTED:" + secret.ID + "]")})
		r.maxLen = max(r.maxLen, len(secret.Value))
	}
	for i := range r.rules {
		// Arbitrary secrets can themselves equal (or occur inside) a
		// marker. Select from a finite set, ending in an empty replacement,
		// rather than repeatedly extending a colliding marker.
		candidates := [][]byte{r.rules[i].marker, []byte("[REDACTED]"), []byte("[hidden]"), []byte("***"), []byte("?"), nil}
		for _, candidate := range candidates {
			collision := false
			for _, other := range r.rules {
				if bytes.Contains(candidate, other.needle) {
					collision = true
					break
				}
			}
			if !collision {
				r.rules[i].marker = bytes.Clone(candidate)
				break
			}
		}
	}
	return r
}

func (r *Redactor) Close() {
	for i := range r.rules {
		clear(r.rules[i].needle)
		clear(r.rules[i].marker)
	}
	clear(r.tail)
	r.rules = nil
	r.tail = nil
}

// Used returns the sorted IDs whose values were replaced.
func (r *Redactor) Used() []string {
	var ids []string
	for _, rule := range r.rules {
		if rule.used {
			ids = append(ids, rule.id)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// matchAt delays output only when the remaining input is a proper prefix of
// a rule. A complete short match also waits if a longer match is still possible.
func (r *Redactor) matchAt(b []byte, at int, final bool) (best int, pending bool) {
	best, length := -1, 0
	remaining := b[at:]
	for _, i := range r.byFirst[remaining[0]] {
		rule := r.rules[i]
		if !final && len(remaining) < len(rule.needle) && bytes.HasPrefix(rule.needle, remaining) {
			pending = true
		}
		if len(rule.needle) > length && bytes.HasPrefix(remaining, rule.needle) {
			best, length = i, len(rule.needle)
		}
	}
	return best, pending
}

// Feed consumes a chunk and returns bytes safe to forward. Only a suffix that
// might become a secret is retained, so ordinary short prompts are forwarded
// immediately. A final call flushes partial (unmatched) prefixes at EOF.
func (r *Redactor) Feed(chunk []byte, final bool) []byte {
	if len(r.rules) == 0 {
		return bytes.Clone(chunk)
	}
	all := make([]byte, 0, len(r.tail)+len(chunk))
	all = append(all, r.tail...)
	all = append(all, chunk...)
	clear(r.tail)
	r.tail = nil
	defer clear(all)
	out := make([]byte, 0, len(all))
	start, at := 0, 0
	replaced := false
	for at < len(all) {
		idx, pending := r.matchAt(all, at, final)
		if pending {
			break
		}
		if idx < 0 {
			at++
			continue
		}
		rule := &r.rules[idx]
		out = append(out, all[start:at]...)
		out = append(out, rule.marker...)
		rule.used, replaced = true, true
		at += len(rule.needle)
		start = at
	}
	out = append(out, all[start:at]...)
	r.tail = bytes.Clone(all[at:])
	// A replacement marker can join with adjacent ordinary text and recreate a
	// different stored secret (for example marker `]` + following `tail`). Drop
	// the affected output conservatively; this rare pathological case is safer
	// than emitting a newly constructed secret. The next chunks remain
	// protected by the same rules. Without a replacement, any needle in out or
	// across out and tail would already have matched or been held back.
	if replaced && r.outputContainsNeedle(out, r.tail) {
		clear(out)
		clear(r.tail)
		r.tail = nil
		return nil
	}
	return out
}

func (r *Redactor) outputContainsNeedle(out, tail []byte) bool {
	for _, rule := range r.rules {
		if bytes.Contains(out, rule.needle) {
			return true
		}
		if len(out) == 0 || len(tail) == 0 {
			continue
		}
		for n := 1; n < len(rule.needle) && n <= len(out) && n <= len(tail); n++ {
			if bytes.HasSuffix(out, rule.needle[:n]) && bytes.HasPrefix(tail, rule.needle[n:]) {
				return true
			}
		}
	}
	return false
}
