package redact

import (
	"bytes"
	"sort"
)

// Secret associates an exact byte sequence with its public credential ID.
type Secret struct {
	ID    string
	Value []byte
}

type replacement struct {
	needle []byte
	marker []byte
	used   bool
}

// Redactor replaces exact secret bytes across arbitrary stream boundaries.
// Its retained input is bounded by the longest secret. Each stream owns one
// Redactor; callers may clear their input secrets after construction.
type Redactor struct {
	rules  []replacement
	maxLen int
	tail   []byte
}

// New preserves the unlabelled redactor API for callers without credential IDs.
func New(needles ...[]byte) *Redactor {
	secrets := make([]Secret, len(needles))
	for i, n := range needles {
		secrets[i].Value = n
	}
	return NewWithSecrets(secrets...)
}

// NewWithSecrets labels replacements with the corresponding stable record ID.
func NewWithSecrets(secrets ...Secret) *Redactor {
	r := &Redactor{}
	for _, secret := range secrets {
		if len(secret.Value) == 0 {
			continue
		}
		duplicate := false
		for _, rule := range r.rules {
			if bytes.Equal(rule.needle, secret.Value) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		marker := "[REDACTED]"
		if secret.ID != "" {
			marker = "[REDACTED:" + secret.ID + "]"
		}
		r.rules = append(r.rules, replacement{needle: bytes.Clone(secret.Value), marker: []byte(marker)})
		if len(secret.Value) > r.maxLen {
			r.maxLen = len(secret.Value)
		}
	}
	for i := range r.rules {
		// Arbitrary credentials can themselves equal (or occur inside) a
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

// Replacements returns the unique markers actually emitted, in stable order.
// An empty marker denotes the rare case where every visible marker collided
// with a secret and the matching secret was removed entirely.
func (r *Redactor) Replacements() []string {
	seen := make(map[string]bool)
	for _, rule := range r.rules {
		if rule.used {
			seen[string(rule.marker)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for marker := range seen {
		out = append(out, marker)
	}
	sort.Strings(out)
	return out
}

// matchAt delays output only when the remaining input is a proper prefix of
// a rule. A complete short match also waits if a longer match is still possible.
func (r *Redactor) matchAt(b []byte, at int, final bool) (best int, pending bool) {
	best, length := -1, 0
	remaining := b[at:]
	for i, rule := range r.rules {
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
	var out []byte
	start, at := 0, 0
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
		rule.used = true
		at += len(rule.needle)
		start = at
	}
	out = append(out, all[start:at]...)
	r.tail = bytes.Clone(all[at:])
	// A replacement marker can join with adjacent ordinary text and recreate a
	// different stored secret (for example marker `]` + following `tail`). Drop
	// the affected output conservatively; this rare pathological case is safer
	// than emitting a newly constructed credential. The next chunks remain
	// protected by the same rules.
	if r.outputContainsNeedle(out, r.tail) {
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
