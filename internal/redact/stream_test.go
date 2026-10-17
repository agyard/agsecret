package redact

import (
	"bytes"
	"testing"
)

func TestRedactorHandlesChunkBoundariesAndLongestNeedle(t *testing.T) {
	r := New(Secret{ID: "a", Value: []byte("secret")}, Secret{ID: "b", Value: []byte("secret-long")})
	defer r.Close()
	var out bytes.Buffer
	for _, chunk := range [][]byte{[]byte("prefix:se"), []byte("cret-long:suffix")} {
		out.Write(r.Feed(chunk, false))
	}
	out.Write(r.Feed(nil, true))
	if got, want := out.String(), "prefix:[REDACTED:b]:suffix"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRedactorMarkerCannotEqualSecret(t *testing.T) {
	r := New(Secret{ID: "a", Value: []byte("[REDACTED:a]")})
	defer r.Close()
	got := append(r.Feed([]byte("[REDACTED:a]"), false), r.Feed(nil, true)...)
	if string(got) == "[REDACTED:a]" {
		t.Fatal("redaction marker would reveal a secret equal to the marker")
	}
}

func TestLabelledRedactorAllChunkSizes(t *testing.T) {
	const id = "ags_0123456789abcdef"
	input := []byte("before secret-long after secret end")
	want := "before [REDACTED:" + id + "] after [REDACTED:" + id + "] end"
	for size := 1; size <= len(input); size++ {
		r := New(Secret{ID: id, Value: []byte("secret")}, Secret{ID: id, Value: []byte("secret-long")})
		var out bytes.Buffer
		for i := 0; i < len(input); i += size {
			out.Write(r.Feed(input[i:min(i+size, len(input))], false))
			if len(r.tail) > r.maxLen-1 {
				t.Fatalf("chunk size %d retained %d bytes for max needle %d", size, len(r.tail), r.maxLen)
			}
		}
		out.Write(r.Feed(nil, true))
		if got := out.String(); got != want {
			t.Fatalf("chunk size %d: got %q, want %q", size, got, want)
		}
		if got := r.Used(); len(got) != 1 || got[0] != id {
			t.Fatalf("unexpected replacements: %v", got)
		}
		r.Close()
	}
}

func TestRedactorNoMatchDoesNotReportReplacement(t *testing.T) {
	r := New(Secret{ID: "ags_0123456789abcdef", Value: []byte("secret")})
	defer r.Close()
	got := append(r.Feed([]byte("harmless"), false), r.Feed(nil, true)...)
	if string(got) != "harmless" || len(r.Used()) != 0 {
		t.Fatalf("got output %q and replacements %v", got, r.Used())
	}
}

func TestShortPromptsAreNotHeldUntilExit(t *testing.T) {
	r := New(Secret{ID: "a", Value: []byte("synthetic-password-long-enough")})
	defer r.Close()
	if got := r.Feed([]byte("Ready? "), false); string(got) != "Ready? " || len(r.tail) != 0 {
		t.Fatalf("nonmatching prompt buffered: %q", got)
	}
}

func TestOnlyAmbiguousSuffixIsBuffered(t *testing.T) {
	r := New(Secret{ID: "a", Value: []byte("token")}, Secret{ID: "b", Value: []byte("token-long")})
	defer r.Close()
	if got := r.Feed([]byte("Ready: token"), false); string(got) != "Ready: " {
		t.Fatalf("partial longer secret not withheld: %q", got)
	}
	if got := r.Feed([]byte("-long!"), false); string(got) != "[REDACTED:b]!" {
		t.Fatalf("longest match not protected: %q", got)
	}
	if got := r.Feed([]byte(" token"), false); string(got) != " " {
		t.Fatalf("ambiguous suffix not withheld: %q", got)
	}
	if got := r.Feed(nil, true); string(got) != "[REDACTED:a]" {
		t.Fatalf("complete shorter secret lost at EOF: %q", got)
	}
}

func TestMarkerCannotRecreateAdjacentSecret(t *testing.T) {
	r := New(Secret{ID: "a", Value: []byte("abcdef")}, Secret{ID: "b", Value: []byte("]tail")})
	defer r.Close()
	out := append(r.Feed([]byte("abcdeftail"), false), r.Feed(nil, true)...)
	if bytes.Contains(out, []byte("]tail")) {
		t.Fatalf("redaction marker recreated another secret: %q", out)
	}
}

func TestRedactorCollidingMarkersHaveBoundedFallback(t *testing.T) {
	const id = "ags_0123456789abcdef"
	needles := [][]byte{[]byte("[REDACTED:" + id + "]"), []byte("[REDACTED]"), []byte("[hidden]"), []byte("***"), []byte("?")}
	secrets := make([]Secret, len(needles))
	for i, needle := range needles {
		secrets[i] = Secret{ID: id, Value: needle}
	}
	r := New(secrets...)
	defer r.Close()
	var out bytes.Buffer
	for _, needle := range needles {
		out.Write(r.Feed(needle, false))
	}
	out.Write(r.Feed(nil, true))
	if out.Len() != 0 {
		t.Fatalf("colliding markers should be removed, got %q", out.String())
	}
	if len(r.Used()) != 1 {
		t.Fatal("empty-marker replacements were not counted")
	}
}
