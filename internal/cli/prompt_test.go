package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/agyard/agsecret/internal/store"
)

func TestReadMasked(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"enter", "pass\nnext", "pass"},
		{"return", "pass\rnext", "pass"},
		{"unicode", "a\u5bc6\u7801\n", "a\u5bc6\u7801"},
		{"backspace", "ab\u754c\x7f\u8bed\b\u6587\n", "ab\u6587"},
		{"empty-backspace", "\b\x7fpass\n", "pass"},
		{"clear-line", "old\u5bc6\u7801\x15new\n", "new"},
		{"clear-word", "first second  \x17last\n", "first last"},
		{"controls", "a\x00\t\x01b\n", "ab"},
		{"partial-eof", "pass", "pass"},
		{"ctrl-d", "pass\x04next", "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReader(tc.input)
			var out bytes.Buffer
			got, err := readMasked(in, &out)
			if err != nil || string(got) != tc.want {
				t.Fatalf("value=%q err=%v", got, err)
			}
			if strings.Contains(out.String(), tc.want) {
				t.Fatalf("input was echoed: %q", out.String())
			}
			if strings.HasSuffix(tc.input, "next") && in.Len() != 4 {
				t.Fatalf("consumed the next prompt's input: %d bytes remain", in.Len())
			}
			if tc.name == "unicode" && out.String() != "•••" {
				t.Fatalf("mask should count Unicode characters: %q", out.String())
			}
		})
	}
}

func TestReadMaskedErrors(t *testing.T) {
	for _, input := range []string{"", "\x04"} {
		if got, err := readMasked(strings.NewReader(input), io.Discard); len(got) != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("empty input %q: value=%q err=%v", input, got, err)
		}
	}
	for _, input := range []string{"secret\x03", "secret\x1b"} {
		got, err := readMasked(strings.NewReader(input), io.Discard)
		var exit *exitError
		if len(got) != 0 || !errors.As(err, &exit) || exit.code != 130 || exit.Error() != "input cancelled" {
			t.Fatalf("cancellation: value=%q err=%v", got, err)
		}
	}
	if got, err := readMasked(strings.NewReader(strings.Repeat("x", store.MaxSecretLen+1)), io.Discard); len(got) != 0 || err == nil {
		t.Fatalf("oversized input: length=%d err=%v", len(got), err)
	}
	wantErr := errors.New("terminal failed")
	for _, tc := range []struct {
		name string
		in   io.Reader
		out  io.Writer
	}{
		{"read", io.MultiReader(strings.NewReader("secret"), failingTerminal{wantErr}), io.Discard},
		{"write", strings.NewReader("secret\n"), failingTerminal{wantErr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := readMasked(tc.in, tc.out); len(got) != 0 || !errors.Is(err, wantErr) {
				t.Fatalf("value=%q err=%v", got, err)
			}
		})
	}
}

type failingTerminal struct{ err error }

func (f failingTerminal) Read([]byte) (int, error)  { return 0, f.err }
func (f failingTerminal) Write([]byte) (int, error) { return 0, f.err }
