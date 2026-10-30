package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agyard/agsecret/internal/store"
)

func TestKeyAndRemoteManagement(t *testing.T) {
	c := newTestCLI(t)
	for _, command := range []string{"key", "remote"} {
		if out, _ := c.ok("", command, "ls", "--json"); out != "[]\n" {
			t.Fatalf("empty %s ls: %q", command, out)
		}
	}
	rules := []string{"pku_*:*", "!pku_*:otp", "literal,comma"}
	args := []string{"key", "create", "laptop"}
	for _, rule := range rules {
		args = append(args, "--rule", rule)
	}
	out, errOut := c.ok("", args...)
	key := strings.TrimSuffix(out, "\n")
	if !store.ValidAPIKey(key) || errOut != "" || strings.Count(out, "\n") != 1 {
		t.Fatalf("key create output: %q, %q", out, errOut)
	}
	keys := c.json("", "key", "ls").([]any)
	if len(keys) != 1 {
		t.Fatalf("key metadata: %v", keys)
	}
	entry := keys[0].(map[string]any)
	wantRules := []any{rules[0], rules[1], rules[2]}
	if entry["name"] != "laptop" || !reflect.DeepEqual(entry["rules"], wantRules) || len(entry) != 2 {
		t.Fatalf("key metadata: %v", keys)
	}
	if code, out, errOut := c.call("", args...); code != 1 || out != "" || !strings.Contains(errOut, "already exists") {
		t.Fatalf("duplicate key: %d, %q, %q", code, out, errOut)
	}
	c.ok(key+"\n", "remote", "add", "10_work", "https://example.com/", "--key-stdin")
	c.ok(key, "remote", "add", "00_home", "http://127.0.0.1:8765", "--key-stdin")
	mounts := c.json("", "remote", "ls").([]any)
	if len(mounts) != 2 || mounts[0].(map[string]any)["name"] != "00_home" || mounts[1].(map[string]any)["name"] != "10_work" {
		t.Fatalf("mount ordering: %v", mounts)
	}
	for _, mount := range mounts {
		if len(mount.(map[string]any)) != 2 {
			t.Fatalf("unexpected mount metadata: %v", mount)
		}
	}
	for _, command := range []string{"key", "remote"} {
		for _, flags := range [][]string{nil, {"--json"}} {
			out, errOut := c.ok("", append([]string{command, "ls"}, flags...)...)
			if strings.Contains(out+errOut, key) || strings.Contains(out+errOut, "agk_") {
				t.Fatalf("%s ls exposed key material", command)
			}
		}
	}
	if code, out, errOut := c.call(key, "remote", "add", "10_work", "https://example.com", "--key-stdin"); code != 1 || out != "" || !strings.Contains(errOut, "already exists") {
		t.Fatalf("duplicate remote: %d, %q, %q", code, out, errOut)
	}
	if code, out, errOut := c.call(key, "remote", "add", "new", "https://example.com"); code != 1 || out != "" || !strings.Contains(errOut, "--key-stdin") {
		t.Fatalf("missing key input flag: %d, %q, %q", code, out, errOut)
	}
	if code, out, errOut := c.call("invalid-private-input", "remote", "add", "new", "https://example.com", "--key-stdin"); code != 1 || out != "" || strings.Contains(errOut, "invalid-private-input") {
		t.Fatalf("invalid key input: %d, %q, %q", code, out, errOut)
	}
	c.ok("", "key", "delete", "laptop")
	c.ok("", "remote", "delete", "00_home")
	c.ok("", "remote", "delete", "10_work")
	for _, command := range []string{"key", "remote"} {
		if out, _ := c.ok("", command, "ls", "--json"); out != "[]\n" {
			t.Fatalf("%s after deletion: %q", command, out)
		}
	}
}

type unusedKeyInput struct{ read bool }

func (r *unusedKeyInput) Read([]byte) (int, error) {
	r.read = true
	return 0, fmt.Errorf("unexpected API key read")
}

func TestNetworkUsageValidation(t *testing.T) {
	for _, args := range [][]string{
		{"key", "create", "laptop"},
		{"key", "create", "laptop", "--rule", "["},
		{"key", "create", "laptop", "--rule", "!*"},
		{"remote", "add", "local", "https://example.com", "--key-stdin"},
		{"remote", "add", "invalid name", "https://example.com", "--key-stdin"},
		{"remote", "add", "work", "ftp://example.com", "--key-stdin"},
		{"remote", "add", "work", "https://user:pass@example.com", "--key-stdin"},
		{"remote", "add", "work", "https://example.com?key=private", "--key-stdin"},
		{"serve", "--tls-cert", "cert.pem"},
		{"serve", "--tls-key", "key.pem"},
	} {
		input := &unusedKeyInput{}
		var out, errOut bytes.Buffer
		code := Execute(args, input, &out, &errOut)
		if code != 2 || input.read || out.Len() != 0 {
			t.Fatalf("%v: code=%d read=%t out=%q err=%q", args, code, input.read, out.String(), errOut.String())
		}
	}
}

func TestServeHTTPAndShutdown(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("AGSECRET_DB", "")
	t.Setenv("AGSECRET_PASS_FILE", "")
	c := newTestCLI(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root := newRoot(&options{in: strings.NewReader(""), out: io.Discard, errOut: write})
	root.SetArgs([]string{"--db", c.db, "--pass-file", c.pass, "serve", "--listen", "0.0.0.0:0"})
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- root.ExecuteContext(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(6 * time.Second):
			t.Error("serve cleanup timed out")
		}
	}()
	line := make(chan string, 1)
	go func() {
		text, _ := bufio.NewReader(read).ReadString('\n')
		line <- text
	}()
	var address string
	select {
	case output := <-line:
		address = strings.TrimSpace(strings.TrimPrefix(output, "Serving "))
	case err := <-done:
		t.Fatalf("serve stopped during startup: %v", err)
	case <-ctx.Done():
		t.Fatal("serve startup timed out")
	}
	address = strings.Replace(address, "http://0.0.0.0:", "http://127.0.0.1:", 1)
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(address + "/v1/fields")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status: %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve shutdown: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("serve shutdown timed out")
	}
}
