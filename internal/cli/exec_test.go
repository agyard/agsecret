package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agyard/agsecret/internal/store"
)

func TestExecEnvironmentGlobalRedactionAndFooter(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("used", "used-secret")["id"].(string)
	otherID := c.put("unused", "other-secret")["id"].(string)
	t.Setenv("AGSECRET_EXEC_HELPER", "1")
	t.Setenv("AGSECRET_EXEC_VALUE", id)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--"}
	call := func(mode string) (int, string, string) {
		return c.call("", append(append([]string(nil), args...), mode, id)...)
	}
	code, out, errOut := call("both")
	if code != 0 || out != "[REDACTED:"+id+"]|[REDACTED:"+id+"]\n" {
		t.Fatalf("environment expansion: code=%d out=%q err=%q", code, out, errOut)
	}
	ids := []string{id, otherID}
	slices.Sort(ids)
	if errOut != "[REDACTED:"+otherID+"]\nagsecret: redacted "+ids[0]+", "+ids[1]+" in the output above; this is not a leak\n" {
		t.Fatalf("unused stored secret or note not protected: %q", errOut)
	}
	code, out, errOut = call("silent")
	if code != 0 || out != "safe output\n" || errOut != "" {
		t.Fatalf("no-hit output should have no footer: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = call("large")
	if code != 0 || out != strings.Repeat("x", 96*1024)+"[REDACTED:"+id+"]" || !strings.HasSuffix(errOut, "this is not a leak\n") {
		t.Fatalf("trailing output lost: code=%d output bytes=%d stderr=%q", code, len(out), errOut)
	}
	code, out, errOut = call("exit")
	if code != 7 || !strings.Contains(out, "[REDACTED:"+id+"]") || !strings.Contains(errOut, "redacted "+id) {
		t.Fatalf("exit status or footer: code=%d out=%q err=%q", code, out, errOut)
	}
	shortID := c.put("short", "xy")["id"].(string)
	seedID := c.put("seed", "otpauth://totp/demo?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq", "--type", "totp")["id"].(string)
	code, out, errOut = c.call("", append(append([]string(nil), args...), "seed", shortID)...)
	want := "[REDACTED:" + shortID + "]|[REDACTED:" + seedID + "]|[REDACTED:" + seedID + "]"
	if code != 0 || out != want || !strings.Contains(errOut, "redacted") || !strings.Contains(errOut, shortID) {
		t.Fatalf("short injected pass or URI seed leaked: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("AGSECRET_EXEC_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 3 {
		os.Exit(90)
	}
	mode, value := args[1], args[2]
	switch mode {
	case "both":
		fmt.Fprintf(os.Stdout, "%s|%s\n", value, os.Getenv("AGSECRET_EXEC_VALUE"))
		fmt.Fprint(os.Stderr, "other-secret")
	case "silent":
		fmt.Fprintln(os.Stdout, "safe output")
	case "prompt":
		fmt.Fprint(os.Stdout, "Ready? ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil || line != "continue\n" {
			os.Exit(92)
		}
		fmt.Fprintln(os.Stdout, value)
	case "large":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 96*1024), value)
	case "exit":
		fmt.Fprintln(os.Stdout, value)
		os.Exit(7)
	case "seed":
		const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		fmt.Fprint(os.Stdout, value, "|", seed, "|", strings.ToLower(seed))
	default:
		os.Exit(91)
	}
	os.Exit(0)
}

type promptOutput struct {
	bytes.Buffer
	seen chan struct{}
	once sync.Once
}

func (p *promptOutput) Write(b []byte) (int, error) {
	n, err := p.Buffer.Write(b)
	if strings.Contains(p.Buffer.String(), "Ready? ") {
		p.once.Do(func() { close(p.seen) })
	}
	return n, err
}

func TestExecPromptCanBeAnsweredBeforeChildExits(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("api", "synthetic-password-long-enough")["id"].(string)
	t.Setenv("AGSECRET_EXEC_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, input := io.Pipe()
	defer in.Close()
	defer input.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	out := &promptOutput{seen: make(chan struct{})}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Execute([]string{"--db", c.db, "--pass-file", c.pass, "exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--", "prompt", id}, in, out, &stderr)
	}()
	select {
	case <-out.seen:
		_, err = io.WriteString(input, "continue\n")
		input.Close()
	case <-ctx.Done():
		input.Close()
		<-done
		t.Fatal("exec hid the child prompt until the input deadline")
	}
	code := <-done
	if err != nil || code != 0 || out.String() != "Ready? [REDACTED:"+id+"]\n" {
		t.Fatalf("prompt round trip: code=%d write=%v out=%q err=%q", code, err, out.String(), stderr.String())
	}
}

func TestExpandTokensIsSinglePassAndChecksPolicy(t *testing.T) {
	const id = "ags_0123456789abcdef"
	now := time.Unix(59, 0).UTC()
	records := map[string]store.Record{
		id: {ID: id, Type: "password", Secret: []byte("literal ags_fedcba9876543210"), AllowExec: true},
	}
	got, err := expandTokens("prefix="+id+":suffix", records, now, make(map[string][]byte))
	if err != nil || got != "prefix=literal ags_fedcba9876543210:suffix" {
		t.Fatalf("single-pass expansion: %q %v", got, err)
	}
	for _, old := range []string{"agsecret://v1/name", "{{agsecret:name}}", "flags_deadbeefcafe", "ags_project", "x" + id} {
		got, err := expandTokens(old, records, now, make(map[string][]byte))
		if err != nil || got != old {
			t.Fatalf("removed syntax was interpreted: %q %v", got, err)
		}
	}
	if _, err := expandTokens("ags_fedcba9876543210", records, now, make(map[string][]byte)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing ID: %v", err)
	}
	for _, typo := range []string{"ags_0123456789abcde", "ags_0123456789ABCDEF", "AGS_0123456789abcdef", id + "0"} {
		if _, err := expandTokens("Bearer "+typo, records, now, make(map[string][]byte)); err == nil || !strings.Contains(err.Error(), "not a valid ID") {
			t.Fatalf("near-miss ID %q: %v", typo, err)
		}
	}
	r := records[id]
	r.AllowExec = false
	records[id] = r
	if _, err := expandTokens(id, records, now, make(map[string][]byte)); err == nil {
		t.Fatal("disabled execution was allowed")
	}
	r.AllowExec, r.ExpiresAt = true, &now
	records[id] = r
	if _, err := expandTokens(id, records, now, make(map[string][]byte)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired ID: %v", err)
	}
	r.Type, r.ExpiresAt, r.Secret = "totp", nil, []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	records[id] = r
	otp := make(map[string][]byte)
	got, err = expandTokens(id, records, now, otp)
	if err != nil || got != "287082" || !bytes.Equal(otp[id], []byte(got)) {
		t.Fatalf("TOTP expansion: %q %v", got, err)
	}
}

func TestUnsafeArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"sh", "-c", "curl $1", "sh", "ags_x"}, "-c|curl $1"},
		{[]string{"/bin/bash", "-o", "pipefail", "-ec", "script"}, "-o|pipefail|-ec|script"},
		{[]string{"zsh", "script.sh", "ags_x"}, "script.sh"},
		{[]string{"fish", "--command=echo"}, "--command=echo"},
		{[]string{"env", "sh", "-c", "script"}, "-c|script"},
		{[]string{"timeout", "5", "/bin/bash", "-lc", "script", "arg"}, "-lc|script"},
		{[]string{"python3", "-c", "code", "arg"}, "-c|code"},
		{[]string{"node", "-e", "code"}, "-e|code"},
		{[]string{"tmux", "send-keys", "-t", "0", "x"}, "tmux|send-keys|-t|0|x"},
		{[]string{"curl", "-H", "x", "sh"}, ""},
	} {
		if got := strings.Join(unsafeArgs(tc.args), "|"); got != tc.code {
			t.Fatalf("%v: got %q, want %q", tc.args, got, tc.code)
		}
	}
}
