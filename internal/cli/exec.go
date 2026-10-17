package cli

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agyard/agsecret/internal/redact"
	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newExec(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:   "exec -- COMMAND [ARGUMENTS...]",
		Short: "Expand credential IDs and run a command with output redaction",
		Long: `COMMAND is executed directly. Every ags_ followed by 16 lowercase hex
characters in arguments and environment values is replaced with its credential.
For TOTP records this is the current code. The executable name must stay fixed.

The child's stdout and stderr are streamed through exact-byte redaction of all
unexpired passwords of at least four bytes and TOTP seeds, plus every injected value.
Matches split across reads are protected. A note is appended to stderr only
when a replacement occurred. The command's exit status is preserved.

Use a program-specific environment interface when available: secrets in argv
can be visible to process inspectors. Output written directly to a terminal,
file, or network connection bypasses this wrapper.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usage("exec requires COMMAND after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.json {
				return usage("exec preserves the command's stdout/stderr and cannot use --json")
			}
			return runExpandedCommand(cmd.Context(), o, cmd, args)
		},
	}
	c.Flags().SetInterspersed(false)
	return c
}

var tokenPattern = regexp.MustCompile(`ags_[0-9a-f]{16}`)

// expandTokens performs a single pass so a secret that happens to contain a
// different record ID is never interpreted recursively.
func expandTokens(value string, records map[string]store.Record, now time.Time, injectedValues map[string][]byte) (string, error) {
	indices := tokenPattern.FindAllStringIndex(value, -1)
	if len(indices) == 0 {
		return value, nil
	}
	var b strings.Builder
	b.Grow(len(value))
	last := 0
	for _, idx := range indices {
		id := value[idx[0]:idx[1]]
		r, found := records[id]
		if !found {
			return "", fmt.Errorf("credential %s: %w", id, store.ErrNotFound)
		}
		if r.Expired(now) {
			return "", fmt.Errorf("credential %s: %w", id, store.ErrExpired)
		}
		if !r.AllowExec {
			return "", fmt.Errorf("exec is disabled for credential %s", id)
		}
		secret, resolved := injectedValues[id]
		if !resolved {
			var err error
			secret, err = credentialValue(r, now)
			if err != nil {
				return "", err
			}
			injectedValues[id] = secret
		}
		b.WriteString(value[last:idx[0]])
		b.Write(secret)
		last = idx[1]
	}
	b.WriteString(value[last:])
	return b.String(), nil
}

func runExpandedCommand(ctx context.Context, o *options, cmd *cobra.Command, args []string) (resultErr error) {
	if tokenPattern.MatchString(args[0]) {
		return errors.New("credential tokens are not allowed in COMMAND; keep the executable name fixed")
	}
	var records []store.Record
	err := o.withStore(false, func(s *store.Store) error {
		var err error
		records, err = s.ListWithSecrets()
		return err
	})
	if err != nil {
		return err
	}
	defer func() {
		for _, r := range records {
			clear(r.Secret)
		}
	}()
	byID := make(map[string]store.Record, len(records))
	var protected []redact.Secret
	defer func() {
		for _, secret := range protected {
			clear(secret.Value)
		}
	}()
	// Wrapper diagnostics can contain credentials too (for example in an
	// executable path). Include report's prefix in the protected output, then
	// return only the exit code so Execute does not print the error a second time.
	defer func() {
		if resultErr == nil {
			return
		}
		// Child exit statuses and cancellation are already represented by
		// their dedicated process codes; printing a wrapper diagnostic would
		// add noise and change the command's observable behavior.
		var childExit *exitError
		if errors.As(resultErr, &childExit) || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) {
			return
		}
		diagnostic := newFilteredOutput(cmd.ErrOrStderr(), &sync.Mutex{}, protected)
		defer diagnostic.redactor.Close()
		code := report(resultErr, diagnostic)
		_ = diagnostic.flush()
		resultErr = &exitError{code: code}
	}()
	now := nowUTC()
	for _, r := range records {
		byID[r.ID] = r
		if !r.Expired(now) && (r.Type == "totp" || len(r.Secret) >= 4) {
			protected = append(protected, redact.Secret{ID: r.ID, Value: r.Secret})
			if r.Type == "totp" {
				config, err := totp.Parse(string(r.Secret))
				if err != nil {
					return err
				}
				canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(config.Key)
				padded := base32.StdEncoding.EncodeToString(config.Key)
				config.Clear()
				protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(canonical)})
				protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(padded)})
				protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(strings.ToLower(canonical))})
				protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(strings.ToLower(padded))})
				if uri, err := url.Parse(string(r.Secret)); err == nil && strings.EqualFold(uri.Scheme, "otpauth") {
					protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(uri.Query().Get("secret"))})
				}
			}
		}
	}
	injectedValues := make(map[string][]byte)
	defer func() {
		for _, value := range injectedValues {
			clear(value)
		}
	}()
	expanded := make([]string, len(args))
	for i, arg := range args {
		expanded[i], err = expandTokens(arg, byID, now, injectedValues)
		if err != nil {
			return err
		}
	}
	env := os.Environ()
	for i, item := range env {
		key, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		value, err = expandTokens(value, byID, now, injectedValues)
		if err != nil {
			return err
		}
		env[i] = key + "=" + value
	}
	for id, value := range injectedValues {
		protected = append(protected, redact.Secret{ID: id, Value: value})
	}

	// Supplying Writers lets os/exec own its copy goroutines and wait for
	// their EOF before returning. Calling Wait before custom StdoutPipe
	// readers finish can close those pipes and discard their final bytes.
	var outputMu sync.Mutex
	stdout := newFilteredOutput(cmd.OutOrStdout(), &outputMu, protected)
	stderr := newFilteredOutput(cmd.ErrOrStderr(), &outputMu, protected)
	defer stdout.redactor.Close()
	defer stderr.redactor.Close()
	child := exec.CommandContext(ctx, expanded[0], expanded[1:]...)
	child.Env = env
	child.Stdin = cmd.InOrStdin()
	child.Stdout, child.Stderr = stdout, stderr
	// Bound inherited pipes held open by grandchildren after the command
	// exits or is canceled. Normal output is still fully drained first.
	child.WaitDelay = 2 * time.Second
	if err = child.Start(); err != nil {
		return fmt.Errorf("cannot start command: %w", err)
	}
	waitErr := child.Wait()
	stdoutErr, stderrErr := stdout.flush(), stderr.flush()
	markers := append(stdout.redactor.Replacements(), stderr.redactor.Replacements()...)
	if len(markers) > 0 {
		sort.Strings(markers)
		unique := markers[:0]
		for _, marker := range markers {
			if len(unique) == 0 || marker != unique[len(unique)-1] {
				unique = append(unique, marker)
			}
		}
		prefix := ""
		if stderr.wrote && stderr.last != '\n' {
			prefix = "\n"
		}
		description := strings.Join(unique, ", ")
		if description == "" {
			description = "matching bytes removed"
		}
		note := fmt.Sprintf("%sagsecret: redacted secret output (%s); see \"agsecret help --agent\" for details.\n", prefix, description)
		err = stderr.emit(stderr.redactor.Feed([]byte(note), true))
		if stderrErr == nil {
			stderrErr = err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var processErr *exec.ExitError
	if errors.As(waitErr, &processErr) {
		return &exitError{code: processExitCode(processErr)}
	}
	if waitErr != nil {
		return &exitError{code: 125}
	}
	if stdoutErr != nil || stderrErr != nil {
		return errors.New("cannot write protected command output")
	}
	return nil
}

type filteredOutput struct {
	out      io.Writer
	mu       *sync.Mutex
	redactor *redact.Redactor
	wrote    bool
	last     byte
}

func newFilteredOutput(out io.Writer, mu *sync.Mutex, secrets []redact.Secret) *filteredOutput {
	return &filteredOutput{out: out, mu: mu, redactor: redact.NewWithSecrets(secrets...)}
}

func (w *filteredOutput) emit(value []byte) error {
	defer clear(value)
	if len(value) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.out.Write(value)
	if n > 0 {
		w.wrote, w.last = true, value[n-1]
	}
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return err
}

func (w *filteredOutput) Write(chunk []byte) (int, error) {
	err := w.emit(w.redactor.Feed(chunk, false))
	return len(chunk), err
}

func (w *filteredOutput) flush() error {
	return w.emit(w.redactor.Feed(nil, true))
}

func processExitCode(err *exec.ExitError) int {
	code := err.ProcessState.ExitCode()
	if code >= 0 {
		return code
	}
	v := reflect.ValueOf(err.ProcessState.Sys())
	if v.IsValid() {
		m := v.MethodByName("Signal")
		if m.IsValid() && m.Type().NumIn() == 0 && m.Type().NumOut() == 1 {
			out := m.Call(nil)
			if len(out) == 1 && out[0].Kind() >= reflect.Int && out[0].Kind() <= reflect.Int64 {
				return 128 + int(out[0].Int())
			}
		}
	}
	return 1
}

const capturedOutputRefusal = `refused to print secret directly to captured stdout. Use exec or send; run "agsecret help --agent" for safe usage.`

func trustedTerminal(out, _ io.Writer) error {
	if runtime.GOOS == "linux" {
		pid, err := shellCommandAncestor(os.Getppid(), os.ReadFile)
		if err != nil {
			return usage(capturedOutputRefusal)
		}
		if pid != 0 {
			if isIndirectOutput(out, pid) {
				return nil
			}
			return usage(capturedOutputRefusal)
		}
	}
	if isTerminalWriter(out) {
		return nil
	}
	return usage(capturedOutputRefusal)
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func isIndirectOutput(out io.Writer, shellPID int) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	current, err := f.Stat()
	// A regular-file redirect cannot be distinguished from a shell child whose
	// parent kept its original stdout: the shell's fd 1/2 then differ even though
	// the child is a top-level redirect. Accept pipes only; this fails closed for
	// ambiguous files while keeping command substitution and pipelines useful.
	if err != nil || current.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	for _, fd := range []int{1, 2} {
		ancestor, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", shellPID, fd))
		if err != nil || os.SameFile(current, ancestor) {
			return false
		}
	}
	return true
}

func suspiciousShellParent() bool {
	pid, err := shellCommandAncestor(os.Getppid(), os.ReadFile)
	return err != nil || pid != 0
}

// proc stat's comm field may contain spaces and parentheses. The final ')'
// closes it; the following fields begin at state, then PPID.
func parseParentPID(stat string) (int, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		return 0, errors.New("invalid process stat")
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid < 0 {
		return 0, errors.New("invalid process parent PID")
	}
	return pid, nil
}

func shellCommandAncestor(pid int, readFile func(string) ([]byte, error)) (int, error) {
	seen := make(map[int]bool)
	for pid > 0 {
		if seen[pid] || len(seen) >= 4096 {
			return 0, errors.New("cyclic process ancestry")
		}
		seen[pid] = true
		cmdline, err := readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return 0, err
		}
		if isShellCommand(strings.Split(string(cmdline), "\x00")) {
			return pid, nil
		}
		if pid == 1 {
			return 0, nil
		}
		stat, err := readFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0, err
		}
		pid, err = parseParentPID(string(stat))
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func isShellCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	name := strings.TrimPrefix(strings.ToLower(filepathBase(args[0])), "-")
	if name == "busybox" && len(args) > 1 {
		args = args[1:]
		name = strings.ToLower(filepathBase(args[0]))
	}
	switch name {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "fish":
	default:
		return false
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--command" || strings.HasPrefix(arg, "--command=") {
			return true
		}
		if arg == "-o" || arg == "+o" || arg == "-O" || arg == "+O" || arg == "--rcfile" || arg == "--init-file" {
			i++ // Shell options that consume a separate option name or file.
			continue
		}
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			return false
		}
		if !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg[1:], 'c') {
			return true
		}
	}
	return false
}

func filepathBase(s string) string {
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}
