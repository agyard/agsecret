package cli

import (
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agyard/agsecret/internal/redact"
	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
	"github.com/spf13/cobra"
)

func newExec(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:        "exec -- COMMAND [ARG...]",
		SuggestFor: []string{"run"},
		Short:      "Run a command with secrets filled in by ID",
		Long: `Run a command, replacing each secret ID in its arguments and environment
variables with the secret's value (for a TOTP secret, its current code).

Any stored value that shows up in the command's output is replaced with
[REDACTED:ID], and a note on standard error lists the IDs. Only exact copies
are caught: encoded values, files, network connections and writes straight to
the terminal are not.

The command runs without a shell. A shell or interpreter would run a value
placed in its code, so IDs in code such as sh -c or python -c are refused, as
are IDs given to tmux or screen (use send for those). Pass the ID in an
environment variable instead:

  TOKEN=ID agsecret exec -- sh -c 'curl -H "Authorization: Bearer $TOKEN" URL'

Environment variables are also safer than arguments, which other users can
see with ps.

The command's input and output go through pipes, and it runs without a
controlling terminal, so it cannot write to the terminal past the filter.
Programs that prompt on the terminal, such as ssh or sudo asking for a
password, cannot prompt; use send for those. Pagers and REPLs may behave
differently.

The exit status is the command's own, or 128+N if signal N killed it. If the
command cannot be run, agsecret exits with 126, or 127 if it is not found. For
any other agsecret error, it exits with 125.`,
		DisableFlagsInUseLine: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: %s", cmd.UseLine())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runExpanded(o, cmd, args)
			if _, ok := errors.AsType[*exitError](err); err != nil && !ok {
				err = &exitError{code: 125, err: err}
			}
			return err
		},
	}
	c.Flags().SetInterspersed(false)
	return c
}

// tokenPattern also matches near-miss IDs so that a mistyped ID fails loudly
// instead of reaching the command as literal text.
var tokenPattern = regexp.MustCompile(`(?i)\bags_[0-9a-f]{8,}`)

// expandTokens performs a single pass so a secret that happens to contain a
// different record ID is never interpreted recursively.
func expandTokens(value string, records map[string]store.Record, now time.Time, injected map[string][]byte) (string, error) {
	if !strings.Contains(strings.ToLower(value), "ags_") {
		return value, nil // Skips the regexp for most environment values.
	}
	var b strings.Builder
	last := 0
	for _, idx := range tokenPattern.FindAllStringIndex(value, -1) {
		id := value[idx[0]:idx[1]]
		if err := store.CheckID(id); err != nil {
			return "", err
		}
		r, found := records[id]
		if !found {
			return "", fmt.Errorf("secret %s %w", id, store.ErrNotFound)
		}
		secret, resolved := injected[id]
		if !resolved {
			var err error
			if secret, err = useValue(r, now, "exec"); err != nil {
				return "", err
			}
			injected[id] = secret
		}
		b.WriteString(value[last:idx[0]])
		b.Write(secret)
		last = idx[1]
	}
	if last == 0 {
		return value, nil
	}
	b.WriteString(value[last:])
	return b.String(), nil
}

// codeRunners parse their options and first operand as code, so a secret
// placed there would run instead of being passed as data.
var codeRunners = []string{"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "fish", "python", "python3", "node", "perl", "ruby", "php"}

// unsafeArgs returns the arguments in which an ID is refused: the code given
// to a code runner, which may follow wrappers such as env, timeout or sudo,
// and everything given to tmux or screen, which could type it into a pane
// where send would refuse.
func unsafeArgs(args []string) []string {
	for i, arg := range args {
		if strings.Contains(arg, "=") {
			continue
		}
		switch name := filepath.Base(arg); {
		case name == "tmux" || name == "screen":
			return args[i:]
		case slices.Contains(codeRunners, name):
			for j := i + 1; j < len(args); j++ {
				switch a := args[j]; {
				case slices.Contains([]string{"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}, a):
					j++ // The next argument is this option's value.
				case !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+"):
					return args[i+1 : j+1]
				}
			}
			return args[i+1:]
		}
	}
	return nil
}

// protectedValues lists what output filtering removes: unexpired passwords of
// at least four bytes, and unexpired TOTP seeds as stored and in canonical
// Base32. The caller adds the values it injects.
func protectedValues(records []store.Record, now time.Time) ([]redact.Secret, error) {
	var protected []redact.Secret
	for _, r := range records {
		if r.Expired(now) || (r.Type == "password" && len(r.Secret) < 4) {
			continue
		}
		protected = append(protected, redact.Secret{ID: r.ID, Value: r.Secret})
		if r.Type != "totp" {
			continue
		}
		config, err := totp.Parse(string(r.Secret))
		if err != nil {
			return nil, err
		}
		canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(config.Key)
		config.Clear()
		for _, v := range []string{canonical, strings.ToLower(canonical)} {
			protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(v)})
		}
		if uri, err := url.Parse(string(r.Secret)); err == nil && strings.EqualFold(uri.Scheme, "otpauth") {
			protected = append(protected, redact.Secret{ID: r.ID, Value: []byte(uri.Query().Get("secret"))})
		}
	}
	return protected, nil
}

func runExpanded(o *options, cmd *cobra.Command, args []string) error {
	if tokenPattern.MatchString(args[0]) {
		return errors.New("the command name cannot contain a secret ID; pass IDs as separate arguments")
	}
	for _, arg := range unsafeArgs(args) {
		if !tokenPattern.MatchString(arg) {
			continue
		}
		if name := filepath.Base(args[0]); name == "tmux" || name == "screen" {
			return errors.New("use agsecret send to type a secret into a terminal pane")
		}
		return errors.New(`the secret would be read as code; pass the ID in an environment variable instead, for example TOKEN=ID agsecret exec -- sh -c '... "$TOKEN" ...'`)
	}
	var records []store.Record
	err := o.withStore(func(s *store.Store) error {
		var err error
		records, err = s.List(true)
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
	now := time.Now()
	protected, err := protectedValues(records, now)
	defer func() {
		for _, secret := range protected {
			clear(secret.Value)
		}
	}()
	if err != nil {
		return err
	}
	byID := make(map[string]store.Record, len(records))
	for _, r := range records {
		byID[r.ID] = r
	}
	injected := make(map[string][]byte)
	defer func() {
		for _, value := range injected {
			clear(value)
		}
	}()
	expanded := make([]string, len(args))
	for i, arg := range args {
		if expanded[i], err = expandTokens(arg, byID, now, injected); err != nil {
			return err
		}
	}
	env := os.Environ()
	for i, item := range env {
		key, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		if value, err = expandTokens(value, byID, now, injected); err != nil {
			return fmt.Errorf("in environment variable %s: %w", key, err)
		}
		env[i] = key + "=" + value
	}
	if len(injected) == 0 {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "agsecret: note: no secret IDs found in the command or environment, so nothing was filled in")
	}
	for id, value := range injected {
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
	child := exec.Command(expanded[0], expanded[1:]...)
	child.Env = env
	child.Stdout, child.Stderr = stdout, stderr
	// Give the command a pipe, never the terminal itself, which it could
	// write to past the filter. Wait does not wait for this copy: a read
	// from the terminal may block until exit, which is harmless.
	stdin, err := child.StdinPipe()
	if err != nil {
		return err
	}
	// Bound inherited pipes held open by grandchildren after the command
	// exits. Normal output is still fully drained first.
	child.WaitDelay = 2 * time.Second
	detach(child)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(signals) // No sends after Stop returns, so closing is safe.
		close(signals)
	}()
	if err := child.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			msg := "command not found: " + args[0]
			if strings.Contains(args[0], " ") {
				msg += " (pass the command and each argument as separate words)"
			}
			return &exitError{code: 127, err: errors.New(msg)}
		}
		if pe, ok := errors.AsType[*fs.PathError](err); ok {
			err = pe.Err
		}
		return &exitError{code: 126, err: fmt.Errorf("cannot run %s: %w", args[0], err)}
	}
	go func() {
		_, _ = io.Copy(stdin, cmd.InOrStdin())
		stdin.Close()
	}()
	// The command has its own session, so relay signals such as Ctrl-C to it.
	go func() {
		for sig := range signals {
			_ = signalGroup(child.Process, sig)
		}
	}()
	waitErr := child.Wait()
	stdoutErr, stderrErr := stdout.flush(), stderr.flush()
	if ids := slices.Concat(stdout.redactor.Used(), stderr.redactor.Used()); len(ids) > 0 {
		slices.Sort(ids)
		prefix := ""
		if stderr.last != '\n' {
			prefix = "\n"
		}
		note := fmt.Sprintf("%sagsecret: redacted %s in the output above; this is not a leak\n", prefix, strings.Join(slices.Compact(ids), ", "))
		stderrErr = errors.Join(stderrErr, stderr.emit(stderr.redactor.Feed([]byte(note), true)))
	}
	if state := child.ProcessState; state != nil && !state.Success() {
		return &exitError{code: exitCode(state)}
	}
	if waitErr != nil {
		return waitErr
	}
	if stdoutErr != nil || stderrErr != nil {
		return errors.New("cannot write the command's output")
	}
	return nil
}

func exitCode(state *os.ProcessState) int {
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return max(state.ExitCode(), 1)
}

type filteredOutput struct {
	out      io.Writer
	mu       *sync.Mutex
	redactor *redact.Redactor
	last     byte // last byte written, so a note can start on a new line
}

func newFilteredOutput(out io.Writer, mu *sync.Mutex, secrets []redact.Secret) *filteredOutput {
	return &filteredOutput{out: out, mu: mu, redactor: redact.New(secrets...), last: '\n'}
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
		w.last = value[n-1]
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
