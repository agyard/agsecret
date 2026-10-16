package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/thezzisu/agsecret/internal/store"
)

var Version = "dev"

type options struct {
	db       string
	passFile string
	json     bool
	quiet    bool
	in       io.Reader
	out      io.Writer
	errOut   io.Writer
}

type usageError struct{ message string }

func (e *usageError) Error() string { return e.message }

type exitError struct{ code int }

func (e *exitError) Error() string { return "command exited" }

func dataHome() string {
	if v := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(v) {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return filepath.Join(home, ".local", "share")
}

func defaultDBPath() string {
	if v := os.Getenv("AGSECRET_DB"); v != "" {
		return v
	}
	return filepath.Join(dataHome(), "agsecret", "secrets.db")
}

func defaultPassFile() string {
	if v := os.Getenv("AGSECRET_PASS_FILE"); v != "" {
		return v
	}
	path := filepath.Join(dataHome(), "agsecret", "session.pass")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// Execute runs the CLI and returns its process exit code.
func Execute(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	o := &options{db: defaultDBPath(), passFile: defaultPassFile(), in: in, out: out, errOut: errOut}
	root := newRoot(o)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		return report(err, errOut)
	}
	return 0
}

func report(err error, out io.Writer) int {
	if err == nil {
		return 0
	}
	var ex *exitError
	if errors.As(err, &ex) {
		return ex.code
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	code := 1
	var ue *usageError
	if errors.As(err, &ue) {
		code = 2
	}
	message := err.Error()
	if message == "" {
		message = "operation failed"
	}
	_, _ = fmt.Fprintln(out, "agsecret:", safeText(message))
	return code
}

// safeText keeps metadata and errors on one visual line and prevents terminal
// escape sequences or Unicode direction controls from executing on display.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == 0:
			b.WriteString(`\0`)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func newRoot(o *options) *cobra.Command {
	var showVersion bool
	r := &cobra.Command{
		Use:           "agsecret",
		Short:         "Keep Agent credentials out of model-visible command output",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `AG-Secret keeps passwords and TOTP seeds in an encrypted SQLite database.
Credentials have random IDs such as ags_9f8e7d6c5b4a3210. IDs are tokens,
not plaintext secrets. A changed secret gets a new ID and invalidates the old
one. All single-credential commands accept a name or current ID.

Agent usage guide:
  Discover credentials with agsecret list and agsecret view NAME|ID. view shows
  metadata, leak history and a masked value by default. Use --json for structure.
  The default mask is [set]; prefix/suffix masks intentionally reveal characters.

  Pass a token to a command with agsecret exec -- COMMAND [ARGUMENTS...]. Tokens
  in arguments and environment variable values are replaced just before launch:
    agsecret exec -- curl -H 'Authorization: Bearer ags_9f8e7d6c5b4a3210' URL
    API_KEY=ags_9f8e7d6c5b4a3210 agsecret exec -- your-program
  The child runs directly, without an implicit shell. Known active passwords
  and TOTP seeds are redacted on stdout/stderr as [REDACTED:ags_<16hex>]. A notice
  is printed only when a replacement actually occurs. Redaction is exact-byte;
  transformed values, files, network traffic and programs opening their own TTY
  are outside this protection. Expanded arguments may be visible to local
  process inspectors, so prefer an environment or program-specific stdin input.

  get emits a password only to an interactive TTY or an indirect pipe/substitution
  under a non-interactive shell on Linux:
    your-program --password "$(agsecret get NAME)"
    agsecret get NAME | your-program --password-stdin
  Top-level captured output and regular-file redirects are refused. Only a distinct
  pipe compared with the shell's fd 1/2 is treated as indirect. The receiving program must not print the
  password; indirect get does not redact downstream output. A TOTP get prints the
  current short-lived code. --dangerously-skip-check bypasses the output check.

  Inject a password or current TOTP code into an existing tmux prompt:
    agsecret send tmux:dev:0.1 NAME
  The target TTY must have ECHO disabled (a password prompt). --enter=false skips
  Enter, while --force-echo overrides the echo check and may expose the value.

  If plaintext is exposed, report it immediately without repeating it in chat:
    agsecret report ags_9f8e7d6c5b4a3210 --reason 'unexpected command output'
    agsecret report ags_9f8e7d6c5b4a3210 --context 'log excerpt' --attachment /path/to/log
    printf '%s' "$LEAKED_VALUE" | agsecret report --secret-stdin
  Reports append the event to every pass record sharing the same plaintext,
  including expired or disabled records, and never change access policy.
  --secret-stdin matches stored passphrases. TOTP credentials do not support
  reports. report --json always returns an array of affected pass records.
  Use --quiet with list/view/doctor to suppress periodic tips. A human decides
  whether to change permissions or rotate; reports never do either automatically.
  A changed secret receives a new ID and clears that record's leak history;
  same-value updates retain both. Save the ID returned by put --json. A stale ID
  fails; do not retry a delayed incident report against the replacement by name.

  Store or rotate a password with agsecret put NAME|ID --secret-stdin. For a TOTP seed or
  otpauth://totp URI add --type totp. New credentials permit get/exec/send; expiry
  and per-credential policies still apply. view never exposes a TOTP seed; its
  dangerous mode only shows the current short-lived code.

Run agsecret init to create the database and a random owner-only default pass
file. An external --pass-file or AGSECRET_PASS_FILE can supply the passphrase.
Encrypted SQLite uses a pure-Go VFS and does not require CGO.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if showVersion {
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), map[string]any{"version": Version, "schema_version": store.SchemaVersion})
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "agsecret "+safeText(Version))
				return err
			}
			return cmd.Help()
		},
	}
	r.SetIn(o.in)
	r.SetOut(o.out)
	r.SetErr(o.errOut)
	r.PersistentFlags().StringVar(&o.db, "db", o.db, "encrypted database path (AGSECRET_DB or XDG data default)")
	r.PersistentFlags().StringVar(&o.passFile, "pass-file", o.passFile, "owner-only passphrase file (AGSECRET_PASS_FILE or secure default)")
	r.PersistentFlags().BoolVar(&o.json, "json", false, "emit structured JSON where supported")
	r.PersistentFlags().BoolVar(&o.quiet, "quiet", false, "suppress the periodic agent-safety tip on stderr")
	r.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "print version")
	r.CompletionOptions.DisableDefaultCmd = true
	r.AddCommand(newInit(o))
	r.AddCommand(newPut(o))
	r.AddCommand(newGet(o))
	r.AddCommand(newView(o))
	r.AddCommand(newSend(o))
	r.AddCommand(newReport(o))
	r.AddCommand(newExec(o))
	r.AddCommand(newList(o))
	r.AddCommand(newDelete(o))
	r.AddCommand(newDoctor(o))
	r.AddCommand(&cobra.Command{Use: "version", Short: "Print version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if o.json {
			return encodeJSON(cmd.OutOrStdout(), map[string]any{"version": Version, "schema_version": store.SchemaVersion})
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "agsecret "+safeText(Version))
		return err
	}})
	return r
}

func encodeJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}

func usage(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}
