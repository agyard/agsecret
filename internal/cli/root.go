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

	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
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

const agentHelpText = `Agent workflow

Discover credentials with agsecret list --json and agsecret view ID --json.
Replace ID below with the current ags_<16 lowercase hex> ID from those results.

  agsecret exec -- curl -H 'Authorization: Bearer ID' URL
  agsecret send tmux:<PANE> ID
  agsecret get TOTP_ID
  agsecret report ID --reason 'unexpected plaintext output'

exec expands IDs in argv/environment and filters stdout/stderr. Pass IDs as
arguments or environment values, not shell source. Filtering matches exact
bytes; transformed output, files and direct terminal writes bypass it.
[REDACTED:ID] marks removed bytes; it does not mean plaintext escaped.
send requires a password prompt with TTY ECHO disabled.

Pass get refuses captured stdout. On Linux, indirect use such as
consumer "$(agsecret get ID)" or agsecret get ID | consumer is allowed;
the consumer must not echo the value. Prefer exec or send. TOTP get returns a
current code; TOTP seeds are never printed and TOTP is not reportable.

If plaintext escapes, report its ID before rotation. All matching pass records
receive the report; permissions never change. report --json returns an array;
report --secret-stdin matches exact pass bytes. A changed secret/type gets a new
ID. Never retry an old-ID report by name: it could blame a replacement secret.

Keep JSON stdout separate from stderr; --quiet suppresses the periodic tip.
For command options: agsecret COMMAND --help or agsecret help COMMAND`

func newRoot(o *options) *cobra.Command {
	var showVersion bool
	r := &cobra.Command{
		Use:           "agsecret",
		Short:         "Keep Agent credentials out of model-visible command output",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Encrypted local credentials for Agent workflows.
Use list/view to discover current IDs, put --json to capture an ID, and exec to
expand IDs while filtering child output. Use "agsecret help --agent" for the
short Agent workflow guide.`,
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
	var agentOnly bool
	help := &cobra.Command{Use: "help [COMMAND]", Short: "Show command help", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if agentOnly {
			if len(args) != 0 {
				return usage("--agent cannot be combined with COMMAND; use agsecret COMMAND --help for command flags")
			}
			_, err := io.WriteString(cmd.OutOrStdout(), agentHelpText+"\n")
			return err
		}
		target, rest, err := r.Find(args)
		if err != nil || len(rest) != 0 {
			return usage("unknown command %q; use agsecret help --agent for Agent workflow guidance", strings.Join(args, " "))
		}
		target.InitDefaultHelpFlag()
		return target.Help()
	}}
	help.Flags().BoolVar(&agentOnly, "agent", false, "show the concise Agent workflow guide")
	r.SetHelpCommand(help)
	return r
}

func encodeJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}

func usage(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}
