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

var agentHelpTopics = map[string]string{
	"agent": `Agent workflow

1. Create/open the vault: agsecret init
2. Store through stdin and save the returned ID:
     printf '%s' "$VALUE" | agsecret put NAME --secret-stdin --json
3. Use the ID for later commands:
     agsecret view ID --json --quiet
     agsecret exec -- curl -H 'Authorization: Bearer ID' URL
4. If pass output is exposed, report before rotating:
     agsecret report ID --reason '...'
5. Rotate with put. A changed secret gets a new ID; the old ID stops resolving.

TOTP seeds are never printed or reportable. Use get, exec, or send for codes.
Use --quiet when stderr is merged into machine-readable stdout.

Topics: put, view, get, exec, send, report, list, doctor.`,
	"put": `put NAME|ID [SECRET]

Create with a NAME; update with NAME or the current ID. Prefer --secret-stdin or
--secret-file. Use --json and save .id. Policy-only updates keep the ID and leak
history. A changed secret or type gets a new ID and clears that record's history.
Pass duplicates are reported on stderr by ID; no secret is printed.

Options: --type pass|totp, --ttl, --mask, --allow-get, --allow-exec.`,
	"view": `view NAME|ID

Shows metadata, policy, status, leak history, and a masked value. Prefer --json.
TOTP values always display as [set]. --dangerously-show-secret reveals a pass
only; for TOTP it displays the current code and never the seed. --quiet suppresses
the periodic stderr tip.`,
	"get": `get NAME|ID

Checks expiry and allow_get. Pass output requires a terminal or an indirect pipe
on Linux; captured stdout and regular-file redirects fail closed. TOTP returns a
current code. Use --dangerously-skip-check only for a destination you trust.
Prefer exec or send for Agent workflows.`,
	"exec": `exec -- COMMAND [ARGS...]

Replaces ags_<16 lowercase hex> IDs in argv and inherited environment values,
then starts COMMAND directly. TOTP IDs become current codes. Child stdout/stderr
are filtered for active secrets; a stderr note appears only after a match.
Prefer argv positions or environment values over shell source.`,
	"send": `send tmux:<TARGET> NAME|ID

Sends a pass or current TOTP code to a tmux pane after checking TTY ECHO and
allow_exec. --enter=false skips Enter; --force-echo overrides only the ECHO
check. Pass values containing terminal control characters are rejected; use exec.`,
	"report": `report ID|NAME [--secret-stdin]

Appends a leak event without changing permissions. Prefer the current ID. An ID
or NAME report resolves one pass and appends to every pass record with the same
exact value, including expired or disabled records. --secret-stdin matches exact
pass bytes and never TOTP. --json always returns an array. There is no --revoke.`,
	"list": `list [--json]

Lists current names, IDs, types, statuses, and masks. Save IDs from JSON output.
Use --quiet when stderr is merged with stdout.`,
	"doctor": `doctor [--json]

Checks the vault and lists credentials with leak history. It does not change
permissions or rotate values. Use --quiet when stderr is merged with stdout.`,
}

func newRoot(o *options) *cobra.Command {
	var showVersion bool
	r := &cobra.Command{
		Use:           "agsecret",
		Short:         "Keep Agent credentials out of model-visible command output",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Encrypted local credentials for Agent workflows.
Use list/view to discover current IDs, put --json to capture an ID, and exec to
expand IDs while filtering child output. Use "agsecret help agent" for the
short workflow guide and "agsecret help TOPIC" for safety details.`,
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
	help := &cobra.Command{Use: "help [TOPIC|COMMAND]", Short: "Show concise Agent workflow help", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Root().Help()
		}
		if text, ok := agentHelpTopics[args[0]]; ok {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), text)
			return err
		}
		target, rest, err := r.Find(args)
		if err != nil || len(rest) != 0 {
			return usage("unknown help topic %q; choose agent, put, view, get, exec, send, report, list, or doctor", strings.Join(args, " "))
		}
		target.InitDefaultHelpFlag()
		return target.Help()
	}}
	r.SetHelpCommand(help)
	return r
}

func encodeJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}

func usage(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}
