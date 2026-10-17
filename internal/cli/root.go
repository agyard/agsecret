package cli

import (
	"cmp"
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
	db          string
	passFile    string
	defaultPass bool // passFile is the default path, not chosen by the user
	json        bool
	started     bool // a command began running; earlier errors are usage errors
	in          io.Reader
	out         io.Writer
	errOut      io.Writer
}

// exitError sets the process exit code. A nil err prints nothing.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return fmt.Sprint(e.err) }

// noJSON marks commands whose output is the value or a child's output.
var noJSON = map[string]string{"json": "none"}

func dataDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = "."
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "agsecret")
}

// resolve applies flags, then environment variables, then XDG defaults.
func (o *options) resolve() error {
	envPass := os.Getenv("AGSECRET_PASS_FILE")
	o.defaultPass = o.passFile == "" && envPass == ""
	o.passFile = cmp.Or(o.passFile, envPass, filepath.Join(dataDir(), "session.pass"))
	var err error
	o.db, err = filepath.Abs(cmp.Or(o.db, os.Getenv("AGSECRET_DB"), filepath.Join(dataDir(), "secrets.db")))
	return err
}

// Execute runs the CLI and returns its process exit code: 0 success, 1 error,
// 2 for a command line rejected before running, or a code chosen by exec.
func Execute(args []string, in io.Reader, out, errOut io.Writer) int {
	o := &options{in: in, out: out, errOut: errOut}
	root := newRoot(o)
	root.SetArgs(args)
	err := root.Execute()
	code := 1
	ex, isExit := errors.AsType[*exitError](err)
	switch {
	case err == nil:
		return 0
	case isExit:
		code, err = ex.code, ex.err
	case !o.started:
		code = 2
	}
	if err != nil {
		message := err.Error()
		if errors.Is(err, store.ErrNotFound) {
			message += "; run agsecret list to see current names and IDs"
		}
		// Fields joins cobra's multi-line suggestions into one line.
		_, _ = fmt.Fprintln(errOut, "agsecret:", safeText(strings.Join(strings.Fields(message), " ")))
	}
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

const guide = `Store passwords and TOTP secrets in an encrypted local vault, and let AI
agents use them without seeing them. Agents refer to each secret by an ID such
as ags_3f2a9c0b7d1e4f60. Run "agsecret list" to see the IDs.

Examples:
  # Call an API with a token; the token never appears in the output
  agsecret exec -- curl -H 'Authorization: Bearer ID' https://api.example.com

  # Need a shell? Pass the ID in an environment variable
  TOKEN=ID agsecret exec -- sh -c 'curl -H "Authorization: Bearer $TOKEN" URL | jq'

  # Type a password into a tmux pane that is waiting at a password prompt
  agsecret send tmux:PANE ID

  # Print the current code of a TOTP secret
  agsecret get ID

Notes for agents:
  - [REDACTED:ID] in output means the value was hidden from you. That is not
    a leak, and there is nothing to report.
  - If a secret is refused because it expired or is disabled, ask the user.
    Do not look for a way around it.
  - If you see a password in plain text anyway, run "agsecret report ID" and
    tell the user.
  - Only exact copies are hidden. Encoded values, files and writes straight to
    the terminal are not.`

func newRoot(o *options) *cobra.Command {
	r := &cobra.Command{
		Use:           "agsecret",
		Short:         "Let AI agents use secrets without seeing them",
		Long:          guide,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if o.json && cmd.Annotations["json"] == "none" {
				return fmt.Errorf("%s has no JSON output", cmd.Name())
			}
			return o.resolve()
		},
	}
	r.SetVersionTemplate("agsecret {{.Version}}\n")
	r.SetIn(o.in)
	r.SetOut(o.out)
	r.SetErr(o.errOut)
	flags := r.PersistentFlags()
	flags.StringVar(&o.db, "db", "", "path to the vault (default: $AGSECRET_DB, then ~/.local/share/agsecret/secrets.db)")
	flags.StringVar(&o.passFile, "pass-file", "", "file holding the vault passphrase (default: $AGSECRET_PASS_FILE, then session.pass next to the default vault)")
	flags.BoolVar(&o.json, "json", false, "print results as JSON")
	r.CompletionOptions.DisableDefaultCmd = true
	r.AddCommand(newInit(o), newPut(o), newList(o), newView(o), newGet(o), newExec(o), newSend(o), newReport(o), newDelete(o), newDoctor(o))
	r.AddCommand(&cobra.Command{Use: "version", Short: "Print the version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if o.json {
			return encodeJSON(cmd.OutOrStdout(), map[string]any{"version": Version, "schema_version": store.SchemaVersion})
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "agsecret", Version)
		return err
	}})
	// Cobra validates flag groups after the pre-run hooks, so only the start
	// of RunE reliably separates usage errors from runtime errors.
	for _, c := range r.Commands() {
		if run := c.RunE; run != nil {
			c.RunE = func(cmd *cobra.Command, args []string) error {
				o.started = true
				return run(cmd, args)
			}
		}
	}
	return r
}

func encodeJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}
