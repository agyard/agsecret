package cli

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	defaultPass bool // passFile was not chosen by the user
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

// resolve applies flags, then environment variables, then defaults. The pass
// file defaults to the vault path with a .pass extension.
func (o *options) resolve() error {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot find the default vault: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	db, err := filepath.Abs(cmp.Or(o.db, os.Getenv("AGSECRET_DB"), filepath.Join(base, "agsecret", "secrets.db")))
	if err != nil {
		return err
	}
	o.db = db
	envPass := os.Getenv("AGSECRET_PASS_FILE")
	o.defaultPass = o.passFile == "" && envPass == ""
	o.passFile = cmp.Or(o.passFile, envPass, strings.TrimSuffix(db, filepath.Ext(db))+".pass")
	return nil
}

// Execute runs the CLI and returns its exit code: 0 on success, 1 on error,
// 2 for a command line rejected before running, or a code chosen by exec.
func Execute(args []string, in io.Reader, out, errOut io.Writer) int {
	o := &options{in: in, out: out, errOut: errOut}
	root := newRoot(o)
	root.SetArgs(args)
	cmd, err := root.ExecuteC()
	code := 1
	ex, isExit := errors.AsType[*exitError](err)
	switch {
	case err == nil:
		return 0
	case isExit:
		code, err = ex.code, ex.err
	case !o.started:
		code, err = 2, usageError(cmd, args, err)
	}
	if err != nil {
		message := err.Error()
		if errors.Is(err, store.ErrNotFound) {
			message += "; run agsecret ls to see current names and IDs"
		}
		_, _ = fmt.Fprintln(errOut, "agsecret:", safeText(message))
	}
	return code
}

// usageError rewrites cobra's argument and flag errors in plain words.
func usageError(cmd *cobra.Command, args []string, err error) error {
	msg := err.Error()
	switch {
	case !cmd.HasParent() && len(args) > 0 && !strings.HasPrefix(args[0], "-"):
		// Prefer a command's own SuggestFor words over cobra's spelling matches.
		suggestions := cmd.SuggestionsFor(args[0])
		for _, c := range cmd.Commands() {
			if slices.Contains(c.SuggestFor, args[0]) {
				suggestions = []string{c.Name()}
			}
		}
		if len(suggestions) > 0 {
			return fmt.Errorf("unknown command %q; did you mean %q?", args[0], suggestions[0])
		}
		return fmt.Errorf("unknown command %q; run agsecret --help to see the commands", args[0])
	case strings.Contains(msg, "arg(s)") || strings.HasPrefix(msg, "unknown command"):
		// A stray "false" usually means --flag false; bool flags need --flag=false.
		if slices.Contains(cmd.Flags().Args(), "false") {
			return errors.New("write boolean flags as --flag=false, with no space")
		}
		return fmt.Errorf("usage: %s", cmd.UseLine())
	case strings.HasPrefix(msg, "if any flags in the group"):
		return errors.New("use only one of these flags: " + strings.Trim(strings.Fields(msg)[6], "[]"))
	}
	return err
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

const guide = `Store passwords, TOTP seeds and visible plain values in an encrypted vault.
Use CREDENTIAL:FIELD names to group an account's fields. Choose any field
names; groups exist while they contain fields. Run "agsecret ls" for IDs,
or "agsecret credential view NAME" to see one account.

Getting started:
  agsecret init                              # create the vault
  agsecret put github:username alice --type plain
  agsecret put github:password               # masked password input
  agsecret credential view github --json     # plain values and sensitive IDs

Use rename OLD NEW to change a name or move a field into/out of a credential.
Renaming preserves IDs, values, limits and leak reports. Changing a value or
type assigns a new ID. After put NAME VALUE, remove sensitive values from
shell history.

Mounted servers join the same namespace: local fields take precedence, then
remote names in lexical order. IDs address their original source. Management
changes affect the local vault; report goes to the source that owns the ID.

Examples:
  # Recommended: keep shell code fixed and pass IDs through the environment
  TOKEN=ID agsecret exec -c 'curl -H "Authorization: Bearer $TOKEN" URL | jq'

  # Pass a password as an ordinary argument, with output redaction
  agsecret exec -- agent-browser fill e1 ID

  # A TOTP ID becomes its current code
  agsecret exec -- curl "https://example.com/login?code=ID"

  # Type a password at a tmux password prompt
  agsecret send tmux:PANE ID

  # Use tmux's marked pane on another server
  AGSECRET_TMUX_SOCKET=/tmp/work.sock agsecret send 'tmux:{marked}' ID

  # Read a plain value or current TOTP code
  agsecret get github:username
  agsecret get TOTP_ID

Notes for agents:
  - [REDACTED:ID] marks a value that was successfully hidden. Report only
    exposed passwords.
  - If a secret is refused because it expired, is disabled or has no uses left,
    ask the user. put NAME --ttl 1h --uses 2 sets a lifetime and shared use cap.
    Never use options whose names start with --dangerously.
  - Use exec or send for passwords. get prints plain values and TOTP codes;
    passwords require a human override. exec substitutes IDs and filters
    its child's stdout/stderr.
  - Prefer exec -c with environment variables and quoted expansions. IDs in
    its script are refused. With exec --, bash -c, node -e and similar inputs
    can execute a substituted value. Keep values out of code and eval.
  - Passwords and TOTP share a counter per ID across get, exec and send.
    Each authorized invocation costs one use, even if the downstream command
    fails. Each distinct ID costs one use per exec. ls, view and report are free.
  - plain values are directly visible and unlimited. Use them for URLs,
    usernames or notes. Protection flags apply to password and TOTP fields.
  - TOTP codes remain visible; stored seeds are redacted.
  - If you see a password in plain text, run "agsecret report ID" and
    tell the user.
  - Redaction matches exact values; encodings, files and network traffic bypass
    it. AG-Secret reduces accidental exposure. Use a stronger isolation system
    for highly sensitive credentials.`

func newRoot(o *options) *cobra.Command {
	r := &cobra.Command{
		Use:               "agsecret",
		Short:             "Use credentials in agent workflows with less accidental exposure",
		Long:              guide,
		Version:           Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: func(*cobra.Command, []string) error { return o.resolve() },
	}
	r.SetVersionTemplate("agsecret {{.Version}}\n")
	r.SetIn(o.in)
	r.SetOut(o.out)
	r.SetErr(o.errOut)
	r.PersistentFlags().StringVar(&o.db, "db", "", "vault file (default $AGSECRET_DB or $XDG_DATA_HOME/agsecret/secrets.db)")
	r.PersistentFlags().StringVar(&o.passFile, "pass-file", "", "file with the vault passphrase (default $AGSECRET_PASS_FILE or the vault path with its extension changed to .pass)")
	r.CompletionOptions.DisableDefaultCmd = true
	r.SetHelpCommand(&cobra.Command{Use: "help [COMMAND]", Short: "Show help for a command", RunE: func(_ *cobra.Command, args []string) error {
		target, rest, err := r.Find(args)
		if err != nil || len(rest) > 0 {
			return fmt.Errorf("no help for %q; run agsecret --help to see the commands", strings.Join(args, " "))
		}
		target.InitDefaultHelpFlag()
		target.InitDefaultVersionFlag()
		return target.Help()
	}})
	r.AddCommand(newInit(o), newPut(o), newList(o), newView(o), newGet(o), newExec(o), newSend(o), newReport(o), newDelete(o), newRename(o), newCredential(o), newServe(o), newKey(o), newRemote(o))
	var markStarted func(*cobra.Command)
	markStarted = func(c *cobra.Command) {
		// Cobra validates flag groups after the pre-run hooks, so only the
		// start of RunE reliably separates usage errors from runtime errors.
		if run := c.RunE; run != nil {
			c.RunE = func(cmd *cobra.Command, args []string) error {
				o.started = true
				return run(cmd, args)
			}
		}
		for _, child := range c.Commands() {
			markStarted(child)
		}
	}
	markStarted(r)
	return r
}

// addJSONFlag gives c a --json flag; other commands have no JSON output.
func addJSONFlag(c *cobra.Command, o *options) *cobra.Command {
	c.Flags().BoolVar(&o.json, "json", false, "print JSON")
	return c
}

func encodeJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}
