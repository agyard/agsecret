package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
	"github.com/spf13/cobra"
)

func newPut(o *options) *cobra.Command {
	var kind, ttlText, accessText string
	var maxUses int64
	var fromStdin bool
	var c store.Change
	cmd := &cobra.Command{
		Use:        "put NAME [VALUE]",
		SuggestFor: []string{"add", "set", "store", "insert", "update"},
		Short:      "Add or update a secret",
		Long: `Add or update a value by NAME or CREDENTIAL:FIELD.

Provide VALUE directly, use --stdin, or type at the terminal prompt.
The prompt shows the field's type: plain input is visible, while passwords
and TOTP seeds are hidden. --stdin also uses this prompt when stdin is a terminal.
Passwords and TOTP seeds passed as VALUE may remain in shell history; remove
that command from history, or prefer --stdin/the hidden prompt. With --type
totp, the value is a Base32 seed or an otpauth://totp/ URI. plain values are
directly visible and accept no access, expiry or usage protection options.

New fields default to password. Options you leave out keep their current
values, including the type of an existing field. You can narrow access or
bring the expiry closer without the value, for example with --access exec.
Widening access or extending the expiry needs the value to discourage
accidental changes to the user's limits. Changing the value or type gives it a
new ID, and the old ID stops working. --uses limits total get/exec/send
authorizations for that ID (0 means unlimited). A changed value or type resets
the counter; resubmitting the same value preserves it. Increasing the limit
requires the value, just like extending expiry.
A put always names the field; use its ID with get, view, send, exec or report.`,
		Example: `  # Store a token from an environment variable
  printf '%s' "$GITHUB_TOKEN" | agsecret put github --stdin

  # Type a TOTP seed at a hidden prompt; keep it for 30 days
  agsecret put github-otp --type totp --ttl 30d

  # Store a visible account name in a credential
  agsecret put example:username alice --type plain

  # Let agents use a secret only through exec and send
  agsecret put github --access exec`,
		// Option values are checked here, before any value is read.
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.RangeArgs(1, 2)(cmd, args); err != nil {
				return err
			}
			if store.ValidID(args[0]) {
				return errors.New("put takes a name, not an ID; changing the value creates a new ID automatically")
			}
			if err := store.ValidateName(args[0]); err != nil {
				return err
			}
			if len(args) == 2 && fromStdin {
				return errors.New("use either VALUE or --stdin, not both")
			}
			if cmd.Flags().Changed("type") {
				if kind != "password" && kind != "totp" && kind != "plain" {
					return errors.New("the type must be password, totp or plain")
				}
				c.Type = &kind
			}
			if cmd.Flags().Changed("ttl") {
				expires, err := parseTTL(ttlText)
				if err != nil {
					return err
				}
				c.ExpiresAt = &expires
			}
			if cmd.Flags().Changed("access") {
				get, exec, err := parseAccess(accessText)
				if err != nil {
					return err
				}
				c.AllowGet, c.AllowExec = &get, &exec
			}
			if cmd.Flags().Changed("uses") {
				if maxUses < 0 {
					return errors.New("--uses must be zero or greater (0 means unlimited)")
				}
				c.MaxUses = &maxUses
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				effectiveType := kind
				if c.Type == nil {
					previous, err := s.Get(args[0], false)
					if err == nil {
						effectiveType = previous.Type
						clear(previous.Secret)
					} else if !errors.Is(err, store.ErrNotFound) {
						return err
					}
				}
				if effectiveType == "plain" && (c.ExpiresAt != nil || c.AllowGet != nil || c.MaxUses != nil || cmd.Flags().Changed("dangerously-skip-check")) {
					return errors.New("plain values do not support expiry, access restrictions, usage limits or bypass options")
				}
				in := cmd.InOrStdin()
				prompt := func() ([]byte, error) {
					// Store the type shown to the user even if another put changes
					// this field while they are typing.
					c.Type = &effectiveType
					label := effectiveType + "; hidden"
					if effectiveType == "plain" {
						label = "plain; visible, not secret"
					} else if effectiveType == "totp" {
						label = "totp seed; hidden"
					}
					return promptValue(in, cmd.ErrOrStderr(), args[0]+" ["+label+"]: ", effectiveType == "plain")
				}
				var err error
				// Policy-only edits need no value unless they loosen a limit.
				switch {
				case len(args) == 2:
					c.Secret = []byte(args[1])
				case !fromStdin && c.Type == nil && (c.ExpiresAt != nil || c.AllowGet != nil || c.MaxUses != nil):
				case isTerminal(in):
					c.Secret, err = prompt()
				case fromStdin:
					c.Secret, err = readValue(in)
				default:
					return errors.New("give VALUE or --stdin, or run put in a terminal to type it")
				}
				if err != nil {
					return err
				}
				defer func() { clear(c.Secret) }()
				if len(args) == 2 && effectiveType != "plain" {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "agsecret: warning: a sensitive value was supplied on the command line; remove this command from shell history. Prefer --stdin or the hidden prompt.")
				}
				result, err := s.Put(args[0], c)
				if errors.Is(err, store.ErrNeedsValue) && isTerminal(in) {
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "This loosens the limits; enter the value to confirm."); err != nil {
						return err
					}
					if c.Secret, err = prompt(); err != nil {
						return err
					}
					result, err = s.Put(args[0], c)
				}
				if err != nil {
					return err
				}
				r := result.Record
				defer clear(r.Secret)
				if len(result.Duplicates) > 0 {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agsecret: note: the same value is also stored as %s; a leak report on one marks them all\n", strings.Join(result.Duplicates, ", "))
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(r))
				}
				switch {
				case result.Created:
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "Added %s (%s)\n", r.Name, r.ID)
				case result.PreviousID != "":
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated %s; its new ID is %s, and %s no longer works\n", r.Name, r.ID, result.PreviousID)
				default:
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated %s (%s)\n", r.Name, r.ID)
				}
				return err
			})
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the value from standard input (a trailing newline is dropped)")
	cmd.Flags().StringVarP(&kind, "type", "t", "password", "password, totp or plain (existing fields keep their type when omitted)")
	cmd.Flags().StringVar(&ttlText, "ttl", "", "time until the secret expires, such as 12h, 7d or 2w, or 0 for never")
	cmd.Flags().Int64Var(&maxUses, "uses", 0, "total get/exec/send authorizations allowed for this ID (0 means unlimited)")
	cmd.Flags().StringVar(&accessText, "access", "", "what agents may do: get,exec (the default), exec (which includes send), get or none")
	cmd.Flags().BoolVar(&c.SkipCheck, "dangerously-skip-check", false, "loosen access, expiry or usage limits without the value (for people only)")
	return addJSONFlag(cmd, o)
}

func parseTTL(v string) (*time.Time, error) {
	if v == "0" {
		return nil, nil
	}
	d, err := time.ParseDuration(v)
	// d and w scale a single number: accepting "1h2d" would read "1h2h" as 3 days.
	var hours time.Duration
	if v != "" {
		hours = map[byte]time.Duration{'d': 24, 'w': 7 * 24}[v[len(v)-1]]
	}
	if err != nil && hours != 0 {
		quantity := v[:len(v)-1]
		if _, numberErr := strconv.ParseFloat(quantity, 64); numberErr == nil {
			// ParseDuration rejects trailing characters, infinities and overflow.
			if d, err = time.ParseDuration(quantity + "h"); d <= 0 || d > time.Duration(1<<63-1)/hours {
				d = 0
			}
			d *= hours
		}
	}
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("invalid --ttl %q: use a duration such as 90m, 12h, 7d or 2w, or 0 for never", v)
	}
	t := time.Now().Add(d)
	return &t, nil
}

func parseAccess(v string) (get, exec bool, err error) {
	if v == "none" {
		return false, false, nil
	}
	for part := range strings.SplitSeq(v, ",") {
		switch part {
		case "get":
			get = true
		case "exec":
			exec = true
		default:
			return false, false, fmt.Errorf("invalid --access %q: use get,exec, exec, get or none", v)
		}
	}
	return get, exec, nil
}

func access(r store.Record) string {
	switch {
	case r.AllowGet && r.AllowExec:
		return "get,exec"
	case r.AllowGet:
		return "get"
	case r.AllowExec:
		return "exec"
	}
	return "none"
}

// useValue returns the value that action ("get", "exec" or "send") hands out,
// which is the current code for a TOTP secret. Refusals point people to the
// fix without handing agents a command to lift the limit themselves.
func useValue(r store.Record, now time.Time, action string) ([]byte, error) {
	if r.Type == "plain" {
		return bytes.Clone(r.Secret), nil
	}
	allowed := r.AllowExec
	if action == "get" {
		allowed = r.AllowGet
	}
	if r.Expired(now) {
		return nil, fmt.Errorf("%s (%s) has expired; renewing it is up to the user (see agsecret put --help)", r.Name, r.ID)
	}
	if !allowed {
		return nil, fmt.Errorf("%s is turned off for %s (%s); turning it on is up to the user (see agsecret put --help)", action, r.Name, r.ID)
	}
	if r.MaxUses > 0 && r.UsedCount >= r.MaxUses {
		return nil, fmt.Errorf("%s (%s) has no uses left; ask the user to change its limit", r.Name, r.ID)
	}
	if r.Type == "totp" {
		code, err := totp.Generate(string(r.Secret), now)
		return []byte(code), err
	}
	return bytes.Clone(r.Secret), nil
}

func newGet(o *options) *cobra.Command {
	var skipCheck bool
	c := &cobra.Command{
		Use:   "get NAME|ID",
		Short: "Print a plain value or current TOTP code",
		Long: `Print a plain value or the current code of a TOTP secret.

Passwords go to programs through exec or send. get refuses passwords by
default in every shell and output context, including terminals, pipes and
command substitutions. People who intentionally need plaintext may use
--dangerously-skip-check; its output is not filtered. Agents must not use it.
Each authorized sensitive get consumes one use, shared with exec and send.
plain values have no access, expiry or usage restrictions.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				r, err := s.Get(args[0], true)
				if err != nil {
					return err
				}
				defer clear(r.Secret)
				if r.Type == "password" && !skipCheck {
					return &exitError{code: 2, err: errors.New("get does not print passwords by default; use agsecret exec or send (people: see agsecret get --help)")}
				}
				value, err := useValue(r, time.Now(), "get")
				if err != nil {
					return err
				}
				defer clear(value)
				if err := consumeUses(s, []string{r.ID}, "get"); err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", value)
				return err
			})
		},
	}
	c.Flags().BoolVar(&skipCheck, "dangerously-skip-check", false, "print a password (for people only, never for agents)")
	return c
}

func newView(o *options) *cobra.Command {
	return addJSONFlag(&cobra.Command{
		Use:        "view NAME|ID",
		SuggestFor: []string{"show", "info", "inspect"},
		Short:      "Show details about a secret",
		Long:       "Show a field's ID, type and metadata. plain values are displayed directly;\npasswords and TOTP seeds are never shown. Use credential view NAME for a group.",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				r, err := s.Get(args[0], false)
				if err != nil {
					return err
				}
				defer clear(r.Secret)
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(r))
				}
				expires := "never"
				if r.ExpiresAt != nil {
					expires = r.ExpiresAt.Local().Format(time.DateTime)
				}
				w := newTable(cmd.OutOrStdout())
				fmt.Fprintf(w, "Name:\t%s\nID:\t%s\nType:\t%s\n", r.Name, r.ID, r.Type)
				if r.Type == "plain" {
					fmt.Fprintf(w, "Value:\t%s\n", safeText(string(r.Secret)))
				} else {
					fmt.Fprintf(w, "Status:\t%s\nAccess:\t%s\nExpires:\t%s\nUses:\t%s\n", status(r), access(r), expires, usageText(r))
				}
				for _, leak := range r.Leaks {
					fmt.Fprintf(w, "Leaked:\t%s %s\n", leak.ReportedAt.Local().Format(time.DateTime), safeText(leak.Reason))
				}
				return w.Flush()
			})
		},
	}, o)
}

func status(r store.Record) string {
	var parts []string
	if n := len(r.Leaks); n > 0 {
		parts = append(parts, fmt.Sprintf("leaked (%d)", n))
	}
	if r.Expired(time.Now()) {
		parts = append(parts, "expired")
	}
	if r.MaxUses > 0 && r.UsedCount >= r.MaxUses {
		parts = append(parts, "exhausted")
	}
	if len(parts) == 0 {
		return "active"
	}
	return strings.Join(parts, ", ")
}

func newTable(out io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(out, 0, 0, 2, ' ', 0) }

func usageText(r store.Record) string {
	if r.MaxUses == 0 {
		return fmt.Sprintf("%d/unlimited", r.UsedCount)
	}
	return fmt.Sprintf("%d/%d", r.UsedCount, r.MaxUses)
}

func newList(o *options) *cobra.Command {
	return addJSONFlag(&cobra.Command{
		Use:        "ls",
		SuggestFor: []string{"list", "lst", "lsit"},
		Short:      "List secrets and their IDs",
		Long:       "List standalone fields first, then credentials and their fields in lexical\norder. plain values are visible; sensitive values are represented by their IDs.",
		Args:       cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.withStore(func(s *store.Store) error {
				records, err := s.List(false)
				if err != nil {
					return err
				}
				defer func() {
					for _, r := range records {
						clear(r.Secret)
					}
				}()
				out := cmd.OutOrStdout()
				switch {
				case o.json:
					return encodeJSON(out, recordsJSON(records))
				case len(records) == 0:
					_, err = fmt.Fprintln(out, "No secrets yet. Add one with: agsecret put NAME")
					return err
				}
				return renderRecords(out, records)
			})
		},
	}, o)
}

func renderRecords(out io.Writer, records []store.Record) error {
	w := newTable(out)
	fmt.Fprintln(w, "NAME\tID\tTYPE\tSTATUS\tACCESS\tUSES\tVALUE")
	previousGroup := ""
	for _, r := range records {
		group, field := store.SplitName(r.Name)
		if group != previousGroup {
			fmt.Fprintf(w, "%s:\t\t\t\t\t\t\n", group)
			previousGroup = group
		}
		if group != "" {
			field = "  " + field
		}
		state, permissions, uses, value := status(r), access(r), usageText(r), ""
		if r.Type == "plain" {
			state, permissions, uses, value = "-", "-", "-", safeText(string(r.Secret))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", field, r.ID, r.Type, state, permissions, uses, value)
	}
	return w.Flush()
}

func newDelete(o *options) *cobra.Command {
	return addJSONFlag(&cobra.Command{
		Use:        "delete NAME|ID",
		Aliases:    []string{"rm"},
		SuggestFor: []string{"remove", "del"},
		Short:      "Delete a secret",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				r, err := s.Get(args[0], false)
				if err != nil {
					return err
				}
				if err := s.Delete(r.ID); err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(r))
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s (%s)\n", r.Name, r.ID)
				return err
			})
		},
	}, o)
}

func newReport(o *options) *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:   "report ID",
		Short: "Report that a password was exposed",
		Long: `Record that a password was exposed in plain text, for example printed by a
debug endpoint or written to a log. The report is added to every password with
the same value. It does not change what agents may do with the secret; the
user decides whether to replace it.

report takes the ID that was exposed, not a name. If the secret has been
replaced since then, the exposed value is gone, and there is nothing to report.`,
		Example: "  agsecret report ID --reason 'printed by a debug endpoint'",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && !store.ValidID(args[0]) {
				return fmt.Errorf("report takes the exposed ID, not a name, so a report never marks a newer value; run agsecret ls to find it")
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				records, err := s.Report(args[0], reason)
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("no secret has ID %s; if it was replaced or deleted, the exposed value is gone and needs no report", args[0])
				}
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordsJSON(records))
				}
				names := make([]string, len(records))
				for i, r := range records {
					names[i] = fmt.Sprintf("%s (%s)", r.Name, r.ID)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Reported a leak of %s\n", strings.Join(slices.Sorted(slices.Values(names)), ", "))
				return err
			})
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "how the password was exposed")
	return addJSONFlag(c, o)
}
