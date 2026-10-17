package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/agyard/agsecret/internal/redact"
	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
	"github.com/spf13/cobra"
)

func newPut(o *options) *cobra.Command {
	var kind, mask, ttlText, secretFile string
	var secretStdin, allowGet, allowExec bool
	c := &cobra.Command{
		Use:   "put NAME|ID",
		Short: "Add or update a secret",
		Long: `Add a secret, or update an existing one by name or ID.

The value comes from standard input with --secret-stdin, from a file with
--secret-file, or from a hidden prompt when you run put in a terminal. Avoid
putting values on the command line, where shell history would keep them.
A TOTP secret is a Base32 seed or an otpauth://totp/ URI.

When you update a secret, options you leave out keep their current values.
Changing the value or type gives the secret a new ID and clears its leak
reports.`,
		Example: `  # Store a token from an environment variable
  printf '%s' "$GITHUB_TOKEN" | agsecret put github --secret-stdin

  # Type a TOTP seed at a hidden prompt; keep it for 30 days
  agsecret put github-otp --type totp --ttl 30d`,
		Args: func(cmd *cobra.Command, args []string) error {
			if !secretStdin && secretFile == "" && !isTerminal(cmd.InOrStdin()) {
				return errors.New("no value given; use --secret-stdin or --secret-file, or run put in a terminal to type it")
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := redact.Parse(mask); err != nil {
				return err
			}
			expires, err := parseTTL(ttlText)
			if err != nil {
				return err
			}
			var secret []byte
			switch in := cmd.InOrStdin(); {
			case secretFile != "":
				secret, err = readPassFile(secretFile)
			case secretStdin:
				secret, err = readSecretInput(in, true)
			default:
				secret, err = promptSecret(in, cmd.ErrOrStderr(), "Secret for "+args[0]+": ")
			}
			if err != nil {
				return err
			}
			defer clear(secret)
			return o.withStore(func(s *store.Store) error {
				changed := map[string]bool{}
				for _, name := range []string{"type", "mask", "ttl", "allow-get", "allow-exec"} {
					changed[name] = cmd.Flags().Changed(name)
				}
				result, err := s.Put(store.Record{Name: args[0], Type: kind, Mask: mask, Secret: secret, ExpiresAt: expires, AllowGet: allowGet, AllowExec: allowExec}, changed)
				if err != nil {
					return err
				}
				if len(result.DuplicateIDs) > 0 {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agsecret: note: the same value is also stored as %s; a leak report on one marks them all\n", strings.Join(result.DuplicateIDs, ", "))
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(result.Record))
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Stored %s (%s)\n", result.Record.Name, result.Record.ID)
				return err
			})
		},
	}
	c.Flags().StringVarP(&kind, "type", "t", "pass", "pass (a password) or totp")
	c.Flags().StringVar(&mask, "mask", redact.DefaultMask, "how view displays a password: fixed[:TEXT], prefix:N, suffix:N, both:N,M, length or hash")
	c.Flags().StringVar(&ttlText, "ttl", "0", "how long the secret stays valid, such as 12h, 7d or 2w (0 means forever)")
	c.Flags().StringVar(&secretFile, "secret-file", "", "read the value from a file that only you can read")
	c.Flags().BoolVar(&secretStdin, "secret-stdin", false, "read the value from standard input (a trailing newline is dropped)")
	c.Flags().BoolVar(&allowGet, "allow-get", true, "let get print the value")
	c.Flags().BoolVar(&allowExec, "allow-exec", true, "let exec and send use the value")
	c.MarkFlagsMutuallyExclusive("secret-stdin", "secret-file")
	return c
}

func parseTTL(v string) (*time.Time, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "0" || v == "permanent" || v == "never" {
		return nil, nil
	}
	d, err := time.ParseDuration(v)
	// d and w scale a single number: accepting "1h2d" would read "1h2h" as 3 days.
	var hours time.Duration
	switch v[len(v)-1] {
	case 'd':
		hours = 24
	case 'w':
		hours = 7 * 24
	}
	if quantity := v[:len(v)-1]; err != nil && hours != 0 {
		if _, numberErr := strconv.ParseFloat(quantity, 64); numberErr == nil {
			// ParseDuration rejects trailing characters, infinities and overflow.
			if d, err = time.ParseDuration(quantity + "h"); d <= 0 || d > time.Duration(1<<63-1)/hours {
				d = 0
			}
			d *= hours
		}
	}
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("invalid --ttl %q: use 0 for no expiry, or a duration such as 90m, 12h, 7d or 2w", v)
	}
	t := nowUTC().Add(d)
	return &t, nil
}

// useValue returns the value that action ("get", "exec" or "send") hands out,
// which is the current code for a TOTP secret. Refusals are the owner's
// policy, so their messages tell an agent the fix is not its to make.
func useValue(r store.Record, now time.Time, action string) ([]byte, error) {
	allowed := r.AllowExec
	if action == "get" {
		allowed = r.AllowGet
	}
	if r.Expired(now) {
		return nil, fmt.Errorf("%s (%s) has expired; only its owner can renew it", r.Name, r.ID)
	}
	if !allowed {
		return nil, fmt.Errorf("%s is disabled for %s (%s); only its owner can enable it", action, r.Name, r.ID)
	}
	if r.Type == "totp" {
		code, err := totp.Generate(string(r.Secret), now)
		return []byte(code), err
	}
	return bytes.Clone(r.Secret), nil
}

func newGet(o *options) *cobra.Command {
	var skipCheck bool
	c := &cobra.Command{Use: "get NAME|ID", Short: "Print a TOTP code, or a password in a terminal",
		Long: `Print the current code of a TOTP secret, or the value of a password.

Passwords are printed only to a terminal. When the output is captured or
piped, get refuses; use exec or send to hand a password to a program.`,
		Annotations: noJSON, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				r, err := s.GetByNameOrID(args[0], true)
				if err != nil {
					return err
				}
				defer clear(r.Secret)
				value, err := useValue(r, nowUTC(), "get")
				if err != nil {
					return err
				}
				defer clear(value)
				if r.Type == "pass" && !skipCheck && !isTerminal(cmd.OutOrStdout()) {
					return fmt.Errorf("not printing password %s (%s) because the output is not a terminal; use agsecret exec or send to pass it to a program", r.Name, r.ID)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", value)
				return err
			})
		}}
	c.Flags().BoolVar(&skipCheck, "dangerously-skip-check", false, "print a password even when the output is not a terminal")
	return c
}

func newView(o *options) *cobra.Command {
	return &cobra.Command{Use: "view NAME|ID", Short: "Show details about a secret", Long: "Show a secret's ID, type, status, access, expiry, masked value and leak\nreports. The value itself is never shown.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withStore(func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[0], true)
			if err != nil {
				return err
			}
			defer clear(r.Secret)
			// Every mask except fixed reveals something about a TOTP seed.
			value := "[set]"
			if r.Type == "pass" {
				if value, err = redact.Apply(r.Mask, r.Secret); err != nil {
					return err
				}
			}
			if o.json {
				data := recordJSON(r)
				data["value"] = value
				return encodeJSON(cmd.OutOrStdout(), data)
			}
			w := newTable(cmd.OutOrStdout())
			fmt.Fprintf(w, "Name:\t%s\nID:\t%s\nType:\t%s\nStatus:\t%s\nAccess:\t%s\nExpires:\t%s\nValue:\t%s\n",
				r.Name, r.ID, r.Type, recordStatus(r), access(r), expiryText(r.ExpiresAt), safeText(value))
			for _, leak := range r.Leaks {
				line := leak.ReportedAt.Format(time.RFC3339) + " " + leak.Reason
				if leak.Context != "" {
					line += "; context: " + leak.Context
				}
				if len(leak.Attachments) > 0 {
					line += "; attachments: " + strings.Join(leak.Attachments, ", ")
				}
				fmt.Fprintf(w, "Leak:\t%s\n", safeText(line))
			}
			return w.Flush()
		})
	}}
}

func expiryText(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}

func recordStatus(r store.Record) string {
	var parts []string
	if n := len(r.Leaks); n > 0 {
		parts = append(parts, fmt.Sprintf("leaked (%d)", n))
	}
	if r.Expired(nowUTC()) {
		parts = append(parts, "expired")
	}
	if len(parts) == 0 {
		return "active"
	}
	return strings.Join(parts, ", ")
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

func newTable(out io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(out, 0, 0, 2, ' ', 0) }

func printRecords(out io.Writer, records []store.Record) error {
	w := newTable(out)
	fmt.Fprintln(w, "NAME\tID\tTYPE\tSTATUS\tACCESS")
	for _, r := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.ID, r.Type, recordStatus(r), access(r))
	}
	return w.Flush()
}

func recordsJSON(records []store.Record) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, recordJSON(r))
	}
	return out
}

func newList(o *options) *cobra.Command {
	return &cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List secrets and their IDs", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return o.withStore(func(s *store.Store) error {
			records, err := s.List()
			if err != nil {
				return err
			}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), recordsJSON(records))
			}
			return printRecords(cmd.OutOrStdout(), records)
		})
	}}
}

func newDelete(o *options) *cobra.Command {
	return &cobra.Command{Use: "delete NAME|ID", Aliases: []string{"rm"}, Short: "Delete a secret", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withStore(func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[0], false)
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
	}}
}

func newDoctor(o *options) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check the vault and list leaked secrets", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return o.withStore(func(s *store.Store) error {
			records, err := s.List()
			if err != nil {
				return err
			}
			var leaked []store.Record
			for _, r := range records {
				if len(r.Leaks) > 0 {
					leaked = append(leaked, r)
				}
			}
			if o.json {
				data := o.vaultJSON()
				data["credentials"], data["leaked"] = len(records), recordsJSON(leaked)
				return encodeJSON(cmd.OutOrStdout(), data)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Vault: %s\nPass file: %s\nSecrets: %d\nLeaked: %d\n", safeText(o.db), safeText(o.passFile), len(records), len(leaked))
			if len(leaked) == 0 {
				return nil
			}
			fmt.Fprintln(out, "\nReplace these leaked secrets with agsecret put:")
			return printRecords(out, leaked)
		})
	}}
}
