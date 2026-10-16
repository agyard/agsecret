package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/thezzisu/agsecret/internal/redact"
	"github.com/thezzisu/agsecret/internal/store"
	"github.com/thezzisu/agsecret/internal/totp"
)

func newPut(o *options) *cobra.Command {
	var kind, mask, ttlText, secretFile string
	var secretStdin bool
	var allowGet, allowExec bool
	c := &cobra.Command{
		Use: "put NAME|ID [SECRET]", Short: "Store or rotate a credential",
		Long: `Store a password or TOTP seed. Prefer --secret-stdin or --secret-file to
avoid shell history. New credentials allow get and exec by default and use the
fixed:[set] mask. Updating a credential preserves omitted options. Changing the
secret or type creates a new ID and clears leak history; policy-only updates keep
the ID and history. TTL accepts 15m,
2h, 7d, 1w or 0 (permanent). Disabled permissions stay disabled unless explicitly enabled.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return usage("put requires NAME and at most one SECRET")
			}
			if secretStdin && secretFile != "" {
				return usage("choose one of --secret-stdin and --secret-file")
			}
			if (secretStdin || secretFile != "") && len(args) == 2 {
				return usage("do not provide SECRET with --secret-stdin or --secret-file")
			}
			if !secretStdin && secretFile == "" && len(args) != 2 {
				return usage("SECRET is required unless --secret-stdin or --secret-file is used")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, err := readSecret(args, secretStdin, secretFile, cmd.InOrStdin())
			if err != nil {
				return err
			}
			defer clear(secret)
			if _, err := redact.Parse(mask); err != nil {
				return err
			}
			expires, err := parseTTL(ttlText)
			if err != nil {
				return err
			}
			return o.withStore(true, func(s *store.Store) error {
				r := store.Record{Name: args[0], Type: kind, Mask: mask, Secret: secret, ExpiresAt: expires, AllowGet: allowGet, AllowExec: allowExec}
				changed := map[string]bool{}
				for _, name := range []string{"type", "mask", "ttl", "allow-get", "allow-exec"} {
					changed[name] = cmd.Flags().Changed(name)
				}
				result, err := s.PutWithOptionsResult(r, changed)
				if err != nil {
					return err
				}
				if len(result.DuplicateIDs) > 0 {
					if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "agsecret: warning: this passphrase is also stored under %s; reporting any matching ID records a leak for all of them.\n", strings.Join(result.DuplicateIDs, ", ")); err != nil {
						return err
					}
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(result.Record))
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "stored %s (%s)\n", result.Record.Name, result.Record.ID)
				return err
			})
		},
	}
	c.Flags().StringVarP(&kind, "type", "t", "pass", "credential type: pass or totp")
	c.Flags().StringVar(&mask, "mask", redact.DefaultMask, "view mask: fixed[:TEXT], prefix:N, suffix:N, both:N,M, length or hash")
	c.Flags().StringVar(&ttlText, "ttl", "0", "validity duration (0 is permanent; supports s, m, h, d, w)")
	c.Flags().StringVar(&secretFile, "secret-file", "", "read the secret from an owner-only file")
	c.Flags().BoolVar(&secretStdin, "secret-stdin", false, "read the secret from stdin")
	c.Flags().BoolVar(&allowGet, "allow-get", true, "allow get")
	c.Flags().BoolVar(&allowExec, "allow-exec", true, "allow exec and send")
	return c
}

func readSecret(args []string, stdin bool, file string, in io.Reader) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case stdin:
		b, err = readSecretInput(in)
	case file != "":
		b, err = readPassFile(file)
	default:
		b = []byte(args[1])
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		clear(b)
		return nil, errors.New("secret is too large")
	}
	if len(b) == 0 {
		clear(b)
		return nil, errors.New("secret is empty")
	}
	for _, c := range b {
		if c == 0 {
			clear(b)
			return nil, errors.New("secret contains NUL")
		}
	}
	return b, nil
}

func parseTTL(v string) (*time.Time, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "0" || v == "permanent" || v == "never" {
		return nil, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		for _, suffix := range []struct {
			name string
			mult time.Duration
		}{{"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}} {
			if strings.HasSuffix(v, suffix.name) {
				quantity := strings.TrimSuffix(v, suffix.name)
				// d/w are scalar extensions, not a second duration parser.
				// Accepting "1h2d" here would turn "1h2h" into 3 * 24h.
				if _, numberErr := strconv.ParseFloat(quantity, 64); numberErr != nil {
					break
				}
				// ParseDuration rejects trailing characters, infinities and overflow.
				d, err = time.ParseDuration(quantity + "h")
				if err == nil {
					factor := suffix.mult / time.Hour
					if d <= 0 || d > time.Duration(1<<63-1)/factor {
						err = errors.New("ttl is too large")
					} else {
						d *= factor
					}
				}
				break
			}
		}
	}
	if err != nil || d <= 0 {
		return nil, errors.New("ttl must be 0/permanent, a positive Go duration (e.g. 1h30m), or a single number followed by d/w (e.g. 7d); use hours for mixed day/week durations")
	}
	t := nowUTC().Add(d)
	return &t, nil
}

func credentialValue(r store.Record, now time.Time) ([]byte, error) {
	if r.Type == "totp" {
		value, err := totp.Generate(string(r.Secret), now)
		return []byte(value), err
	}
	return append([]byte(nil), r.Secret...), nil
}

func newGet(o *options) *cobra.Command {
	var skipCheck bool
	c := &cobra.Command{Use: "get NAME|ID", Short: "Read a password through a safe output path, or get a current TOTP code", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if o.json {
			return usage("get cannot use --json because it would make secret transport ambiguous")
		}
		return o.withStore(false, func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[0], true)
			if err != nil {
				return err
			}
			defer clear(r.Secret)
			if r.Expired(nowUTC()) {
				return store.ErrExpired
			}
			if !r.AllowGet {
				return errors.New("get is disabled for this credential; re-store it with --allow-get")
			}
			if !skipCheck && r.Type != "totp" {
				if err := trustedTerminal(cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					return err
				}
			}
			value, err := credentialValue(r, nowUTC())
			if err != nil {
				return err
			}
			defer clear(value)
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(value))
			return err
		})
	}}
	c.Flags().BoolVar(&skipCheck, "dangerously-skip-check", false, "print a secret even when stdout is directly captured")
	return c
}

func newView(o *options) *cobra.Command {
	var showSecret bool
	c := &cobra.Command{Use: "view NAME|ID", Short: "Show credential metadata and its masked value", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withStore(false, func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[0], true)
			if err != nil {
				return err
			}
			defer clear(r.Secret)
			// A TOTP seed is an authentication factor, not a value that can be
			// safely previewed.  In particular, prefix/suffix/length/hash masks
			// still disclose useful information about the seed.  Keep the view
			// deliberately opaque for every TOTP mask, including custom masks.
			value := "[set]"
			if r.Type != "totp" {
				value, err = redact.Apply(r.Mask, r.Secret)
				if err != nil {
					return err
				}
			}
			data := recordJSON(r)
			data["value"] = value
			if showSecret {
				if r.Type == "totp" {
					code, err := credentialValue(r, nowUTC())
					if err != nil {
						return err
					}
					data["current_otp"] = string(code)
					clear(code)
				} else {
					data["secret"] = string(r.Secret)
				}
			}
			if err := maybeLecture(cmd, s, o.quiet); err != nil {
				return err
			}
			if showSecret && r.Type == "pass" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), `agsecret: warning: --dangerously-show-secret exposed plaintext; rotate if this output was captured.`)
			}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), data)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\nID: %s\nType: %s\nStatus: %s\nExpiresAt: %s\nAllowGet: %t\nAllowExec: %t\nValue: %s\n", safeText(r.Name), safeText(r.ID), safeText(r.Type), recordStatus(r), expiryText(r.ExpiresAt), r.AllowGet, r.AllowExec, safeText(value)); err != nil {
				return err
			}
			for _, leak := range r.Leaks {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "ReportedAt: %s\nReason: %s\nContext: %s\nAttachments: %s\n", leak.ReportedAt.UTC().Format(time.RFC3339Nano), safeText(leak.Reason), safeText(leak.Context), safeText(strings.Join(leak.Attachments, ", "))); err != nil {
					return err
				}
			}
			if showSecret {
				if r.Type == "totp" {
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "CurrentOTP: %s\n", data["current_otp"])
					return err
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Secret: %s\n", r.Secret); err != nil {
					return err
				}
			}
			return nil
		})
	}}
	c.Flags().BoolVar(&showSecret, "dangerously-show-secret", false, "include a password, or the current TOTP code (never the TOTP seed)")
	return c
}

func expiryText(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func recordStatus(r store.Record) string {
	status := "active"
	if len(r.Leaks) > 0 {
		status = fmt.Sprintf("leaked (%d times)", len(r.Leaks))
	}
	if r.Expired(nowUTC()) {
		if len(r.Leaks) > 0 {
			status += ",expired"
		} else {
			status = "expired"
		}
	}
	return status
}

func maybeLecture(cmd *cobra.Command, s *store.Store, quiet bool) error {
	if quiet {
		return nil
	}
	if isTerminalWriter(cmd.OutOrStdout()) {
		return nil
	}
	show, err := s.ClaimLecture(nowUTC(), 12*time.Hour)
	if err != nil {
		return err
	}
	if show {
		_, err = fmt.Fprintln(cmd.ErrOrStderr(), `agsecret: tip: run "agsecret help" for agent-safe usage patterns.`)
	}
	return err
}

func newList(o *options) *cobra.Command {
	return &cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List credential metadata and current IDs", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return o.withStore(false, func(s *store.Store) error {
			records, err := s.List()
			if err != nil {
				return err
			}
			if err := maybeLecture(cmd, s, o.quiet); err != nil {
				return err
			}
			if o.json {
				out := make([]map[string]any, 0, len(records))
				for _, r := range records {
					out = append(out, recordJSON(r))
				}
				return encodeJSON(cmd.OutOrStdout(), out)
			}
			for _, r := range records {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", r.Name, r.ID, r.Type, recordStatus(r), safeText(r.Mask)); err != nil {
					return err
				}
			}
			return nil
		})
	}}
}

func newDelete(o *options) *cobra.Command {
	return &cobra.Command{Use: "delete NAME|ID", Aliases: []string{"rm"}, Short: "Delete a credential", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withStore(false, func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[0], false)
			if err != nil {
				return err
			}
			if err := s.Delete(r.ID); err != nil {
				return err
			}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), map[string]any{"deleted": r.Name, "id": r.ID})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "deleted %s (%s)\n", r.Name, r.ID)
			return err
		})
	}}
}

func newDoctor(o *options) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check database access and reported credential leaks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return o.withStore(false, func(s *store.Store) error {
			records, err := s.List()
			if err != nil {
				return err
			}
			leaked := make([]map[string]any, 0)
			for _, r := range records {
				if len(r.Leaks) > 0 {
					leaked = append(leaked, recordJSON(r))
				}
			}
			if err := maybeLecture(cmd, s, o.quiet); err != nil {
				return err
			}
			data := map[string]any{"database": filepath.Clean(o.db), "schema_version": store.SchemaVersion, "credentials": len(records), "pass_file": o.passFile, "leaked_credentials": len(leaked), "leaked": leaked}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), data)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Database: %s\nCredentials: %d\nLeaked credentials: %d\n", safeText(o.db), len(records), len(leaked)); err != nil {
				return err
			}
			if len(leaked) > 0 {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Warning: rotate reported leaked credentials with agsecret put."); err != nil {
					return err
				}
				for _, r := range leaked {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  %s (%s): %s\n", r["name"], r["id"], r["status"]); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}}
}
