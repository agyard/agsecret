package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thezzisu/agsecret/internal/store"
)

func newReport(o *options) *cobra.Command {
	var secretStdin bool
	var reason, context string
	var attachments []string
	c := &cobra.Command{
		Use: "report [ID|NAME]", Short: "Record an accidental plaintext leak",
		Long: `Append a leak event to a credential's history. Prefer the current ags_ ID;
the human-readable NAME is also accepted. --secret-stdin matches an exact
stored passphrase. TOTP credentials do not support leak reports; the CLI exposes
their generated codes and never offers a seed-reveal operation.
Attachments are stored as path references. Reporting does not change access
policy; a human decides policy separately. All pass records with the same exact
value receive the report, including expired or disabled records. --json always
returns an array of affected records. Changing the secret with put clears history
and assigns a new ID; an old ID cannot report a replacement secret.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if secretStdin && len(args) != 0 {
				return usage("use either NAME|ID or --secret-stdin")
			}
			if !secretStdin && len(args) != 1 {
				return usage("report requires ID|NAME or --secret-stdin")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var secret []byte
			if secretStdin {
				var err error
				secret, err = readExactSecretInput(cmd.InOrStdin())
				if err != nil {
					return err
				}
				defer clear(secret)
			}
			return o.withStore(false, func(s *store.Store) error {
				leak := store.Leak{ReportedAt: nowUTC(), Reason: reason, Context: context, Attachments: append([]string{}, attachments...)}
				var records []store.Record
				var err error
				if secretStdin {
					records, err = s.ReportSecret(secret, leak)
				} else {
					records, err = s.ReportLeak(args[0], leak)
				}
				if err != nil {
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
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "reported leak for %s (%s) (total leaks: %d)\n", r.Name, r.ID, len(r.Leaks)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	c.Flags().BoolVar(&secretStdin, "secret-stdin", false, "match a stored passphrase from stdin")
	c.Flags().StringVar(&reason, "reason", "reported by agent", "reason for reporting the leak")
	c.Flags().StringVar(&context, "context", "", "additional context or log excerpt")
	c.Flags().StringArrayVar(&attachments, "attachment", nil, "attachment path reference (repeatable)")
	return c
}
