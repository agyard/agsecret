package cli

import (
	"errors"
	"fmt"

	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
)

func newReport(o *options) *cobra.Command {
	var secretStdin bool
	var leak store.Leak
	c := &cobra.Command{
		Use:   "report ID",
		Short: "Report that a password was exposed",
		Long: `Record that a password was exposed in plain text, for example printed by a
debug endpoint or written to a log. The report is added to every password with
the same value.

Reporting does not change what agents may do with the secret; the user decides
whether to replace it. With --secret-stdin, report finds the passwords by the
leaked value instead of by ID. TOTP secrets cannot be reported.`,
		Example: "  agsecret report ID --reason 'printed by a debug endpoint' --attachment run.log",
		Args: func(cmd *cobra.Command, args []string) error {
			if secretStdin && len(args) == 0 || !secretStdin && len(args) == 1 && store.ValidID(args[0]) {
				return nil
			}
			return errors.New("report needs a secret ID (see agsecret list) or --secret-stdin")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var secret []byte
			if secretStdin {
				var err error
				if secret, err = readSecretInput(cmd.InOrStdin(), false); err != nil {
					return err
				}
				defer clear(secret)
			}
			return o.withStore(func(s *store.Store) error {
				var records []store.Record
				var err error
				if secretStdin {
					records, err = s.ReportSecret(secret, leak)
				} else {
					records, err = s.ReportLeak(args[0], leak)
				}
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("%w (a replaced or deleted secret needs no report)", err)
				}
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordsJSON(records))
				}
				for _, r := range records {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Reported a leak of %s (%s); it now has %d leak report(s)\n", r.Name, r.ID, len(r.Leaks)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	c.Flags().BoolVar(&secretStdin, "secret-stdin", false, "find the passwords by the leaked value on standard input")
	c.Flags().StringVar(&leak.Reason, "reason", "reported by agent", "how the password was exposed")
	c.Flags().StringVar(&leak.Context, "context", "", "more detail, such as a log excerpt")
	c.Flags().StringArrayVar(&leak.Attachments, "attachment", nil, "path to a related file, recorded but not copied (repeatable)")
	return c
}
