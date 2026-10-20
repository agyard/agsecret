package cli

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
)

func newRename(o *options) *cobra.Command {
	return addJSONFlag(&cobra.Command{
		Use:   "rename NAME|ID NEW_NAME",
		Short: "Rename a secret or move it into or out of a credential",
		Long: `Rename a field, preserving its ID, value, limits and leak reports.
Use CREDENTIAL:FIELD to move it into a credential, or FIELD to make it
independent. The destination name must be available.`,
		Example: "  agsecret rename password account:password\n  agsecret rename account:password password",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(2)(cmd, args); err != nil {
				return err
			}
			return store.ValidateName(args[1])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				r, err := s.Rename(args[0], args[1])
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), recordJSON(r))
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renamed to %s (%s)\n", r.Name, r.ID)
				return err
			})
		},
	}, o)
}

type credentialSummary struct {
	Name   string `json:"name"`
	Fields int    `json:"fields"`
}

func credentialArgs(count int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(count)(cmd, args); err != nil {
			return err
		}
		for _, name := range args {
			if err := store.ValidateCredential(name); err != nil {
				return err
			}
		}
		return nil
	}
}

func newCredential(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:   "credential",
		Short: "Manage groups of named fields",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		Long: `A credential groups secrets named CREDENTIAL:FIELD. Field names are yours
to choose; plain fields can hold usernames, URLs or notes. A credential exists
while it has fields. Add fields with put and move them with rename.`,
	}
	c.AddCommand(addJSONFlag(&cobra.Command{
		Use:   "ls",
		Short: "List credentials and their field counts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.withStore(func(s *store.Store) error {
				records, err := s.List(false)
				if err != nil {
					return err
				}
				counts := make(map[string]int)
				for _, r := range records {
					if name, _ := store.SplitName(r.Name); name != "" {
						counts[name]++
					}
				}
				groups := make([]credentialSummary, 0, len(counts))
				for name, count := range counts {
					groups = append(groups, credentialSummary{name, count})
				}
				slices.SortFunc(groups, func(a, b credentialSummary) int { return cmp.Compare(a.Name, b.Name) })
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), groups)
				}
				if len(groups) == 0 {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), "No credentials yet. Add a field with: agsecret put CREDENTIAL:FIELD")
					return err
				}
				w := newTable(cmd.OutOrStdout())
				fmt.Fprintln(w, "NAME\tFIELDS")
				for _, group := range groups {
					fmt.Fprintf(w, "%s\t%d\n", group.Name, group.Fields)
				}
				return w.Flush()
			})
		},
	}, o), addJSONFlag(&cobra.Command{
		Use:   "view NAME",
		Short: "Show a credential's fields, including plain values",
		Long:  "Show field metadata and plain values. Passwords and TOTP seeds stay hidden.\nViewing fields preserves usage counts.",
		Args:  credentialArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				records, err := s.Credential(args[0])
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), map[string]any{"name": args[0], "fields": recordsJSON(records)})
				}
				return renderRecords(cmd.OutOrStdout(), records)
			})
		},
	}, o), addJSONFlag(&cobra.Command{
		Use:   "rename NAME NEW_NAME",
		Short: "Rename a credential and all its fields",
		Long:  "Rename all fields together, preserving their IDs, values and limits.\nThe destination credential name must be available.",
		Args:  credentialArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				records, err := s.RenameCredential(args[0], args[1])
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), map[string]any{"name": args[1], "fields": recordsJSON(records)})
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renamed credential %s to %s (%d fields)\n", args[0], args[1], len(records))
				return err
			})
		},
	}, o), addJSONFlag(&cobra.Command{
		Use:     "delete NAME",
		Aliases: []string{"rm"},
		Short:   "Delete a credential and all its fields",
		Args:    credentialArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				count, err := s.DeleteCredential(args[0])
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), map[string]any{"deleted": args[0], "fields": count})
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted credential %s (%d fields)\n", args[0], count)
				return err
			})
		},
	}, o))
	return c
}
