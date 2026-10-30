package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agyard/agsecret/internal/remote"
	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
)

func newServe(o *options) *cobra.Command {
	var listen, certFile, keyFile string
	c := &cobra.Command{
		Use:   "serve",
		Short: "Serve the local vault through API keys",
		Long:  "Serve local fields for viewing, use and leak reports. API key rules control access.\nUse HTTPS or an encrypted private network to protect API keys and values in transit.",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return err
			}
			if (certFile == "") != (keyFile == "") {
				return errors.New("use --tls-cert and --tls-key together")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.withStore(func(s *store.Store) error {
				var config *tls.Config
				scheme := "http"
				if certFile != "" {
					cert, err := tls.LoadX509KeyPair(certFile, keyFile)
					if err != nil {
						return err
					}
					config = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
					scheme = "https"
				}
				listener, err := net.Listen("tcp", listen)
				if err != nil {
					return err
				}
				defer listener.Close()
				server := &http.Server{
					Handler:           remote.NewHandler(s),
					TLSConfig:         config,
					ReadHeaderTimeout: 5 * time.Second,
					ReadTimeout:       15 * time.Second,
					WriteTimeout:      30 * time.Second,
					IdleTimeout:       60 * time.Second,
					MaxHeaderBytes:    16 << 10,
				}
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Serving %s://%s\n", scheme, listener.Addr()); err != nil {
					return err
				}
				done := make(chan error, 1)
				go func() {
					if config != nil {
						done <- server.ServeTLS(listener, "", "")
					} else {
						done <- server.Serve(listener)
					}
				}()
				select {
				case err := <-done:
					return err
				case <-ctx.Done():
					shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					err := server.Shutdown(shutdown)
					if err != nil {
						_ = server.Close()
					}
					<-done
					return err
				}
			})
		},
	}
	c.Flags().StringVar(&listen, "listen", "127.0.0.1:8765", "listen address")
	c.Flags().StringVar(&certFile, "tls-cert", "", "TLS certificate file")
	c.Flags().StringVar(&keyFile, "tls-key", "", "TLS private key file")
	return c
}

func newKey(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Manage server API keys",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var rules []string
	create := &cobra.Command{
		Use:   "create NAME --rule PATTERN [--rule PATTERN...]",
		Short: "Create an API key and print it once",
		Long: `Rules match complete field names with *, ? and []. Wildcards also match : and /.
A leading ! excludes.
The last matching rule wins; access starts denied. Rules apply dynamically.
Store the printed key for remote add.`,
		Example: "  agsecret key create laptop --rule 'pku_*:*' --rule '!pku_*:otp'",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			if err := store.ValidateAPIKeyName(args[0]); err != nil {
				return err
			}
			return store.ValidateRules(rules)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				key, err := s.CreateAPIKey(args[0], rules)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), key)
				return err
			})
		},
	}
	create.Flags().StringArrayVar(&rules, "rule", nil, "ordered field pattern; prefix ! to exclude (repeatable)")
	c.AddCommand(create, addJSONFlag(&cobra.Command{
		Use:   "ls",
		Short: "List API key names and rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.withStore(func(s *store.Store) error {
				keys, err := s.APIKeys()
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), keys)
				}
				w := newTable(cmd.OutOrStdout())
				fmt.Fprintln(w, "NAME\tRULES")
				for _, key := range keys {
					fmt.Fprintf(w, "%s\t%s\n", safeText(key.Name), safeText(strings.Join(key.Rules, ", ")))
				}
				return w.Flush()
			})
		},
	}, o), &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				if err := s.DeleteAPIKey(args[0]); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("API key %s does not exist; run agsecret key ls", args[0])
					}
					return err
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Deleted API key %s\n", safeText(args[0]))
				return err
			})
		},
	})
	return c
}

func newRemote(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:   "remote",
		Short: "Manage remote vault mounts",
		Long:  "Remote names determine lookup order after the local vault, in alphabetical order.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var keyStdin bool
	add := &cobra.Command{
		Use:   "add NAME URL",
		Short: "Mount a remote vault",
		Long:  "Read the API key from a masked terminal prompt or --key-stdin.\nUse HTTPS or HTTP over an encrypted private network.",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(2)(cmd, args); err != nil {
				return err
			}
			if err := store.ValidateRemoteName(args[0]); err != nil {
				return err
			}
			return remote.ValidateURL(args[1])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				var key []byte
				var err error
				switch {
				case keyStdin:
					key, err = readValue(cmd.InOrStdin())
				case isTerminal(cmd.InOrStdin()):
					key, err = promptValue(cmd.InOrStdin(), cmd.ErrOrStderr(), "API key: ", false)
				default:
					return errors.New("use --key-stdin or run remote add in a terminal")
				}
				if err != nil {
					return err
				}
				defer clear(key)
				if !store.ValidAPIKey(string(key)) {
					return errors.New("invalid API key")
				}
				if err := s.AddRemote(args[0], args[1], string(key)); err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Mounted %s\n", safeText(args[0]))
				return err
			})
		},
	}
	add.Flags().BoolVar(&keyStdin, "key-stdin", false, "read the API key from standard input")
	c.AddCommand(add, addJSONFlag(&cobra.Command{
		Use:   "ls",
		Short: "List remote names and URLs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.withStore(func(s *store.Store) error {
				mounts, err := s.Remotes()
				if err != nil {
					return err
				}
				if o.json {
					return encodeJSON(cmd.OutOrStdout(), mounts)
				}
				w := newTable(cmd.OutOrStdout())
				fmt.Fprintln(w, "NAME\tURL")
				for _, mount := range mounts {
					fmt.Fprintf(w, "%s\t%s\n", safeText(mount.Name), safeText(mount.URL))
				}
				return w.Flush()
			})
		},
	}, o), &cobra.Command{
		Use:   "delete NAME",
		Short: "Unmount a remote vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.withStore(func(s *store.Store) error {
				if err := s.DeleteRemote(args[0]); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("remote %s does not exist; run agsecret remote ls", args[0])
					}
					return err
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Unmounted %s\n", safeText(args[0]))
				return err
			})
		},
	})
	return c
}
