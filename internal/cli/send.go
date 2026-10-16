package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/thezzisu/agsecret/internal/store"
)

func parseTmuxTarget(value string) (string, error) {
	if !strings.HasPrefix(value, "tmux:") {
		return "", usage("send requires a tmux target: agsecret send tmux:<pane> NAME|ID")
	}
	pane := strings.TrimPrefix(value, "tmux:")
	if pane == "" || strings.ContainsAny(pane, "\x00\r\n") {
		return "", usage("send requires a non-empty tmux target, for example tmux:0, tmux:dev:0.1 or tmux:%%1")
	}
	return pane, nil
}

func newSend(o *options) *cobra.Command {
	var enter, forceEcho bool
	c := &cobra.Command{Use: "send tmux:<target> NAME|ID", Short: "Type a credential into a tmux password prompt", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		pane, err := parseTmuxTarget(args[0])
		if err != nil {
			return err
		}
		if o.json {
			return usage("send does not produce JSON")
		}
		return o.withStore(false, func(s *store.Store) error {
			r, err := s.GetByNameOrID(args[1], true)
			if err != nil {
				return err
			}
			defer clear(r.Secret)
			if r.Expired(nowUTC()) {
				return store.ErrExpired
			}
			if !r.AllowExec {
				return errors.New("send is disabled for this credential; re-store it with --allow-exec")
			}
			// tmux's literal mode only disables key-name interpretation. The
			// terminal still processes newlines, interrupt keys and other control
			// characters, potentially submitting the prompt before sending ends.
			// Check pass values before even resolving the pane; TOTP seeds can
			// contain whitespace but only their generated digits are sent.
			if r.Type == "pass" && bytes.IndexFunc(r.Secret, unicode.IsControl) >= 0 {
				return errors.New("refused to send secret: terminal control characters are not supported; use agsecret exec instead")
			}
			output, err := exec.CommandContext(cmd.Context(), "tmux", "display-message", "-p", "-t", pane, "#{pane_tty}").Output()
			if err != nil {
				return fmt.Errorf("cannot resolve tmux pane: %w", err)
			}
			ttyPath := strings.TrimSpace(string(output))
			echo, err := targetEchoEnabled(ttyPath)
			if err != nil {
				return err
			}
			if echo && !forceEcho {
				return errors.New("refused to send secret: target pane TTY has ECHO enabled (not at a password prompt); pass --force-echo to override")
			}
			if r.Expired(nowUTC()) {
				return store.ErrExpired
			}
			value, err := credentialValue(r, nowUTC())
			if err != nil {
				return err
			}
			defer clear(value)
			if err := exec.CommandContext(cmd.Context(), "tmux", "send-keys", "-t", pane, "-l", "--", string(value)).Run(); err != nil {
				return fmt.Errorf("cannot send credential to tmux pane: %w", err)
			}
			if enter {
				if err := exec.CommandContext(cmd.Context(), "tmux", "send-keys", "-t", pane, "Enter").Run(); err != nil {
					return fmt.Errorf("cannot send Enter to tmux pane: %w", err)
				}
			}
			return nil
		})
	}}
	c.Flags().BoolVar(&enter, "enter", true, "press Enter after typing the credential")
	c.Flags().BoolVar(&forceEcho, "force-echo", false, "send even if the target terminal will echo input")
	c.Long = `Type a password or current TOTP code into the specified tmux pane.
The pane must have ECHO disabled unless --force-echo is supplied. Passwords
containing newlines or terminal control characters are rejected before contacting
tmux, including with --force-echo; use exec for those values. --enter=false skips
the final Enter key.`
	return c
}
