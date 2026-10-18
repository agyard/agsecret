package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
)

func newSend(o *options) *cobra.Command {
	var noEnter, skipCheck bool
	c := &cobra.Command{
		Use:   "send tmux:PANE NAME|ID",
		Short: "Type a secret into a tmux password prompt",
		Long: `Type a password, or the current code of a TOTP secret, into a tmux pane and
press Enter. PANE is any tmux target, such as 0, work:1.0 or %3.

The pane must be waiting at a password prompt that hides what you type, like
the ones from sudo, ssh or psql. Other panes are refused, so a secret is never
typed into a shell where it would be shown or run as a command.

Passwords that contain newlines or other control characters cannot be typed
safely; use exec for those. After the pane check passes, each send consumes one
use shared with get and exec, even if the subsequent injection fails.`,
		Example: "  agsecret send tmux:db ID\n  agsecret send tmux:%3 ID --no-enter",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(2)(cmd, args); err != nil {
				return err
			}
			if pane, ok := strings.CutPrefix(args[0], "tmux:"); !ok || pane == "" || strings.ContainsAny(pane, "\x00\r\n") {
				return errors.New("send needs a tmux pane such as tmux:0, tmux:work:1.0 or tmux:%3")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			pane := strings.TrimPrefix(args[0], "tmux:")
			return o.withStore(func(s *store.Store) error {
				r, err := s.Get(args[1], true)
				if err != nil {
					return err
				}
				defer clear(r.Secret)
				value, err := useValue(r, time.Now(), "send")
				if err != nil {
					return err
				}
				defer clear(value)
				// tmux's literal mode only disables key-name interpretation; the
				// terminal still acts on newlines and interrupt keys.
				if bytes.IndexFunc(value, unicode.IsControl) >= 0 {
					return errors.New("cannot type this password because it contains control characters that the terminal would act on; use agsecret exec instead")
				}
				// display-message falls back to the current pane for unknown
				// targets, so check the target with send-keys first.
				if out, err := exec.Command("tmux", "send-keys", "-t", pane).CombinedOutput(); err != nil {
					return fmt.Errorf("no tmux pane %q: %s", pane, strings.TrimSpace(string(out)))
				}
				out, err := exec.Command("tmux", "display-message", "-p", "-t", pane, "#{pane_tty}").Output()
				if err != nil {
					return fmt.Errorf("cannot inspect tmux pane %q: %w", pane, err)
				}
				prompt, err := atPasswordPrompt(strings.TrimSpace(string(out)))
				if err != nil {
					return err
				}
				if !prompt && !skipCheck {
					return fmt.Errorf("tmux pane %q is not waiting at a password prompt, so the secret could be shown or run as a command", pane)
				}
				if err := consumeUses(s, []string{r.ID}, "send"); err != nil {
					return err
				}
				if err := exec.Command("tmux", "send-keys", "-t", pane, "-l", "--", string(value)).Run(); err != nil {
					return fmt.Errorf("cannot type into tmux pane %q: %w", pane, err)
				}
				if !noEnter {
					if err := exec.Command("tmux", "send-keys", "-t", pane, "Enter").Run(); err != nil {
						return fmt.Errorf("cannot press Enter in tmux pane %q: %w", pane, err)
					}
				}
				return nil
			})
		},
	}
	c.Flags().BoolVar(&noEnter, "no-enter", false, "do not press Enter after typing")
	c.Flags().BoolVar(&skipCheck, "dangerously-skip-check", false, "type even if the pane is not at a password prompt (for people only, never for agents)")
	return c
}
