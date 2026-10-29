package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
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
		Short: "Type a value into a tmux pane",
		Long: `Type a plain value, password, or current TOTP code into a tmux pane and
press Enter. PANE uses tmux target syntax, such as 0, work:1.0, %3 or {marked}.
Set AGSECRET_TMUX_SOCKET to a socket path to select another tmux server.
Otherwise tmux uses its usual environment, including TMUX and TMUX_TMPDIR.

Passwords and TOTP codes require a password prompt, such as sudo, ssh or psql.
Plain values can be typed at any prompt.

Use exec for values containing newlines or other control characters.
After the pane check passes, sending a password or TOTP code
consumes one use shared with get and exec, even if injection fails.`,
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
			return o.withSources(func(s *sources) error {
				r, err := s.get(cmd.Context(), args[1])
				if err != nil {
					return err
				}
				defer clear(r.Secret)
				if err := checkUse(r, time.Now(), "send"); err != nil {
					return err
				}
				// Local values can be checked before consuming a use. Remote
				// passwords become available only after server authorization.
				if r.Source == "local" {
					preview, err := s.local.Get(r.ID, true)
					if err != nil {
						return err
					}
					value, err := currentValue(preview, time.Now())
					clear(preview.Secret)
					if err == nil {
						err = checkSendValue(value)
					}
					clear(value)
					if err != nil {
						return err
					}
				}
				// display-message falls back to the current pane for unknown
				// targets, so check the target with send-keys first.
				if out, err := tmuxCommand("send-keys", "-t", pane).CombinedOutput(); err != nil {
					return fmt.Errorf("no tmux pane %q: %s", pane, strings.TrimSpace(string(out)))
				}
				out, err := tmuxCommand("display-message", "-p", "-t", pane, "#{pane_id}\t#{pane_tty}").Output()
				if err != nil {
					return fmt.Errorf("cannot inspect tmux pane %q: %w", pane, err)
				}
				// Keep relative and marked targets fixed between inspection and typing.
				paneID, ttyPath, ok := strings.Cut(strings.TrimSpace(string(out)), "\t")
				if !ok || !strings.HasPrefix(paneID, "%") || ttyPath == "" {
					return fmt.Errorf("cannot resolve tmux pane %q", pane)
				}
				if r.Type != "plain" {
					prompt, err := atPasswordPrompt(ttyPath)
					if err != nil {
						return err
					}
					if !prompt && !skipCheck {
						return fmt.Errorf("tmux pane %q requires a password prompt", pane)
					}
				}
				values, err := s.use(cmd.Context(), []store.Record{r}, "send")
				if err != nil {
					return err
				}
				defer clearRecords(values)
				value := values[0].Secret
				if err := checkSendValue(value); err != nil {
					return fmt.Errorf("%w; this use was consumed", err)
				}
				if r.Source != "local" && r.Type != "plain" && !skipCheck {
					prompt, err := atPasswordPrompt(ttyPath)
					if err != nil {
						return err
					}
					if !prompt {
						return fmt.Errorf("tmux pane %q requires a password prompt; this use was consumed", pane)
					}
				}
				if err := tmuxCommand("send-keys", "-t", paneID, "-l", "--", string(value)).Run(); err != nil {
					return fmt.Errorf("cannot type into tmux pane %q: %w", pane, err)
				}
				if !noEnter {
					if err := tmuxCommand("send-keys", "-t", paneID, "Enter").Run(); err != nil {
						return fmt.Errorf("cannot press Enter in tmux pane %q: %w", pane, err)
					}
				}
				return nil
			})
		},
	}
	c.Flags().BoolVar(&noEnter, "no-enter", false, "skip Enter after typing")
	c.Flags().BoolVar(&skipCheck, "dangerously-skip-check", false, "skip the password prompt check (human use only)")
	return c
}

func tmuxCommand(args ...string) *exec.Cmd {
	if socket := os.Getenv("AGSECRET_TMUX_SOCKET"); socket != "" {
		args = append([]string{"-S", socket}, args...)
	}
	return exec.Command("tmux", args...)
}

func checkSendValue(value []byte) error {
	// tmux literal mode still passes terminal control characters through.
	if bytes.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("value contains control characters; use agsecret exec")
	}
	return nil
}
