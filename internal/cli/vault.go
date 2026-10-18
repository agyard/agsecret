package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/agyard/agsecret/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func (o *options) passphrase() ([]byte, error) {
	f, err := store.OpenPrivateFile(o.passFile)
	if errors.Is(err, os.ErrNotExist) && o.defaultPass && isTerminal(o.in) {
		return promptSecret(o.in, o.errOut, "Vault passphrase: ")
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("pass file %s does not exist", o.passFile)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := readValue(f)
	if err != nil {
		return nil, fmt.Errorf("pass file %s: %w", o.passFile, err)
	}
	return b, nil
}

// readValue reads at most 1 MiB without one final LF, CRLF or CR. The size is
// checked before trimming, so a line break exactly at the limit cannot hide
// unread trailing bytes.
func readValue(in io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, store.MaxSecretLen+1))
	if err == nil && len(b) > store.MaxSecretLen {
		err = errors.New("the value is larger than 1 MiB")
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	if err == nil && (len(b) == 0 || bytes.IndexByte(b, 0) >= 0) {
		err = errors.New("the value is empty or contains a NUL byte")
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

// promptSecret reads a line without echo; callers check isTerminal(in).
func promptSecret(in io.Reader, errOut io.Writer, label string) ([]byte, error) {
	_, _ = fmt.Fprint(errOut, label)
	b, err := readHidden(in.(*os.File))
	_, _ = fmt.Fprintln(errOut)
	if err == io.EOF || err == nil && len(b) == 0 {
		err = errors.New("nothing was entered")
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

func (o *options) checkVault() error {
	if _, err := os.Lstat(o.db); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no vault at %s; run agsecret init, or set AGSECRET_DB if the vault is elsewhere", o.db)
	}
	return nil
}

func (o *options) withStore(fn func(*store.Store) error) error {
	if err := o.checkVault(); err != nil {
		return err
	}
	pass, err := o.passphrase()
	if err != nil {
		return err
	}
	s, err := store.Open(o.db, pass)
	clear(pass)
	if err != nil {
		return err
	}
	err = fn(s)
	if closeErr := s.Close(); err == nil {
		err = closeErr
	}
	return err
}

func newInit(o *options) *cobra.Command {
	return addJSONFlag(&cobra.Command{Use: "init", Short: "Create the vault", Args: cobra.NoArgs,
		Long: `Create an encrypted vault. Unless you choose a pass file with --pass-file or
AGSECRET_PASS_FILE, init also creates one beside the vault, holding a random
passphrase. Anyone who can read the pass file can open the vault.

Running init again on an existing vault only checks that it opens.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			created := false
			if _, err := os.Lstat(o.db); err == nil {
				if err := o.withStore(func(*store.Store) error { return nil }); err != nil {
					return err
				}
			} else if err := o.create(); err != nil {
				return err
			} else {
				created = true
			}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), map[string]any{"vault": o.db, "pass_file": o.passFile, "created": created})
			}
			status := "Vault already exists:"
			if created {
				status = "Created vault:"
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\nPass file: %s\n", status, safeText(o.db), safeText(o.passFile))
			return err
		},
	}, o)
}

func (o *options) create() error {
	// Never generate a new key for a vault whose database went missing.
	if _, err := os.Lstat(o.db + ".unlock"); err == nil {
		return fmt.Errorf("found %s.unlock but no vault; move it away before running init", o.db)
	}
	if err := os.MkdirAll(filepath.Dir(o.db), 0700); err != nil {
		return err
	}
	if o.defaultPass {
		key := make([]byte, 32)
		rand.Read(key)
		text := append(hex.AppendEncode(nil, key), '\n')
		clear(key)
		// Exclusive creation never replaces another initializer's pass file.
		err := store.WritePrivateFile(o.passFile, text)
		clear(text)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	pass, err := o.passphrase()
	if err != nil {
		return err
	}
	s, err := store.Create(o.db, pass)
	clear(pass)
	if err != nil {
		return err
	}
	return s.Close()
}

func recordJSON(r store.Record) map[string]any {
	return map[string]any{
		"name": r.Name, "id": r.ID, "type": r.Type,
		"created_at": r.CreatedAt, "updated_at": r.UpdatedAt,
		"expires_at": r.ExpiresAt, "expired": r.Expired(time.Now()),
		"access": access(r), "leaks": r.Leaks,
		"max_uses": r.MaxUses, "used_count": r.UsedCount,
	}
}

// Values were prepared from a snapshot. Recheck the current IDs and consume
// all uses atomically before handing any value to another process or output.
func consumeUses(s *store.Store, ids []string, action string) error {
	records, err := s.ConsumeMany(ids, action)
	for _, r := range records {
		clear(r.Secret)
	}
	return err
}

func recordsJSON(records []store.Record) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, recordJSON(r))
	}
	return out
}
