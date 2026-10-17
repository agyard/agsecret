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
	b, err := readPassFile(o.passFile)
	if !errors.Is(err, os.ErrNotExist) {
		return b, err
	}
	if !o.defaultPass {
		return nil, fmt.Errorf("pass file %s does not exist", o.passFile)
	}
	if !isTerminal(o.in) {
		return nil, fmt.Errorf("no pass file at %s; use --pass-file, or run in a terminal to type the passphrase", o.passFile)
	}
	return promptSecret(o.in, o.errOut, "AG-Secret passphrase: ")
}

func readPassFile(path string) ([]byte, error) {
	f, err := store.OpenPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSecretInput(f, true)
}

// readSecretInput reads at most 1 MiB, optionally without one final LF, CRLF
// or CR. The raw size is checked first so a line break exactly at the limit
// cannot hide unread trailing bytes.
func readSecretInput(in io.Reader, trimNewline bool) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, store.MaxSecretLen+1))
	if err == nil && len(b) > store.MaxSecretLen {
		err = errors.New("the value is larger than 1 MiB")
	}
	if trimNewline {
		b = bytes.TrimSuffix(b, []byte("\n"))
		b = bytes.TrimSuffix(b, []byte("\r"))
	}
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
	fd := int(in.(*os.File).Fd())
	_, _ = fmt.Fprint(errOut, label)
	b, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(errOut)
	if err == nil && len(b) == 0 {
		err = errors.New("nothing was entered")
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

func (o *options) withStore(fn func(*store.Store) error) error {
	if _, err := os.Lstat(o.db); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no vault at %s; run agsecret init", o.db)
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

// ensureDefaultPassFile creates a random pass file unless one exists. Exclusive
// creation prevents concurrent initializers from replacing another's key.
func ensureDefaultPassFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	key := make([]byte, 32)
	rand.Read(key)
	text := append(hex.AppendEncode(nil, key), '\n')
	clear(key)
	defer clear(text)
	if err := store.WritePrivateFile(path, text); !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func newInit(o *options) *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Create the vault", Args: cobra.NoArgs,
		Long: `Create an encrypted vault. Unless you pass --pass-file or set
AGSECRET_PASS_FILE, init also creates a random pass file next to the vault.
Anyone who can read that file can open the vault.

Running init again on an existing vault only checks that it opens.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			print := func(created bool) error {
				if o.json {
					data := o.vaultJSON()
					data["created"] = created
					return encodeJSON(cmd.OutOrStdout(), data)
				}
				status := "already exists"
				if created {
					status = "created"
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Vault %s: %s\nPass file: %s\n", status, safeText(o.db), safeText(o.passFile))
				return err
			}
			if _, err := os.Lstat(o.db); err == nil {
				return o.withStore(func(*store.Store) error { return print(false) })
			}
			// Never generate a replacement key for a vault that lost its database.
			if _, err := os.Lstat(o.db + ".unlock"); err == nil {
				return fmt.Errorf("found %s.unlock but no vault; move it away before running init", o.db)
			}
			if o.defaultPass {
				if err := ensureDefaultPassFile(o.passFile); err != nil {
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
			if err := s.Close(); err != nil {
				return err
			}
			return print(true)
		},
	}
}

func (o *options) vaultJSON() map[string]any {
	return map[string]any{"database": o.db, "pass_file": o.passFile, "schema_version": store.SchemaVersion}
}

func recordJSON(r store.Record) map[string]any {
	return map[string]any{
		"name": r.Name, "id": r.ID, "type": r.Type, "mask": r.Mask,
		"created_at": r.CreatedAt, "updated_at": r.UpdatedAt,
		"expires_at": r.ExpiresAt, "expired": r.Expired(nowUTC()),
		"leaks": r.Leaks, "allow_get": r.AllowGet, "allow_exec": r.AllowExec,
	}
}

func nowUTC() time.Time { return time.Now().UTC() }
