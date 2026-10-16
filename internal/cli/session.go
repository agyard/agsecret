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
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/thezzisu/agsecret/internal/store"
	"golang.org/x/term"
)

func (o *options) passphrase() ([]byte, error) {
	if o.passFile != "" {
		b, err := readPassFile(o.passFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pass-file %s does not exist; provide an existing pass file or unset AGSECRET_PASS_FILE", o.passFile)
		}
		return b, err
	}
	return promptPassphrase(o.in, o.errOut)
}

func secureDefaultPassPath() string { return filepath.Join(dataHome(), "agsecret", "session.pass") }

func readPassFile(path string) ([]byte, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, errors.New("secret file must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && lst.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret file must be owner-only (mode 0600 or stricter)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(lst, st) || !st.Mode().IsRegular() {
		return nil, errors.New("secret file changed while opening")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret file must be owner-only (mode 0600 or stricter)")
	}
	return readSecretInput(f)
}

// Check the raw input size before trimming a line terminator. Otherwise a
// newline exactly at LimitReader's boundary can hide unread trailing bytes.
func readSecretInput(in io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) > 1<<20 {
		clear(b)
		return nil, errors.New("secret input exceeds 1 MiB")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 || bytes.IndexByte(b, 0) >= 0 {
		clear(b)
		return nil, errors.New("secret input must be nonempty without NUL")
	}
	return b, nil
}

// readExactSecretInput preserves every byte. report --secret-stdin uses this
// variant so a stored passphrase ending in a line break cannot be confused
// with the same passphrase without that byte.
func readExactSecretInput(in io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) > 1<<20 {
		clear(b)
		return nil, errors.New("secret input exceeds 1 MiB")
	}
	if len(b) == 0 || bytes.IndexByte(b, 0) >= 0 {
		clear(b)
		return nil, errors.New("secret input must be nonempty without NUL")
	}
	return b, nil
}

func promptPassphrase(in io.Reader, errOut io.Writer) ([]byte, error) {
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, errors.New("use --pass-file or run in a terminal")
	}
	if _, err := fmt.Fprint(errOut, "AG-Secret passphrase: "); err != nil {
		return nil, err
	}
	b, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(errOut)
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("passphrase is empty")
	}
	return b, nil
}

func (o *options) absoluteDB() error {
	if o.db == "" {
		return errors.New("database path is empty")
	}
	abs, err := filepath.Abs(o.db)
	if err != nil {
		return err
	}
	o.db = abs
	return nil
}

func (o *options) withStore(create bool, fn func(*store.Store) error) error {
	if err := o.absoluteDB(); err != nil {
		return err
	}
	pass, err := o.passphrase()
	if err != nil {
		return err
	}
	defer clear(pass)
	var s *store.Store
	if _, statErr := os.Lstat(o.db); create && os.IsNotExist(statErr) {
		s, err = store.Create(o.db, pass)
	} else {
		s, err = store.Open(o.db, pass)
	}
	if err != nil {
		return err
	}
	runErr := fn(s)
	closeErr := s.Close()
	if runErr != nil {
		return runErr
	}
	return closeErr
}

// init generates a pass file only when no external pass file was selected.
// O_EXCL prevents concurrent initializers from replacing another user's key.
func ensureDefaultPassFile(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	defer clear(key[:])
	text := make([]byte, hex.EncodedLen(len(key))+1)
	hex.Encode(text, key[:])
	text[len(text)-1] = '\n'
	defer clear(text)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.Write(text)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func newInit(o *options) *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Create an encrypted vault and a private random pass file", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.absoluteDB(); err != nil {
				return err
			}
			// Do not generate a replacement key if an existing vault lost its pass file.
			for _, path := range []string{o.db, o.db + ".unlock"} {
				if _, err := os.Lstat(path); err == nil {
					return errors.New("database or unlock descriptor already exists")
				} else if !os.IsNotExist(err) {
					return err
				}
			}
			if !cmd.Flags().Changed("pass-file") && os.Getenv("AGSECRET_PASS_FILE") == "" {
				o.passFile = secureDefaultPassPath()
				if err := ensureDefaultPassFile(o.passFile); err != nil {
					return err
				}
			}
			pass, err := o.passphrase()
			if err != nil {
				return err
			}
			defer clear(pass)
			s, err := store.Create(o.db, pass)
			if err != nil {
				return err
			}
			if err := s.Close(); err != nil {
				return err
			}
			if o.json {
				return encodeJSON(cmd.OutOrStdout(), map[string]any{"database": o.db, "schema_version": store.SchemaVersion, "pass_file": o.passFile})
			}
			passLabel := o.passFile
			if passLabel == "" {
				passLabel = "(interactive; no file)"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Database: %s\nPassFile: %s\n", safeText(o.db), safeText(passLabel))
			return err
		},
	}
}

func recordJSON(r store.Record) map[string]any {
	leaks := r.Leaks
	if leaks == nil {
		leaks = []store.Leak{}
	} else {
		leaks = append([]store.Leak{}, leaks...)
		for i := range leaks {
			if leaks[i].Attachments == nil {
				leaks[i].Attachments = []string{}
			}
		}
	}
	return map[string]any{
		"name": r.Name, "id": r.ID, "type": r.Type, "mask": r.Mask,
		"created_at": r.CreatedAt, "updated_at": r.UpdatedAt,
		"expires_at": r.ExpiresAt, "expired": r.Expired(nowUTC()),
		"status": recordStatus(r), "leaks": leaks,
		"allow_get": r.AllowGet, "allow_exec": r.AllowExec,
	}
}

func nowUTC() time.Time { return time.Now().UTC() }
