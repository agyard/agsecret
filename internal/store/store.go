// Package store is the encrypted vault of secrets.
//
// ncruces' pure-Go Adiantum VFS encrypts the SQLite pages with a random key.
// That key is encrypted with XChaCha20-Poly1305 under an Argon2id key derived
// from the passphrase, and stored in a small .unlock file beside the database,
// so the passphrase never appears in a SQLite URI.
package store

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agyard/agsecret/internal/totp"
	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SchemaVersion            = 1
	MaxSecretLen             = 1 << 20
	maxNameBytes             = 128
	maxUnlockDescriptorBytes = 4096
)

var (
	ErrNotFound = errors.New("not found")
	// ErrNeedsValue means a change without the value would loosen limits.
	ErrNeedsValue = errors.New("put needs the value")
)

// Record is a stored secret. Secret holds the value only when a caller asks
// for it.
type Record struct {
	Name      string
	ID        string
	Type      string // "password" or "totp"
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt *time.Time
	AllowGet  bool
	AllowExec bool
	Leaks     []Leak
	Secret    []byte
}

// Leak is a report that a password's value was exposed. Changing the value
// clears its reports.
type Leak struct {
	ReportedAt time.Time `json:"reported_at"`
	Reason     string    `json:"reason"`
}

func (r Record) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt)
}

// Store is used by one process. SQLite provides the cross-process locking
// needed when several short-lived CLI calls overlap.
type Store struct {
	db  *sql.DB
	key []byte
}

type unlockDescriptor struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Wrapped []byte `json:"wrapped"`
}

func wrapPassphrase(pass, key []byte) ([]byte, error) {
	u := unlockDescriptor{Version: 2, Salt: make([]byte, 16), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(u.Salt)
	rand.Read(u.Nonce)
	k := argon2.IDKey(pass, u.Salt, 1, 16*1024, 2, 32)
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	u.Wrapped = aead.Seal(nil, u.Nonce, key, []byte("agsecret-store-v1"))
	return json.Marshal(u)
}

func unwrapPassphrase(pass, b []byte) ([]byte, error) {
	var u unlockDescriptor
	if err := json.Unmarshal(b, &u); err != nil || u.Version != 2 || len(u.Salt) != 16 || len(u.Nonce) != chacha20poly1305.NonceSizeX || len(u.Wrapped) != 32+chacha20poly1305.Overhead {
		return nil, errors.New("the vault's .unlock file is invalid")
	}
	k := argon2.IDKey(pass, u.Salt, 1, 16*1024, 2, 32)
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, u.Nonce, u.Wrapped, []byte("agsecret-store-v1"))
	if err != nil {
		return nil, errors.New("wrong passphrase, or the vault's .unlock file is damaged")
	}
	return key, nil
}

func validSize(b []byte) bool {
	return len(b) > 0 && len(b) <= MaxSecretLen && bytes.IndexByte(b, 0) < 0
}

func validatePassphrase(pass []byte) error {
	if !validSize(pass) {
		return errors.New("the passphrase must be 1 byte to 1 MiB without NUL bytes")
	}
	return nil
}

// WritePrivateFile creates an owner-only file, failing if the path exists.
func WritePrivateFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// OpenPrivateFile opens a regular file that is not a symlink and, on Unix, is
// accessible only by its owner. The opened file must be the one inspected.
func OpenPrivateFile(name string) (*os.File, error) {
	lst, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", name)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	switch {
	case err != nil:
	case !os.SameFile(lst, st):
		err = fmt.Errorf("%s changed while opening", name)
	case runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0:
		err = fmt.Errorf("%s must be private to you; run chmod 600 %s", name, name)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Create creates a vault at an absolute path in an existing directory. The
// database and .unlock file are created exclusively and owner-only.
func Create(name string, pass []byte) (*Store, error) {
	if err := validatePassphrase(pass); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	rand.Read(key)
	descriptor, err := wrapPassphrase(pass, key)
	if err == nil {
		err = WritePrivateFile(name+".unlock", descriptor)
	}
	if err != nil {
		clear(key)
		return nil, err
	}
	// Claim the database path exclusively before SQLite opens it. A failed
	// concurrent creator must never remove another process's database.
	if err := WritePrivateFile(name, nil); err != nil {
		_ = os.Remove(name + ".unlock")
		clear(key)
		return nil, err
	}
	s, err := connect(name, key, true)
	if err != nil {
		for _, suffix := range []string{"", "-wal", "-shm", ".unlock"} {
			_ = os.Remove(name + suffix)
		}
		return nil, err
	}
	return s, nil
}

// Open opens the vault at an absolute path.
func Open(name string, pass []byte) (*Store, error) {
	if err := validatePassphrase(pass); err != nil {
		return nil, err
	}
	lst, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	unlock, err := readUnlockDescriptor(name + ".unlock")
	if err != nil {
		return nil, err
	}
	key, err := unwrapPassphrase(pass, unlock)
	if err != nil {
		return nil, err
	}
	return connect(name, key, false)
}

func readUnlockDescriptor(name string) ([]byte, error) {
	f, err := OpenPrivateFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUnlockDescriptorBytes+1))
	if err == nil && len(b) > maxUnlockDescriptorBytes {
		err = fmt.Errorf("%s exceeds the 4096-byte limit", name)
	}
	return b, err
}

func openDatabase(name string, key []byte, create bool) (*sql.DB, error) {
	mode := "rw"
	if create {
		mode = "rwc"
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(name)}
	u.RawQuery = url.Values{"vfs": {"adiantum"}, "mode": {mode}, "_txlock": {"immediate"}}.Encode()
	db, err := driver.Open(u.String(), func(c *sqlite3.Conn) error {
		return c.Exec("PRAGMA hexkey='" + hex.EncodeToString(key) + "'; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY;")
	})
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

const schema = `CREATE TABLE secrets (
 name TEXT PRIMARY KEY NOT NULL,
 id TEXT NOT NULL UNIQUE,
 type TEXT NOT NULL CHECK(type IN ('password','totp')),
 secret BLOB NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at TEXT,
 allow_get INTEGER NOT NULL,
 allow_exec INTEGER NOT NULL,
 leaks TEXT NOT NULL
);
PRAGMA user_version=1;`

// connect takes ownership of key and erases it on failure or Close.
func connect(name string, key []byte, create bool) (*Store, error) {
	db, err := openDatabase(name, key, create)
	if err != nil {
		clear(key)
		return nil, err
	}
	s := &Store{db: db, key: key}
	fail := func(e error) (*Store, error) { _ = s.Close(); return nil, e }
	if create {
		if _, err = db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			return fail(err)
		}
		if _, err = db.Exec(schema); err != nil {
			return fail(err)
		}
	} else if err = checkSchema(db); err != nil {
		return fail(err)
	}
	if err = os.Chmod(name, 0600); err != nil {
		return fail(err)
	}
	return s, nil
}

func checkSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return errors.New("cannot read the vault; it may be damaged or not an agsecret vault")
	}
	if version != SchemaVersion {
		return fmt.Errorf("the vault has format version %d, but this agsecret reads version %d", version, SchemaVersion)
	}
	return nil
}

func (s *Store) Close() error {
	// Close active connections before erasing the key used by their opener.
	err := s.db.Close()
	clear(s.key)
	s.key = nil
	return err
}

// ValidID reports whether id has the form of a secret ID.
func ValidID(id string) bool {
	if len(id) != 20 || !strings.HasPrefix(id, "ags_") {
		return false
	}
	for _, c := range id[4:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// CheckID explains why text that looks like an ID is not a valid one.
func CheckID(id string) error {
	if ValidID(id) {
		return nil
	}
	return fmt.Errorf("%q is not a valid ID; IDs are ags_ followed by 16 lowercase hex digits", id)
}

// crypto/rand.Read cannot fail since Go 1.24; it aborts the program instead.
func newID() string {
	var random [8]byte
	rand.Read(random[:])
	return "ags_" + hex.EncodeToString(random[:])
}

// validateRef accepts a current ID or a secret name.
func validateRef(ref string) error {
	switch {
	case ValidID(ref):
		return nil
	case strings.HasPrefix(strings.ToLower(ref), "ags_"):
		return fmt.Errorf("%w, and names cannot start with ags_", CheckID(ref))
	case ref == "" || len(ref) > maxNameBytes:
		return errors.New("a name must be 1 to 128 bytes long")
	case strings.ContainsFunc(ref, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/@+-", r))
	}):
		return errors.New("a name may contain only letters, digits, '.', '_', '/', '@', '+' and '-'")
	}
	return nil
}

// Stored timestamps have whole seconds so JSON output has one fixed width.
func now() time.Time { return time.Now().UTC().Truncate(time.Second) }

func encodeTime(t time.Time) string          { return t.UTC().Format(time.RFC3339) }
func decodeTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

// Change describes an update. Nil fields keep their stored values. Without
// Secret, a change may only narrow access or bring the expiry closer, unless
// SkipCheck is set: knowing the value shows the caller could already use it.
type Change struct {
	Secret    []byte
	Type      *string
	ExpiresAt **time.Time
	AllowGet  *bool
	AllowExec *bool
	SkipCheck bool
}

// PutResult describes a committed put. Record.Secret is not set.
type PutResult struct {
	Record     Record
	Created    bool
	PreviousID string   // set when the value or type changed
	Duplicates []string // names of other passwords with the same value
}

// Put stores a secret under its name or current ID. Without a value, only the
// options change. A new value or type assigns a new ID and clears the leak
// reports in the same transaction, so the old ID stops working.
func (s *Store) Put(ref string, c Change) (PutResult, error) {
	if err := validateRef(ref); err != nil {
		return PutResult{}, err
	}
	if c.Secret != nil && (!validSize(c.Secret) || !utf8.Valid(c.Secret)) {
		return PutResult{}, errors.New("the value must be 1 byte to 1 MiB of UTF-8 text without NUL bytes")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return PutResult{}, err
	}
	defer tx.Rollback()
	r, err := getRecord(tx, ref, true)
	defer clear(r.Secret)
	created := errors.Is(err, ErrNotFound) && !ValidID(ref)
	switch {
	case created && c.Secret == nil:
		return PutResult{}, fmt.Errorf("secret %s does not exist yet, so it needs a value", ref)
	case created:
		r = Record{Name: ref, Type: "password", AllowGet: true, AllowExec: true, Leaks: []Leak{}}
	case err != nil:
		return PutResult{}, err
	}
	previous := r
	if c.Secret != nil {
		r.Secret = c.Secret
	}
	if c.Type != nil {
		r.Type = *c.Type
	}
	if c.ExpiresAt != nil {
		r.ExpiresAt = *c.ExpiresAt
	}
	if c.AllowGet != nil {
		r.AllowGet = *c.AllowGet
	}
	if c.AllowExec != nil {
		r.AllowExec = *c.AllowExec
	}
	switch r.Type {
	case "password":
	case "totp":
		config, err := totp.Parse(string(r.Secret))
		if err != nil {
			return PutResult{}, err
		}
		config.Clear()
	default:
		return PutResult{}, errors.New("the type must be password or totp")
	}
	if r.ExpiresAt != nil {
		expires := r.ExpiresAt.UTC().Truncate(time.Second)
		r.ExpiresAt = &expires
	}
	if c.Secret == nil && !c.SkipCheck && loosens(previous, r) {
		return PutResult{}, fmt.Errorf("%w of %s to widen its access or extend its expiry", ErrNeedsValue, r.Name)
	}
	result := PutResult{Created: created}
	r.UpdatedAt = now()
	if created || !bytes.Equal(previous.Secret, r.Secret) || previous.Type != r.Type {
		if !created {
			result.PreviousID = previous.ID
		}
		if r.ID, err = uniqueID(tx); err != nil {
			return PutResult{}, err
		}
		r.CreatedAt, r.Leaks = r.UpdatedAt, []Leak{}
	}
	var expires any
	if r.ExpiresAt != nil {
		expires = encodeTime(*r.ExpiresAt)
	}
	leaks, err := json.Marshal(r.Leaks)
	if err != nil {
		return PutResult{}, err
	}
	_, err = tx.Exec(`INSERT INTO secrets(name,id,type,secret,created_at,updated_at,expires_at,allow_get,allow_exec,leaks)
 VALUES(?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(name) DO UPDATE SET id=excluded.id,type=excluded.type,secret=excluded.secret,created_at=excluded.created_at,
 updated_at=excluded.updated_at,expires_at=excluded.expires_at,allow_get=excluded.allow_get,allow_exec=excluded.allow_exec,leaks=excluded.leaks`,
		r.Name, r.ID, r.Type, r.Secret, encodeTime(r.CreatedAt), encodeTime(r.UpdatedAt), expires, r.AllowGet, r.AllowExec, string(leaks))
	if err != nil {
		return PutResult{}, err
	}
	if r.Type == "password" {
		// This query shares the write transaction. A concurrent put cannot
		// create a duplicate between checking and committing without seeing us.
		if result.Duplicates, err = queryStrings(tx, "SELECT name FROM secrets WHERE type='password' AND secret=? AND id<>? ORDER BY name", r.Secret, r.ID); err != nil {
			return PutResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PutResult{}, err
	}
	r.Secret = nil
	result.Record = r
	return result, nil
}

// loosens reports whether after allows more than before: more access, or a
// later expiry.
func loosens(before, after Record) bool {
	return after.AllowGet && !before.AllowGet || after.AllowExec && !before.AllowExec ||
		before.ExpiresAt != nil && (after.ExpiresAt == nil || after.ExpiresAt.After(*before.ExpiresAt))
}

func queryStrings(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func uniqueID(tx *sql.Tx) (string, error) {
	for {
		id := newID()
		var exists bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE id=?)", id).Scan(&exists); err != nil || !exists {
			return id, err
		}
	}
}

func columns(includeSecret bool) string {
	secret := "NULL"
	if includeSecret {
		secret = "secret"
	}
	return "name,id,type," + secret + ",created_at,updated_at,expires_at,allow_get,allow_exec,leaks"
}

func scanRecord(scanner interface{ Scan(...any) error }, includeSecret bool) (Record, error) {
	var r Record
	var secret []byte
	var created, updated, leaks string
	var expires sql.NullString
	if err := scanner.Scan(&r.Name, &r.ID, &r.Type, &secret, &created, &updated, &expires, &r.AllowGet, &r.AllowExec, &leaks); err != nil {
		return r, err
	}
	defer clear(secret)
	var err error
	if r.CreatedAt, err = decodeTime(created); err != nil {
		return r, err
	}
	if r.UpdatedAt, err = decodeTime(updated); err != nil {
		return r, err
	}
	if expires.Valid {
		t, err := decodeTime(expires.String)
		if err != nil {
			return r, err
		}
		r.ExpiresAt = &t
	}
	if err := json.Unmarshal([]byte(leaks), &r.Leaks); err != nil || r.Leaks == nil {
		return r, fmt.Errorf("the leak reports of %s are damaged", r.Name)
	}
	if includeSecret {
		r.Secret = bytes.Clone(secret)
	}
	return r, nil
}

type rowQuerier interface{ QueryRow(string, ...any) *sql.Row }

func getRecord(db rowQuerier, ref string, includeSecret bool) (Record, error) {
	column := "name"
	if ValidID(ref) {
		column = "id"
	}
	r, err := scanRecord(db.QueryRow("SELECT "+columns(includeSecret)+" FROM secrets WHERE "+column+"=?", ref), includeSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("secret %s %w", ref, ErrNotFound)
	}
	return r, err
}

// Get returns a secret by name or ID, with its value only if includeSecret.
func (s *Store) Get(ref string, includeSecret bool) (Record, error) {
	if err := validateRef(ref); err != nil {
		return Record{}, err
	}
	return getRecord(s.db, ref, includeSecret)
}

// List returns all secrets sorted by name, with values only if includeSecret.
func (s *Store) List(includeSecret bool) ([]Record, error) {
	rows, err := s.db.Query("SELECT " + columns(includeSecret) + " FROM secrets ORDER BY name")
	return scanRecords(rows, err, includeSecret)
}

// scanRecords reads and closes rows. On failure it erases values already read.
func scanRecords(rows *sql.Rows, err error, includeSecret bool) ([]Record, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		if r, err = scanRecord(rows, includeSecret); err != nil {
			break
		}
		out = append(out, r)
	}
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		for _, r := range out {
			clear(r.Secret)
		}
		return nil, err
	}
	return out, nil
}

func (s *Store) Delete(id string) error {
	res, err := s.db.Exec("DELETE FROM secrets WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		err = ErrNotFound
	}
	return err
}

// Report adds a leak report to the password ref and to every other password
// with the same value, in one transaction.
func (s *Store) Report(ref, reason string) ([]Record, error) {
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := getRecord(tx, ref, true)
	if err != nil {
		return nil, err
	}
	defer clear(r.Secret)
	if r.Type != "password" {
		return nil, errors.New("only passwords can be reported, not TOTP secrets")
	}
	rows, err := tx.Query("SELECT "+columns(false)+" FROM secrets WHERE type='password' AND secret=? ORDER BY name", r.Secret)
	records, err := scanRecords(rows, err, false)
	if err != nil {
		return nil, err
	}
	leak := Leak{ReportedAt: now(), Reason: reason}
	for i := range records {
		records[i].Leaks = append(records[i].Leaks, leak)
		records[i].UpdatedAt = leak.ReportedAt
		b, err := json.Marshal(records[i].Leaks)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec("UPDATE secrets SET leaks=?,updated_at=? WHERE id=?", string(b), encodeTime(leak.ReportedAt), records[i].ID); err != nil {
			return nil, err
		}
	}
	return records, tx.Commit()
}
