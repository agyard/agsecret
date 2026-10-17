// Package store contains the encrypted, local credential store.
//
// The SQLite pages are encrypted by ncruces' pure-Go Adiantum VFS.  A random
// database key is wrapped by an Argon2id-derived XChaCha20-Poly1305 key in a
// small sidecar file.  Keeping the random database key separate makes a
// passphrase change cheap and means that the passphrase is never put in a
// SQLite URI.
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
	SchemaVersion            = 2
	MaxSecretLen             = 1 << 20
	maxNameBytes             = 128
	maxUnlockDescriptorBytes = 4096
)

var ErrNotFound = errors.New("not found")

// Record is the metadata returned for a credential. Secret is populated only
// when a caller explicitly requests the secret and is never JSON encoded.
type Record struct {
	Name      string
	ID        string
	Type      string
	Mask      string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt *time.Time
	AllowGet  bool
	AllowExec bool
	Leaks     []Leak
	Secret    []byte `json:"-"`
}

// Leak is an append-only report for the current credential value. Rotation
// clears the reports; attachments are references and are never read by Store.
type Leak struct {
	ReportedAt  time.Time `json:"reported_at"`
	Reason      string    `json:"reason"`
	Context     string    `json:"context"`
	Attachments []string  `json:"attachments"`
}

func (r Record) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt)
}

// Store is used by one process. SQLite provides the cross-process locking
// needed when several short-lived CLI calls overlap.
type Store struct {
	DB   *sql.DB
	Path string
	key  []byte
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
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, errors.New("the vault's .unlock file is invalid")
	}
	if (u.Version != 1 && u.Version != 2) || len(u.Salt) != 16 || len(u.Nonce) != chacha20poly1305.NonceSizeX || len(u.Wrapped) != 32+chacha20poly1305.Overhead {
		return nil, errors.New("the vault's .unlock file is invalid")
	}
	var k []byte
	if u.Version == 1 {
		// Version 1 descriptors retain their original KDF parameters so an
		// upgrade never makes an existing encrypted store inaccessible.
		k = argon2.IDKey(pass, u.Salt, 3, 64*1024, 4, 32)
	} else {
		k = argon2.IDKey(pass, u.Salt, 1, 16*1024, 2, 32)
	}
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
		err = fmt.Errorf("%s must be owner-only; run chmod 600 %s", name, name)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Create creates a new encrypted store at an absolute path. The database and
// unlock sidecar are both created exclusively with owner-only permissions.
func Create(name string, pass []byte) (*Store, error) {
	if err := validatePassphrase(pass); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
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

// Open opens an existing encrypted store at an absolute path.
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

const secretsSchema = `CREATE TABLE secrets (
 name TEXT PRIMARY KEY NOT NULL,
 id TEXT NOT NULL UNIQUE,
 type TEXT NOT NULL CHECK(type IN ('pass','totp')),
 secret BLOB NOT NULL,
 mask TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at TEXT,
 allow_get INTEGER NOT NULL DEFAULT 1,
 allow_exec INTEGER NOT NULL DEFAULT 1,
 leaks TEXT NOT NULL DEFAULT '[]'
);
`

var setSchemaVersion = fmt.Sprintf("PRAGMA user_version=%d;", SchemaVersion)

// connect takes ownership of key and erases it on failure or Close.
func connect(name string, key []byte, create bool) (*Store, error) {
	db, err := openDatabase(name, key, create)
	if err != nil {
		clear(key)
		return nil, err
	}
	s := &Store{DB: db, Path: name, key: key}
	fail := func(e error) (*Store, error) { _ = s.Close(); return nil, e }
	if create {
		if _, err = db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			return fail(err)
		}
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		if _, err = tx.Exec(secretsSchema + setSchemaVersion); err != nil {
			_ = tx.Rollback()
			return fail(err)
		}
		if err = tx.Commit(); err != nil {
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
	if version == 1 {
		return migrateV1(db)
	}
	if version != SchemaVersion {
		return fmt.Errorf("the vault has schema version %d, but this agsecret supports version %d", version, SchemaVersion)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name IN ('id','secret','leaks')").Scan(&count); err != nil || count != 3 {
		return errors.New("the vault has an unexpected table layout")
	}
	return nil
}

// migrateV1 assigns stable IDs and preserves old static OTP values as pass
// credentials: a one-time code cannot be converted into a TOTP seed.
func migrateV1(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == SchemaVersion {
		return tx.Commit()
	}
	if version != 1 {
		return fmt.Errorf("the vault has unsupported schema version %d", version)
	}
	names, err := queryStrings(tx, `SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(strings.Replace(secretsSchema, "CREATE TABLE secrets (", "CREATE TABLE secrets_v2 (", 1)); err != nil {
		return err
	}
	for _, name := range names {
		if _, err = tx.Exec(`INSERT INTO secrets_v2(name,id,type,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec)
SELECT name,?,CASE type WHEN 'otp' THEN 'pass' ELSE type END,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec FROM secrets WHERE name=?`, newID(), name); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DROP TABLE secrets; ALTER TABLE secrets_v2 RENAME TO secrets;" + setSchemaVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	// Close active connections before erasing the key used by their opener.
	err := s.DB.Close()
	clear(s.key)
	s.key = nil
	return err
}

// ValidID recognizes the only credential token format.
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

// crypto/rand.Read cannot fail since Go 1.24; it aborts the program instead.
func newID() string {
	var random [8]byte
	rand.Read(random[:])
	return "ags_" + hex.EncodeToString(random[:])
}

// validateRef accepts a current ID or a credential name.
func validateRef(ref string) error {
	switch {
	case ValidID(ref):
		return nil
	case strings.HasPrefix(ref, "ags_"):
		return fmt.Errorf("%w, and names cannot start with ags_", CheckID(ref))
	case ref == "" || len(ref) > maxNameBytes:
		return errors.New("name must be 1-128 bytes")
	case strings.ContainsFunc(ref, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/@+-", r))
	}):
		return errors.New("name may contain only letters, digits, '.', '_', '/', '@', '+' and '-'")
	}
	return nil
}

// CheckID explains why text that looks like an ID is not a valid one.
func CheckID(id string) error {
	if ValidID(id) {
		return nil
	}
	return fmt.Errorf("%q is not a valid ID; IDs are ags_ followed by 16 lowercase hex digits", id)
}

func validateSecret(secret []byte) error {
	if !validSize(secret) || !utf8.Valid(secret) {
		return errors.New("the value must be 1 byte to 1 MiB of UTF-8 text without NUL bytes")
	}
	return nil
}

// Stored timestamps have whole seconds so JSON output has one fixed width.
func now() time.Time { return time.Now().UTC().Truncate(time.Second) }

func encodeTime(t time.Time) string          { return t.UTC().Format(time.RFC3339Nano) }
func decodeTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

// PutResult is a committed snapshot. Duplicate IDs contain no secret data.
type PutResult struct {
	Record       Record
	DuplicateIDs []string
}

// Put stores r under its name or current ID. Options missing from changed
// keep their previous values. A changed secret or type assigns a new ID and
// clears leak history in the same transaction, invalidating the old ID.
func (s *Store) Put(r Record, changed map[string]bool) (PutResult, error) {
	if err := validateRef(r.Name); err != nil {
		return PutResult{}, err
	}
	if err := validateSecret(r.Secret); err != nil {
		return PutResult{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return PutResult{}, err
	}
	defer tx.Rollback()
	previous, err := getRecord(tx, r.Name, true)
	defer clear(previous.Secret)
	exists := err == nil
	if err != nil && (!errors.Is(err, ErrNotFound) || ValidID(r.Name)) {
		return PutResult{}, err
	}
	if exists {
		r.Name, r.ID, r.CreatedAt = previous.Name, previous.ID, previous.CreatedAt
		if !changed["type"] {
			r.Type = previous.Type
		}
		if !changed["mask"] {
			r.Mask = previous.Mask
		}
		if !changed["ttl"] {
			r.ExpiresAt = previous.ExpiresAt
		}
		if !changed["allow-get"] {
			r.AllowGet = previous.AllowGet
		}
		if !changed["allow-exec"] {
			r.AllowExec = previous.AllowExec
		}
	}
	if r.Type == "" {
		r.Type = "pass"
	}
	if r.ExpiresAt != nil {
		expires := r.ExpiresAt.UTC().Truncate(time.Second)
		r.ExpiresAt = &expires
	}
	switch r.Type {
	case "pass":
	case "totp":
		config, err := totp.Parse(string(r.Secret))
		if err != nil {
			return PutResult{}, err
		}
		config.Clear()
	default:
		return PutResult{}, errors.New("type must be pass or totp")
	}
	r.UpdatedAt = now()
	if !exists || !bytes.Equal(previous.Secret, r.Secret) || previous.Type != r.Type {
		if r.ID, err = uniqueID(tx); err != nil {
			return PutResult{}, err
		}
		r.CreatedAt = r.UpdatedAt
		r.Leaks = []Leak{}
	} else {
		r.Leaks = previous.Leaks
	}
	if r.Mask == "" {
		r.Mask = "fixed:[set]"
	}
	var expires any
	if r.ExpiresAt != nil {
		expires = encodeTime(*r.ExpiresAt)
	}
	leaks, err := json.Marshal(r.Leaks)
	if err != nil {
		return PutResult{}, err
	}
	_, err = tx.Exec(`INSERT INTO secrets(name,id,type,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec,leaks)
 VALUES(?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(name) DO UPDATE SET id=excluded.id,type=excluded.type,secret=excluded.secret,mask=excluded.mask,created_at=excluded.created_at,updated_at=excluded.updated_at,expires_at=excluded.expires_at,
 allow_get=excluded.allow_get,allow_exec=excluded.allow_exec,leaks=excluded.leaks`,
		r.Name, r.ID, r.Type, r.Secret, r.Mask, encodeTime(r.CreatedAt), encodeTime(r.UpdatedAt), expires, r.AllowGet, r.AllowExec, string(leaks))
	if err != nil {
		return PutResult{}, err
	}
	duplicates := []string{}
	if r.Type == "pass" {
		// This query shares the write transaction. A concurrent put cannot
		// create a duplicate between checking and committing without seeing us.
		if duplicates, err = queryStrings(tx, "SELECT id FROM secrets WHERE type='pass' AND secret=? AND id<>? ORDER BY id", r.Secret, r.ID); err != nil {
			return PutResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PutResult{}, err
	}
	r.Secret = nil
	return PutResult{Record: r, DuplicateIDs: duplicates}, nil
}

func queryStrings(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{}
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

const recordColumns = `name,id,type,%s,mask,created_at,updated_at,expires_at,allow_get,allow_exec,leaks`

func selectedColumns(includeSecret bool) string {
	secretColumn := "NULL"
	if includeSecret {
		secretColumn = "secret"
	}
	return fmt.Sprintf(recordColumns, secretColumn)
}

func scanRecord(scanner interface{ Scan(...any) error }, includeSecret bool) (Record, error) {
	var r Record
	var secret []byte
	var created, updated, leaks string
	var expires sql.NullString
	if err := scanner.Scan(&r.Name, &r.ID, &r.Type, &secret, &r.Mask, &created, &updated, &expires, &r.AllowGet, &r.AllowExec, &leaks); err != nil {
		return r, err
	}
	defer clear(secret)
	var err error
	r.CreatedAt, err = decodeTime(created)
	if err != nil {
		return r, err
	}
	r.UpdatedAt, err = decodeTime(updated)
	if err != nil {
		return r, err
	}
	if expires.Valid && expires.String != "" {
		t, err := decodeTime(expires.String)
		if err != nil {
			return r, err
		}
		r.ExpiresAt = &t
	}
	// Writers always store a JSON array with non-null attachments.
	if err := json.Unmarshal([]byte(leaks), &r.Leaks); err != nil || r.Leaks == nil {
		return r, fmt.Errorf("the leak reports of %s are damaged", r.Name)
	}
	if includeSecret {
		r.Secret = append([]byte(nil), secret...)
	}
	return r, nil
}

type rowQuerier interface{ QueryRow(string, ...any) *sql.Row }

func getRecord(db rowQuerier, ref string, includeSecret bool) (Record, error) {
	column := "name"
	if ValidID(ref) {
		column = "id"
	}
	r, err := scanRecord(db.QueryRow("SELECT "+selectedColumns(includeSecret)+" FROM secrets WHERE "+column+"=?", ref), includeSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("secret %s %w", ref, ErrNotFound)
	}
	return r, err
}

// GetByNameOrID returns metadata and optionally an owned copy of its secret.
// Metadata-only reads do not select the secret column at all.
func (s *Store) GetByNameOrID(ref string, includeSecret bool) (Record, error) {
	if err := validateRef(ref); err != nil {
		return Record{}, err
	}
	return getRecord(s.DB, ref, includeSecret)
}

func (s *Store) List() ([]Record, error)            { return s.list(false) }
func (s *Store) ListWithSecrets() ([]Record, error) { return s.list(true) }

func (s *Store) list(includeSecret bool) ([]Record, error) {
	rows, err := s.DB.Query("SELECT " + selectedColumns(includeSecret) + " FROM secrets ORDER BY name")
	return scanRecords(rows, err, includeSecret)
}

// scanRecords reads and closes rows. On failure it erases secrets already read.
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
	res, err := s.DB.Exec("DELETE FROM secrets WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		err = ErrNotFound
	}
	return err
}

// ReportLeak resolves the referenced pass and reports every pass with the same
// value under one transaction. A stale ID fails without looking up a new value.
func (s *Store) ReportLeak(ref string, leak Leak) ([]Record, error) {
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	return s.reportMatches(ref, nil, leak)
}

// ReportSecret matches exact pass bytes, never TOTP seeds or generated codes.
func (s *Store) ReportSecret(secret []byte, leak Leak) ([]Record, error) {
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	return s.reportMatches("", secret, leak)
}

func (s *Store) reportMatches(ref string, secret []byte, leak Leak) ([]Record, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if ref != "" {
		r, err := getRecord(tx, ref, true)
		if err != nil {
			return nil, err
		}
		defer clear(r.Secret)
		if r.Type != "pass" {
			return nil, errors.New("only passwords can be reported, not TOTP secrets")
		}
		secret = r.Secret
	}
	rows, err := tx.Query("SELECT "+selectedColumns(false)+" FROM secrets WHERE type='pass' AND secret=? ORDER BY id", secret)
	records, err := scanRecords(rows, err, false)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no stored password has that value")
	}
	updated := now()
	if leak.ReportedAt.IsZero() {
		leak.ReportedAt = updated
	}
	leak.ReportedAt = leak.ReportedAt.UTC().Truncate(time.Second)
	if leak.Reason == "" {
		leak.Reason = "reported by agent"
	}
	leak.Attachments = append([]string{}, leak.Attachments...)
	for i := range records {
		records[i].Leaks = append(records[i].Leaks, leak)
		records[i].UpdatedAt = updated
		b, err := json.Marshal(records[i].Leaks)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec("UPDATE secrets SET leaks=?,updated_at=? WHERE id=?", string(b), encodeTime(updated), records[i].ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}
