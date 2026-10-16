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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum"
	"github.com/thezzisu/agsecret/internal/totp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SchemaVersion            = 2
	maxNameBytes             = 128
	maxSecretLen             = 1 << 20
	maxUnlockDescriptorBytes = 4096
)

var (
	ErrNotFound = errors.New("secret not found")
	ErrExpired  = errors.New("secret has expired")
)

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

// Store is safe for one process using its database. SQLite provides the
// cross-process locking needed when several short-lived CLI calls overlap.
type Store struct {
	DB   *sql.DB
	Path string
	key  []byte
	mu   sync.Mutex
}

type unlockDescriptor struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Wrapped []byte `json:"wrapped"`
}

func wrapPassphrase(pass, key []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	u := unlockDescriptor{Version: 2, Salt: make([]byte, 16), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	if _, err := rand.Read(u.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(u.Nonce); err != nil {
		return nil, err
	}
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
		return nil, errors.New("invalid unlock descriptor")
	}
	if (u.Version != 1 && u.Version != 2) || len(u.Salt) != 16 || len(u.Nonce) != chacha20poly1305.NonceSizeX || len(u.Wrapped) != 32+chacha20poly1305.Overhead {
		return nil, errors.New("invalid unlock descriptor")
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
		return nil, errors.New("wrong passphrase or damaged unlock descriptor")
	}
	return key, nil
}

func validatePassphrase(pass []byte) error {
	if len(pass) == 0 {
		return errors.New("passphrase is empty")
	}
	if len(pass) > 1<<20 {
		return errors.New("passphrase is too long")
	}
	if bytesContainsNUL(pass) {
		return errors.New("passphrase contains NUL")
	}
	return nil
}

func bytesContainsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func ensureParent(name string) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return nil
}

// Create creates a new encrypted store. The database and unlock sidecar are
// both created with owner-only permissions.
func Create(name string, pass []byte) (*Store, error) {
	var err error
	if err := validatePassphrase(pass); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("database path is empty")
	}
	if !filepath.IsAbs(name) {
		name, err = filepath.Abs(name)
		if err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(name); err == nil {
		return nil, errors.New("database already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Lstat(name + ".unlock"); err == nil {
		return nil, errors.New("unlock descriptor already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := ensureParent(name); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	descriptor, err := wrapPassphrase(pass, key)
	if err != nil {
		clear(key)
		return nil, err
	}
	unlockPath := name + ".unlock"
	f, err := os.OpenFile(unlockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		clear(key)
		return nil, err
	}
	if _, err = f.Write(descriptor); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(unlockPath)
		clear(key)
		return nil, err
	}
	// Claim the database path exclusively before SQLite opens it. A failed
	// concurrent creator must never remove another process's database.
	databaseFile, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = os.Remove(unlockPath)
		clear(key)
		return nil, err
	}
	if err := databaseFile.Close(); err != nil {
		_ = os.Remove(name)
		_ = os.Remove(unlockPath)
		clear(key)
		return nil, err
	}
	s, err := connect(name, key, true)
	if err != nil {
		_ = os.Remove(name)
		_ = os.Remove(name + "-wal")
		_ = os.Remove(name + "-shm")
		_ = os.Remove(unlockPath)
		clear(key)
		return nil, err
	}
	return s, nil
}

// Open opens an existing encrypted store.
func Open(name string, pass []byte) (*Store, error) {
	var err error
	if err := validatePassphrase(pass); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("database path is empty")
	}
	if !filepath.IsAbs(name) {
		name, err = filepath.Abs(name)
		if err != nil {
			return nil, err
		}
	}
	lst, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() || lst.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("database path must be a regular file")
	}
	unlock, err := readUnlockDescriptor(name + ".unlock")
	if err != nil {
		return nil, err
	}
	key, err := unwrapPassphrase(pass, unlock)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(name); err != nil {
		clear(key)
		return nil, err
	}
	s, err := connect(name, key, false)
	if err != nil {
		clear(key)
		return nil, err
	}
	return s, nil
}

func readUnlockDescriptor(name string) ([]byte, error) {
	lst, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() || lst.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unlock descriptor must be a regular file")
	}
	if runtime.GOOS != "windows" && lst.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("unlock descriptor %s must be owner-only", name)
	}
	if lst.Size() > maxUnlockDescriptorBytes {
		return nil, errors.New("unlock descriptor exceeds 4096-byte limit")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(lst, opened) {
		return nil, errors.New("unlock descriptor changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxUnlockDescriptorBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxUnlockDescriptorBytes {
		return nil, errors.New("unlock descriptor exceeds 4096-byte limit")
	}
	return b, nil
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
);`

const auxiliarySchema = `
CREATE INDEX IF NOT EXISTS secrets_expires ON secrets(expires_at);
CREATE TABLE IF NOT EXISTS meta_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
PRAGMA user_version=2;
`

func connect(name string, key []byte, create bool) (*Store, error) {
	db, err := openDatabase(name, key, create)
	if err != nil {
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
		if _, err = tx.Exec(secretsSchema + auxiliarySchema); err != nil {
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
		return errors.New("cannot unlock encrypted database")
	}
	if version == 1 {
		return migrateV1(db)
	}
	if version != SchemaVersion {
		return fmt.Errorf("unsupported database schema version %d; expected %d", version, SchemaVersion)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name IN ('id','secret','leaks')").Scan(&count); err != nil || count != 3 {
		return errors.New("unsupported database layout")
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
		return fmt.Errorf("unsupported database schema version %d", version)
	}
	rows, err := tx.Query(`SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		names = append(names, name)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if _, err = tx.Exec(strings.Replace(secretsSchema, "CREATE TABLE secrets (", "CREATE TABLE secrets_v2 (", 1)); err != nil {
		return err
	}
	for _, name := range names {
		id, err := newID()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO secrets_v2(name,id,type,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec)
SELECT name,?,CASE type WHEN 'otp' THEN 'pass' ELSE type END,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec FROM secrets WHERE name=?`, id, name); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DROP TABLE secrets; ALTER TABLE secrets_v2 RENAME TO secrets;" + auxiliarySchema); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Close active connections before erasing the key used by their opener.
	err := s.DB.Close()
	if s.key != nil {
		clear(s.key)
		s.key = nil
	}
	return err
}

func validateName(name string) error {
	if name == "" || len(name) > maxNameBytes || !utf8.ValidString(name) {
		return errors.New("name must be valid UTF-8 and 1-128 bytes")
	}
	if strings.HasPrefix(name, "ags_") {
		return errors.New("names beginning with ags_ are reserved for credential IDs")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._/@+-", r) {
			continue
		}
		return errors.New("name may contain only letters, digits, '.', '_', '/', '@', '+' and '-'")
	}
	return nil
}

func ValidateNameForCLI(name string) error { return validateName(name) }

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

func newID() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "ags_" + hex.EncodeToString(random[:]), nil
}

func validateRef(ref string) error {
	if ValidID(ref) {
		return nil
	}
	return validateName(ref)
}

func validateSecret(secret []byte) error {
	if len(secret) == 0 {
		return errors.New("secret is empty")
	}
	if len(secret) > maxSecretLen {
		return fmt.Errorf("secret is too long (maximum %d bytes)", maxSecretLen)
	}
	if bytesContainsNUL(secret) || !utf8.Valid(secret) {
		return errors.New("secret must be UTF-8 without NUL")
	}
	return nil
}

func validateType(kind string) error {
	if kind != "pass" && kind != "totp" {
		return errors.New("type must be pass or totp")
	}
	return nil
}

func encodeTime(t time.Time) string          { return t.UTC().Format(time.RFC3339Nano) }
func decodeTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

// PutResult is a committed snapshot. Duplicate IDs contain no secret data.
type PutResult struct {
	Record       Record
	DuplicateIDs []string
}

// Put replaces the value and all supplied policies.
func (s *Store) Put(r Record) error { return s.put(r, nil, nil) }

// PutWithOptions preserves policies omitted by the caller. Passing an existing
// ID is allowed; a changed value invalidates that ID in the same transaction.
func (s *Store) PutWithOptions(r Record, changed map[string]bool) error {
	if changed == nil {
		changed = map[string]bool{}
	}
	return s.put(r, changed, nil)
}

func (s *Store) PutWithOptionsResult(r Record, changed map[string]bool) (PutResult, error) {
	if changed == nil {
		changed = map[string]bool{}
	}
	var result PutResult
	err := s.put(r, changed, &result)
	return result, err
}

func uniqueID(tx *sql.Tx) (string, error) {
	for {
		id, err := newID()
		if err != nil {
			return "", err
		}
		var count int
		if err := tx.QueryRow("SELECT COUNT(*) FROM secrets WHERE id=?", id).Scan(&count); err != nil {
			return "", err
		}
		if count == 0 {
			return id, nil
		}
	}
}

func (s *Store) put(r Record, changed map[string]bool, result *PutResult) error {
	if err := validateRef(r.Name); err != nil {
		return err
	}
	if err := validateSecret(r.Secret); err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	previous, err := getRecord(tx, r.Name, true)
	defer clear(previous.Secret)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if exists {
		r.Name, r.ID, r.CreatedAt = previous.Name, previous.ID, previous.CreatedAt
		if changed != nil {
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
	} else {
		if ValidID(r.Name) {
			return ErrNotFound
		}
		if err := validateName(r.Name); err != nil {
			return err
		}
	}
	if r.Type == "" {
		r.Type = "pass"
	}
	if err := validateType(r.Type); err != nil {
		return err
	}
	if r.Type == "totp" {
		config, err := totp.Parse(string(r.Secret))
		if err != nil {
			return err
		}
		config.Clear()
	}
	rotated := !exists || !bytes.Equal(previous.Secret, r.Secret) || previous.Type != r.Type
	if rotated {
		r.ID, err = uniqueID(tx)
		if err != nil {
			return err
		}
		r.CreatedAt = time.Now().UTC()
		r.Leaks = []Leak{}
	} else {
		r.Leaks = previous.Leaks
	}
	if r.Mask == "" {
		r.Mask = "fixed:[set]"
	}
	r.UpdatedAt = time.Now().UTC()
	var expires any
	if r.ExpiresAt != nil {
		expires = encodeTime(*r.ExpiresAt)
	}
	leaks, err := json.Marshal(r.Leaks)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO secrets(name,id,type,secret,mask,created_at,updated_at,expires_at,allow_get,allow_exec,leaks)
 VALUES(?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(name) DO UPDATE SET id=excluded.id,type=excluded.type,secret=excluded.secret,mask=excluded.mask,created_at=excluded.created_at,updated_at=excluded.updated_at,expires_at=excluded.expires_at,
 allow_get=excluded.allow_get,allow_exec=excluded.allow_exec,leaks=excluded.leaks`,
		r.Name, r.ID, r.Type, r.Secret, r.Mask, encodeTime(r.CreatedAt), encodeTime(r.UpdatedAt), expires, boolInt(r.AllowGet), boolInt(r.AllowExec), string(leaks))
	if err != nil {
		return err
	}
	duplicates := []string{}
	if r.Type == "pass" {
		// This query shares the write transaction. A concurrent put cannot
		// create a duplicate between checking and committing without seeing us.
		rows, err := tx.Query("SELECT id FROM secrets WHERE type='pass' AND secret=? AND id<>? ORDER BY id", r.Secret, r.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			duplicates = append(duplicates, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if result != nil {
		r.Secret = nil
		*result = PutResult{Record: r, DuplicateIDs: duplicates}
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
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
	var get, exec int
	if err := scanner.Scan(&r.Name, &r.ID, &r.Type, &secret, &r.Mask, &created, &updated, &expires, &get, &exec, &leaks); err != nil {
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
	if err := json.Unmarshal([]byte(leaks), &r.Leaks); err != nil {
		return r, errors.New("invalid credential leak history")
	}
	if r.Leaks == nil {
		r.Leaks = []Leak{}
	} else {
		for i := range r.Leaks {
			if r.Leaks[i].Attachments == nil {
				r.Leaks[i].Attachments = []string{}
			}
		}
	}
	r.AllowGet, r.AllowExec = get != 0, exec != 0
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
		return Record{}, ErrNotFound
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

func (s *Store) Get(ref string, includeSecret bool) (Record, error) {
	return s.GetByNameOrID(ref, includeSecret)
}

func (s *Store) List() ([]Record, error)            { return s.list(false) }
func (s *Store) ListWithSecrets() ([]Record, error) { return s.list(true) }

func (s *Store) list(includeSecret bool) ([]Record, error) {
	rows, err := s.DB.Query("SELECT " + selectedColumns(includeSecret) + " FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	clearOut := func() {
		for _, r := range out {
			clear(r.Secret)
		}
	}
	for rows.Next() {
		r, err := scanRecord(rows, includeSecret)
		if err != nil {
			clearOut()
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		clearOut()
		return nil, err
	}
	return out, nil
}

func (s *Store) Delete(ref string) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	column := "name"
	if ValidID(ref) {
		column = "id"
	}
	res, err := s.DB.Exec("DELETE FROM secrets WHERE "+column+"=?", ref)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

func normalizeLeak(leak Leak) Leak {
	if leak.ReportedAt.IsZero() {
		leak.ReportedAt = time.Now().UTC()
	} else {
		leak.ReportedAt = leak.ReportedAt.UTC()
	}
	if leak.Reason == "" {
		leak.Reason = "reported by agent"
	}
	if leak.Attachments == nil {
		leak.Attachments = []string{}
	} else {
		leak.Attachments = append([]string{}, leak.Attachments...)
	}
	return leak
}

func appendLeak(tx *sql.Tx, r Record, leak Leak) (Record, error) {
	r.Leaks = append(r.Leaks, leak)
	b, err := json.Marshal(r.Leaks)
	if err != nil {
		return Record{}, err
	}
	r.UpdatedAt = time.Now().UTC()
	_, err = tx.Exec("UPDATE secrets SET leaks=?,updated_at=? WHERE id=?", string(b), encodeTime(r.UpdatedAt), r.ID)
	return r, err
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
			return nil, errors.New("TOTP credentials do not support leak reports")
		}
		secret = r.Secret
	}
	rows, err := tx.Query("SELECT "+selectedColumns(false)+" FROM secrets WHERE type='pass' AND secret=? ORDER BY id", secret)
	if err != nil {
		return nil, err
	}
	records := []Record{}
	for rows.Next() {
		r, err := scanRecord(rows, false)
		if err != nil {
			rows.Close()
			return nil, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ErrNotFound
	}
	leak = normalizeLeak(leak)
	for i, r := range records {
		records[i], err = appendLeak(tx, r, leak)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) GetMeta(key string) (string, error) {
	var value string
	err := s.DB.QueryRow("SELECT value FROM meta_state WHERE key=?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.DB.Exec("INSERT INTO meta_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

// ClaimLecture atomically tests and records the reminder time across processes.
func (s *Store) ClaimLecture(now time.Time, interval time.Duration) (bool, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var value string
	err = tx.QueryRow("SELECT value FROM meta_state WHERE key='lecture_shown_at'").Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil {
		previous, parseErr := decodeTime(value)
		if parseErr == nil && now.Sub(previous) < interval {
			return false, nil
		}
	}
	_, err = tx.Exec("INSERT INTO meta_state(key,value) VALUES('lecture_shown_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", encodeTime(now))
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
