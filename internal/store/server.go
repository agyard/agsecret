package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"
)

var ErrUnauthorized = errors.New("invalid API key")

// APIKey describes access to current field names. The token is returned only
// when created; the vault stores its SHA-256 digest.
type APIKey struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

// Remote is a named server. Names determine lookup order after the local vault.
type Remote struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Key  string `json:"-"`
}

const serverSchema = `CREATE TABLE IF NOT EXISTS api_keys (
 name TEXT PRIMARY KEY NOT NULL,
 digest BLOB NOT NULL UNIQUE,
 rules TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remotes (
 name TEXT PRIMARY KEY NOT NULL,
 url TEXT NOT NULL,
 api_key TEXT NOT NULL
);`

// These optional tables are created by management writes. Existing vaults and
// new vaults use the same schema and operations; reads never modify the schema.
func hasTable(q rowQuerier, name string) (bool, error) {
	var exists bool
	err := q.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)", name).Scan(&exists)
	return exists, err
}

func ValidAPIKey(token string) bool {
	if len(token) != 68 || !strings.HasPrefix(token, "agk_") {
		return false
	}
	for _, c := range token[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidateAPIKeyName(name string) error {
	if name == "" || len(name) > maxNameBytes || strings.ContainsFunc(name, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c))
	}) {
		return errors.New("a name must contain 1 to 128 lowercase letters, digits, '_', '.' or '-'")
	}
	return nil
}

func ValidateRemoteName(name string) error {
	if err := ValidateAPIKeyName(name); err != nil {
		return err
	}
	if name == "local" {
		return errors.New("local is reserved for the local vault")
	}
	return nil
}

// Match whole ASCII names using glob syntax. Unlike path.Match, '*' and '?'
// also match '/'. Character classes already handle '/' as an ordinary rune.
func matchRule(pattern, name string) (bool, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return false, err
	}
	matched := make([]bool, len(name)+1)
	matched[0] = true
	for len(pattern) > 0 {
		if pattern[0] == '*' {
			for i := 1; i <= len(name); i++ {
				matched[i] = matched[i] || matched[i-1]
			}
			pattern = pattern[1:]
			continue
		}
		end := 1
		switch pattern[0] {
		case '\\':
			end = 2
		case '[':
			for pattern[end] != ']' {
				if pattern[end] == '\\' {
					end++
				}
				end++
			}
			end++
		}
		token := pattern[:end]
		for i := len(name); i > 0; i-- {
			match := token == "?" || token == name[i-1:i] || token == "\\"+name[i-1:i]
			if token[0] == '[' {
				match, _ = path.Match(token, name[i-1:i])
			}
			matched[i] = matched[i-1] && match
		}
		matched[0] = false
		pattern = pattern[end:]
	}
	return matched[len(name)], nil
}

func ValidateRules(rules []string) error {
	inclusion := false
	for _, rule := range rules {
		pattern, exclude := strings.CutPrefix(rule, "!")
		if pattern == "" || strings.ContainsFunc(pattern, unicode.IsControl) {
			return errors.New("rules must be nonempty glob patterns on one line")
		}
		if _, err := matchRule(pattern, ""); err != nil {
			return fmt.Errorf("invalid rule %q: %w", rule, err)
		}
		inclusion = inclusion || !exclude
	}
	if !inclusion {
		return errors.New("provide at least one allow rule")
	}
	return nil
}

func rulesAllow(rules []string, name string) bool {
	allowed := false
	for _, rule := range rules {
		pattern, exclude := strings.CutPrefix(rule, "!")
		if match, _ := matchRule(pattern, name); match {
			allowed = !exclude
		}
	}
	return allowed
}

func (s *Store) CreateAPIKey(name string, rules []string) (string, error) {
	if err := ValidateAPIKeyName(name); err != nil {
		return "", err
	}
	if err := ValidateRules(rules); err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(serverSchema); err != nil {
		return "", err
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM api_keys WHERE name=?)", name).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("API key %s already exists", name)
	}
	var random [32]byte
	rand.Read(random[:])
	token := "agk_" + hex.EncodeToString(random[:])
	clear(random[:])
	digest := sha256.Sum256([]byte(token))
	encoded, _ := json.Marshal(rules)
	if _, err := tx.Exec("INSERT INTO api_keys(name,digest,rules) VALUES(?,?,?)", name, digest[:], string(encoded)); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) APIKeys() ([]APIKey, error) {
	keys := []APIKey{}
	exists, err := hasTable(s.db, "api_keys")
	if err != nil || !exists {
		return keys, err
	}
	rows, err := s.db.Query("SELECT name,rules FROM api_keys ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key APIKey
		var rules string
		if err := rows.Scan(&key.Name, &rules); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rules), &key.Rules); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) DeleteAPIKey(name string) error {
	if err := ValidateAPIKeyName(name); err != nil {
		return err
	}
	return s.deleteConfig("api_keys", name)
}

func (s *Store) AddRemote(name, address, key string) error {
	if err := ValidateRemoteName(name); err != nil {
		return err
	}
	if !ValidAPIKey(key) {
		return ErrUnauthorized
	}
	u, err := url.Parse(address)
	if err != nil || strings.Contains(address, "#") || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("remote URL must be an absolute HTTP or HTTPS URL")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("remote URL must use the server root")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(serverSchema); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM remotes WHERE name=?)", name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("remote %s already exists", name)
	}
	if _, err := tx.Exec("INSERT INTO remotes(name,url,api_key) VALUES(?,?,?)", name, strings.TrimRight(address, "/"), key); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Remotes() ([]Remote, error) {
	remotes := []Remote{}
	exists, err := hasTable(s.db, "remotes")
	if err != nil || !exists {
		return remotes, err
	}
	rows, err := s.db.Query("SELECT name,url,api_key FROM remotes ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Remote
		if err := rows.Scan(&r.Name, &r.URL, &r.Key); err != nil {
			return nil, err
		}
		remotes = append(remotes, r)
	}
	return remotes, rows.Err()
}

func (s *Store) DeleteRemote(name string) error {
	if err := ValidateRemoteName(name); err != nil {
		return err
	}
	return s.deleteConfig("remotes", name)
}

func (s *Store) deleteConfig(table, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(serverSchema); err != nil {
		return err
	}
	result, err := tx.Exec("DELETE FROM "+table+" WHERE name=?", name)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func authenticate(tx *sql.Tx, token string) ([]string, error) {
	if !ValidAPIKey(token) {
		return nil, ErrUnauthorized
	}
	exists, err := hasTable(tx, "api_keys")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrUnauthorized
	}
	digest := sha256.Sum256([]byte(token))
	var encoded string
	if err := tx.QueryRow("SELECT rules FROM api_keys WHERE digest=?", digest[:]).Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	var rules []string
	if err := json.Unmarshal([]byte(encoded), &rules); err != nil {
		return nil, err
	}
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func scopedRecords(records []Record, rules []string) []Record {
	visible := records[:0]
	for _, r := range records {
		if rulesAllow(rules, r.Name) {
			visible = append(visible, r)
		} else {
			clear(r.Secret)
		}
	}
	clear(records[len(visible):])
	return visible
}

// APIList returns authorized metadata and plain values from the local vault.
func (s *Store) APIList(token string) ([]Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rules, err := authenticate(tx, token)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(listQuery(false))
	records, err := scanRecords(rows, err, false)
	if err != nil {
		return nil, err
	}
	return scopedRecords(records, rules), nil
}

// APIGet applies the same scope to names and IDs, including renamed fields.
func (s *Store) APIGet(token, ref string) (Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	rules, err := authenticate(tx, token)
	if err != nil {
		return Record{}, err
	}
	if err := validateRef(ref); err != nil {
		return Record{}, err
	}
	r, err := getRecord(tx, ref, false)
	if err != nil {
		return Record{}, err
	}
	if !rulesAllow(rules, r.Name) {
		clear(r.Secret)
		return Record{}, ErrNotFound
	}
	return r, nil
}

// APIConsume authorizes and consumes all IDs atomically with API key checks.
func (s *Store) APIConsume(token string, ids []string, action string) ([]Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rules, err := authenticate(tx, token)
	if err != nil {
		return nil, err
	}
	if action != "get" && action != "exec" && action != "send" {
		return nil, fmt.Errorf("unknown consume action %q", action)
	}
	for _, id := range ids {
		if err := CheckID(id); err != nil {
			return nil, err
		}
	}
	records, err := consumeMany(tx, ids, action, rules)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clearRecords(records)
		return nil, err
	}
	return records, nil
}

// APIReport updates every password copy but returns only authorized records.
func (s *Store) APIReport(token, id, reason string) ([]Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rules, err := authenticate(tx, token)
	if err != nil {
		return nil, err
	}
	if err := CheckID(id); err != nil {
		return nil, err
	}
	records, err := report(tx, id, reason, rules)
	if err != nil {
		return nil, err
	}
	return records, tx.Commit()
}
