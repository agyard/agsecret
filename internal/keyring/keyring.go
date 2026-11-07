// Package keyring caches vault unlock passphrases in the desktop keyring.
// Backends never enumerate unrelated items or request an interactive unlock.
package keyring

import "errors"

var ErrUnavailable = errors.New("system keyring unavailable")

// Backend addresses exactly one vault by its non-secret unlock descriptor ID.
// A successful Get returns a caller-owned buffer, which the caller must clear.
type Backend interface {
	Get(account string) ([]byte, error)
	Set(account string, passphrase []byte) error
}
