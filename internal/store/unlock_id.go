package store

import (
	"crypto/sha256"
	"encoding/hex"
)

// UnlockID identifies the encrypted unlock descriptor without storing another
// file or deriving an identifier from secret plaintext. Moving/copying a vault
// preserves its keyring entry; independently created vaults have different IDs.
func UnlockID(name string) (string, error) {
	b, err := readUnlockDescriptor(name + ".unlock")
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}
