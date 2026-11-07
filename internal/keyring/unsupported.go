//go:build !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package keyring

type unavailable struct{}

// New preserves pass-file operation on platforms without a Secret Service backend.
func New() Backend                             { return unavailable{} }
func (unavailable) Get(string) ([]byte, error) { return nil, ErrUnavailable }
func (unavailable) Set(string, []byte) error   { return ErrUnavailable }
