// Package totp implements RFC 6238 using only the Go standard library.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Config is a decoded TOTP secret. Call Clear when the key is no longer needed.
type Config struct {
	Key       []byte
	Algorithm string
	Digits    int
	Period    uint64
}

// Clear erases the decoded key owned by this configuration.
func (c Config) Clear() { clear(c.Key) }

// Parse accepts a Base32 seed or an otpauth://totp URI. Raw seeds ignore
// whitespace, hyphens, case, and optional Base32 padding.
func Parse(seed string) (Config, error) {
	c := Config{Algorithm: "SHA1", Digits: 6, Period: 30}
	seed = strings.TrimSpace(seed)
	if strings.Contains(seed, "://") {
		u, err := url.Parse(seed)
		if err != nil || !strings.EqualFold(u.Scheme, "otpauth") || !strings.EqualFold(u.Host, "totp") || u.User != nil || u.Fragment != "" {
			return Config{}, errors.New("invalid TOTP URI; expected otpauth://totp/LABEL?secret=SEED")
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(q["secret"]) != 1 {
			return Config{}, errors.New("a TOTP URI must have exactly one secret parameter")
		}
		for _, name := range []string{"algorithm", "digits", "period"} {
			if len(q[name]) > 1 {
				return Config{}, fmt.Errorf("a TOTP URI must not repeat %s", name)
			}
		}
		seed = q.Get("secret")
		if a := q.Get("algorithm"); a != "" {
			c.Algorithm = strings.ToUpper(a)
		}
		if d := q.Get("digits"); d != "" {
			c.Digits, err = strconv.Atoi(d)
			if err != nil || (c.Digits != 6 && c.Digits != 8) {
				return Config{}, errors.New("TOTP codes must have 6 or 8 digits")
			}
		}
		if p := q.Get("period"); p != "" {
			c.Period, err = strconv.ParseUint(p, 10, 32)
			if err != nil || c.Period == 0 || c.Period > 86400 {
				return Config{}, errors.New("the TOTP period must be 1 to 86400 seconds")
			}
		}
	}
	if c.Algorithm != "SHA1" && c.Algorithm != "SHA256" && c.Algorithm != "SHA512" {
		return Config{}, errors.New("the TOTP algorithm must be SHA1, SHA256 or SHA512")
	}
	seed = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' {
			return -1
		}
		return unicode.ToUpper(r)
	}, seed)
	seed = strings.TrimRight(seed, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil || len(key) == 0 {
		clear(key)
		return Config{}, errors.New("the TOTP seed must be non-empty Base32 text")
	}
	c.Key = key
	return c, nil
}

// Generate parses a seed and calculates the code valid at now.
func Generate(seed string, now time.Time) (string, error) {
	c, err := Parse(seed)
	if err != nil {
		return "", err
	}
	defer c.Clear()
	return c.Generate(now)
}

// Generate calculates a time-based code with the configured hash and period.
func (c Config) Generate(now time.Time) (string, error) {
	if len(c.Key) == 0 || c.Period == 0 || (c.Digits != 6 && c.Digits != 8) || now.Unix() < 0 {
		return "", errors.New("invalid TOTP configuration or time")
	}
	var newHash func() hash.Hash
	switch c.Algorithm {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return "", errors.New("unsupported TOTP algorithm")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix())/c.Period)
	mac := hmac.New(newHash, c.Key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	defer clear(sum)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1000000)
	if c.Digits == 8 {
		mod = 100000000
	}
	return fmt.Sprintf("%0*d", c.Digits, value%mod), nil
}
