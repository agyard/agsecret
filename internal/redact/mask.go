// Package redact implements the user-visible credential masks and the
// streaming output filter used by `agsecret exec`.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const DefaultMask = "fixed:[set]"

// Spec is a validated mask expression. Expressions are deliberately small and
// explicit so a credential never becomes visible merely because a formatter
// guessed an unsafe default.
type Spec struct {
	Mode    string
	A       int
	B       int
	Literal string
}

// Parse accepts:
//   - fixed:text (or fixed, which means fixed:[set])
//   - prefix:N
//   - suffix:N
//   - both:N,M
//   - length (reveals only the length)
//   - hash (reveals a short, one-way fingerprint)
func Parse(expr string) (Spec, error) {
	if expr == "" {
		expr = DefaultMask
	}
	if expr == "fixed" {
		expr = DefaultMask
	}
	if strings.HasPrefix(expr, "fixed:") {
		literal := strings.TrimPrefix(expr, "fixed:")
		if literal == "" || strings.ContainsAny(literal, "\r\n") || !utf8.ValidString(literal) {
			return Spec{}, errors.New("fixed mask must be non-empty UTF-8 without newlines")
		}
		return Spec{Mode: "fixed", Literal: literal}, nil
	}
	if expr == "length" || expr == "hash" {
		return Spec{Mode: expr}, nil
	}
	if strings.HasPrefix(expr, "prefix:") {
		n, err := parseCount(strings.TrimPrefix(expr, "prefix:"))
		if err != nil {
			return Spec{}, fmt.Errorf("prefix mask: %w", err)
		}
		return Spec{Mode: "prefix", A: n}, nil
	}
	if strings.HasPrefix(expr, "suffix:") {
		n, err := parseCount(strings.TrimPrefix(expr, "suffix:"))
		if err != nil {
			return Spec{}, fmt.Errorf("suffix mask: %w", err)
		}
		return Spec{Mode: "suffix", A: n}, nil
	}
	if strings.HasPrefix(expr, "both:") {
		parts := strings.Split(strings.TrimPrefix(expr, "both:"), ",")
		if len(parts) != 2 {
			return Spec{}, errors.New("both mask must be both:PREFIX,SUFFIX")
		}
		a, err := parseCount(parts[0])
		if err != nil {
			return Spec{}, fmt.Errorf("both mask prefix: %w", err)
		}
		b, err := parseCount(parts[1])
		if err != nil {
			return Spec{}, fmt.Errorf("both mask suffix: %w", err)
		}
		return Spec{Mode: "both", A: a, B: b}, nil
	}
	return Spec{}, errors.New("mask must be fixed[:TEXT], prefix:N, suffix:N, both:N,M, length, or hash")
}

func parseCount(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 128 {
		return 0, errors.New("count must be an integer from 0 to 128")
	}
	return n, nil
}

func runeSlice(secret []byte) []rune {
	return []rune(string(secret))
}

// Apply renders a validated mask. The returned string contains no more secret
// material than the expression explicitly requested by the owner.
func Apply(expr string, secret []byte) (string, error) {
	spec, err := Parse(expr)
	if err != nil {
		return "", err
	}
	runes := runeSlice(secret)
	switch spec.Mode {
	case "fixed":
		return spec.Literal, nil
	case "length":
		return fmt.Sprintf("[set length=%d]", len(runes)), nil
	case "hash":
		h := sha256.Sum256(secret)
		return "sha256:" + hex.EncodeToString(h[:])[:12], nil
	case "prefix":
		if spec.A >= len(runes) {
			return "[set]", nil
		}
		return string(runes[:spec.A]) + "...", nil
	case "suffix":
		if spec.A >= len(runes) {
			return "[set]", nil
		}
		return "..." + string(runes[len(runes)-spec.A:]), nil
	case "both":
		if spec.A+spec.B >= len(runes) {
			return "[set]", nil
		}
		return string(runes[:spec.A]) + "..." + string(runes[len(runes)-spec.B:]), nil
	default:
		return "", errors.New("unknown mask mode")
	}
}
