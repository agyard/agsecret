package cli

import (
	"bufio"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"

	"github.com/agyard/agsecret/internal/store"
)

// singleByteReader keeps buffered rune decoding from consuming the next prompt's input.
type singleByteReader struct{ io.Reader }

func (r singleByteReader) Read(b []byte) (int, error) { return r.Reader.Read(b[:min(len(b), 1)]) }

func readMasked(in io.Reader, out io.Writer) (value []byte, err error) {
	reader := bufio.NewReader(singleByteReader{in})
	defer func() {
		if err != nil {
			clear(value)
			value = nil
		}
	}()
	erase := func() error {
		_, size := utf8.DecodeLastRune(value)
		clear(value[len(value)-size:])
		value = value[:len(value)-size]
		_, err := io.WriteString(out, "\b \b")
		return err
	}
	for {
		ch, size, readErr := reader.ReadRune()
		if readErr != nil {
			if readErr == io.EOF && len(value) > 0 {
				return value, nil
			}
			return value, readErr
		}
		switch ch {
		case '\r', '\n':
			return value, nil
		case 3, 27: // Ctrl-C, Escape
			return value, &exitError{code: 130, err: errors.New("input cancelled")}
		case 4: // Ctrl-D
			if len(value) == 0 {
				return value, io.EOF
			}
			return value, nil
		case 8, 127: // Backspace
			if len(value) > 0 {
				if err := erase(); err != nil {
					return value, err
				}
			}
		case 21, 23: // Ctrl-U, Ctrl-W
			word := false
			for len(value) > 0 {
				last, _ := utf8.DecodeLastRune(value)
				if ch == 23 && word && unicode.IsSpace(last) {
					break
				}
				word = word || !unicode.IsSpace(last)
				if err := erase(); err != nil {
					return value, err
				}
			}
		default:
			if unicode.IsControl(ch) {
				continue
			}
			if ch == utf8.RuneError && size == 1 {
				return value, errors.New("the value must be UTF-8 text")
			}
			if len(value)+size > store.MaxSecretLen {
				return value, errors.New("the value is larger than 1 MiB")
			}
			value = utf8.AppendRune(value, ch)
			if _, err := io.WriteString(out, "•"); err != nil {
				return value, err
			}
		}
	}
}
