package remote

import (
	"bytes"
	"io"
	"sync"
)

// requestBody prevents transport replay and erases serialized put values when
// closed. Transport may close a body concurrently with its final Read.
type requestBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
	data   []byte
}

func newRequestBody(data []byte) *requestBody {
	return &requestBody{reader: bytes.NewReader(data), data: data}
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *requestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.data)
	b.data, b.reader = nil, nil
	return nil
}
