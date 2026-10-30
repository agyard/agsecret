package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agyard/agsecret/internal/store"
)

// Client talks to a single origin. It never follows redirects or retries a
// mutation, whose result may already have been committed by the server.
type Client struct {
	address string
	key     string
	http    *http.Client
}

// ValidateURL accepts HTTP(S) origins.
func ValidateURL(address string) error {
	u, err := url.Parse(address)
	if err != nil || strings.Contains(address, "#") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return errors.New("remote URL must be an HTTP(S) origin, such as https://secrets.example.com")
	}
	if u.Scheme == "https" || u.Scheme == "http" {
		return nil
	}
	return errors.New("remote URL must use HTTP or HTTPS")
}

func NewClient(address, key string) (*Client, error) {
	if err := ValidateURL(address); err != nil {
		return nil, err
	}
	if !store.ValidAPIKey(key) {
		return nil, errors.New("invalid API key")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DisableCompression = true
	u, _ := url.Parse(address)
	if u.Scheme == "http" {
		// Private networks may provide transport encryption themselves. Keep
		// API keys and values off environment-configured HTTP proxies.
		transport.Proxy = nil
	}
	return &Client{
		address: strings.TrimSuffix(address, "/"), key: key,
		http: &http.Client{
			Transport: transport, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Close releases idle connections. Calls already in flight may finish.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) List(ctx context.Context) ([]store.Record, error) {
	var fields []field
	if err := c.request(ctx, "/v1/fields", nil, &fields); err != nil {
		return nil, err
	}
	return fromFields(fields, false)
}

func (c *Client) Get(ctx context.Context, ref string) (store.Record, error) {
	var f field
	if err := c.request(ctx, "/v1/field?ref="+url.QueryEscape(ref), nil, &f); err != nil {
		return store.Record{}, err
	}
	if f.ID != ref && f.Name != ref {
		return store.Record{}, errors.New("remote returned a different field")
	}
	records, err := fromFields([]field{f}, false)
	if err != nil {
		return store.Record{}, err
	}
	return records[0], nil
}

func (c *Client) Use(ctx context.Context, ids []string, action string) ([]store.Record, error) {
	var fields []field
	if err := c.request(ctx, "/v1/use", useRequest{IDs: ids, Action: action}, &fields); err != nil {
		return nil, err
	}
	expected := make(map[string]bool, len(ids))
	for _, id := range ids {
		expected[id] = true
	}
	for _, f := range fields {
		if !expected[f.ID] {
			return nil, errors.New("remote returned an unexpected field; uses may have been consumed")
		}
		delete(expected, f.ID)
	}
	if len(expected) != 0 {
		return nil, errors.New("remote omitted a field; uses may have been consumed")
	}
	records, err := fromFields(fields, true)
	if err != nil {
		return nil, fmt.Errorf("%w; uses may have been consumed", err)
	}
	return records, nil
}

func (c *Client) Report(ctx context.Context, id, reason string) ([]store.Record, error) {
	var fields []field
	if err := c.request(ctx, "/v1/report", reportRequest{ID: id, Reason: reason}, &fields); err != nil {
		return nil, err
	}
	found := false
	for _, f := range fields {
		found = found || f.ID == id
		if f.Type != "password" {
			return nil, errors.New("invalid remote report response")
		}
	}
	if !found {
		return nil, errors.New("remote report response omitted the requested ID")
	}
	return fromFields(fields, false)
}

func (c *Client) request(ctx context.Context, path string, input, output any) error {
	method := http.MethodGet
	var body io.ReadCloser
	var size int64
	if input != nil {
		method = http.MethodPost
		data, err := json.Marshal(input)
		if err != nil || len(data) > maxRequestBytes {
			return errors.New("remote request exceeds 1 MiB")
		}
		size = int64(len(data))
		// An opaque reader keeps GetBody nil, so the transport cannot replay it.
		body = io.NopCloser(bytes.NewReader(data))
	}
	r, err := http.NewRequestWithContext(ctx, method, c.address+path, body)
	if err != nil {
		return errors.New("invalid remote request")
	}
	r.ContentLength = size
	r.Header.Set("Authorization", "Bearer "+c.key)
	r.Header.Set("Accept", "application/json")
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(r)
	if err != nil {
		if requestErr, ok := errors.AsType[*url.Error](err); ok {
			err = requestErr.Err
		}
		return uncertainMutation(path, fmt.Errorf("remote connection failed: %w", err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var problem errorResponse
		limited := &io.LimitedReader{R: response.Body, N: 4097}
		decodeErr := decodeJSON(limited, &problem)
		switch {
		case response.StatusCode == http.StatusUnauthorized:
			return store.ErrUnauthorized
		case response.StatusCode == http.StatusNotFound && decodeErr == nil && limited.N > 0 && problem.Error == "not_found":
			return store.ErrNotFound
		case response.StatusCode == http.StatusForbidden && problem.Error == "expired":
			return store.ErrExpired
		case response.StatusCode == http.StatusForbidden && problem.Error == "no_uses":
			return store.ErrNoUses
		case response.StatusCode == http.StatusForbidden:
			return store.ErrNotAllowed
		case response.StatusCode == http.StatusBadRequest && problem.Error == "report_type":
			return store.ErrReportType
		case response.StatusCode >= 300 && response.StatusCode < 400:
			return errors.New("remote redirects are refused")
		default:
			return uncertainMutation(path, fmt.Errorf("remote returned HTTP %d", response.StatusCode))
		}
	}
	limited := &io.LimitedReader{R: response.Body, N: maxResponseBytes + 1}
	if err := decodeJSON(limited, output); err != nil || limited.N <= 0 {
		return uncertainMutation(path, errors.New("invalid remote response (maximum 64 MiB)"))
	}
	return nil
}

func uncertainMutation(path string, err error) error {
	switch path {
	case "/v1/use":
		return fmt.Errorf("%w; uses may have been consumed", err)
	case "/v1/report":
		return fmt.Errorf("%w; the report may have been recorded", err)
	default:
		return err
	}
}
