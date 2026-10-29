package remote

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
)

// NewHandler serves only the local vault. The caller owns its lifetime and
// configures the HTTP server's listener, TLS and timeouts.
func NewHandler(s *store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" || len(r.Header.Values("Authorization")) != 1 {
			writeError(w, store.ErrUnauthorized)
			return
		}
		var records []store.Record
		var err error
		used := false
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fields":
			records, err = s.APIList(token)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/field":
			ref := r.URL.Query().Get("ref")
			if !store.ValidID(ref) && store.ValidateName(ref) != nil {
				writeStatus(w, http.StatusBadRequest, "invalid_request")
				return
			}
			var record store.Record
			record, err = s.APIGet(token, ref)
			if err == nil {
				defer clear(record.Secret)
				_ = json.NewEncoder(w).Encode(toField(record, false))
				return
			}
		case r.Method == http.MethodPost && r.URL.Path == "/v1/use":
			var request useRequest
			if !readRequest(w, r, &request) {
				return
			}
			if len(request.IDs) == 0 || request.Action != "get" && request.Action != "exec" && request.Action != "send" {
				writeStatus(w, http.StatusBadRequest, "invalid_request")
				return
			}
			for _, id := range request.IDs {
				if !store.ValidID(id) {
					writeStatus(w, http.StatusBadRequest, "invalid_request")
					return
				}
			}
			records, err = s.APIConsume(token, request.IDs, request.Action)
			used = true
			if err == nil {
				now := time.Now()
				for i := range records {
					if records[i].Type == "totp" {
						var code string
						code, err = totp.Generate(string(records[i].Secret), now)
						clear(records[i].Secret)
						records[i].Secret = []byte(code)
						if err != nil {
							break
						}
					}
				}
			}
		case r.Method == http.MethodPost && r.URL.Path == "/v1/report":
			var request reportRequest
			if !readRequest(w, r, &request) {
				return
			}
			if !store.ValidID(request.ID) {
				writeStatus(w, http.StatusBadRequest, "invalid_request")
				return
			}
			records, err = s.APIReport(token, request.ID, request.Reason)
		default:
			writeStatus(w, http.StatusNotFound, "unknown_endpoint")
			return
		}
		defer clearRecords(records)
		if err != nil {
			writeError(w, err)
			return
		}
		fields := make([]field, len(records))
		for i, record := range records {
			fields[i] = toField(record, used)
		}
		_ = json.NewEncoder(w).Encode(fields)
	})
}

func readRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeStatus(w, http.StatusUnsupportedMediaType, "invalid_request")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	if err := decodeJSON(r.Body, dst); err != nil {
		writeStatus(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeStatus(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, store.ErrNotFound):
		writeStatus(w, http.StatusNotFound, "not_found")
	case errors.Is(err, store.ErrExpired):
		writeStatus(w, http.StatusForbidden, "expired")
	case errors.Is(err, store.ErrNotAllowed):
		writeStatus(w, http.StatusForbidden, "not_allowed")
	case errors.Is(err, store.ErrNoUses):
		writeStatus(w, http.StatusForbidden, "no_uses")
	case errors.Is(err, store.ErrReportType):
		writeStatus(w, http.StatusBadRequest, "report_type")
	default:
		writeStatus(w, http.StatusInternalServerError, "server_error")
	}
}

func writeStatus(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: code})
}
