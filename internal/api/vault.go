package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/AlteredParadox/ansbui/internal/ansible"
)

// decodeJSONBody is the per-handler boilerplate for "read JSON request
// body or 400 with a wrapped decode error". Returns false if the
// response has already been written, in which case the caller should
// just `return`. Centralised so the wrapping format ("decode body:
// %w") lives in one place — Sonar S1192 flagged the duplication.
//
// Strictness: DisallowUnknownFields catches client typos (a misspelled
// field would otherwise silently default), and the trailing-content
// check rejects clients that sneak a second JSON object past the first
// (json.Decoder is happy to read a single value and stop, leaving
// arbitrary bytes unread).
//
// dec.More() is the wrong primitive for "is there another value after
// this one" — it's only meaningful inside an array/object stream. Use
// a second Decode and require io.EOF: any successful decode means a
// second top-level value snuck through, any other error means
// non-whitespace bytes after the first value.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", maxErr.Limit))
			return false
		}
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return false
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("decode body: unexpected trailing data"))
		return false
	}
	return true
}

// /api/vault — list vault-encrypted files discovered in the active
// server's workDir. Metadata only; no plaintext is read. The response
// also echoes the workDir so the UI can tell the operator where we
// looked (and where new files should land).
func (s *Server) listVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	files, err := ansible.ListVaultFiles(r.Context(), s.Pool, srv)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"files":   files,
		"workDir": srv.WorkDir,
	})
}

// viewVaultBody carries both the path and the caller-supplied vault
// password. Sent over POST (not GET) so the password isn't logged in
// access logs or cached in the browser history.
type viewVaultBody struct {
	Path     string `json:"path"`
	Password string `json:"password"`
}

// /api/vault/view — decrypts the named file with the supplied
// password and returns the plaintext. Errors from ansible-vault
// (wrong password, missing file, etc.) come back as 502 with the
// vault's own message so the UI can surface it verbatim.
func (s *Server) viewVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body viewVaultBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Path == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("path and password are required"))
		return
	}
	plaintext, err := ansible.ViewVault(r.Context(), s.Pool, srv, body.Path, body.Password)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": plaintext})
}

type writeVaultBody struct {
	Path     string `json:"path"`
	Password string `json:"password"`
	Content  string `json:"content"`
}

// /api/vault/content — encrypts `content` with `password` and writes
// to `path` (relative to the server's workDir). Overwrites if the
// file already exists.
func (s *Server) writeVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body writeVaultBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Path == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("path and password are required"))
		return
	}
	if err := ansible.WriteVault(r.Context(), s.Pool, srv, body.Path, body.Password, body.Content); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type inlineListBody struct {
	Path string `json:"path"`
}

// POST /api/vault/inline/list — list every `!vault |` key in an
// inline vault file. Doesn't need a password; just text-parses the
// file. POST (not GET) so the rel path doesn't show up in upstream
// reverse-proxy access logs.
func (s *Server) listInlineVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body inlineListBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Path == "" {
		writeError(w, http.StatusBadRequest, errors.New("path is required"))
		return
	}
	keys, err := ansible.ListInlineVaultKeys(r.Context(), s.Pool, srv, body.Path)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

type inlineDecryptBody struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// /api/vault/inline/decrypt — decrypts a single `!vault |` value from
// an inline file. POST so the password isn't logged in access logs.
func (s *Server) decryptInlineVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body inlineDecryptBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Path == "" || body.Name == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("path, name, and password are required"))
		return
	}
	plaintext, err := ansible.DecryptInlineVaultValue(r.Context(), s.Pool, srv, body.Path, body.Name, body.Password)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": plaintext})
}

type inlineUpsertBody struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Password string `json:"password"`
}

// /api/vault/inline/upsert — encrypts `value` under `name` with the
// supplied vault password, then either replaces the existing block in
// the inline file or appends a new one. The rest of the file
// (comments, cleartext keys) is preserved verbatim.
func (s *Server) upsertInlineVault(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body inlineUpsertBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Path == "" || body.Name == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("path, name, and password are required"))
		return
	}
	if err := ansible.UpsertInlineVaultValue(r.Context(), s.Pool, srv, body.Path, body.Name, body.Value, body.Password); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
