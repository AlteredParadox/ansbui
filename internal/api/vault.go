package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/AlteredParadox/relay/internal/ansible"
)

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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
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
