package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/bootstrap"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

func (s *Server) listServers(w http.ResponseWriter, _ *http.Request) {
	snap := s.Config.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":        snap.Servers,
		"activeServerId": snap.ActiveServerID,
	})
}

func (s *Server) upsertServer(w http.ResponseWriter, r *http.Request) {
	var srv config.Server
	if !decodeJSONBody(w, r, &srv) {
		return
	}
	saved, err := s.Config.UpsertServer(srv)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	s.Pool.Drop(id)
	if err := s.Config.DeleteServer(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) activateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Config.SetActive(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"activeServerId": id})
}

func (s *Server) testServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	srv, ok := s.Config.ServerByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown server %q", id))
		return
	}
	ctx := r.Context()
	client, err := s.Pool.Client(ctx, srv)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	// sshpool.Run (not a raw session) so the probe inherits ctx
	// cancellation, the default execution deadline, and output caps —
	// a responsive sshd fronting a hung `ansible --version` used to
	// retain this handler indefinitely.
	out, _, err := sshpool.Run(ctx, client, "ansible --version 2>&1 | head -n1")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("probe ansible: %v", err),
		})
		return
	}
	// ansible answered; now check that the account's login shell reads
	// ansbui's quoting correctly. Every later command depends on it,
	// and nothing else would tell the operator that it does not hold.
	if err := ansible.CheckShellQuoting(ctx, client); err != nil {
		msg := fmt.Sprintf("shell check: %v", err)
		if errors.Is(err, ansible.ErrShellQuoting) {
			msg = fmt.Sprintf("%v. ansbui builds its commands for sh, bash, dash, ksh or zsh; under another shell (fish, for example) a value containing a quote or a backslash can be split into separate commands. Change the login shell of %q on the control node, e.g. `chsh -s /bin/bash %s`", err, srv.User, srv.User)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      false,
			"error":   msg,
			"version": strings.TrimSpace(out),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": strings.TrimSpace(out),
	})
}

type settingsBody struct {
	PrometheusURL      string `json:"prometheusUrl"`
	PrometheusLabel    string `json:"prometheusHostLabel"`
	AutoGatherFacts    bool   `json:"autoGatherFacts"`
	GeoIPEnabled       bool   `json:"geoIpEnabled"`
	ControlPrivKeyPath string `json:"controlPrivKeyPath"`

	// BootstrapRequireHostKey reports whether strict bootstrap
	// host-key mode is on. Read-only: it comes from the environment,
	// not config.json, so setSettings ignores it — it is carried on
	// this body (rather than a new endpoint) because the frontend
	// already loads settings once at boot into globalThis.
	// AnsbuiSettings, which is where the bootstrap form reads it to
	// decide whether the reinstall acknowledgement applies.
	BootstrapRequireHostKey bool `json:"bootstrapRequireHostKey"`
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	snap := s.Config.Snapshot()
	writeJSON(w, http.StatusOK, settingsBody{
		PrometheusURL:      snap.PrometheusURL,
		PrometheusLabel:    snap.PrometheusLabel,
		AutoGatherFacts:    snap.AutoGatherFacts,
		GeoIPEnabled:       snap.GeoIPEnabled,
		ControlPrivKeyPath: snap.ControlPrivKeyPath,

		BootstrapRequireHostKey: bootstrap.HostKeyRequired(),
	})
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	var body settingsBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	// One transactional write — previously this called four
	// individual setters and a disk error mid-sequence could leave
	// (e.g.) PrometheusURL applied but AutoGatherFacts at its old
	// value. SetSettings validates first and persists once.
	if err := s.Config.SetSettings(config.SettingsUpdate{
		PrometheusURL:      body.PrometheusURL,
		PrometheusLabel:    body.PrometheusLabel,
		AutoGatherFacts:    body.AutoGatherFacts,
		GeoIPEnabled:       body.GeoIPEnabled,
		ControlPrivKeyPath: body.ControlPrivKeyPath,
	}); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}
