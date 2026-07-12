package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// The connection probe must answer quickly with ok:false for a
// server it can't reach — it now runs through sshpool.Run, whose
// deadline/caps are what keep a hung probe from retaining the
// handler. This exercises the endpoint through the converted path.
func TestTestServer_UnreachableAnswersFast(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	saved, err := cfg.UpsertServer(config.Server{
		Name: "dead",
		Host: "127.0.0.1",
		Port: 1, // nothing listens on tcp/1
		User: "nobody",
		// No KeyPath and no agent → buildAuth fails fast; even if an
		// agent leaks in from the environment, the dial to :1 refuses.
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := &Server{Config: cfg, Pool: sshpool.New()}
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+saved.ID+"/test", nil)
	req.SetPathValue("id", saved.ID)
	w := httptest.NewRecorder()

	start := time.Now()
	s.testServer(w, req)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("probe took %s for an unreachable server", elapsed)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if body.OK || body.Error == "" {
		t.Fatalf("expected ok:false with an error, got %+v", body)
	}
}
