// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"testing"
)

// The binary must carry its own license and the notices for what is linked
// into it: these are what /license and /third-party-licenses serve, and an
// embed that silently came up empty would leave the AGPL offer unanswered.
func TestLegalTextsAreEmbedded(t *testing.T) {
	legal := legalTexts()
	if !bytes.Contains(legal.License, []byte("GNU AFFERO GENERAL PUBLIC LICENSE")) {
		t.Errorf("embedded LICENSE is not the AGPL text (%d bytes)", len(legal.License))
	}
	for _, want := range []string{
		"# Third-party licenses",
		"Go standard library and runtime",
		"github.com/gorilla/websocket",
		"web/vendor/react.production.min.js",
		"web/vendor/babel.min.js",
		"caniuse-lite",
		"web/fonts/InterVariable.woff2",
		"JetBrains Mono",
	} {
		if !bytes.Contains(legal.ThirdPartyLicenses, []byte(want)) {
			t.Errorf("embedded THIRD_PARTY_LICENSES.md does not mention %q", want)
		}
	}
	// A test binary is never stamped, so this is the default a plain
	// `go build` reports.
	if legal.Version != "dev" {
		t.Errorf("unstamped version = %q, want \"dev\"", legal.Version)
	}
}
