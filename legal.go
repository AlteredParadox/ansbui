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

// The repo-root legal texts are embedded here so every distributed artifact
// carries its own license and the third-party notices for everything
// statically linked or embedded into it. They are handed to the HTTP server
// (api.Server.Legal) and served without login at /license and
// /third-party-licenses; scripts/gen-third-party-licenses.sh regenerates the
// notices.

package main

import (
	// Blank import for its side effect: it enables the //go:embed
	// directives below.
	_ "embed"

	"github.com/AlteredParadox/ansbui/internal/api"
)

// version is stamped at build time by `make build` and the release workflow
// via -ldflags "-X main.version=vX.Y.Z". A plain `go build` reports "dev".
var version = "dev"

// licenseText is the project's own license (GNU AGPL-3.0-or-later).
//
//go:embed LICENSE
var licenseText []byte

// thirdPartyLicenses reproduces the license and copyright notices of all
// bundled third-party code: the Go modules linked into the binary and the
// scripts and fonts embedded from web/. Regenerate with `make notices` after
// any dependency or asset change; `make notices-check` (run by the release
// workflow) fails if the committed copy is stale.
//
//go:embed THIRD_PARTY_LICENSES.md
var thirdPartyLicenses []byte

// legalTexts is what main hands to the HTTP server.
func legalTexts() api.Legal {
	return api.Legal{
		License:            licenseText,
		ThirdPartyLicenses: thirdPartyLicenses,
		Version:            version,
	}
}
