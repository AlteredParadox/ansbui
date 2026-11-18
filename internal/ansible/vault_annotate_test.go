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

package ansible

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestVaultAnnotateCmdHostileFilenames executes the batch annotate
// command against a real shell with quote-breaking filenames. Before
// the fix, the `>>path` marker spliced the path raw into printf's
// format string, so a filename like `'; touch pwned; '.yml` ran
// arbitrary commands as the SSH user and quote-only names silently
// lost their annotations.
func TestVaultAnnotateCmdHostileFilenames(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"a'b.yml",
		"'; touch pwned; '.yml",
		"sub $(touch pwned2).yml",
	}
	files := make([]VaultFile, len(names))
	for i, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("$ANSIBLE_VAULT;1.2;AES256;dev\npayload\n"), 0o600); err != nil {
			t.Fatalf("write %q: %v", n, err)
		}
		files[i] = VaultFile{Path: n, Name: n}
	}

	out, err := exec.Command("sh", "-c", vaultAnnotateCmd(dir, files)).Output()
	if err != nil {
		t.Fatalf("annotate command failed: %v", err)
	}
	parseVaultAnnotations(string(out), files)

	for i := range files {
		if files[i].Size == 0 {
			t.Errorf("%q: stat annotation lost (marker mangled by quoting)", names[i])
		}
		if files[i].Kind != "whole" || files[i].VaultID != "dev" {
			t.Errorf("%q: header not parsed, kind=%q vaultId=%q", names[i], files[i].Kind, files[i].VaultID)
		}
	}
	for _, marker := range []string{"pwned", "pwned2"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			t.Fatalf("filename escaped quoting: %s was created by injected command", marker)
		}
	}
}
