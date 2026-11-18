BINARY := ansbui
# Stamped into the binary as main.version. The release workflow overrides
# this with the tag; local builds report the git description, or "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# The stamp reaches the recipe through the environment, never as text of
# the command line. A tag's name is whatever its author wrote, tags arrive
# with any remote that is fetched, and the shell would run what a name such
# as v1.0-$(...) holds if make pasted it into the recipe.
export ANSBUI_VERSION := $(VERSION)

.PHONY: build run test vet notices notices-check license-headers license-check clean

# `notices` runs FIRST: THIRD_PARTY_LICENSES.md is embedded into the binary
# (legal.go), so regenerating it here means what ships always matches what
# is actually linked in — no separate step to forget after a dependency bump.
# The committed copy exists only so a bare `go build` still works.
build: notices
	@case "$$ANSBUI_VERSION" in ''|*[!A-Za-z0-9._+-]*) echo "build: the version stamp has characters a version does not: refusing it (set VERSION=... to choose one)" >&2; exit 1;; esac
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$$ANSBUI_VERSION" -o $(BINARY) .

run:
	go run .

test:
	go test ./...

vet:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

# Regenerate the third-party notices from the modules actually linked in and
# the front-end files embedded from web/.
notices:
	@./scripts/gen-third-party-licenses.sh >/dev/null

# Fail if the committed notices are stale. Deliberately NOT part of the CI
# gate: Dependabot bumps go.mod but cannot regenerate this file, so gating
# every PR on it would make each gomod PR red for a reason the bot can't fix.
# The release workflow runs it instead — that is the point where the notice
# legally has to match the artifact being published.
notices-check:
	@tmp=$$(mktemp); \
	./scripts/gen-third-party-licenses.sh "$$tmp" >/dev/null; \
	if ! diff -q "$$tmp" THIRD_PARTY_LICENSES.md >/dev/null; then \
		echo "FAIL: THIRD_PARTY_LICENSES.md is stale — run 'make notices'"; \
		diff -u THIRD_PARTY_LICENSES.md "$$tmp" | head -40; \
		rm -f "$$tmp"; exit 1; \
	fi; \
	rm -f "$$tmp"; \
	echo "notices-check: THIRD_PARTY_LICENSES.md is current"

# Stamp the AGPL notice on any first-party source missing it.
license-headers:
	@./scripts/license-headers.sh

# Cheap and deterministic (no network, no build), so this one DOES gate CI.
license-check:
	@./scripts/license-headers.sh --check

clean:
	rm -f $(BINARY)
