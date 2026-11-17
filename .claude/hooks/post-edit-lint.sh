#!/bin/bash
# PostToolUse hook: lint the file an Edit/Write/MultiEdit just touched.
#
# - .go files run through golangci-lint at the file's package level.
# - .js/.jsx files run through eslint with the project's flat config.
#
# Reads the tool's JSON input from stdin (Claude Code passes it that
# way), pulls out tool_input.file_path, and dispatches by extension.
# Linter findings get written to stderr with exit 2 so Claude sees
# them as a blocking signal and can fix immediately. Clean runs
# exit 0 silently (no transcript noise on every edit).
#
# Lives in the repo so a fresh checkout gets the same linting
# automatically — .claude/settings.json registers this hook.
#
# No absolute paths: the repo root is derived from this script's own
# location (it lives at <repo>/.claude/hooks/), and the linters are
# resolved from PATH with the usual per-toolchain fallbacks. Any tool
# that isn't installed makes its branch a silent no-op, so the hook
# never blocks a machine that lacks it.

set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

GOLANGCI=$(command -v golangci-lint 2>/dev/null)
if [[ -z "$GOLANGCI" ]] && command -v go >/dev/null 2>&1; then
  GOLANGCI="$(go env GOPATH)/bin/golangci-lint"
fi

ESLINT="$REPO/node_modules/.bin/eslint"
[[ -x "$ESLINT" ]] || ESLINT=$(command -v eslint 2>/dev/null)

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  exit 0
fi

# Only lint files inside the repo.
case "$FILE" in
  "$REPO"/*) ;;
  *) exit 0 ;;
esac

emit_findings() {
  local label=$1
  local body=$2
  printf '%s findings on %s:\n%s\n' "$label" "$FILE" "$body" >&2
  exit 2
}

case "$FILE" in
  *.go)
    if [[ ! -x "$GOLANGCI" ]]; then
      exit 0
    fi
    DIR=$(dirname "$FILE")
    # Run on the package containing the changed file. Per-file
    # invocation isn't supported; per-package is the smallest
    # meaningful unit.
    OUT=$(cd "$REPO" && "$GOLANGCI" run "${DIR#$REPO/}/..." 2>&1)
    EC=$?
    if [[ $EC -ne 0 && -n "$OUT" ]]; then
      emit_findings "golangci-lint" "$OUT"
    fi
    ;;
  *.js|*.jsx)
    if [[ ! -x "$ESLINT" ]]; then
      exit 0
    fi
    OUT=$("$ESLINT" --no-warn-ignored "$FILE" 2>&1)
    EC=$?
    if [[ $EC -ne 0 && -n "$OUT" ]]; then
      emit_findings "eslint" "$OUT"
    fi
    ;;
  *)
    # Any other kind of file: nothing to lint.
    ;;
esac

exit 0
