#!/bin/bash
# Checks the pinned bin456789/reinstall commit against everything
# internal/bootstrap/reinstall.go depends on, without running the script.
#
# ansbui pins reinstall.sh to a commit and a SHA-256 (reinstallScriptCommit,
# reinstallScriptSHA256), rewrites three things in it before running it, and
# then parses its output and polls the installer it boots. Each of those is
# a place where a new upstream commit can break a reinstall, or where a
# wrong pin shows. This script downloads the pinned files and checks them:
#
#   1. reinstall.sh still downloads and has the pinned SHA-256;
#   2. the rewrites in reinstallPrepScript apply: both confhome assignments
#      can be pointed at the commit, and `curl --insecure` can be removed;
#   3. the patched script still parses (bash -n; it is never executed);
#   4. the flags ansbui passes exist and are allowed for debian and ubuntu;
#   5. the "Network Info" lines ansbui parses are still printed;
#   6. trans.sh still parks at "hold 2" without rebooting, writes
#      /reinstall.log, and marks errors the way the installer probe expects;
#   7. the helper scripts and the outside downloads a run needs answer:
#      the location lookup, the Alpine installer, and the OS images.
#
# The sed and grep expressions in step 2 are copies of the ones in
# reinstallPrepScript. Change them together.
#
# What it cannot tell you: whether a reinstall works. Only a real run
# against a disposable machine does that.
#
# Usage: scripts/check-reinstall-pin.sh [commit]
#   With a commit, checks that upstream commit instead of the pinned one
#   (step 1 then prints its SHA-256 instead of comparing) — the way to try
#   a candidate before changing the constants.
set -euo pipefail
export LC_ALL=C
cd "$(git rev-parse --show-toplevel)"

SRC=internal/bootstrap/reinstall.go
pinned_commit=$(sed -n 's/^const reinstallScriptCommit = "\([0-9a-f]\{40\}\)"$/\1/p' "$SRC")
pinned_sha=$(sed -n 's/^const reinstallScriptSHA256 = "\([0-9a-f]\{64\}\)"$/\1/p' "$SRC")
[[ -n "$pinned_commit" && -n "$pinned_sha" ]] || { echo "cannot read the pin from $SRC" >&2; exit 1; }

commit=${1:-$pinned_commit}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "commit must be a full 40-character hash" >&2; exit 1; }
base="https://raw.githubusercontent.com/bin456789/reinstall/$commit"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; failed=1; }
# has <file> <fixed string> <description>
has() { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
# answers <url>: the URL responds 2xx (redirects followed, headers only).
answers() {
	local code
	code=$(curl -sS -o /dev/null -L -I --max-time 30 -w '%{http_code}' "$1" 2>/dev/null || true)
	if [[ "$code" == 2* ]]; then ok "$1"; else bad "$1 (HTTP ${code:-none})"; fi
}

echo "commit $commit"
echo "1. download and checksum"
for f in reinstall.sh trans.sh; do
	curl --proto '=https' -fsSL --max-time 60 -o "$work/$f" "$base/$f" || { bad "download $f"; exit 1; }
done
sha=$(sha256sum "$work/reinstall.sh" | cut -d' ' -f1)
if [[ "$commit" == "$pinned_commit" ]]; then
	if [[ "$sha" == "$pinned_sha" ]]; then ok "reinstall.sh matches reinstallScriptSHA256"; else bad "reinstall.sh is $sha, pinned $pinned_sha"; fi
else
	echo "  note  candidate commit; its reinstall.sh sha256 is $sha"
fi

echo "2. rewrites applied by reinstallPrepScript"
cp "$work/reinstall.sh" "$work/patched.sh"
sed -i -e "s|^confhome=.*|confhome=$base|" \
	-e "s|^confhome_cn=.*|confhome_cn=$base|" \
	-e 's|command curl --insecure |command curl |g' "$work/patched.sh"
if grep -qxF "confhome=$base" "$work/patched.sh"; then ok "confhome points at the commit"; else bad "confhome rewrite did not apply"; fi
if grep -qxF "confhome_cn=$base" "$work/patched.sh"; then ok "confhome_cn points at the commit"; else bad "confhome_cn rewrite did not apply"; fi
if grep -q 'command curl --insecure' "$work/reinstall.sh"; then
	if grep -q 'command curl --insecure' "$work/patched.sh"; then bad "curl --insecure survives the rewrite"; else ok "curl --insecure removed"; fi
else
	echo "  note  upstream no longer passes --insecure to curl; the rewrite and its check can go"
fi
if grep -nE 'curl[^|#]*(--insecure|[[:space:]]-k[[:space:]])' "$work/patched.sh" | grep -v '^[0-9]*:[[:space:]]*#' >"$work/insecure" && [[ -s "$work/insecure" ]]; then
	bad "another curl call skips certificate checks:"
	sed 's/^/          /' "$work/insecure"
else
	ok "no other curl call skips certificate checks"
fi

echo "3. patched script parses"
if bash -n "$work/patched.sh" 2>"$work/syntax"; then ok "bash -n"; else bad "bash -n: $(head -1 "$work/syntax")"; fi

echo "4. flags ansbui passes"
for flag in --ci --hold --ssh-port --ssh-key; do
	if grep -qE "^[[:space:]]*${flag}([[:space:]]|\)|\|)" "$work/reinstall.sh"; then ok "$flag is parsed"; else bad "$flag is not an option any more"; fi
done
if grep -qE '^[[:space:]]*--user([[:space:]]|\)|\|)' "$work/reinstall.sh"; then ok "--user is parsed"; else bad "--user is not an option any more"; fi
# Newer scripts list, per distribution, which options are accepted.
if grep -q '^get_long_opts_linux()' "$work/reinstall.sh"; then
	for d in debian ubuntu; do
		if awk '/^get_long_opts_linux\(\)/,/^}/' "$work/reinstall.sh" | grep -E '^ci[[:space:]]' | grep -qw "$d"; then ok "--ci allowed for $d"; else bad "--ci not allowed for $d"; fi
	done
	for opt in 'user:' 'ssh-key:' 'ssh-port:' 'hold:'; do
		if awk '/^get_long_opts_linux\(\)/,/^}/' "$work/reinstall.sh" | grep -qF "$opt"; then ok "${opt%:} allowed for Linux targets"; else bad "${opt%:} not in the Linux option list"; fi
	done
fi

echo "5. output ansbui parses"
for line in 'IPv4 Address: ' 'IPv4 Gateway: ' 'IPv6 Address: ' 'IPv6 Gateway: '; do
	has "$work/reinstall.sh" "echo \"$line" "prints \"$line…\""
done

echo "6. installer stage (trans.sh)"
if grep -A3 -F 'if [ "$hold" = 2 ]; then' "$work/trans.sh" | grep -q 'info "hold 2"' &&
	grep -A3 -F 'if [ "$hold" = 2 ]; then' "$work/trans.sh" | grep -qx '[[:space:]]*exit'; then
	ok "hold 2 prints its marker and exits without rebooting"
else
	bad "hold 2 no longer prints \"hold 2\" and exits"
fi
has "$work/trans.sh" '***** $msg *****' 'info() wraps messages as ***** MSG *****'
has "$work/trans.sh" '***** ERROR *****' 'error() prints ***** ERROR *****'
has "$work/trans.sh" '/reinstall.log' 'the install log is /reinstall.log'

echo "7. helpers and outside downloads answer"
for f in trans.sh initrd-network.sh fix-eth-name.sh get-xda.sh ttys.sh; do answers "$base/$f"; done
# The location lookup must answer with a loc= line or the script exits.
if curl -sS -L --max-time 20 http://www.qualcomm.cn/cdn-cgi/trace 2>/dev/null | grep -q '^loc='; then ok "location lookup answers"; else bad "location lookup (http://www.qualcomm.cn/cdn-cgi/trace) gave no loc= line"; fi
alpine=$(grep -m1 -oE "'alpine +[0-9.|]+'" "$work/reinstall.sh" | grep -oE '[0-9.]+' | tail -1)
if [[ -n "$alpine" ]]; then
	for f in vmlinuz-virt initramfs-virt modloop-virt; do
		answers "http://dl-cdn.alpinelinux.org/alpine/v$alpine/releases/x86_64/netboot/$f"
	done
else
	bad "cannot tell which Alpine release the installer uses"
fi
# The images for the OS matrix in reinstall.go (amd64).
while read -r codename ver; do
	answers "https://cdimage.debian.org/images/cloud/$codename/latest/debian-$ver-nocloud-amd64.qcow2"
done <<'IMAGES'
trixie 13
bookworm 12
bullseye 11
IMAGES
while read -r codename ver; do
	answers "https://cloud-images.ubuntu.com/releases/$codename/release/ubuntu-$ver-server-cloudimg-amd64.img"
done <<'IMAGES'
resolute 26.04
noble 24.04
jammy 22.04
focal 20.04
IMAGES

echo
if [[ "$failed" = 0 ]]; then
	echo "check-reinstall-pin: every check passed for $commit"
else
	echo "check-reinstall-pin: FAILED for $commit" >&2
	exit 1
fi
