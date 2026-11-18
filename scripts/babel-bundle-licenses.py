#!/usr/bin/env python3
"""Regenerates web/vendor/babel-standalone.THIRD-PARTY.txt.

web/vendor/babel.min.js is @babel/standalone: one file that bundles Babel's
own packages together with code from other packages they depend on. The
npm package ships a single MIT licence, Babel's own, which does not cover
those other packages. This script works out which packages are in the
bundle and collects the licence each one ships.

How it knows what is in the bundle: upstream publishes a source map next
to the file (babel.min.js.map). Its "sources" list names every input file,
and each path under node_modules/ names a package. Versions come from
Babel's yarn.lock at the release tag; where the lockfile holds several
versions of a package, the one whose file content equals the content
recorded in the source map is taken.

It is a maintenance tool for the moment babel.min.js is replaced, not part
of the build: it downloads from unpkg.com and raw.githubusercontent.com,
and nothing in CI or `make build` runs it. Standard library only.

Usage: scripts/babel-bundle-licenses.py <version> [workdir]
  e.g. scripts/babel-bundle-licenses.py 7.29.14
The version must be the one of the vendored file; the script refuses to
write anything if the upstream file for that version differs from
web/vendor/babel.min.js. Downloads are cached in workdir (default: a
temporary directory), which may be reused between runs.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

UNPKG = "https://unpkg.com/"
LOCK = "https://raw.githubusercontent.com/babel/babel/v{version}/yarn.lock"
OUT = "web/vendor/babel-standalone.THIRD-PARTY.txt"
VENDORED = "web/vendor/babel.min.js"
# Yarn aliases Babel uses to carry two versions of one package side by side.
ALIAS = re.compile(r"-BABEL_8_BREAKING-(true|false)$")
LICENSE_NAME = re.compile(r"^/(LICEN[CS]E|COPYING|NOTICE)[^/]*$", re.I)


def fetch(workdir, url):
    """Returns the bytes at url, cached on disk under workdir."""
    cache = workdir / hashlib.sha256(url.encode()).hexdigest()
    if not cache.exists():
        req = urllib.request.Request(url, headers={"User-Agent": "curl"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            cache.write_bytes(resp.read())
    return cache.read_bytes()


def fetch_ok(workdir, url):
    try:
        return fetch(workdir, url)
    except OSError:
        return None


def unpkg(name, version, path=""):
    return UNPKG + urllib.parse.quote(name, safe="@/") + "@" + version + path


def bundled_packages(source_map):
    """{package name: [(path inside the package, source content)]}."""
    out = {}
    contents = source_map.get("sourcesContent") or []
    for i, src in enumerate(source_map["sources"]):
        hits = list(re.finditer(r"node_modules/((?:@[^/]+/)?[^/]+)/", src))
        if not hits:
            continue  # Babel's own packages, covered by Babel's licence
        last = hits[-1]
        name = last.group(1)
        content = contents[i] if i < len(contents) else None
        # Where Babel carries two versions of a package, the file under
        # the package's own name is a few lines written by Babel's build
        # that pick one of the two aliases. It is not the package.
        if content and f'require("{name}-BABEL_8_BREAKING-' in content:
            continue
        out.setdefault(name, []).append((src[last.end():], content))
    return out


def lock_versions(lock_text):
    """{name as written in the lockfile: {(real package name, version)}}."""
    out = {}
    entry = re.compile(
        r'^"?([^\n"]+)"?:\n  version: [^\n]+\n  resolution: "([^"]+)"', re.M)
    for m in entry.finditer(lock_text):
        resolution = m.group(2)
        if "@npm:" not in resolution:
            continue  # workspace and conditional entries name no tarball
        real, version = resolution.rsplit("@npm:", 1)
        for descriptor in m.group(1).split(", "):
            name = descriptor.strip().rsplit("@", 1)[0]
            if name.endswith("@npm:" + real) or "@npm:" in name:
                name = name.split("@npm:")[0]
            out.setdefault(name, set()).add((real, version))
    return out


def normalise(text):
    return (text or "").replace("\r\n", "\n").strip()


def resolve(workdir, name, files, candidates):
    """The (package, [versions]) whose files equal the source map's content.

    More than one version is returned only when every bundled file is
    identical in each of them, so the bundle cannot say which was used.
    """
    candidates = sorted(candidates)
    if len(candidates) == 1:
        return candidates[0][0], [candidates[0][1]]
    matches = []
    for real, version in candidates:
        ok = True
        for path, content in files:
            body = fetch_ok(workdir, unpkg(real, version, "/" + path))
            if body is None or normalise(body.decode("utf-8", "replace")) != normalise(content):
                ok = False
                break
        if ok:
            matches.append((real, version))
    if not matches or len({real for real, _ in matches}) != 1:
        raise SystemExit(f"{name}: cannot tell which of {candidates} is bundled (matches: {matches})")
    return matches[0][0], [version for _, version in matches]


def license_files(workdir, real, version):
    """[(file name, text)] for every licence file the package ships."""
    meta = json.loads(fetch(workdir, unpkg(real, version, "/?meta")))
    names = sorted(f["path"] for f in meta.get("files", []) if LICENSE_NAME.match(f["path"]))
    out = []
    for path in names:
        text = fetch(workdir, unpkg(real, version, path)).decode("utf-8", "replace")
        out.append((path.lstrip("/"), text.replace("\r\n", "\n").rstrip("\n") + "\n"))
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    version = sys.argv[1]
    root = pathlib.Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True).strip())
    tmp = None
    if len(sys.argv) > 2:
        workdir = pathlib.Path(sys.argv[2])
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory()
        workdir = pathlib.Path(tmp.name)

    upstream = fetch(workdir, unpkg("@babel/standalone", version, "/babel.min.js"))
    if upstream != (root / VENDORED).read_bytes():
        raise SystemExit(f"{VENDORED} is not @babel/standalone {version}: refusing to describe it")

    source_map = json.loads(fetch(workdir, unpkg("@babel/standalone", version, "/babel.min.js.map")))
    packages = bundled_packages(source_map)
    locked = lock_versions(fetch(workdir, LOCK.format(version=version)).decode())

    resolved = {}  # (real name, (versions...)) -> number of bundled files
    for name, files in sorted(packages.items()):
        # A package Babel pins differently for its next major has only a
        # "conditional" lockfile entry under its own name; the version a
        # Babel 7 build uses is listed under the -false alias.
        candidates = locked.get(name, set()) | locked.get(name + "-BABEL_8_BREAKING-false", set())
        if not candidates:
            raise SystemExit(f"{name}: in the bundle but not in Babel's yarn.lock")
        real, versions = resolve(workdir, name, files, candidates)
        key = (real, tuple(versions))
        resolved[key] = resolved.get(key, 0) + len(files)

    lines = [
        f"Third-party packages bundled in web/vendor/babel.min.js (@babel/standalone {version})",
        "",
        "babel.min.js is one file built from Babel's own packages and from the",
        "packages listed here. Babel's own licence is in babel-standalone.LICENSE;",
        "it does not cover these. The list is every package named under",
        "node_modules/ in the source map upstream publishes with the file, at the",
        "version Babel's lockfile for this release resolves it to. Each entry",
        "reproduces the licence file(s) that version of the package ships.",
        "",
        "Generated by scripts/babel-bundle-licenses.py; do not edit by hand.",
        "",
    ]
    for (real, versions), count in sorted(resolved.items()):
        texts = [license_files(workdir, real, v) for v in versions]
        if not texts[0]:
            raise SystemExit(f"{real}@{versions[0]}: ships no licence file; add its notice by hand")
        if any(t != texts[0] for t in texts):
            raise SystemExit(f"{real}: versions {versions} match the bundle but ship different licence files")
        manifest = json.loads(fetch(workdir, unpkg(real, versions[0], "/package.json")))
        declared = manifest.get("license") or "not declared in package.json"
        if isinstance(declared, dict):
            declared = declared.get("type", "not declared in package.json")
        shown = " or ".join(versions)
        if len(versions) > 1:
            shown += " (the bundled files are identical in these versions)"
        lines += ["=" * 78, f"{real} {shown}", f"License: {declared}",
                  f"Files in the bundle: {count}", "=" * 78, ""]
        for fname, text in texts[0]:
            lines += [f"--- {fname} ---", "", text]
    (root / OUT).write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT}: {len(resolved)} packages")
    if tmp:
        tmp.cleanup()


if __name__ == "__main__":
    main()
