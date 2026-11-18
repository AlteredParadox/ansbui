#!/usr/bin/env python3
"""Regenerates web/vendor/babel-standalone.THIRD-PARTY.txt.

web/vendor/babel.min.js is @babel/standalone: one file that bundles Babel's
own packages together with code from other packages they depend on. The
npm package ships a single MIT licence, Babel's own, which does not cover
those other packages. This script works out which packages are in the
bundle and collects the licence each one ships.

How it knows what is in the bundle: upstream publishes a source map next
to the file (babel.min.js.map). Its "sources" list names every input file
and "sourcesContent" holds each one's text; a path under node_modules/
names a package. Versions come from Babel's yarn.lock at the release tag.
Every candidate version's npm tarball is downloaded and each bundled file
is compared with the text recorded in the source map, so a version is
listed only when the package's files really are the ones in the bundle.

It is a maintenance tool for the moment babel.min.js is replaced, not part
of the build: it downloads from unpkg.com, registry.npmjs.org and
raw.githubusercontent.com, and nothing in CI or `make build` runs it.
Tarballs are read in memory and never unpacked to disk. Standard library
only.

Usage: scripts/babel-bundle-licenses.py <version>
  e.g. scripts/babel-bundle-licenses.py 7.29.14
The version must be the one of the vendored file; the script refuses to
write anything if the upstream file for that version differs from
web/vendor/babel.min.js.
"""

import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "web" / "vendor" / "babel-standalone.THIRD-PARTY.txt"
VENDORED = ROOT / "web" / "vendor" / "babel.min.js"

STANDALONE = "https://unpkg.com/@babel/standalone@{version}/{file}"
LOCK = "https://raw.githubusercontent.com/babel/babel/v{version}/yarn.lock"
TARBALL = "https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"

VERSION = re.compile(r"\d+\.\d+\.\d+")
NPM = "@npm:"
# The alias under which Babel's lockfile carries the version a Babel 7
# build uses, for a package it pins differently for its next major.
ALIAS = "-BABEL_8_BREAKING-false"
PACKAGE_IN_PATH = re.compile(r"node_modules/((?:@[^/]+/)?[^/]+)/")
LOCK_ENTRY = re.compile(
    r'^"?([^\n"]+)"?:\n {2}version: [^\n]+\n {2}resolution: "([^"]+)"', re.M)
LICENSE_NAME = re.compile(r"(LICEN[CS]E|COPYING|NOTICE)[^/]*", re.I)
RULE = "=" * 78

_cache = {}


def fetch(url):
    """Returns the bytes at url (each URL is downloaded once per run)."""
    if url not in _cache:
        req = urllib.request.Request(url, headers={"User-Agent": "curl"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            _cache[url] = resp.read()
    return _cache[url]


def package_files(name, version):
    """{path inside the package: text} read from its npm tarball."""
    url = TARBALL.format(name=urllib.parse.quote(name, safe="@/"),
                         base=name.rsplit("/", 1)[-1], version=version)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(fetch(url)), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            # Members are "package/<path>"; nothing is written to disk.
            path = member.name.split("/", 1)[-1]
            files[path] = tar.extractfile(member).read().decode("utf-8", "replace")
    return files


def bundled_packages(source_map):
    """{package name: [(path inside the package, source text)]}."""
    out = {}
    contents = source_map.get("sourcesContent") or []
    for i, src in enumerate(source_map["sources"]):
        hits = list(PACKAGE_IN_PATH.finditer(src))
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
    for entry in LOCK_ENTRY.finditer(lock_text):
        resolution = entry.group(2)
        if NPM not in resolution:
            continue  # workspace and conditional entries name no tarball
        real, version = resolution.rsplit(NPM, 1)
        for descriptor in entry.group(1).split(", "):
            # "semver@npm:^6.3.1", or for an alias
            # "semver-BABEL_8_BREAKING-false@npm:semver@^6.3.1".
            name = descriptor.strip().split(NPM, 1)[0]
            out.setdefault(name, set()).add((real, version))
    return out


def normalise(text):
    return (text or "").replace("\r\n", "\n").strip()


def matches(bundled, shipped):
    """True if every bundled file equals the package's file of that path."""
    return all(normalise(shipped.get(path)) == normalise(content)
               for path, content in bundled)


def resolve(name, bundled, candidates):
    """(package, [versions], files) for the candidates whose files are the
    bundled ones.

    More than one version is returned only when every bundled file is
    identical in each of them, so the bundle cannot say which was used.
    """
    found = []
    for real, version in sorted(candidates):
        shipped = package_files(real, version)
        if matches(bundled, shipped):
            found.append((real, version, shipped))
    if not found or len({real for real, _, _ in found}) != 1:
        raise SystemExit(f"{name}: none of {sorted(candidates)} has the files that are in the bundle")
    return found[0][0], [version for _, version, _ in found], [shipped for _, _, shipped in found]


def license_texts(shipped):
    """[(file name, text)] for every top-level licence file of a package."""
    return [(path, shipped[path].replace("\r\n", "\n").rstrip("\n") + "\n")
            for path in sorted(shipped) if LICENSE_NAME.fullmatch(path)]


def resolve_all(packages, locked):
    """{(package, (versions...)): (bundled file count, shipped files)}."""
    resolved = {}
    for name, bundled in sorted(packages.items()):
        candidates = locked.get(name, set()) | locked.get(name + ALIAS, set())
        if not candidates:
            raise SystemExit(f"{name}: in the bundle but not in Babel's yarn.lock")
        real, versions, shipped = resolve(name, bundled, candidates)
        texts = [license_texts(files) for files in shipped]
        if not texts[0]:
            raise SystemExit(f"{real}@{versions[0]}: ships no licence file; add its notice by hand")
        if any(t != texts[0] for t in texts):
            raise SystemExit(f"{real}: versions {versions} match the bundle but ship different licence files")
        key = (real, tuple(versions))
        count = resolved[key][0] if key in resolved else 0
        resolved[key] = (count + len(bundled), shipped[0])
    return resolved


def declared_license(shipped):
    declared = json.loads(shipped["package.json"]).get("license")
    if isinstance(declared, dict):
        declared = declared.get("type")
    return declared or "not declared in package.json"


def render(version, resolved):
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
    for (real, versions), (count, shipped) in sorted(resolved.items()):
        shown = " or ".join(versions)
        if len(versions) > 1:
            shown += " (the bundled files are identical in these versions)"
        lines += [RULE, f"{real} {shown}", f"License: {declared_license(shipped)}",
                  f"Files in the bundle: {count}", RULE, ""]
        for fname, text in license_texts(shipped):
            lines += [f"--- {fname} ---", "", text]
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2 or not VERSION.fullmatch(sys.argv[1]):
        raise SystemExit(__doc__)
    version = VERSION.fullmatch(sys.argv[1]).group(0)

    upstream = fetch(STANDALONE.format(version=version, file="babel.min.js"))
    if upstream != VENDORED.read_bytes():
        raise SystemExit(f"{VENDORED.name} is not @babel/standalone {version}: refusing to describe it")

    source_map = json.loads(fetch(STANDALONE.format(version=version, file="babel.min.js.map")))
    locked = lock_versions(fetch(LOCK.format(version=version)).decode())
    resolved = resolve_all(bundled_packages(source_map), locked)

    OUT.write_text(render(version, resolved), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(resolved)} packages")


if __name__ == "__main__":
    main()
