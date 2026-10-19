#!/usr/bin/env python3
"""dep-audit - check your project's dependencies against the OSV database.

Parses a dependency manifest or lockfile (Python ``requirements.txt`` with
pinned versions, or an npm ``package-lock.json``), queries the free OSV.dev API
for known vulnerabilities affecting each exact package version, and reports what
it finds with severity, advisory id, and a fixed version when one exists.

OSV (https://osv.dev) is Google's open vulnerability database; the query API
needs no key. Results are cached locally so re-running during a triage session
does not re-hit the service.

This is a read-only supply-chain hygiene tool. It sends only the package name
and version (never your code) to OSV, and it modifies nothing in your project.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

OSV_API_URL = "https://api.osv.dev/v1/query"

_CACHE_DIR = os.path.join(tempfile.gettempdir(), "dep-audit-cache")
_CACHE_TTL = 6 * 3600  # seconds

# OSV severity bands from a CVSS base score, so output can sort worst-first.
HIGH, MEDIUM, LOW, UNKNOWN = "HIGH", "MEDIUM", "LOW", "UNKNOWN"
_RANK = {"CRITICAL": 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4}


class ManifestError(ValueError):
    """Raised when a manifest cannot be parsed."""


# ----------------------------------------------------------------------------
# Manifest parsing
# ----------------------------------------------------------------------------

# A pinned requirement line: name==version, tolerating extras and markers.
_REQ_PIN = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*==\s*"
    r"([A-Za-z0-9._+!-]+)\s*(?:;.*)?$")


def parse_requirements(text: str) -> list[dict]:
    """Parse pinned (``==``) lines from a pip requirements file.

    Unpinned lines, comments, options (``-r``, ``--hash``), and blank lines are
    skipped; only exact versions can be checked against OSV.
    """
    packages: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Drop an inline hash/comment tail before matching.
        line = line.split(" #", 1)[0].strip()
        match = _REQ_PIN.match(line)
        if match:
            packages.append({"ecosystem": "PyPI",
                             "name": match.group(1),
                             "version": match.group(2)})
    return packages


def parse_package_lock(text: str) -> list[dict]:
    """Parse an npm ``package-lock.json`` (v1, v2, or v3) into packages."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid package-lock.json: {exc}") from exc

    packages: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str) -> None:
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            packages.append({"ecosystem": "npm", "name": name,
                             "version": version})

    # lockfile v2/v3: "packages" keyed by install path.
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue  # "" is the root project itself.
        name = meta.get("name") or path.split("node_modules/")[-1]
        add(name, meta.get("version"))

    # lockfile v1: nested "dependencies".
    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                add(name, meta.get("version"))
                walk(meta.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return packages


def detect_and_parse(path: str) -> list[dict]:
    """Choose a parser from the filename and parse the manifest at ``path``."""
    base = os.path.basename(path).lower()
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if base == "package-lock.json":
        return parse_package_lock(text)
    if base.endswith(".txt") or "require" in base:
        return parse_requirements(text)
    # Fall back to content sniffing.
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return parse_package_lock(text)
    return parse_requirements(text)


# ----------------------------------------------------------------------------
# OSV querying
# ----------------------------------------------------------------------------

def _cache_path(ecosystem: str, name: str, version: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{ecosystem}-{name}-{version}")
    return os.path.join(_CACHE_DIR, f"{safe}.json")


def _read_cache(path: str):
    try:
        if time.time() - os.path.getmtime(path) < _CACHE_TTL:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return None


def _write_cache(path: str, payload) -> None:
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
    except OSError:
        pass  # a cache write failure must never break the audit.


def query_osv(package: dict, *, use_cache: bool = True,
              opener=None, timeout: float = 15.0) -> dict:
    """Query OSV for one package version; return the raw response dict.

    ``opener`` is injectable so tests drive this against a local fake server.
    """
    # Resolve the opener at call time so a monkeypatched urlopen is honoured.
    opener = opener or urllib.request.urlopen
    cache_file = _cache_path(package["ecosystem"], package["name"],
                             package["version"])
    if use_cache:
        cached = _read_cache(cache_file)
        if cached is not None:
            return cached

    body = json.dumps({
        "version": package["version"],
        "package": {"name": package["name"],
                    "ecosystem": package["ecosystem"]},
    }).encode("utf-8")
    request = urllib.request.Request(
        OSV_API_URL, data=body,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json"},
        method="POST")

    try:
        with opener(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # HTTPError is also a response object holding an open buffer; close it
        # or the interpreter emits a ResourceWarning (fatal under -W error).
        exc.close()
        raise RuntimeError(
            f"OSV returned HTTP {exc.code} for {package['name']}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"OSV query failed for {package['name']}: {exc}") from exc

    if use_cache:
        _write_cache(cache_file, payload)
    return payload


def _severity_from_vuln(vuln: dict) -> str:
    """Map an OSV vulnerability to a coarse severity band."""
    # Prefer a database_specific severity label when present.
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in _RANK:
        return label.upper()
    # Otherwise derive a band from a CVSS vector's base score if we can.
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score", "")
        band = _band_from_cvss_vector(score)
        if band != UNKNOWN:
            return band
    return UNKNOWN


_CVSS_BASE = re.compile(r"/?\b(\d+(?:\.\d+)?)\b")


def _band_from_cvss_vector(vector: str) -> str:
    """Very small CVSS-to-band mapping; only used when OSV gives no label.

    OSV severity scores are CVSS vector strings, not numbers, so we cannot read
    a base score directly without a full CVSS calculator. We keep this simple:
    an unparsable or vector-only value yields UNKNOWN, which is honest.
    """
    if not vector:
        return UNKNOWN
    # A bare numeric score (some sources emit one) can be banded.
    try:
        value = float(vector)
    except (TypeError, ValueError):
        return UNKNOWN
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return HIGH
    if value >= 4.0:
        return MEDIUM
    if value > 0:
        return LOW
    return UNKNOWN


def _fixed_versions(vuln: dict) -> list[str]:
    """Extract the 'fixed' versions from a vuln's affected ranges."""
    fixes: list[str] = []
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    fixes.append(event["fixed"])
    return sorted(set(fixes))


def summarise_vuln(vuln: dict) -> dict:
    """Reduce a raw OSV vuln record to the fields a report needs."""
    return {
        "id": vuln.get("id", "UNKNOWN"),
        "summary": vuln.get("summary") or vuln.get("details", "")[:120],
        "severity": _severity_from_vuln(vuln),
        "fixed": _fixed_versions(vuln),
        "aliases": vuln.get("aliases", []) or [],
    }


def audit_packages(packages: list[dict], *, use_cache: bool = True,
                   opener=None) -> list[dict]:
    """Audit every package, returning findings sorted worst-first."""
    findings: list[dict] = []
    for package in packages:
        response = query_osv(package, use_cache=use_cache, opener=opener)
        for vuln in response.get("vulns", []) or []:
            summary = summarise_vuln(vuln)
            summary["package"] = package["name"]
            summary["version"] = package["version"]
            summary["ecosystem"] = package["ecosystem"]
            findings.append(summary)
    findings.sort(key=lambda f: (_RANK.get(f["severity"], 9), f["package"]))
    return findings


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _print_human(findings: list[dict], package_count: int) -> None:
    if not findings:
        print(f"Audited {package_count} package(s): no known vulnerabilities.")
        return
    affected = len({(f["package"], f["version"]) for f in findings})
    print(f"Audited {package_count} package(s): "
          f"{len(findings)} advisory/advisories across {affected} package(s).\n")
    for finding in findings:
        fixed = ", ".join(finding["fixed"]) if finding["fixed"] \
            else "no fixed version listed"
        print(f"[{finding['severity']:<8}] {finding['package']}"
              f"=={finding['version']}  ({finding['ecosystem']})")
        print(f"           {finding['id']}: {finding['summary']}")
        print(f"           fix: {fixed}")
        if finding["aliases"]:
            print(f"           aka: {', '.join(finding['aliases'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-audit",
        description="Check pinned dependencies against the OSV vulnerability "
                    "database (read-only).")
    parser.add_argument(
        "manifest",
        help="path to requirements.txt (pinned) or package-lock.json")
    parser.add_argument(
        "--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--no-cache", action="store_true",
        help="ignore and bypass the local response cache")
    parser.add_argument(
        "--fail-on", choices=["CRITICAL", HIGH, MEDIUM, LOW],
        help="exit non-zero if any finding is at this severity or worse")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.manifest):
        print(f"error: manifest not found: {args.manifest}", file=sys.stderr)
        return 2
    try:
        packages = detect_and_parse(args.manifest)
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not packages:
        print("No pinned dependencies found to audit. OSV needs exact "
              "versions (name==version / a lockfile).", file=sys.stderr)
        return 0

    try:
        findings = audit_packages(packages, use_cache=not args.no_cache)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        _print_human(findings, len(packages))

    if args.fail_on:
        threshold = _RANK[args.fail_on]
        if any(_RANK.get(f["severity"], 9) <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
