# dep-audit

Check your project's dependencies against the [OSV](https://osv.dev)
vulnerability database. Point it at a `requirements.txt` or a
`package-lock.json` and it tells you which exact versions have known, published
vulnerabilities — with the advisory id and the version that fixes each one.

## Why

Most real-world risk in an application is not in the code you wrote; it is in
the hundred packages you depend on. OSV is Google's free, open vulnerability
database that aggregates GitHub advisories, PyPA, the npm registry, and more.
`dep-audit` turns "are any of my pinned dependencies known-vulnerable?" into one
command, with no account and no API key.

It sends only the **package name and version** to OSV — never your code — and it
changes nothing in your project.

## Ecosystems

| Manifest | Ecosystem |
| --- | --- |
| `requirements.txt` (pinned `name==version` lines) | PyPI |
| `package-lock.json` (v1, v2, v3) | npm |

Only exact versions can be audited: OSV answers "is *this* version affected?",
so unpinned (`>=`, `~=`, ranges) requirement lines are skipped.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Audit a Python project
python3 dep_audit.py requirements.txt

# Audit an npm lockfile
python3 dep_audit.py package-lock.json

# Machine-readable
python3 dep_audit.py requirements.txt --json

# Fail CI if anything is HIGH or worse
python3 dep_audit.py requirements.txt --fail-on HIGH

# Ignore the local cache
python3 dep_audit.py requirements.txt --no-cache
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `manifest` | Path to `requirements.txt` or `package-lock.json` | required |
| `--json` | Emit findings as JSON | off |
| `--no-cache` | Bypass the 6-hour local response cache | off |
| `--fail-on` | Exit non-zero at this severity or worse (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) | — |

## Example

```
$ python3 dep_audit.py requirements.txt --fail-on HIGH
Audited 14 package(s): 2 advisory/advisories across 1 package(s).

[HIGH    ] flask==2.0.1  (PyPI)
           GHSA-m2qf-hxjv-5gpq: possible disclosure of a permanent session
           cookie due to a missing Vary: Cookie header
           fix: 2.2.5, 2.3.2
           aka: CVE-2023-30861, PYSEC-2023-62
$ echo $?
1
```

## Caching

Responses are cached for six hours under your system temp directory, keyed by
ecosystem, package, and version. Repeated audits during a triage session do not
re-hit OSV. Use `--no-cache` to force fresh queries.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audited successfully (and `--fail-on`, if set, not reached) |
| `1` | A finding met or exceeded the `--fail-on` severity |
| `2` | The manifest was missing or could not be parsed |
| `3` | An OSV query failed (network or service error) |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Standard-library `unittest`. Network calls are exercised against a local fake
HTTP server, so the suite never contacts OSV.

## License

MIT — see [LICENSE](LICENSE).
