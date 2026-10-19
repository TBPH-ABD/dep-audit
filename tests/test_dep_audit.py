"""Tests for dep-audit: manifest parsing, OSV querying (faked), and CLI."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.request

import dep_audit
from dep_audit import (ManifestError, audit_packages, detect_and_parse,
                       parse_package_lock, parse_requirements, query_osv,
                       summarise_vuln)
from tests.support.fakes import capture_cli, http_fake


def osv_vuln(vuln_id="GHSA-xxxx", summary="A flaw", severity="HIGH",
             fixed="2.0.1", aliases=("CVE-2099-0001",)):
    return {
        "id": vuln_id,
        "summary": summary,
        "database_specific": {"severity": severity},
        "aliases": list(aliases),
        "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": fixed}]}]}],
    }


class RequirementsParsingTests(unittest.TestCase):
    def test_pinned_lines_parsed(self):
        pkgs = parse_requirements("flask==2.0.1\nrequests==2.31.0\n")
        self.assertEqual(len(pkgs), 2)
        self.assertEqual(pkgs[0], {"ecosystem": "PyPI", "name": "flask",
                                   "version": "2.0.1"})

    def test_unpinned_lines_skipped(self):
        pkgs = parse_requirements("flask>=2.0\nrequests\ndjango~=4.2\n")
        self.assertEqual(pkgs, [])

    def test_comments_and_options_skipped(self):
        text = "# deps\n-r other.txt\n--hash=sha256:abc\nflask==2.0.1\n"
        pkgs = parse_requirements(text)
        self.assertEqual(len(pkgs), 1)

    def test_extras_and_markers_tolerated(self):
        pkgs = parse_requirements(
            "uvicorn[standard]==0.23.2 ; python_version>='3.8'\n")
        self.assertEqual(pkgs[0]["name"], "uvicorn")
        self.assertEqual(pkgs[0]["version"], "0.23.2")

    def test_inline_comment_stripped(self):
        pkgs = parse_requirements("flask==2.0.1  # pinned for CVE\n")
        self.assertEqual(pkgs[0]["version"], "2.0.1")


class PackageLockParsingTests(unittest.TestCase):
    def test_v2_packages_parsed(self):
        lock = json.dumps({"packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.20"},
            "node_modules/axios": {"version": "0.21.1"},
        }})
        pkgs = parse_package_lock(lock)
        names = {p["name"]: p["version"] for p in pkgs}
        self.assertEqual(names["lodash"], "4.17.20")
        self.assertEqual(names["axios"], "0.21.1")
        self.assertNotIn("root", names)

    def test_v1_dependencies_parsed(self):
        lock = json.dumps({"dependencies": {
            "lodash": {"version": "4.17.20", "dependencies": {
                "nested": {"version": "1.0.0"}}}}})
        pkgs = parse_package_lock(lock)
        names = {p["name"] for p in pkgs}
        self.assertIn("lodash", names)
        self.assertIn("nested", names)

    def test_duplicates_collapsed(self):
        lock = json.dumps({"packages": {
            "node_modules/a": {"name": "a", "version": "1.0.0"},
            "node_modules/b/node_modules/a": {"name": "a", "version": "1.0.0"},
        }})
        pkgs = parse_package_lock(lock)
        self.assertEqual(len(pkgs), 1)

    def test_invalid_json_raises(self):
        with self.assertRaises(ManifestError):
            parse_package_lock("{not json")


class DetectAndParseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as handle:
            handle.write(content)
        return path

    def test_detects_requirements(self):
        path = self._write("requirements.txt", "flask==2.0.1\n")
        pkgs = detect_and_parse(path)
        self.assertEqual(pkgs[0]["ecosystem"], "PyPI")

    def test_detects_package_lock(self):
        path = self._write("package-lock.json", json.dumps(
            {"packages": {"node_modules/x": {"name": "x", "version": "1.0"}}}))
        pkgs = detect_and_parse(path)
        self.assertEqual(pkgs[0]["ecosystem"], "npm")

    def test_sniffs_json_by_content(self):
        path = self._write("deps.lock", json.dumps(
            {"packages": {"node_modules/x": {"name": "x", "version": "1.0"}}}))
        pkgs = detect_and_parse(path)
        self.assertEqual(pkgs[0]["ecosystem"], "npm")


class SummariseVulnTests(unittest.TestCase):
    def test_extracts_core_fields(self):
        summary = summarise_vuln(osv_vuln(fixed="3.1.0"))
        self.assertEqual(summary["severity"], "HIGH")
        self.assertEqual(summary["fixed"], ["3.1.0"])
        self.assertIn("CVE-2099-0001", summary["aliases"])

    def test_unknown_severity_when_absent(self):
        summary = summarise_vuln({"id": "X", "summary": "y"})
        self.assertEqual(summary["severity"], "UNKNOWN")

    def test_multiple_fixed_versions_deduped_sorted(self):
        vuln = {"id": "X", "affected": [
            {"ranges": [{"events": [{"fixed": "2.0"}]}]},
            {"ranges": [{"events": [{"fixed": "1.5"}, {"fixed": "2.0"}]}]},
        ]}
        self.assertEqual(summarise_vuln(vuln)["fixed"], ["1.5", "2.0"])


class QueryOsvTests(unittest.TestCase):
    def _opener_for(self, base_url):
        def opener(request, timeout=15.0):
            # Redirect the hard-coded OSV URL to the local fake server.
            new_url = base_url + "/v1/query"
            redirected = urllib.request.Request(
                new_url, data=request.data,
                headers=dict(request.header_items()), method="POST")
            return urllib.request.urlopen(redirected, timeout=timeout)
        return opener

    def test_query_returns_vulns(self):
        body = json.dumps({"vulns": [osv_vuln()]})
        with http_fake({"/v1/query": (200, {}, body)}) as (base, _rec):
            result = query_osv({"ecosystem": "PyPI", "name": "flask",
                                "version": "2.0.1"},
                               use_cache=False, opener=self._opener_for(base))
        self.assertEqual(len(result["vulns"]), 1)

    def test_query_sends_package_in_body(self):
        body = json.dumps({"vulns": []})
        with http_fake({"/v1/query": (200, {}, body)}) as (base, recorder):
            query_osv({"ecosystem": "PyPI", "name": "flask",
                       "version": "2.0.1"},
                      use_cache=False, opener=self._opener_for(base))
        self.assertEqual(recorder.requests[0]["method"], "POST")

    def test_http_error_raises_runtime(self):
        with http_fake({"/v1/query": (500, {}, "boom")}) as (base, _rec):
            with self.assertRaises(RuntimeError):
                query_osv({"ecosystem": "PyPI", "name": "x", "version": "1"},
                          use_cache=False, opener=self._opener_for(base))


class AuditPackagesTests(unittest.TestCase):
    def _opener_for(self, base_url):
        def opener(request, timeout=15.0):
            new_url = base_url + "/v1/query"
            redirected = urllib.request.Request(
                new_url, data=request.data,
                headers=dict(request.header_items()), method="POST")
            return urllib.request.urlopen(redirected, timeout=timeout)
        return opener

    def test_findings_tagged_and_sorted(self):
        responses = {
            "/v1/query": [
                (200, {}, json.dumps({"vulns": [osv_vuln(severity="LOW")]})),
                (200, {}, json.dumps(
                    {"vulns": [osv_vuln(severity="CRITICAL")]})),
            ]
        }
        packages = [
            {"ecosystem": "PyPI", "name": "low-pkg", "version": "1.0"},
            {"ecosystem": "PyPI", "name": "crit-pkg", "version": "1.0"},
        ]
        with http_fake(responses) as (base, _rec):
            findings = audit_packages(packages, use_cache=False,
                                      opener=self._opener_for(base))
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["package"], "crit-pkg")

    def test_clean_package_yields_no_findings(self):
        with http_fake({"/v1/query": (200, {}, json.dumps({"vulns": []}))}) \
                as (base, _rec):
            findings = audit_packages(
                [{"ecosystem": "PyPI", "name": "safe", "version": "1.0"}],
                use_cache=False, opener=self._opener_for(base))
        self.assertEqual(findings, [])


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = dep_audit._CACHE_DIR
        dep_audit._CACHE_DIR = self.tmp

    def tearDown(self):
        dep_audit._CACHE_DIR = self._orig

    def _opener_for(self, base_url):
        def opener(request, timeout=15.0):
            redirected = urllib.request.Request(
                base_url + "/v1/query", data=request.data,
                headers=dict(request.header_items()), method="POST")
            return urllib.request.urlopen(redirected, timeout=timeout)
        return opener

    def test_second_query_served_from_cache(self):
        body = json.dumps({"vulns": [osv_vuln()]})
        pkg = {"ecosystem": "PyPI", "name": "flask", "version": "2.0.1"}
        with http_fake({"/v1/query": (200, {}, body)}) as (base, recorder):
            opener = self._opener_for(base)
            query_osv(pkg, use_cache=True, opener=opener)
            query_osv(pkg, use_cache=True, opener=opener)
        # The fake server saw exactly one request; the second hit the cache.
        self.assertEqual(len(recorder.requests), 1)


class SeverityBandTests(unittest.TestCase):
    def test_numeric_score_banded(self):
        self.assertEqual(dep_audit._band_from_cvss_vector("9.8"), "CRITICAL")
        self.assertEqual(dep_audit._band_from_cvss_vector("7.5"), "HIGH")
        self.assertEqual(dep_audit._band_from_cvss_vector("5.0"), "MEDIUM")
        self.assertEqual(dep_audit._band_from_cvss_vector("2.0"), "LOW")

    def test_empty_and_vector_unknown(self):
        self.assertEqual(dep_audit._band_from_cvss_vector(""), "UNKNOWN")
        self.assertEqual(
            dep_audit._band_from_cvss_vector("CVSS:3.1/AV:N/AC:L"), "UNKNOWN")

    def test_severity_derived_from_cvss_entry(self):
        vuln = {"id": "X", "severity": [{"type": "CVSS_V3", "score": "9.1"}]}
        self.assertEqual(summarise_vuln(vuln)["severity"], "CRITICAL")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _run_with_fake(self, manifest_path, response_body, extra_args=None):
        """Run main() with OSV's URL pointed at a local fake."""
        with http_fake({"/v1/query": (200, {}, response_body)}) as (base, _r):
            orig = dep_audit.urllib.request.urlopen
            base_url = base

            def fake_urlopen(request, timeout=15.0):
                redirected = urllib.request.Request(
                    base_url + "/v1/query", data=request.data,
                    headers=dict(request.header_items()), method="POST")
                return orig(redirected, timeout=timeout)

            dep_audit.urllib.request.urlopen = fake_urlopen
            try:
                return capture_cli(dep_audit.main,
                                   [manifest_path, "--no-cache",
                                    *(extra_args or [])])
            finally:
                dep_audit.urllib.request.urlopen = orig

    def test_reports_findings_human(self):
        path = os.path.join(self.tmp, "requirements.txt")
        with open(path, "w") as handle:
            handle.write("flask==2.0.1\n")
        body = json.dumps({"vulns": [osv_vuln(vuln_id="GHSA-abcd")]})
        code, out = self._run_with_fake(path, body)
        self.assertEqual(code, 0)
        self.assertIn("GHSA-abcd", out)

    def test_json_output(self):
        path = os.path.join(self.tmp, "requirements.txt")
        with open(path, "w") as handle:
            handle.write("flask==2.0.1\n")
        body = json.dumps({"vulns": [osv_vuln()]})
        code, out = self._run_with_fake(path, body, ["--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out))

    def test_fail_on_high_exits_one(self):
        path = os.path.join(self.tmp, "requirements.txt")
        with open(path, "w") as handle:
            handle.write("flask==2.0.1\n")
        body = json.dumps({"vulns": [osv_vuln(severity="HIGH")]})
        code, _out = self._run_with_fake(path, body, ["--fail-on", "HIGH"])
        self.assertEqual(code, 1)

    def test_clean_manifest_reports_none(self):
        path = os.path.join(self.tmp, "requirements.txt")
        with open(path, "w") as handle:
            handle.write("flask==2.0.1\n")
        code, out = self._run_with_fake(path, json.dumps({"vulns": []}))
        self.assertEqual(code, 0)
        self.assertIn("no known vulnerabilities", out)

    def test_missing_manifest_exits_two(self):
        code, err = capture_cli(dep_audit.main,
                                [os.path.join(self.tmp, "nope.txt")])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_no_pinned_deps_exits_zero(self):
        path = os.path.join(self.tmp, "requirements.txt")
        with open(path, "w") as handle:
            handle.write("flask>=2.0\n")
        code, _out = capture_cli(dep_audit.main, [path])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
