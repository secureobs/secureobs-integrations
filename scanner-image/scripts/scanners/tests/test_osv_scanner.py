"""OSV-Scanner v1.9.2 driver tests, driven by real captured output.

Fixtures in ``fixtures/osv-1.9.2`` were produced by the pinned binary against
the deliberately vulnerable project in ``sca_fixture_project.py`` (see
``fixtures/README.md`` for provenance).
"""
import json
import subprocess
from pathlib import Path

import pytest

from scanners import osv_scanner, tool_output

FIXTURES = Path(__file__).parent / "fixtures" / "osv-1.9.2"
WORKSPACE = "/workspace"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _evidence(finding: dict) -> dict:
    payload = json.loads(finding["rawPayload"])
    assert payload["schema"] == "secureobs.evidence.v1"
    assert payload["kind"] == "sca"
    return payload["sca"]


@pytest.fixture(scope="module")
def mixed():
    return osv_scanner.parse_report(_load("recursive-mixed.json"), WORKSPACE, "proj", "run-1")


def _find(result, package: str, version: str, rule: str) -> dict:
    matches = [f for f in result.findings
               if _evidence(f)["packageName"] == package
               and _evidence(f)["installedVersion"] == version and f["ruleId"] == rule]
    assert len(matches) == 1, f"expected exactly one {package}@{version} {rule}, got {len(matches)}"
    return matches[0]


# ── v1 nested JSON: results[].packages[].vulnerabilities ────────────────────

def test_parses_nested_package_vulnerabilities(mixed):
    # The previous driver iterated results[].vulnerabilities and found nothing.
    assert len(mixed.findings) > 20
    manifests = {_evidence(f)["manifestPath"] for f in mixed.findings}
    assert manifests == {
        "go-svc/go.mod", "java/gradle.lockfile", "java/pom.xml", "requirements.txt",
        "services/worker/poetry.lock", "src/Api/packages.lock.json", "web/package-lock.json",
    }


def test_every_supported_ecosystem_is_reported(mixed):
    ecosystems = {_evidence(f)["ecosystem"] for f in mixed.findings}
    assert {"npm", "PyPI", "NuGet", "Maven", "Go"} <= ecosystems


def test_multiple_packages_per_source_and_multiple_vulns_per_package(mixed):
    web = [f for f in mixed.findings if f["filePath"] == "web/package-lock.json"]
    packages = {(_evidence(f)["packageName"], _evidence(f)["installedVersion"]) for f in web}
    assert {("lodash", "4.17.20"), ("lodash", "4.17.15"), ("async", "2.6.3"), ("minimist", "1.2.5")} <= packages
    lodash_20 = [f for f in web if _evidence(f)["installedVersion"] == "4.17.20"]
    assert len(lodash_20) >= 2


def test_alias_groups_produce_one_finding_with_cve_and_ghsa(mixed):
    finding = _find(mixed, "lodash", "4.17.20", "CVE-2021-23337")
    ev = _evidence(finding)
    assert ev["vulnerabilityId"] == "CVE-2021-23337"
    assert "GHSA-35jh-r3h4-6jhm" in ev["aliases"]
    # OSV grouped GHSA-35jh… with its alias GHSA-r5fr…; they must not become two rows.
    ghsa_rows = [f for f in mixed.findings
                 if "GHSA-r5fr-rjxr-66jc" in _evidence(f).get("aliases", [])
                 and _evidence(f)["installedVersion"] == "4.17.20"]
    assert len(ghsa_rows) == 1


def test_extracts_fix_severity_description_and_advisory(mixed):
    finding = _find(mixed, "org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228")
    ev = _evidence(finding)
    assert finding["severity"] == "CRITICAL"
    assert ev["cvssScore"] == 10.0 and ev["severitySource"] == "osv-max-cvss"
    assert ev["fixedVersions"] == ["2.15.0"] and ev["fixStatus"] == "fixed"
    assert ev["advisoryUrl"] == "https://osv.dev/vulnerability/CVE-2021-44228"
    assert ev["title"] == "Remote code injection in Log4j"
    assert finding["description"].startswith("Remote code injection in Log4j (org.apache.logging.log4j:log4j-core 2.14.1).")
    assert "CWE-502" in finding["cweIds"]
    assert len(finding["description"]) <= 8_192


def test_cvss_vector_is_never_mistaken_for_a_score(mixed):
    # severity[].score is a vector string ("CVSS:3.1/AV:N/…"); the old parser fell
    # back to MEDIUM for every advisory. Severity must follow max_severity.
    finding = _find(mixed, "lodash", "4.17.20", "CVE-2020-28500")
    ev = _evidence(finding)
    assert ev["cvssScore"] == 5.3 and finding["severity"] == "MEDIUM"
    assert ev["cvssVector"].startswith("CVSS:3.1/")


def test_severity_unknown_is_not_invented(mixed):
    unknown = [f for f in mixed.findings if f["severity"] == "UNKNOWN"]
    assert unknown, "fixture contains Go advisories without a published score"
    for f in unknown:
        assert "severity" not in _evidence(f)
        assert "cvssScore" not in _evidence(f)


def test_dependency_scope_dev_and_unknown_relationship(mixed):
    minimist = _find(mixed, "minimist", "1.2.5", "CVE-2021-44906")
    assert _evidence(minimist)["dependencyScope"] == "development"
    # OSV v1 does not report direct vs transitive: it must stay unknown.
    assert "dependencyRelationship" not in _evidence(minimist)
    requests = _find(mixed, "requests", "2.19.0", "CVE-2018-18074")
    assert "dependencyScope" not in _evidence(requests)  # "requirements" is a file group, not a scope


def test_separate_versions_of_one_package_stay_separate(mixed):
    a = _find(mixed, "lodash", "4.17.20", "CVE-2021-23337")
    b = _find(mixed, "lodash", "4.17.15", "CVE-2021-23337")
    assert a["fingerprint"] != b["fingerprint"]


def test_fingerprints_are_stable_across_parses(mixed):
    again = osv_scanner.parse_report(_load("recursive-mixed.json"), WORKSPACE, "proj", "run-2")
    assert [f["fingerprint"] for f in mixed.findings] == [f["fingerprint"] for f in again.findings]
    assert len({f["fingerprint"] for f in mixed.findings}) == len(mixed.findings)


def test_no_purl_is_synthesized(mixed):
    assert all("purl" not in _evidence(f) for f in mixed.findings)


# ── Command line and exit codes ─────────────────────────────────────────────

def test_command_is_recursive_v1_syntax():
    cmd = osv_scanner.build_command("/workspace", "/tmp/out.json")
    assert cmd == ["osv-scanner", "--format", "json", "--output", "/tmp/out.json",
                   "--recursive", "/workspace"]
    assert "scan" not in cmd  # `osv-scanner scan <dir>` is non-recursive in v1.9.2


def test_non_recursive_scan_subcommand_misses_nested_lockfiles():
    # Captured evidence of the old driver bug: only the top-level file was scanned.
    data = _load("non-recursive-scan-subcommand.json")
    assert [r["source"]["path"] for r in data["results"]] == ["/workspace/requirements.txt"]


def test_clean_scan_is_completed_with_zero_findings(tmp_path):
    out = tmp_path / "osv.json"
    out.write_text((FIXTURES / "clean.json").read_text(), encoding="utf-8")
    stderr = _load("cases.json")["clean"]["stderr_tail"]
    result = osv_scanner.interpret(0, stderr, str(out), "/srv/secureobs-fixtures/clean", "p", "r")
    assert result.findings == [] and not result.skipped and not result.not_applicable
    assert result.sources_analyzed == 1


def test_no_manifests_is_not_applicable_not_failure(tmp_path):
    case = _load("cases.json")["no-manifests"]
    assert case["returncode"] == 128 and not case["output_file_written"]
    result = osv_scanner.interpret(case["returncode"], case["stderr_tail"],
                                   str(tmp_path / "missing.json"), "/srv/secureobs-fixtures/no-manifests", "p", "r")
    assert result.not_applicable and result.skipped and result.findings == []
    assert result.sources_analyzed == 0
    assert result.warnings == [osv_scanner.NO_SOURCES_WARNING]


def test_only_lockfile_unparseable_is_a_failure(tmp_path):
    case = _load("cases.json")["malformed-lockfile"]
    with pytest.raises(RuntimeError, match="could not parse any lockfile: web/package-lock.json"):
        osv_scanner.interpret(case["returncode"], case["stderr_tail"], str(tmp_path / "missing.json"),
                              "/srv/secureobs-fixtures/malformed", "p", "r")


def test_partial_parse_failure_keeps_results_and_warns(tmp_path):
    out = tmp_path / "osv.json"
    out.write_text((FIXTURES / "recursive-mixed.json").read_text(), encoding="utf-8")
    stderr = ("Attempted to scan lockfile but failed: /workspace/legacy/package-lock.json\n"
              + _load("cases.json")["recursive-mixed"]["stderr_tail"])
    result = osv_scanner.interpret(1, stderr, str(out), WORKSPACE, "p", "r")
    assert result.findings and not result.skipped
    assert any("legacy/package-lock.json" in w for w in result.warnings)


def test_api_failure_exit_code_is_a_failure_not_a_clean_scan(tmp_path):
    observed = _load("observed-api-failure.json")
    with pytest.raises(RuntimeError, match="could not query the OSV vulnerability API"):
        osv_scanner.interpret(observed["returncode"], observed["stderr_tail"],
                              str(tmp_path / "missing.json"), WORKSPACE, "p", "r")


def test_success_exit_without_output_file_is_a_failure(tmp_path):
    with pytest.raises(tool_output.ToolOutputError, match="wrote no output file"):
        osv_scanner.interpret(1, "", str(tmp_path / "missing.json"), WORKSPACE, "p", "r")


@pytest.mark.parametrize("content", ['{"results": [', "[1, 2]", '{"results": NaN}', ""])
def test_malformed_output_is_a_failure(tmp_path, content):
    out = tmp_path / "osv.json"
    out.write_text(content, encoding="utf-8")
    with pytest.raises(tool_output.ToolOutputError):
        osv_scanner.interpret(0, "", str(out), WORKSPACE, "p", "r")


def test_oversized_output_is_refused(tmp_path, monkeypatch):
    out = tmp_path / "osv.json"
    out.write_text(json.dumps({"results": []}) + " " * 2048, encoding="utf-8")
    monkeypatch.setattr(tool_output, "MAX_TOOL_OUTPUT_BYTES", 1024)
    with pytest.raises(tool_output.ToolOutputError, match="safety limit"):
        osv_scanner.interpret(0, "", str(out), WORKSPACE, "p", "r")


def test_malicious_source_paths_never_leave_the_workspace():
    data = {"results": [
        {"source": {"path": "/etc/passwd", "type": "lockfile"},
         "packages": [{"package": {"name": "x", "version": "1.0.0", "ecosystem": "npm"},
                       "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc"}],
                       "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "aliases": []}]}]},
        {"source": {"path": "/workspace/../../root/.ssh/id_rsa\n", "type": "lockfile"},
         "packages": [{"package": {"name": "y", "version": "1.0.0", "ecosystem": "npm"},
                       "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-dddd"}]}]},
    ]}
    result = osv_scanner.parse_report(data, WORKSPACE, "p", "r")
    assert len(result.findings) == 2
    for f in result.findings:
        assert f["filePath"] is None
        assert "manifestPath" not in _evidence(f)


def test_hostile_strings_are_sanitized():
    data = {"results": [{"source": {"path": "/workspace/package-lock.json"}, "packages": [{
        "package": {"name": "evil\x1b[31m", "version": "1.0.0", "ecosystem": "npm"},
        "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "<script>alert(1)</script>\x00",
                             "references": [{"type": "ADVISORY", "url": "javascript:alert(1)"},
                                            {"type": "ADVISORY", "url": "https://evil.example/advisories/x"}]}],
    }]}]}
    finding = osv_scanner.parse_report(data, WORKSPACE, "p", "r").findings[0]
    ev = _evidence(finding)
    assert ev["packageName"] == "evil"
    assert "\x00" not in ev["title"]
    assert ev.get("references") is None  # neither the javascript: nor the unknown host survives
    assert ev["advisoryUrl"] == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"


def test_run_invokes_real_command_and_interprets(monkeypatch, tmp_path):
    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(cmd, 128, "", "No package sources found, --help for usage information.")

    monkeypatch.setattr(osv_scanner.subprocess, "run", fake_run)
    monkeypatch.setattr(osv_scanner, "_OUTPUT_FILE", str(tmp_path / "osv.json"))
    result = osv_scanner.run(str(tmp_path), "p", "r")
    assert calls["cmd"][-2:] == ["--recursive", str(tmp_path)]
    assert calls["timeout"] == tool_output.TOOL_TIMEOUT_SECONDS
    assert result.not_applicable


@pytest.mark.parametrize("exit_code", [127, 128])
def test_retries_failed_maven_resolution_with_coverage_warning(monkeypatch, tmp_path, exit_code):
    output = tmp_path / "osv.json"
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert not output.exists()
        if len(calls) == 1:
            output.write_text('{"results": []}', encoding="utf-8")
            stderr = "Attempted to scan lockfile but failed: /workspace/java/pom.xml\n"
            return subprocess.CompletedProcess(cmd, exit_code, "", stderr)
        output.write_text((FIXTURES / "recursive-mixed.json").read_text(), encoding="utf-8")
        stderr = "Scanned /workspace/java/pom.xml file and found 2 packages\n"
        return subprocess.CompletedProcess(cmd, 1, "", stderr)

    monkeypatch.setattr(osv_scanner.subprocess, "run", fake_run)
    monkeypatch.setattr(osv_scanner, "_OUTPUT_FILE", str(output))
    result = osv_scanner.run(WORKSPACE, "p", "r")

    assert len(calls) == 2
    assert "--experimental-no-resolve" not in calls[0]
    assert calls[1][-3:] == ["--recursive", "--experimental-no-resolve", WORKSPACE]
    assert _find(result, "org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228")
    assert result.warnings == [osv_scanner.MAVEN_FALLBACK_WARNING]


@pytest.mark.parametrize("manifest, retry_count", [("java/pom.xml", 2), ("package-lock.json", 1)])
def test_unreadable_manifests_still_fail(monkeypatch, tmp_path, manifest, retry_count):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        stderr = f"Attempted to scan lockfile but failed: /workspace/{manifest}\n"
        return subprocess.CompletedProcess(cmd, 127, "", stderr)

    monkeypatch.setattr(osv_scanner.subprocess, "run", fake_run)
    monkeypatch.setattr(osv_scanner, "_OUTPUT_FILE", str(tmp_path / "osv.json"))
    with pytest.raises(RuntimeError, match=f"could not scan lockfile.*{manifest}"):
        osv_scanner.run(WORKSPACE, "p", "r")
    assert len(calls) == retry_count


def test_timeout_is_a_failure(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(osv_scanner.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="exceeded"):
        osv_scanner.run(str(tmp_path), "p", "r")
