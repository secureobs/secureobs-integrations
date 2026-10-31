"""Trivy 0.70.0 driver tests, driven by real captured output (fixtures/trivy-0.70.0)."""
import json
import subprocess
from pathlib import Path

import pytest

from scanners import sca, tool_output, trivy

FIXTURES = Path(__file__).parent / "fixtures" / "trivy-0.70.0"
WORKSPACE = "/workspace"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _payload(finding: dict) -> dict:
    payload = json.loads(finding["rawPayload"])
    assert payload["schema"] == "secureobs.evidence.v1"
    return payload


@pytest.fixture(scope="module")
def mixed():
    return trivy.parse_report(_load("fs-mixed.json"), WORKSPACE, "proj", "run-1")


def _by_kind(result, kind):
    return [f for f in result.findings if _payload(f)["kind"] == kind]


def _sca(result, package, version, rule):
    rows = [f for f in _by_kind(result, "sca")
            if _payload(f)["sca"]["packageName"] == package
            and _payload(f)["sca"]["installedVersion"] == version and f["ruleId"] == rule]
    assert len(rows) == 1
    return rows[0], _payload(rows[0])["sca"]


# ── Category separation ─────────────────────────────────────────────────────

def test_mixed_output_keeps_sca_iac_and_secrets_apart(mixed):
    kinds = {_payload(f)["kind"] for f in mixed.findings}
    assert kinds == {"sca", "iac", "secret"}
    assert {f["ruleId"] for f in _by_kind(mixed, "iac")} == {"DS-0001", "DS-0002", "DS-0026"}
    assert [f["ruleId"] for f in _by_kind(mixed, "secret")] == ["github-pat"]
    assert mixed.sources_analyzed == 7 and mixed.warnings == []


def test_secret_value_is_never_in_sca_metadata_or_evidence(mixed):
    secret = _by_kind(mixed, "secret")[0]
    body = _payload(secret)["secret"]
    assert set(body) == {"ruleId", "category", "title", "detectedBy"}
    # Trivy masks the value itself; the snippet keeps that masked form only.
    assert secret["codeSnippet"] == "GITHUB_TOKEN=****************************************"
    for f in mixed.findings:
        assert "ghp_" not in json.dumps(f)


def test_misconfiguration_payload_drops_ansi_highlighted_code(mixed):
    for f in _by_kind(mixed, "iac"):
        raw = f["rawPayload"]
        assert "\u001b" not in raw and "Code" not in raw
    ds001 = next(f for f in _by_kind(mixed, "iac") if f["ruleId"] == "DS-0001")
    assert ds001["startLine"] == 1  # Trivy 0.70 reports CauseMetadata.StartLine


# ── SCA evidence ────────────────────────────────────────────────────────────

def test_vulnerability_with_known_fix(mixed):
    finding, ev = _sca(mixed, "Newtonsoft.Json", "12.0.1", "CVE-2024-21907")
    assert finding["filePath"] == "src/Api/packages.lock.json"
    assert ev["ecosystem"] == "NuGet"
    assert ev["fixedVersions"] == ["13.0.1"] and ev["fixStatus"] == "fixed"
    assert ev["aliases"] == ["GHSA-5crp-9r3c-p9vr"]
    assert ev["purl"] == "pkg:nuget/Newtonsoft.Json@12.0.1"
    assert ev["dependencyRelationship"] == "direct"
    assert ev["severity"] == "HIGH" and finding["severity"] == "HIGH"
    assert ev["advisoryUrl"] == "https://osv.dev/vulnerability/CVE-2024-21907"
    assert finding["startLine"] == 5 and finding["endLine"] == 10


def test_transitive_relationship_is_reported_when_known(mixed):
    _, ev = _sca(mixed, "System.Text.Encodings.Web", "4.5.0", "CVE-2021-26701")
    assert ev["dependencyRelationship"] == "transitive"


def test_relationship_stays_unknown_when_trivy_does_not_report_it(mixed):
    # pip and gradle lockfile analyzers emit no Relationship.
    _, ev = _sca(mixed, "requests", "2.19.0", "CVE-2018-18074")
    assert "dependencyRelationship" not in ev
    gradle = [_payload(f)["sca"] for f in _by_kind(mixed, "sca") if f["filePath"] == "java/gradle.lockfile"]
    assert gradle and all("dependencyRelationship" not in ev for ev in gradle)


def test_vulnerability_without_known_fix():
    data = _load("fs-mixed.json")
    vuln = data["Results"][0]["Vulnerabilities"][0]
    vuln.pop("FixedVersion", None)
    vuln["Status"] = "affected"
    result = trivy.parse_report(data, WORKSPACE, "p", "r")
    ev = _payload(result.findings[0])["sca"]
    assert ev["fixStatus"] == "no_fix" and "fixedVersions" not in ev


def test_fix_status_unknown_is_not_reported_as_no_fix():
    data = _load("fs-mixed.json")
    vuln = data["Results"][0]["Vulnerabilities"][0]
    vuln.pop("FixedVersion", None)
    vuln.pop("Status", None)
    ev = _payload(trivy.parse_report(data, WORKSPACE, "p", "r").findings[0])["sca"]
    assert ev["fixStatus"] == "unknown"


def test_fixed_versions_on_older_release_lines_are_dropped(mixed):
    rows = [_payload(f)["sca"] for f in _by_kind(mixed, "sca")
            if _payload(f)["sca"]["packageName"] == "com.fasterxml.jackson.core:jackson-databind"
            and f["ruleId"] == "CVE-2019-14379"]
    # Trivy reports "2.9.9.2, 2.8.11.4, 2.7.9.6"; only 2.9.9.2 upgrades 2.9.8.
    assert rows and rows[0]["fixedVersions"] == ["2.9.9.2"]


def test_go_and_python_identity_normalization(mixed):
    _, go = _sca(mixed, "golang.org/x/text", "v0.3.5", "CVE-2021-38561")
    assert go["ecosystem"] == "Go"
    rec = sca.ScaRecord(tool="trivy", ecosystem="Go", package_name="golang.org/x/text",
                        installed_version="v0.3.5", manifest_path="go-svc/go.mod",
                        vulnerability_id="CVE-2021-38561")
    assert rec.identity() == ("go", "golang.org/x/text", "0.3.5", "go-svc/go.mod", "CVE-2021-38561")
    _, py = _sca(mixed, "PyYAML", "5.3", "CVE-2020-14343")
    assert py["ecosystem"] == "PyPI" and py["purl"] == "pkg:pypi/pyyaml@5.3"


def test_score_and_vector_from_the_severity_source(mixed):
    _, ev = _sca(mixed, "lodash", "4.17.15", "CVE-2020-8203")
    assert ev["severitySource"] == "ghsa" and ev["cvssScore"] == 7.4
    assert ev["cvssVector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"


def test_unknown_severity_is_passed_through_not_invented():
    data = _load("fs-mixed.json")
    vuln = data["Results"][0]["Vulnerabilities"][0]
    vuln["Severity"] = "UNKNOWN"
    vuln.pop("CVSS", None)
    finding = trivy.parse_report(data, WORKSPACE, "p", "r").findings[0]
    ev = _payload(finding)["sca"]
    assert finding["severity"] == "UNKNOWN"
    assert "severity" not in ev and "cvssScore" not in ev


def test_advisory_links_are_https_and_allowlisted(mixed):
    for f in _by_kind(mixed, "sca"):
        ev = _payload(f)["sca"]
        for url in [ev["advisoryUrl"], *ev.get("references", [])]:
            assert url.startswith("https://")
            assert "github.com/lodash" not in url  # project pages are not advisories


def test_payloads_and_descriptions_respect_api_limits(mixed):
    for f in mixed.findings:
        assert len(f["rawPayload"]) <= 65_536
        json.loads(f["rawPayload"])  # never truncated mid-JSON
        assert len(f["description"]) <= 8_192


# ── Fingerprints ────────────────────────────────────────────────────────────

def test_legacy_fingerprint_is_preserved_for_existing_findings(mixed):
    finding, _ = _sca(mixed, "lodash", "4.17.20", "CVE-2021-23337")
    # Formula used by every previous image: (trivy, vuln, id, "pkg@ver (target)", pkg, ver).
    expected = sca.fingerprint("trivy", "vuln", "CVE-2021-23337",
                               "lodash@4.17.20 (web/package-lock.json)", "lodash", "4.17.20")
    assert finding["fingerprint"] == expected


def test_fingerprints_stable_and_distinct_for_package_versions(mixed):
    again = trivy.parse_report(_load("fs-mixed.json"), WORKSPACE, "proj", "run-2")
    assert [f["fingerprint"] for f in mixed.findings] == [f["fingerprint"] for f in again.findings]
    a, _ = _sca(mixed, "lodash", "4.17.20", "CVE-2021-23337")
    b, _ = _sca(mixed, "lodash", "4.17.15", "CVE-2021-23337")
    assert a["fingerprint"] != b["fingerprint"]


# ── Outcomes ────────────────────────────────────────────────────────────────

def test_clean_lockfile_is_zero_findings_with_one_source():
    result = trivy.parse_report(_load("fs-clean.json"), "/srv/secureobs-fixtures/clean", "p", "r")
    assert result.findings == [] and result.sources_analyzed == 1 and result.warnings == []


def test_no_manifests_warns_and_reports_zero_sources():
    result = trivy.parse_report(_load("fs-no-manifests.json"), "/srv/secureobs-fixtures/no-manifests", "p", "r")
    assert result.findings == [] and result.sources_analyzed == 0
    assert result.warnings == [trivy.NO_SOURCES_WARNING]


@pytest.mark.parametrize("data", [[], "x", {"Results": "nope"}])
def test_malformed_report_is_a_failure(data):
    with pytest.raises(tool_output.ToolOutputError):
        trivy.parse_report(data, WORKSPACE, "p", "r")


def test_tool_error_exit_code_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(trivy.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 2, "", "FATAL \x1b[31mdb error\x1b[0m"))
    with pytest.raises(RuntimeError, match="unexpected code 2: FATAL db error"):
        trivy.run(str(tmp_path), "p", "r")


def test_success_without_output_is_a_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(trivy, "_OUT", str(tmp_path / "missing.json"))
    monkeypatch.setattr(trivy.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))
    with pytest.raises(tool_output.ToolOutputError):
        trivy.run(str(tmp_path), "p", "r")


def test_oversized_output_is_refused(monkeypatch, tmp_path):
    out = tmp_path / "trivy.json"
    monkeypatch.setattr(trivy, "_OUT", str(out))
    monkeypatch.setattr(tool_output, "MAX_TOOL_OUTPUT_BYTES", 1024)

    def fake_trivy(cmd, **kw):
        out.write_text(json.dumps({"Results": []}) + " " * 4096, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(trivy.subprocess, "run", fake_trivy)
    with pytest.raises(tool_output.ToolOutputError, match="safety limit"):
        trivy.run(str(tmp_path), "p", "r")


def test_paths_outside_workspace_are_not_reported_as_manifests():
    data = _load("fs-mixed.json")
    data["Results"][0]["Target"] = "../../../etc/passwd"
    finding = trivy.parse_report(data, WORKSPACE, "p", "r").findings[0]
    assert "manifestPath" not in _payload(finding)["sca"]
