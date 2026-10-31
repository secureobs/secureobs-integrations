"""import-iast: validation, sanitization, normalization and CLI exit codes.

Fixtures are synthetic SARIF 2.1.0 (see fixtures/README.md). Hostile values are
assembled at runtime so the repository's own secret scanners never flag them.
"""
import argparse
import json
import os
from pathlib import Path

import pytest
import requests

import api_client
from iast import command, providers, redact, sarif

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT = "11111111-1111-1111-1111-111111111111"

# Assembled at runtime: credential-shaped strings that must never survive.
FAKE_JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTYifQ" + ".c2lnbmF0dXJlLXZhbHVl"
FAKE_GH = "gh" + "p_" + "Q" * 36
FAKE_PASSWORD = "hunter" + "2-very-secret"
FAKE_CARD = "4111" + "1111" + "1111" + "1111"
FAKE_COOKIE = "sess" + "ion=topsecretcookievalue"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _build(report, provider="sarif", **kw):
    return sarif.build_findings(report, provider, PROJECT, "run-1", **kw)


def _ev(finding: dict) -> dict:
    payload = json.loads(finding["rawPayload"])
    assert payload["schema"] == "secureobs.evidence.v1" and payload["kind"] == "iast"
    return payload["iast"]


def _hostile_report() -> dict:
    report = _load("valid-generic.sarif")
    result = report["runs"][0]["results"][0]
    result["message"]["text"] = (
        f"Payload reached sink. Authorization: Bearer {FAKE_JWT} cookie: {FAKE_COOKIE} "
        f"password={FAKE_PASSWORD} token {FAKE_GH} card {FAKE_CARD} <script>alert(1)</script>\x1b[31m"
        " see https://api.internal/x?apikey=abc123")
    result["webRequest"] = {
        "method": "post",
        "target": f"https://alice:{FAKE_PASSWORD}@shop.internal:8443/api/reset/{FAKE_JWT}/users/42"
                  f"/{'a' * 40}?token={FAKE_GH}#frag",
        "headers": {"Authorization": f"Bearer {FAKE_JWT}", "Cookie": FAKE_COOKIE},
        "body": {"text": json.dumps({"password": FAKE_PASSWORD, "card": FAKE_CARD})},
        "parameters": {"token": FAKE_GH},
    }
    result["webResponse"] = {"headers": {"Set-Cookie": FAKE_COOKIE}, "body": {"text": FAKE_PASSWORD}}
    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "../../../../etc/passwd"
    rule = report["runs"][0]["tool"]["driver"]["rules"][0]
    rule["helpUri"] = "javascript:alert(document.cookie)"
    rule["help"]["text"] = f"Fix it <b>now</b>; never log {FAKE_JWT}."
    return report


# ── Valid import ───────────────────────────────────────────────────────────

def test_valid_report_imports_runtime_findings_only():
    imported = _build(_load("valid-generic.sarif"))
    assert imported.tool_name == "ExampleIAST Agent" and imported.tool_version == "4.2.0"
    assert imported.total_results == 4
    assert len(imported.findings) == 2                  # SQLi + XSS
    assert imported.skipped_no_runtime_evidence == 1    # weak-hash has no request
    assert imported.skipped_not_findings == 1           # kind: pass
    assert imported.test_session == "nightly-integration-tests/2026-10-14"
    assert any("no runtime evidence" in w for w in imported.warnings)


def test_sql_injection_finding_details():
    finding = _build(_load("valid-generic.sarif")).findings[0]
    ev = _ev(finding)
    assert finding["scanner"] == "iast" and finding["ruleId"] == "sql-injection"
    assert finding["severity"] == "CRITICAL" and ev["severitySource"] == "security-severity"
    assert finding["cweIds"] == ["CWE-89"]
    assert ev["method"] == "POST"
    assert ev["route"] == "/api/users/{id}/orders/{uuid}"     # no host, query, fragment, IDs
    assert ev["testingMethod"] == "IAST" and ev["provider"] == "sarif" and ev["providerVerified"] is True
    assert ev["category"] == "SqlInjection"
    assert ev["codePath"] == "app/src/Orders/OrderRepository.cs"
    assert (finding["filePath"], finding["startLine"], finding["endLine"]) == \
        ("app/src/Orders/OrderRepository.cs", 57, 59)
    assert ev["codeFunction"] == "Shop.Orders.OrderRepository.FindById"
    assert [s.get("kinds") for s in ev["flow"]] == [["source"], None, ["sink"]]
    assert ev["flow"][0]["location"] == "src/Orders/OrdersController.cs:22"
    assert ev["remediation"].startswith("Use parameterized queries")
    assert ev["helpUrl"] == "https://iast.example.com/rules/sql-injection"  # query/fragment dropped
    assert ev["firstObservedAt"] == "2026-10-13T08:00:00Z"
    assert ev["lastObservedAt"] == "2026-10-14T02:15:30Z"
    assert ev["vendorFindingId"] == "6f1c2a8e-3b9d-4e7f-a1c2-0d9e8f7a6b5c"
    assert finding["description"].startswith("SQL injection at POST /api/users/{id}/orders/{uuid}.")


def test_finding_without_source_line_shows_runtime_location_not_a_fake_path():
    xss = _build(_load("valid-generic.sarif")).findings[1]
    ev = _ev(xss)
    assert xss["filePath"] is None and xss["startLine"] is None
    assert "codePath" not in ev
    # Route resolved through run.webRequests[0] (webRequest.index reference).
    assert ev["method"] == "GET" and ev["route"] == "/api/orders/{id}/items"
    assert xss["severity"] == "MEDIUM" and ev["severitySource"] == "sarif-level"
    assert xss["cweIds"] == ["CWE-79"]


def test_request_and_response_bodies_headers_and_params_never_leave_the_job():
    blob = json.dumps(_build(_load("valid-generic.sarif")).findings)
    for forbidden in ("X-Request-Id", "req-0001", "quantity", "page=2", "sort=desc", "frag",
                      "shop.test.internal", "8443", "webResponse", '"headers"', "parameters"):
        assert forbidden not in blob


def test_sensitive_runtime_data_is_redacted():
    imported = _build(_hostile_report())
    blob = json.dumps(imported.findings)
    for secret in (FAKE_JWT, FAKE_GH, FAKE_PASSWORD, FAKE_CARD, "topsecretcookievalue", "alice",
                   "abc123", "<script>", "<b>", "\x1b", "javascript:", "etc/passwd", "a" * 40):
        assert secret not in blob, secret
    ev = _ev(imported.findings[0])
    assert ev["route"] == "/api/reset/{token}/users/{id}/{token}"
    assert "helpUrl" not in ev
    assert "codePath" not in ev and imported.findings[0]["filePath"] is None
    assert "[redacted jwt]" in ev["message"] and "password=[redacted]" in ev["message"]


def test_zero_findings_report_is_a_successful_import():
    imported = _build(_load("zero-results.sarif"))
    assert imported.findings == [] and imported.total_results == 0
    assert imported.test_session == "pr-checks/1234"


def test_repeated_imports_produce_identical_fingerprints():
    first = _build(_load("valid-generic.sarif"))
    second = _build(_load("valid-generic.sarif"))
    assert [f["fingerprint"] for f in first.findings] == [f["fingerprint"] for f in second.findings]
    assert len({f["fingerprint"] for f in first.findings}) == 2


def test_identity_without_vendor_id_uses_route_template():
    report = _load("valid-generic.sarif")
    result = report["runs"][0]["results"][0]
    del result["correlationGuid"]
    a = _build(report).findings[0]["fingerprint"]
    result["webRequest"]["target"] = "/api/users/77/orders/0e0e0e0e-1111-2222-3333-444444444444"
    b = _build(report).findings[0]["fingerprint"]
    result["webRequest"]["target"] = "/api/admins/77/orders/x"
    c = _build(report).findings[0]["fingerprint"]
    assert a == b       # same route template, different IDs
    assert a != c       # different route


def test_cli_test_session_overrides_report_value():
    imported = _build(_load("valid-generic.sarif"), test_session_id="gh run 99 / attempt 1",
                      environment="ci\nstaging")
    ev = _ev(imported.findings[0])
    assert ev["testSession"] == "gh-run-99-/-attempt-1"
    assert ev["environment"] == "ci staging"


# ── Rejections ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,match", [
    ("static-semgrep.sarif", "static/dependency/DAST tool"),
    ("no-runtime-evidence.sarif", "carry runtime evidence"),
    ("wrong-version.sarif", "only 2.1.0"),
    ("results-null.sarif", "did not run"),
])
def test_misleading_or_unsupported_reports_are_rejected(name, match):
    with pytest.raises(sarif.ReportRejected, match=match):
        _build(_load(name))


@pytest.mark.parametrize("report,match", [
    ([], "not a SARIF log"),
    ({"version": "2.1.0"}, "no runs"),
    ({"version": "2.1.0", "runs": []}, "no runs"),
    ({"version": "2.1.0", "$schema": "https://example.com/other.json", "runs": [{}]}, "SARIF schema"),
    ({"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": []}]}, "unknown"),
    ({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "OWASP ZAP"}}, "results": []}]}, "DAST"),
    ({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "X", "fullName": "CodeQL"}}, "results": []}]}, "static"),
    ({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "A"}}, "results": []},
                                   {"tool": {"driver": {"name": "B"}}, "results": []}]}, "same engine"),
    ({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "A"}}, "results": "x"}]}, "not an array"),
])
def test_structural_rejections(report, match):
    with pytest.raises(sarif.ReportRejected, match=match):
        _build(report)


def test_unknown_provider_and_provider_mismatch():
    with pytest.raises(sarif.ReportRejected, match="unsupported provider"):
        _build(_load("valid-generic.sarif"), provider="acme")
    with pytest.raises(sarif.ReportRejected, match="does not match provider 'contrast'"):
        _build(_load("valid-generic.sarif"), provider="contrast")


def test_contrast_provider_is_labelled_unverified():
    report = _load("valid-generic.sarif")
    report["runs"][0]["tool"]["driver"]["name"] = "Contrast Assess"
    ev = _ev(_build(report, provider="contrast").findings[0])
    assert ev["provider"] == "contrast" and ev["providerVerified"] is False
    assert providers.PROVIDERS["contrast"].verified is False


def test_too_many_results_rejected(monkeypatch):
    monkeypatch.setattr(sarif, "MAX_RESULTS", 2)
    with pytest.raises(sarif.ReportRejected, match="more than 2 results"):
        _build(_load("valid-generic.sarif"))


def test_missing_and_unreadable_report_files(tmp_path):
    with pytest.raises(sarif.ReportMissing):
        sarif.load_report(str(tmp_path / "nope.sarif"))
    with pytest.raises(sarif.ReportRejected, match="not a regular file"):
        sarif.load_report(str(tmp_path))
    empty = tmp_path / "empty.sarif"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(sarif.ReportRejected, match="empty"):
        sarif.load_report(str(empty))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "pipe.sarif"
    os.mkfifo(fifo)
    with pytest.raises(sarif.ReportRejected, match="not a regular file"):
        sarif.load_report(str(fifo))


@pytest.mark.parametrize("content", ['{"version": "2.1.0", "runs": [', '{"version": NaN}', "\xff\xfe"])
def test_malformed_json_rejected(tmp_path, content):
    f = tmp_path / "bad.sarif"
    f.write_bytes(content.encode("latin-1"))
    with pytest.raises(sarif.ReportRejected, match="not valid JSON"):
        sarif.load_report(str(f))


def test_oversized_report_rejected_before_parsing(tmp_path):
    f = tmp_path / "big.sarif"
    f.write_text(json.dumps(_load("valid-generic.sarif")) + " " * 4096, encoding="utf-8")
    with pytest.raises(sarif.ReportRejected, match="above the 2048-byte limit"):
        sarif.load_report(str(f), max_bytes=2048)


def test_deeply_nested_json_is_rejected_not_crashing(tmp_path):
    f = tmp_path / "deep.sarif"
    f.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(sarif.ReportRejected):
        sarif.load_report(str(f))


@pytest.mark.parametrize("container", ["array", "object"])
def test_json_nesting_limit_boundary(tmp_path, container):
    f = tmp_path / "depth.sarif"
    opening, closing = ("[", "]") if container == "array" else ('{"a":', "}")
    f.write_text(opening * sarif.MAX_JSON_DEPTH + "0" + closing * sarif.MAX_JSON_DEPTH)
    assert sarif.load_report(str(f)) is not None
    f.write_text(opening * (sarif.MAX_JSON_DEPTH + 1) + "0" + closing * (sarif.MAX_JSON_DEPTH + 1))
    with pytest.raises(sarif.ReportRejected, match="nesting exceeds"):
        sarif.load_report(str(f))


def test_json_depth_ignores_brackets_and_escaped_quotes_in_strings(tmp_path):
    f = tmp_path / "strings.sarif"
    data = {"text": '[{\\\"' * 1000 + '"}]}\\\\' * 1000, "unicode": "é"}
    f.write_text(json.dumps(data), encoding="utf-8-sig")
    assert sarif.load_report(str(f)) == data


# ── Redaction helpers ──────────────────────────────────────────────────────

@pytest.mark.parametrize("target,expected", [
    ("https://u:p@h.example:8080/a/b?x=1#y", "/a/b"),
    ("/api/users/123/profile", "/api/users/{id}/profile"),
    ("/files/0123456789abcdef0123", "/files/{token}"),
    ("api/v1/items", "/api/v1/items"),
    ("/x//y", "/x/y"),
    ("/users/bob@example.com", "/users/{email}"),
    ("", None),
])
def test_route_sanitizer(target, expected):
    assert redact.sanitize_route(target) == expected


def test_method_allowlist():
    assert redact.sanitize_method("get") == "GET"
    assert redact.sanitize_method("GET /evil") is None
    assert redact.sanitize_method(None) is None


# ── CLI command: exit codes, status reporting, trust ───────────────────────

class FakeApi:
    def __init__(self, upload_error=None, status_error=None):
        self.uploads = []
        self.statuses = []
        self.upload_error = upload_error
        self.status_error = status_error

    def post_findings_checked(self, api_url, api_key, path, payload):
        if self.upload_error:
            raise self.upload_error
        self.uploads.append((path, payload))
        return {"ingested": len(payload), "deduplicated": 0}

    def post_scan_executions_checked(self, api_url, api_key, project_id, run_id, executions):
        if self.status_error:
            raise self.status_error
        self.statuses.append(executions)

    def post_scan_executions(self, api_url, api_key, project_id, run_id, executions):
        self.statuses.append(executions)
        return True


def _args(path, provider="sarif", **kw):
    return argparse.Namespace(file=str(path), format="sarif", provider=provider, project_id=PROJECT,
                              tenant_id="t", pipeline_run_id="run-1", test_session_id=kw.get("session"),
                              environment=None, max_report_bytes=kw.get("max_bytes", sarif.DEFAULT_MAX_REPORT_BYTES))


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeApi()
    for name in ("post_findings_checked", "post_scan_executions_checked", "post_scan_executions"):
        monkeypatch.setattr(api_client, name, getattr(api, name))
    for var in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "SYSTEM_PULLREQUEST_ISFORK"):
        monkeypatch.delenv(var, raising=False)
    return api


def test_cli_successful_import_uploads_and_records_status(fake_api):
    code = command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key")
    assert code == command.EXIT_OK
    path, payload = fake_api.uploads[0]
    assert path == "findings/bulk-universal" and len(payload) == 2
    status = fake_api.statuses[-1][0]
    assert status["scannerKey"] == "iast" and status["status"] == "completed"
    assert status["findingCount"] == 2 and status["provider"] == "sarif"
    assert status["testSession"] == "nightly-integration-tests/2026-10-14"


def test_cli_zero_findings_is_success_with_distinct_status(fake_api):
    assert command.run(_args(FIXTURES / "zero-results.sarif"), "https://api", "key") == command.EXIT_OK
    assert fake_api.uploads == []
    assert fake_api.statuses[-1][0]["status"] == "completed_no_findings"


def test_cli_missing_report_exits_5_and_records_failure(fake_api, tmp_path):
    code = command.run(_args(tmp_path / "missing.sarif"), "https://api", "key")
    assert code == command.EXIT_REPORT_MISSING
    assert fake_api.statuses[-1][0]["status"] == "failed"
    assert fake_api.statuses[-1][0]["reasonCode"] == "report_missing"


def test_cli_rejected_report_exits_6_without_uploading(fake_api):
    code = command.run(_args(FIXTURES / "static-semgrep.sarif"), "https://api", "key")
    assert code == command.EXIT_REPORT_REJECTED
    assert fake_api.uploads == []
    assert fake_api.statuses[-1][0]["reasonCode"] == "report_rejected"


def test_cli_wrong_project_or_key_exits_1(fake_api):
    fake_api.upload_error = api_client.ApiError(403, "API returned 403", transient=False)
    assert command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key") == command.EXIT_CONFIG
    fake_api.upload_error = api_client.ApiAuthError(401, "auth")
    assert command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key") == command.EXIT_CONFIG


def test_cli_iast_not_enabled_exits_1(fake_api):
    fake_api.status_error = api_client.ApiError(403, "no", code="iast_not_enabled")
    assert command.run(_args(FIXTURES / "zero-results.sarif"), "https://api", "key") == command.EXIT_CONFIG


def test_cli_interrupted_upload_exits_2_and_is_retryable(fake_api):
    fake_api.upload_error = api_client.ApiError(None, "network error", transient=True)
    code = command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key")
    assert code == command.EXIT_API
    assert fake_api.statuses[-1][0]["reasonCode"] == "upload_failed"
    # Retry after the network recovers succeeds with the same fingerprints.
    fake_api.upload_error = None
    assert command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key") == command.EXIT_OK


def test_cli_status_not_recorded_exits_2(fake_api):
    fake_api.status_error = api_client.ApiError(503, "unavailable", transient=True)
    assert command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key") == command.EXIT_API


def test_cli_rejects_bad_size_flag(fake_api):
    code = command.run(_args(FIXTURES / "valid-generic.sarif", max_bytes=10), "https://api", "key")
    assert code == command.EXIT_CONFIG


def test_cli_refuses_fork_pull_requests(fake_api, tmp_path, monkeypatch):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {
        "head": {"repo": {"full_name": "attacker/fork", "fork": True}},
        "base": {"repo": {"full_name": "acme/app"}}}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert command.run(_args(FIXTURES / "valid-generic.sarif"), "https://api", "key") == command.EXIT_CONFIG
    assert fake_api.uploads == [] and fake_api.statuses == []


def test_untrusted_context_detection():
    assert command.untrusted_pr_context({"SYSTEM_PULLREQUEST_ISFORK": "True"})
    assert command.untrusted_pr_context({"GITHUB_EVENT_NAME": "pull_request_target"})
    assert command.untrusted_pr_context({"GITHUB_EVENT_NAME": "push"}) is None
    assert command.untrusted_pr_context({"GITHUB_EVENT_NAME": "pull_request"}) is None
    assert command.untrusted_pr_context({}) is None


def test_same_repo_pull_request_is_allowed(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {
        "head": {"repo": {"full_name": "acme/app", "fork": False}},
        "base": {"repo": {"full_name": "acme/app"}}}}), encoding="utf-8")
    assert command.untrusted_pr_context(
        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event)}) is None


def test_real_http_upload_path_maps_network_failure_to_api_error(monkeypatch):
    def boom(self, *a, **k):
        raise requests.ConnectionError("connection reset")

    monkeypatch.setattr(requests.Session, "post", boom)
    with pytest.raises(api_client.ApiError) as err:
        api_client.post_findings_checked("https://api.invalid", "key", "findings/bulk-universal", [{"a": 1}])
    assert err.value.transient
