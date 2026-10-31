"""Scanner execution states, status reporting from `scan`, and gate exit codes."""
import argparse
import json

import pytest

import api_client
import build_gate
import cli
import execution
from scanners.base import ScanResult
from scanners.registry import Driver


# ── Status mapping: three distinguishable SCA outcomes and failures ─────────

def test_no_supported_manifests_is_not_applicable():
    row = execution.from_result("osv-scanner", ScanResult(
        skipped=True, skip_reason="no_supported_manifests", not_applicable=True,
        sources_analyzed=0, warnings=["No supported dependency manifest or lockfile was found."]))
    assert row.status == execution.SKIPPED_NOT_APPLICABLE
    assert row.reason_code == "no_supported_manifests" and row.sources_analyzed == 0


def test_clean_scan_is_completed_with_zero_findings():
    row = execution.from_result("osv-scanner", ScanResult(findings=[], sources_analyzed=3))
    assert row.status == execution.COMPLETED_NO_FINDINGS and row.reason_code is None


def test_findings_are_completed():
    row = execution.from_result("trivy", ScanResult(findings=[{"x": 1}], sources_analyzed=2))
    assert row.status == execution.COMPLETED and row.finding_count == 1


def test_trivy_with_zero_dependency_sources_is_flagged():
    row = execution.from_result("trivy", ScanResult(findings=[], sources_analyzed=0,
                                                    warnings=["No supported dependency manifest"]))
    assert row.status == execution.COMPLETED_NO_FINDINGS
    assert row.reason_code == "no_supported_manifests"


def test_tool_failures_are_failed():
    assert execution.from_exception("trivy", RuntimeError("boom")).status == execution.FAILED
    nonzero = execution.from_result("bandit", ScanResult(skipped=True, skip_reason="crash", exit_code=2))
    assert nonzero.status == execution.FAILED and nonzero.reason_code == "tool_exit_2"
    missing = execution.from_result("semgrep", ScanResult(skipped=True, skip_reason="no results file"))
    assert missing.status == execution.FAILED


def test_failure_detail_is_redacted():
    token = "gh" + "p_" + "A" * 36
    row = execution.from_exception("trivy", RuntimeError(f"auth failed token={token}\nmore"))
    assert token not in (row.detail or "") and "\n" not in (row.detail or "")


def test_unknown_driver_is_not_configured():
    row = execution.driver_unavailable("future-scanner")
    assert row.status == execution.SKIPPED_NOT_CONFIGURED and row.reason_code == "driver_unavailable"


# ── `scan` reports running, then final states; a failure never looks clean ──

def _scan_args(**kw):
    return argparse.Namespace(project_id="p1", tenant_id="t1", pipeline_run_id="run-9",
                              terraform_plan_json=None, terraform_root=None, terraform_var_files=[],
                              source_revision=None, terraform_root_id=None,
                              require_infrastructure_analysis=False, iac_only=False,
                              sbom_output=kw.get("sbom_output"))


@pytest.fixture
def scan_env(monkeypatch):
    posted = {"status": [], "findings": []}
    monkeypatch.setenv("SECUREOBS_API_KEY", "key")
    monkeypatch.setattr(api_client, "post_scan_executions",
                        lambda url, key, pid, rid, rows: posted["status"].append(rows) or True)
    monkeypatch.setattr(api_client, "post_findings",
                        lambda url, key, path, payload: posted["findings"].append(payload)
                        or {"ingested": len(payload), "deduplicated": 1})

    def ok(w, p, r, c):
        return ScanResult(findings=[{"fingerprint": "a"}, {"fingerprint": "b"}], sources_analyzed=4)

    def boom(w, p, r, c):
        raise RuntimeError("trivy exited with unexpected code 2: db error")

    def na(w, p, r, c):
        return ScanResult(skipped=True, skip_reason="no_supported_manifests", not_applicable=True,
                          sources_analyzed=0)

    registry = {
        "osv-scanner": Driver("osv-scanner", "findings/bulk-universal", ok),
        "trivy": Driver("trivy", "findings/bulk-universal", boom),
        "eslint-security": Driver("eslint-security", "findings/bulk-universal", na),
    }
    monkeypatch.setattr(cli, "REGISTRY", registry)
    monkeypatch.setattr(api_client, "get_active_scanners", lambda *a: [
        {"key": "osv-scanner"}, {"key": "trivy"}, {"key": "eslint-security"}, {"key": "newer-scanner"}])
    return posted


def test_scan_reports_running_then_final_states(scan_env):
    cli.cmd_scan(_scan_args())
    running, final = scan_env["status"]
    assert {r["status"] for r in running} == {"running"}
    assert [r["scannerKey"] for r in running] == ["osv-scanner", "trivy", "eslint-security", "newer-scanner"]
    by_key = {r["scannerKey"]: r for r in final}
    assert by_key["osv-scanner"]["status"] == "completed" and by_key["osv-scanner"]["findingCount"] == 2
    assert by_key["osv-scanner"]["sourcesAnalyzed"] == 4
    assert by_key["trivy"]["status"] == "failed" and by_key["trivy"]["reasonCode"] == "tool_error"
    assert by_key["eslint-security"]["status"] == "skipped_not_applicable"
    assert by_key["newer-scanner"]["status"] == "skipped_not_configured"


def test_scan_exit_code_is_unchanged_when_a_scanner_fails(scan_env):
    # Existing behaviour: continue past a failing scanner and exit 0. The gate,
    # not the scan step, decides whether a failure blocks (opt-in per project).
    cli.cmd_scan(_scan_args())


# ── SBOM output path confinement ────────────────────────────────────────────

def test_sbom_output_paths_are_confined(tmp_path, monkeypatch):
    ws = tmp_path / "workspace"
    out = tmp_path / "output"
    ws.mkdir()
    out.mkdir()
    monkeypatch.setattr(cli, "_WORKSPACE", str(ws))
    monkeypatch.setattr(cli, "_OUTPUT_ROOTS", (str(ws), str(out)))
    assert cli._resolve_output_file("reports/sbom.cdx.json", "--sbom-output") == \
        str(ws / "reports" / "sbom.cdx.json")
    assert cli._resolve_output_file(str(out / "sbom.json"), "--sbom-output") == str(out / "sbom.json")
    for bad in ("../escape.json", "/etc/cron.d/x", "", str(tmp_path / "elsewhere.json")):
        with pytest.raises(SystemExit):
            cli._resolve_output_file(bad, "--sbom-output")


def test_sbom_failure_fails_the_scan(scan_env, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_WORKSPACE", str(tmp_path))
    monkeypatch.setattr(cli, "_OUTPUT_ROOTS", (str(tmp_path),))

    def fail(src, path):
        raise RuntimeError("trivy exited with code 1")

    monkeypatch.setattr(cli.sbom, "generate", fail)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_scan(_scan_args(sbom_output="sbom.json"))
    assert exc.value.code == 2


# ── Gate: 0 pass, 3 blocking findings (unchanged), 4 incomplete ─────────────

@pytest.fixture
def gate_env(monkeypatch):
    state = {"decision": None, "legacy": False}
    monkeypatch.setattr(build_gate, "get_gate_decision", lambda *a: state["decision"])
    monkeypatch.setattr(build_gate, "get_blocking", lambda *a: state["legacy"])
    monkeypatch.setattr(build_gate, "get_pr_findings", lambda *a: [])
    return state


@pytest.mark.parametrize("outcome,code", [("passed", 0), ("blocked", 3), ("incomplete", 4), ("weird", 2)])
def test_gate_exit_codes(gate_env, outcome, code):
    gate_env["decision"] = {"outcome": outcome, "policy": "BlockingFindings", "reasons": [], "scanners": []}
    with pytest.raises(SystemExit) as exc:
        build_gate.run("https://api", "key", "p1", "run-9")
    assert exc.value.code == code


def test_gate_prints_reasons_without_control_characters(gate_env, caplog):
    gate_env["decision"] = {
        "outcome": "incomplete", "policy": "HighAndAbove",
        "reasons": [{"code": "required_scanner_failed", "scanner": "trivy", "blocking": True,
                     "message": "Trivy failed\x1b[31m"},
                    {"code": "iast_not_configured", "blocking": False, "message": "IAST is optional."}],
        "scanners": [{"key": "trivy", "status": "failed", "required": True}],
    }
    with caplog.at_level("INFO"), pytest.raises(SystemExit):
        build_gate.run("https://api", "key", "p1", "run-9")
    text = caplog.text
    assert "✗ required_scanner_failed [trivy]: Trivy failed" in text and "\x1b" not in text
    assert "ℹ iast_not_configured" in text and "trivy" in text and "(required)" in text


@pytest.mark.parametrize("blocking,code", [(True, 3), (False, 0)])
def test_gate_falls_back_to_legacy_endpoint(gate_env, blocking, code):
    gate_env["decision"] = None
    gate_env["legacy"] = blocking
    with pytest.raises(SystemExit) as exc:
        build_gate.run("https://api", "key", "p1", "run-9")
    assert exc.value.code == code


class _Resp:
    def __init__(self, status, body=None, text=""):
        self.status_code = status
        self._body = body
        self.text = text if body is None else json.dumps(body)
        self.ok = 200 <= status < 300
        self.content = self.text.encode()

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


@pytest.mark.parametrize("resp,expected", [
    (_Resp(404, text=""), None),                                       # old API: fall back
    (_Resp(200, {"outcome": "passed"}), {"outcome": "passed"}),
])
def test_gate_decision_client(monkeypatch, resp, expected):
    monkeypatch.setattr(api_client.requests.Session, "get", lambda self, *a, **k: resp)
    assert api_client.get_gate_decision("https://api", "key", "p1", "r") == expected


@pytest.mark.parametrize("resp,code", [
    (_Resp(404, {"error": "project_not_found"}), 1),
    (_Resp(401, {"error": "unauthorized"}), 1),
    (_Resp(500, {"error": "internal_error"}), 2),
    (_Resp(200, {"unexpected": True}), 2),
])
def test_gate_decision_client_failures_never_pass(monkeypatch, resp, code):
    monkeypatch.setattr(api_client.requests.Session, "get", lambda self, *a, **k: resp)
    with pytest.raises(SystemExit) as exc:
        api_client.get_gate_decision("https://api", "key", "p1", "r")
    assert exc.value.code == code


def test_gate_network_error_is_exit_2_not_a_finding(monkeypatch):
    def boom(self, *a, **k):
        raise api_client.requests.ConnectionError("down")

    monkeypatch.setattr(api_client.requests.Session, "get", boom)
    with pytest.raises(SystemExit) as exc:
        api_client.get_gate_decision("https://api", "key", "p1", "r")
    assert exc.value.code == 2


# ── Dedup counts are reported only when the API provides them ────────────────

@pytest.mark.parametrize("resp,expected", [
    (_Resp(201, text=""), None),                                        # current API: 201, no body
    (_Resp(201, {"ingested": 2, "deduplicated": 1}), 1),
])
def test_post_findings_never_invents_a_dedup_count(monkeypatch, resp, expected):
    monkeypatch.setattr(api_client.requests.Session, "post", lambda self, *a, **k: resp)
    result = api_client.post_findings_checked("https://api", "key", "findings/bulk-universal",
                                              [{"fingerprint": "a"}, {"fingerprint": "b"}])
    assert result == {"ingested": 2, "deduplicated": expected}


def test_summary_omits_new_count_when_unknown(caplog):
    caplog.set_level("INFO")
    execution.print_summary([
        execution.Execution(key="trivy", status=execution.COMPLETED, finding_count=107, sources_analyzed=7),
    ])
    assert "107 finding(s)  · 7 dependency source(s)" in caplog.text
    assert "new after dedup" not in caplog.text
    caplog.clear()
    execution.print_summary([
        execution.Execution(key="osv-scanner", status=execution.COMPLETED, finding_count=10, new_after_dedup=4),
    ])
    assert "10 finding(s)  (4 new after dedup)" in caplog.text


def test_eslint_without_js_files_is_not_applicable_not_failed(tmp_path):
    from scanners import eslint_security
    row = execution.from_result("eslint-security", eslint_security.run(str(tmp_path), "p", "r"))
    assert row.status == execution.SKIPPED_NOT_APPLICABLE
    assert row.reason_code == "no_js_files"
