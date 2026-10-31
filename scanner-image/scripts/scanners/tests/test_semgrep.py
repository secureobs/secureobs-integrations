"""Semgrep must produce a valid report before it can be called clean."""
import json
import subprocess
from pathlib import Path

import pytest

from scanners import semgrep, tool_output


def runner(monkeypatch, report=None, returncode=0, stderr=""):
    def run(command, **kwargs):
        if report is not None:
            Path(command[command.index("--output") + 1]).write_text(report)
        return subprocess.CompletedProcess(command, returncode, "", stderr)
    monkeypatch.setattr(subprocess, "run", run)


def test_zero_exit_without_report_is_failure(monkeypatch):
    runner(monkeypatch, stderr="registry could not load")
    with pytest.raises(tool_output.ToolOutputError, match="no output file.*registry could not load"):
        semgrep.run("/workspace", "project", "run")


@pytest.mark.parametrize("report", ["", "{", "null", "[]", "{}", '{"results":null}'])
def test_unusable_report_is_failure(monkeypatch, report):
    runner(monkeypatch, report)
    with pytest.raises(tool_output.ToolOutputError):
        semgrep.run("/workspace", "project", "run")


def test_valid_empty_report_is_clean(monkeypatch):
    runner(monkeypatch, '{"results":[]}')
    result = semgrep.run("/workspace", "project", "run")
    assert not result.skipped
    assert result.findings == []


def test_findings_survive_and_report_is_removed(monkeypatch):
    paths = []
    def run(command, **kwargs):
        path = Path(command[command.index("--output") + 1])
        paths.append(path)
        path.write_text(json.dumps({"results": [{
            "check_id": "java.sql-injection", "path": "src/App.java",
            "start": {"line": 8}, "end": {"line": 8},
            "extra": {"severity": "ERROR", "message": "SQL injection"},
        }]}))
        assert kwargs["timeout"] == tool_output.TOOL_TIMEOUT_SECONDS
        return subprocess.CompletedProcess(command, 1, "", "")
    monkeypatch.setattr(subprocess, "run", run)
    for run_id in ["run-1", "run-2"]:
        result = semgrep.run("/workspace", "project", run_id)
        assert result.findings[0]["checkId"] == "java.sql-injection"
        assert result.findings[0]["pipelineRunId"] == run_id
        assert not paths[-1].exists()
    assert paths[0] != paths[1]


def test_timeout_reports_failure(monkeypatch):
    def run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="exceeded"):
        semgrep.run("/workspace", "project", "run")


def test_non_success_exit_is_failure(monkeypatch):
    runner(monkeypatch, '{"results":[]}', returncode=2, stderr="tool failed")
    with pytest.raises(RuntimeError, match="unexpected code 2.*tool failed"):
        semgrep.run("/workspace", "project", "run")
