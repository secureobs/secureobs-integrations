"""Unit tests for the bandit driver's exit-code handling.

Mirrors test_eslint_security.py's pattern (subprocess.run mocked via
monkeypatch). The specific regression under test: a non-{0, 1} Bandit exit
code used to call ``sys.exit(2)``, which raises SystemExit — a
BaseException that cli.py's ``except Exception:`` handler does NOT catch.
That killed the entire `scan` subcommand outright, silently skipping every
remaining scanner and the infrastructure-analysis phase. It must now raise
a plain exception instead, so cli.py's existing handler marks bandit's own
status as "error" and continues on to the remaining scanners.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from scanners import bandit
from scanners.base import ScanResult


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["bandit"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestExitCodeHandling:
    def test_exit_code_outside_0_1_raises_not_sys_exit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(2, stderr="boom"))

        with pytest.raises(RuntimeError) as exc_info:
            bandit.run(str(tmp_path), "proj", "run-1")

        assert "bandit exited with unexpected code 2" in str(exc_info.value)
        assert "boom" in str(exc_info.value)

    def test_exit_code_outside_0_1_does_not_raise_systemexit(self, tmp_path, monkeypatch):
        """SystemExit is a BaseException that bypasses cli.py's `except
        Exception:` handler entirely — assert we get an ordinary Exception
        subclass, not SystemExit."""
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(2, stderr="boom"))

        try:
            bandit.run(str(tmp_path), "proj", "run-1")
        except SystemExit:
            pytest.fail("bandit.run() raised SystemExit — cli.py cannot catch this")
        except Exception:
            pass  # expected: an ordinary exception, e.g. RuntimeError

    def test_exit_0_no_findings(self, tmp_path, monkeypatch):
        out_file = tmp_path / "bandit-out.json"
        out_file.write_text(json.dumps({"results": []}), encoding="utf-8")
        monkeypatch.setattr(bandit, "_OUT", str(out_file))
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0))

        result = bandit.run(str(tmp_path), "proj", "run-1")

        assert isinstance(result, ScanResult)
        assert result.skipped is False
        assert result.findings == []

    def test_exit_1_findings_present_is_a_normal_result(self, tmp_path, monkeypatch):
        out_file = tmp_path / "bandit-out.json"
        out_file.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "test_id": "B307",
                            "issue_severity": "HIGH",
                            "filename": "app.py",
                            "line_number": 5,
                            "code": "eval(x)",
                            "issue_text": "Use of eval detected.",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(bandit, "_OUT", str(out_file))
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1))

        result = bandit.run(str(tmp_path), "proj", "run-1")

        assert result.skipped is False
        assert len(result.findings) == 1
        assert result.findings[0]["ruleId"] == "B307"
