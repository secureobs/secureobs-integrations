"""Unit tests for the eslint-security driver's exit-code / JSON branching.

These tests mock ``subprocess.run`` so they run fast and without a real
ESLint install. A separate, slower test (``test_real_eslint_...`` below)
shells out to the actual pinned ESLint + eslint-plugin-security versions
when they're available on PATH (skipped otherwise) — see the module
docstring on that test for how to install them locally.
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from scanners import eslint_security
from scanners.base import ScanResult


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["eslint"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _js_workspace(tmp_path):
    """A workspace directory containing at least one JS file."""
    (tmp_path / "app.js").write_text("console.log('hi');\n", encoding="utf-8")
    return tmp_path


@pytest.fixture(autouse=True)
def _valid_config(tmp_path_factory, monkeypatch):
    """Point CFG at a config file that exists, so `run()` gets past the
    "missing config" guard in tests that don't specifically exercise it."""
    cfg_dir = tmp_path_factory.mktemp("eslint-cfg")
    cfg_file = cfg_dir / "eslint-secureobs.json"
    cfg_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(eslint_security, "CFG", str(cfg_file))


class TestExitCodeAndJsonBranching:
    def test_exit_0_valid_json_no_findings(self, tmp_path, monkeypatch):
        workspace = _js_workspace(tmp_path)
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _completed(0, stdout="[]")
        )

        result = eslint_security.run(str(workspace), "proj", "run-1")

        assert isinstance(result, ScanResult)
        assert result.skipped is False
        assert result.findings == []

    def test_exit_0_valid_json_with_findings(self, tmp_path, monkeypatch):
        workspace = _js_workspace(tmp_path)
        payload = [
            {
                "filePath": str(workspace / "app.js"),
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 2,
                        "message": "eval with argument of type Identifier",
                        "line": 3,
                        "endLine": 3,
                    }
                ],
            }
        ]
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _completed(0, stdout=json.dumps(payload))
        )

        result = eslint_security.run(str(workspace), "proj", "run-1")

        assert result.skipped is False
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["ruleId"] == "security/detect-eval-with-expression"
        assert finding["severity"] == "HIGH"
        assert finding["startLine"] == 3

    def test_exit_1_findings_present_is_a_normal_result(self, tmp_path, monkeypatch):
        """Exit 1 means "ESLint ran and found lint issues" — legitimate,
        not a skip and not an error."""
        workspace = _js_workspace(tmp_path)
        payload = [
            {
                "filePath": str(workspace / "app.js"),
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 1,
                        "message": "eval with argument of type Identifier",
                        "line": 1,
                        "endLine": 1,
                    }
                ],
            }
        ]
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _completed(1, stdout=json.dumps(payload))
        )

        result = eslint_security.run(str(workspace), "proj", "run-1")

        assert result.skipped is False
        assert len(result.findings) == 1

    def test_exit_code_outside_0_1_raises_instead_of_skipping(self, tmp_path, monkeypatch):
        """This is the regression this test file guards against: a genuine
        operational failure (e.g. ESLint couldn't even load its config)
        must surface as an exception — NOT get misreported as a benign
        ScanResult(skipped=True, ...)."""
        workspace = _js_workspace(tmp_path)
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: _completed(
                2, stderr="ESLint couldn't find the plugin \"eslint-plugin-security\"."
            ),
        )

        with pytest.raises(RuntimeError) as exc_info:
            eslint_security.run(str(workspace), "proj", "run-1")

        assert "eslint exited with unexpected code 2" in str(exc_info.value)
        assert "eslint-plugin-security" in str(exc_info.value)

    def test_exit_0_malformed_json_raises_instead_of_skipping(self, tmp_path, monkeypatch):
        workspace = _js_workspace(tmp_path)
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _completed(0, stdout="{not valid json")
        )

        with pytest.raises(RuntimeError) as exc_info:
            eslint_security.run(str(workspace), "proj", "run-1")

        assert "invalid JSON" in str(exc_info.value)


class TestLegitimateSkips:
    """These remain ScanResult(skipped=True, ...) — they are "nothing to
    scan" outcomes, not operational failures, and must NOT raise."""

    def test_no_js_files_is_still_a_skip(self, tmp_path, monkeypatch):
        empty_workspace = tmp_path  # no .js/.jsx/.mjs/.cjs files written
        calls = []
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: calls.append(1) or _completed(0, stdout="[]")
        )

        result = eslint_security.run(str(empty_workspace), "proj", "run-1")

        assert result.skipped is True
        assert result.skip_reason == "no_js_files"
        assert calls == []  # eslint must never even be invoked

    def test_missing_config_is_still_a_skip(self, tmp_path, monkeypatch):
        workspace = _js_workspace(tmp_path)
        monkeypatch.setattr(eslint_security, "CFG", str(tmp_path / "does-not-exist.json"))
        calls = []
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: calls.append(1) or _completed(0, stdout="[]")
        )

        result = eslint_security.run(str(workspace), "proj", "run-1")

        assert result.skipped is True
        assert result.skip_reason == "missing_eslint_config"
        assert calls == []  # eslint must never even be invoked


# ---------------------------------------------------------------------------
# Real-invocation test: exercises the actual pinned ESLint + eslint-plugin-
# security versions used by the scanner image's Dockerfile (ESLint 8.57.0,
# eslint-plugin-security 3.0.1), against the repo's real eslint-secureobs.json
# config (with the recommended-legacy fix applied) — no subprocess mocking.
#
# To run these locally: `npm install eslint@8.57.0 eslint-plugin-security@3.0.1`
# somewhere on NODE_PATH (or globally, matching the Dockerfile), so `eslint`
# resolves on PATH and can load eslint-plugin-security. If that isn't set up,
# these tests are skipped rather than failed — the authoritative check is
# still running the driver inside the real built scanner-image container.
# ---------------------------------------------------------------------------

_HAS_REAL_ESLINT = shutil.which("eslint") is not None

_REAL_CONFIG = str(
    __import__("pathlib").Path(__file__).resolve().parents[2] / "eslint-secureobs.json"
)


@pytest.mark.skipif(
    not _HAS_REAL_ESLINT,
    reason="eslint not found on PATH — install eslint@8.57.0 + eslint-plugin-security@3.0.1 to run this test",
)
class TestRealEslintInvocation:
    def test_eval_pattern_is_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(eslint_security, "CFG", _REAL_CONFIG)
        (tmp_path / "bad.js").write_text(
            "const userInput = process.argv[2];\neval(userInput);\n", encoding="utf-8"
        )

        result = eslint_security.run(str(tmp_path), "proj", "run-1")

        assert result.skipped is False
        assert len(result.findings) >= 1
        assert any(
            "eval" in (f["ruleId"] or "").lower() or "eval" in (f["description"] or "").lower()
            for f in result.findings
        )

    def test_clean_file_produces_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(eslint_security, "CFG", _REAL_CONFIG)
        (tmp_path / "clean.js").write_text(
            "function add(a, b) {\n  return a + b;\n}\n\nmodule.exports = { add };\n",
            encoding="utf-8",
        )

        result = eslint_security.run(str(tmp_path), "proj", "run-1")

        assert result.skipped is False
        assert result.findings == []
