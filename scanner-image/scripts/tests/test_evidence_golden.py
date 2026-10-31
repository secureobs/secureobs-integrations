"""Golden findings shared with the .NET test suite.

``fixtures/evidence-golden.json`` holds finding payloads exactly as the drivers
build them from the *real* captured Trivy/OSV output (and the IAST importer from
its SARIF fixture). The .NET tests ingest them to prove server-side projection,
cross-engine deduplication and IAST sanitization against genuine driver output.

Regenerate after an intentional driver change with:
    SECUREOBS_UPDATE_GOLDEN=1 python -m pytest scripts/tests/test_evidence_golden.py
"""
import json
import os
from pathlib import Path

from iast import sarif
from scanners import osv_scanner, trivy

ROOT = Path(__file__).resolve().parents[1]
SCA = ROOT / "scanners" / "tests" / "fixtures"
GOLDEN = Path(__file__).parent / "fixtures" / "evidence-golden.json"
PROJECT = "00000000-0000-0000-0000-0000000000a1"
RUN = "golden-run-1"


def _pick(findings, predicate, label):
    for f in findings:
        if predicate(f):
            return {"label": label, "finding": f}
    raise AssertionError(f"no finding for {label}")


def _sca(f, package, version, rule):
    payload = json.loads(f["rawPayload"])
    return (payload["kind"] == "sca" and payload["sca"]["packageName"] == package
            and payload["sca"]["installedVersion"] == version and f["ruleId"] == rule)


def build_golden() -> dict:
    t = trivy.parse_report(json.loads((SCA / "trivy-0.70.0/fs-mixed.json").read_text()), "/workspace", PROJECT, RUN).findings
    o = osv_scanner.parse_report(json.loads((SCA / "osv-1.9.2/recursive-mixed.json").read_text()),
                                 "/workspace", PROJECT, RUN).findings
    iast = sarif.build_findings(
        json.loads((ROOT / "iast/tests/fixtures/valid-generic.sarif").read_text()), "sarif", PROJECT, RUN).findings
    entries = [
        _pick(t, lambda f: _sca(f, "lodash", "4.17.20", "CVE-2021-23337"), "trivy-lodash-4.17.20-CVE-2021-23337"),
        _pick(o, lambda f: _sca(f, "lodash", "4.17.20", "CVE-2021-23337"), "osv-lodash-4.17.20-CVE-2021-23337"),
        _pick(t, lambda f: _sca(f, "lodash", "4.17.15", "CVE-2021-23337"), "trivy-lodash-4.17.15-CVE-2021-23337"),
        _pick(t, lambda f: _sca(f, "Newtonsoft.Json", "12.0.1", "CVE-2024-21907"), "trivy-newtonsoft-CVE-2024-21907"),
        _pick(o, lambda f: _sca(f, "Newtonsoft.Json", "12.0.1", "CVE-2024-21907"), "osv-newtonsoft-CVE-2024-21907"),
        _pick(o, lambda f: _sca(f, "org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228"),
              "osv-log4j-core-CVE-2021-44228"),
        _pick(t, lambda f: json.loads(f["rawPayload"])["kind"] == "secret", "trivy-secret-github-pat"),
        _pick(t, lambda f: f["ruleId"] == "DS-0001", "trivy-iac-DS-0001"),
        {"label": "iast-sql-injection", "finding": iast[0]},
        {"label": "iast-xss-runtime-only", "finding": iast[1]},
    ]
    return {"projectId": PROJECT, "pipelineRunId": RUN, "entries": entries}


def test_golden_findings_are_current():
    current = build_golden()
    if os.environ.get("SECUREOBS_UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(current, indent=1) + "\n", encoding="utf-8")
    assert json.loads(GOLDEN.read_text(encoding="utf-8")) == current, (
        "Driver output changed; regenerate with SECUREOBS_UPDATE_GOLDEN=1 if intentional.")
