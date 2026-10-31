"""Cross-engine SCA identity: the same vulnerable dependency must collide, different ones must not."""
import json
from pathlib import Path

import pytest

from scanners import osv_scanner, sca, trivy

FIXTURES = Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIXTURES / "sca-identity-vectors.json").read_text(encoding="utf-8"))["vectors"]


def _record(inp: dict) -> sca.ScaRecord:
    return sca.ScaRecord(
        tool="test", ecosystem=inp["ecosystem"], package_name=inp["packageName"],
        installed_version=inp["installedVersion"], manifest_path=inp["manifestPath"],
        vulnerability_id=inp["vulnerabilityId"], aliases=inp["aliases"])


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: f"{v['group']}:{v['engine']}")
def test_identity_vectors(vector):
    assert list(_record(vector["input"]).identity()) == vector["identity"]


def test_groups_collide_and_distinct_groups_do_not():
    by_identity: dict[tuple, set[str]] = {}
    for v in VECTORS:
        by_identity.setdefault(tuple(v["identity"]), set()).add(v["group"])
    assert all(len(groups) == 1 for groups in by_identity.values())


def _identities(findings: list[dict]) -> dict[tuple, dict]:
    out = {}
    for f in findings:
        payload = json.loads(f["rawPayload"])
        if payload["kind"] != "sca":
            continue
        ev = payload["sca"]
        rec = sca.ScaRecord(tool="x", ecosystem=ev.get("ecosystem"), package_name=ev["packageName"],
                            installed_version=ev["installedVersion"], manifest_path=ev.get("manifestPath"),
                            vulnerability_id=ev["vulnerabilityId"], aliases=ev.get("aliases", []))
        out[rec.identity()] = f
    return out


def test_real_trivy_and_osv_output_overlap_on_the_same_dependencies():
    t = trivy.parse_report(json.loads((FIXTURES / "trivy-0.70.0/fs-mixed.json").read_text()), "/workspace", "p", "r")
    o = osv_scanner.parse_report(json.loads((FIXTURES / "osv-1.9.2/recursive-mixed.json").read_text()),
                                 "/workspace", "p", "r")
    ti, oi = _identities(t.findings), _identities(o.findings)
    shared = set(ti) & set(oi)
    expected = {
        ("npm", "lodash", "4.17.20", "web/package-lock.json", "CVE-2021-23337"),
        ("npm", "lodash", "4.17.15", "web/package-lock.json", "CVE-2021-23337"),
        ("go", "golang.org/x/text", "0.3.5", "go-svc/go.mod", "CVE-2021-38561"),
        ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "java/pom.xml", "CVE-2021-44228"),
        ("nuget", "newtonsoft.json", "12.0.1", "src/api/packages.lock.json", "CVE-2024-21907"),
        ("pypi", "pyyaml", "5.3", "requirements.txt", "CVE-2020-14343"),
        ("pypi", "requests", "2.19.0", "requirements.txt", "CVE-2018-18074"),
    }
    assert expected <= shared
    # Both engines keep their own fingerprints (same-scanner rerun identity).
    for ident in expected:
        assert ti[ident]["fingerprint"] != oi[ident]["fingerprint"]
    # Different versions of the same package never share an identity.
    lodash = [i for i in shared if i[1] == "lodash" and i[4] == "CVE-2021-23337"]
    assert {i[2] for i in lodash} == {"4.17.20", "4.17.15"}


@pytest.mark.parametrize("installed,fixed,expected", [
    ("2.9.8", ["2.9.9.2", "2.8.11.4", "2.7.9.6"], ["2.9.9.2"]),
    ("4.17.15", ["4.17.19"], ["4.17.19"]),
    ("v0.3.5", ["0.3.7"], ["0.3.7"]),
    ("1.0.0", ["0.9.0"], ["0.9.0"]),            # nothing newer: keep, never hide data
    ("1.0.0-beta", ["1.0.0", "1.0.0"], ["1.0.0"]),
    ("weird", ["abc"], ["abc"]),
])
def test_upgrade_targets(installed, fixed, expected):
    assert sca.upgrade_targets(installed, fixed) == expected


@pytest.mark.parametrize("score,expected", [
    ("9.8", "CRITICAL"), ("9.0", "CRITICAL"), ("7.2", "HIGH"), ("6.9", "MEDIUM"),
    ("4.0", "MEDIUM"), ("3.9", "LOW"), ("0", None), ("", None), (None, None),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", None), ("11", None),
])
def test_severity_from_cvss(score, expected):
    assert sca.severity_from_cvss(score) == expected
