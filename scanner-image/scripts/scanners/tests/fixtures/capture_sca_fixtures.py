#!/usr/bin/env python3
"""Regenerate the real Trivy / OSV-Scanner output fixtures used by the SCA tests.

Run this whenever TRIVY_VERSION or OSV_SCANNER_VERSION in the scanner Dockerfile
changes. It needs the *pinned* binaries (verify their SHA-256 against the
Dockerfile first) and writes the fixture project to ``/workspace`` so captured
paths are identical to what the scanner container sees.

    python3 capture_sca_fixtures.py --trivy /path/to/trivy --osv /path/to/osv-scanner

OSV-Scanner is run with ``--experimental-offline --experimental-download-offline-databases``
when ``--osv-offline`` is passed (useful where api.osv.dev is unreachable). The
output schema is identical to online mode; only the vulnerability source differs.

Fixtures are verbatim tool output with two size reductions, both applied to
fields the drivers never read: long per-package vulnerability lists are cut to
a few entries (OSV ``groups`` are cut consistently), and OSV ``affected[].versions``
enumerations are removed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent))  # scripts/

from scanners.tests.sca_fixture_project import (  # noqa: E402
    write_project_without_manifests,
    write_vulnerable_project,
)

# Per-package cap for very long advisory lists (jackson-databind has 59, Go stdlib 71).
_MAX_VULNS_PER_PACKAGE = 4
# IDs the tests assert on; always kept even when a list is trimmed.
_ALWAYS_KEEP = {
    "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q",  # log4shell
    "CVE-2021-38561", "GHSA-ppp9-7jff-5vj2",  # x/text
    "CVE-2024-21907", "GHSA-5crp-9r3c-p9vr",  # Newtonsoft.Json
    "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm",  # lodash
    "CVE-2018-18074",                          # requests
}


def _run(cmd: list[str], cwd: str) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1800)
    return proc.returncode, (proc.stderr or "")


def _stderr_tail(stderr: str) -> str:
    keep = [ln for ln in stderr.splitlines()
            if "gitignore" not in ln and "Loaded " not in ln and ln.strip()]
    return "\n".join(keep[-6:])


def _trim_trivy(data: dict) -> dict:
    for result in data.get("Results") or []:
        vulns = result.get("Vulnerabilities")
        if not vulns or len(vulns) <= 15:
            continue
        kept = [v for v in vulns if v.get("VulnerabilityID") in _ALWAYS_KEEP]
        for v in vulns:
            if len(kept) >= _MAX_VULNS_PER_PACKAGE:
                break
            if v not in kept:
                kept.append(v)
        result["Vulnerabilities"] = kept
    return data


def _trim_osv(data: dict) -> dict:
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            groups = pkg.get("groups") or []
            if len(groups) > _MAX_VULNS_PER_PACKAGE:
                keep = [g for g in groups if set(g.get("aliases") or []) & _ALWAYS_KEEP]
                for g in groups:
                    if len(keep) >= _MAX_VULNS_PER_PACKAGE:
                        break
                    if g not in keep:
                        keep.append(g)
                pkg["groups"] = keep
                kept_ids = {i for g in keep for i in g.get("ids") or []}
                pkg["vulnerabilities"] = [
                    v for v in pkg.get("vulnerabilities") or [] if v.get("id") in kept_ids]
            for vuln in pkg.get("vulnerabilities") or []:
                for affected in vuln.get("affected") or []:
                    affected.pop("versions", None)
    return data


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"  wrote {path.relative_to(HERE)} ({path.stat().st_size} bytes)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--osv", required=True)
    ap.add_argument("--osv-offline", action="store_true")
    ap.add_argument("--cases-root", default="/srv/secureobs-fixtures")
    args = ap.parse_args()

    workspace = Path("/workspace")
    write_vulnerable_project(workspace)
    cases = Path(args.cases_root)
    clean = cases / "clean"
    (clean / "web").mkdir(parents=True, exist_ok=True)
    (clean / "web" / "package-lock.json").write_text(json.dumps({
        "name": "clean", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "clean", "version": "1.0.0", "dependencies": {"is-number": "7.0.0"}},
                     "node_modules/is-number": {"version": "7.0.0"}}}), encoding="utf-8")
    nomanifest = write_project_without_manifests(cases / "no-manifests")
    malformed = cases / "malformed" / "web"
    malformed.mkdir(parents=True, exist_ok=True)
    (malformed / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {', encoding="utf-8")

    trivy_dir = HERE / "trivy-0.70.0"
    osv_dir = HERE / "osv-1.9.2"
    trivy_flags = ["fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--output"]

    print("Trivy:")
    for name, target in (("fs-mixed", workspace), ("fs-clean", clean), ("fs-no-manifests", nomanifest)):
        out = f"/tmp/secureobs-trivy-{name}.json"
        rc, err = _run([args.trivy, *trivy_flags, out, str(target)], cwd=str(target))
        if rc != 0:
            print(err, file=sys.stderr)
            return rc
        _write(trivy_dir / f"{name}.json", _trim_trivy(json.loads(Path(out).read_text())))

    print("OSV-Scanner:")
    offline = ["--experimental-offline", "--experimental-download-offline-databases"] if args.osv_offline else []
    osv_cases: dict[str, dict] = {}
    runs = (
        ("recursive-mixed", ["--format", "json", "--output", "{out}", "--recursive", *offline, str(workspace)], workspace),
        ("non-recursive-scan-subcommand", ["scan", "--format", "json", "--output", "{out}", *offline, str(workspace)], workspace),
        ("clean", ["--format", "json", "--output", "{out}", "--recursive", *offline, str(clean)], clean),
        ("no-manifests", ["--format", "json", "--output", "{out}", "--recursive", *offline, str(nomanifest)], nomanifest),
        ("malformed-lockfile", ["--format", "json", "--output", "{out}", "--recursive", *offline, str(malformed.parent)], malformed.parent),
    )
    for name, argv, cwd in runs:
        out = f"/tmp/secureobs-osv-{name}.json"
        if os.path.exists(out):
            os.remove(out)
        rc, err = _run([args.osv, *[a.replace("{out}", out) for a in argv]], cwd=str(cwd))
        produced = os.path.exists(out) and os.path.getsize(out) > 0
        osv_cases[name] = {
            "command": ["osv-scanner", *[("<output-file>" if a == "{out}" else a) for a in argv if a not in offline]],
            "returncode": rc,
            "output_file_written": produced,
            "stderr_tail": _stderr_tail(err),
        }
        if produced and name in ("recursive-mixed", "clean", "non-recursive-scan-subcommand"):
            _write(osv_dir / f"{name}.json", _trim_osv(json.loads(Path(out).read_text())))
    _write(osv_dir / "cases.json", osv_cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
