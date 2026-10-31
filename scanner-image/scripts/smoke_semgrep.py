"""Offline image-build check that Semgrep really scans and writes JSON."""
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="secureobs-smoke-") as directory:
        root = Path(directory)
        source = root / "src"
        source.mkdir()
        (source / "sample.py").write_text("print(123)\n")
        rules = root / "rule.yml"
        rules.write_text(
            "rules:\n  - id: secureobs-smoke\n    pattern: print(...)\n"
            "    message: Offline smoke test\n    languages: [python]\n"
            "    severity: WARNING\n"
        )
        report = root / "report.json"
        subprocess.run(
            ["semgrep", "scan", "--config", str(rules), "--metrics=off",
             "--json", "--output", str(report), str(source)],
            check=True, timeout=120,
        )
        data = json.loads(report.read_text())
        if not any(row.get("check_id", "").endswith("secureobs-smoke")
                   for row in data["results"]):
            raise RuntimeError("Semgrep smoke test did not detect the known pattern")


if __name__ == "__main__":
    main()
