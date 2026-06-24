"""Focused command construction tests for Terraform-aware Checkov analysis."""

from scanners import checkov


def test_static_analysis_is_limited_to_terraform_root(tmp_path):
    command = checkov._build_command(
        "/workspace",
        str(tmp_path),
        {"terraform_root": "/workspace/infra"},
    )

    assert command[:5] == [
        "checkov", "-d", "/workspace/infra", "--framework", "terraform"]
    assert "--deep-analysis" not in command


def test_plan_analysis_uses_enrichment_and_deep_analysis(tmp_path):
    command = checkov._build_command(
        "/workspace",
        str(tmp_path),
        {
            "terraform_root": "/workspace/infra",
            "terraform_plan_json": "/workspace/infra/tfplan.json",
        },
    )

    assert command[:3] == [
        "checkov", "-f", "/workspace/infra/tfplan.json"]
    assert command[command.index("--repo-root-for-plan-enrichment") + 1] == \
        "/workspace/infra"
    assert "--deep-analysis" in command


def test_raw_payload_excludes_source_and_evaluated_values():
    payload = checkov._safe_raw_payload(
        {
            "resource": "azurerm_storage_account.main",
            "file_path": "/main.tf",
            "file_line_range": [1, 10],
            "evaluated_keys": ["public_network_access_enabled"],
            "code_block": [[3, 'password = "secret"']],
            "check_result": {"evaluated_key": "password", "value": "secret"},
        },
        "CKV_AZURE_TEST",
        "test",
        "HIGH",
    )

    assert payload["resource"] == "azurerm_storage_account.main"
    assert payload["evaluated_keys"] == ["public_network_access_enabled"]
    assert "code_block" not in payload
    assert "check_result" not in payload


def test_file_paths_are_stable_relative_to_the_terraform_root(tmp_path):
    root = tmp_path / "infra"
    root.mkdir()
    file_path = root / "main.tf"
    file_path.write_text("", encoding="utf-8")

    assert checkov._normalize_file_path(str(file_path), str(root)) == "main.tf"
    assert checkov._normalize_file_path("/main.tf", str(root)) == "main.tf"
