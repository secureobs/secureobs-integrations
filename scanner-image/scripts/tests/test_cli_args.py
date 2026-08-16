"""Tests for --terraform-root-id argument validation.

The API DTO (TerraformPlanAnalysisRequestDto.TerraformRootId) is a strictly
typed nullable Guid: ASP.NET Core's System.Text.Json binding rejects a
non-UUID string before the request even reaches the controller action or the
validator. These tests confirm the CLI catches a bad value locally, before
any network request, with a clear error message.
"""

import argparse

import pytest

import cli


def _iac_parser() -> argparse.ArgumentParser:
    """A minimal parser exposing only the IaC arguments under test."""
    parser = argparse.ArgumentParser(prog="secureobs-scanner-test")
    cli._add_iac_args(parser)
    return parser


# ── cli._terraform_root_id (argparse type= function) ──────────────────────


def test_terraform_root_id_accepts_valid_uuid_and_returns_it_unchanged():
    value = "b3f1c2d4-5678-4abc-9def-0123456789ab"
    assert cli._terraform_root_id(value) == value


def test_terraform_root_id_rejects_non_uuid_string():
    with pytest.raises(argparse.ArgumentTypeError):
        cli._terraform_root_id("secureobs-infrastructure")


# ── Full argparse wiring via --terraform-root-id ───────────────────────────


def test_valid_uuid_is_accepted_through_parse_args():
    value = "b3f1c2d4-5678-4abc-9def-0123456789ab"
    args = _iac_parser().parse_args(["--terraform-root-id", value])
    assert args.terraform_root_id == value


def test_omitted_flag_defaults_to_none():
    args = _iac_parser().parse_args([])
    assert args.terraform_root_id is None


def test_invalid_uuid_is_rejected_locally_with_system_exit_2(capsys):
    parser = _iac_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--terraform-root-id", "secureobs-infrastructure"])

    # argparse's own error handling converts a type= ArgumentTypeError into
    # a usage message on stderr followed by SystemExit(2) — this asserts
    # that standard behavior rather than assuming it.
    assert exc_info.value.code == 2

    stderr = capsys.readouterr().err
    assert "--terraform-root-id" in stderr
    assert "must be a valid UUID" in stderr
    assert "secureobs-infrastructure" in stderr
