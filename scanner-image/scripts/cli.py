#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import uuid
from typing import Optional

import config
import api_client
import build_gate as gate_module
import execution
from iast import command as iast_command
from iast import providers as iast_providers
from iast import sarif as iast_sarif
from scanners import sbom
from scanners.registry import DEFAULT_KEYS, REGISTRY
from pr_comments import azuredevops, github
from infrastructure import terraform_plan as iac_plan
from infrastructure import terraform_config as iac_config

log = logging.getLogger(__name__)


_WORKSPACE = "/workspace"


def _resolve_workspace_dir(relative_dir: Optional[str]) -> str:
    """Resolve a workspace-relative directory, refusing paths that escape /workspace."""
    rel = (relative_dir or "").strip().strip("/")
    base = os.path.realpath(_WORKSPACE)
    candidate = os.path.realpath(os.path.join(base, rel))
    if candidate != base and not candidate.startswith(base + os.sep):
        raise SystemExit(f"--terraform-root resolves outside the workspace: {relative_dir!r}")
    return candidate


def _resolve_workspace_file(relative_path: Optional[str]) -> str:
    """Resolve a workspace-relative file, refusing paths that escape /workspace."""
    rel = (relative_path or "").strip().strip("/")
    base = os.path.realpath(_WORKSPACE)
    candidate = os.path.realpath(os.path.join(base, rel))
    if not candidate.startswith(base + os.sep):
        raise SystemExit(
            f"--terraform-plan-json resolves outside the workspace: {relative_path!r}")
    return candidate


_OUTPUT_ROOTS = (_WORKSPACE, "/output")


def _resolve_output_file(value: Optional[str], flag: str) -> str:
    """Resolve a file the scanner writes (e.g. the SBOM).

    Relative paths land under /workspace; absolute paths must stay inside
    /workspace or /output (mount a writable directory there when the workspace
    is mounted read-only). Anything else is refused before a byte is written.
    """
    raw = (value or "").strip()
    if not raw:
        raise SystemExit(f"{flag} must not be empty")
    candidate = raw if os.path.isabs(raw) else os.path.join(_WORKSPACE, raw)
    candidate = os.path.realpath(candidate)
    for root in _OUTPUT_ROOTS:
        base = os.path.realpath(root)
        if candidate.startswith(base + os.sep):
            os.makedirs(os.path.dirname(candidate), exist_ok=True)
            return candidate
    raise SystemExit(f"{flag} must point inside /workspace or /output (got {value!r})")


def _terraform_root_id(value: str) -> str:
    """argparse type= for --terraform-root-id: validate locally, fail fast.

    The API DTO (TerraformPlanAnalysisRequestDto.TerraformRootId) is a
    strictly-typed nullable Guid, so a non-UUID string would be rejected by
    ASP.NET Core's JSON binding before ever reaching the validator. Catch that
    here instead of surfacing an opaque HTTP 400 from the API.
    """
    try:
        uuid.UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--terraform-root-id must be a valid UUID (got {value!r}); "
            "omit the flag if you have no managed Terraform-root identity."
        ) from exc
    return value


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--project-id", required=True, help="SecureObs project ID")
    p.add_argument("--tenant-id", required=True, help="SecureObs tenant ID")
    p.add_argument("--pipeline-run-id", required=True, help="Unique pipeline run identifier")


def _add_iac_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--terraform-plan-json",
        default=None,
        metavar="RELATIVE_PATH",
        help=(
            "Path to a pre-generated Terraform plan JSON file, relative to "
            "/workspace. When supplied, SecureObs sanitizes the plan locally "
            "and uploads only an allowlisted infrastructure topology — the raw "
            "plan is never transmitted. Use --terraform-root instead for "
            "credential-free static analysis."
        ),
    )
    p.add_argument(
        "--terraform-root",
        default=None,
        metavar="RELATIVE_DIR",
        help=(
            "Directory of a Terraform root, relative to /workspace, for "
            "CREDENTIAL-FREE static analysis: SecureObs parses the HCL directly "
            "(no terraform plan, no cloud credentials) and uploads only the "
            "allowlisted topology. Azure resources receive typed attack-path "
            "analysis; other providers still receive Checkov findings and generic nodes."
        ),
    )
    p.add_argument(
        "--terraform-var-file",
        action="append",
        default=[],
        dest="terraform_var_files",
        metavar="RELATIVE_PATH",
        help=(
            "Root-relative .tfvars file used to resolve variables during static "
            "analysis (--terraform-root). Repeatable. Ignored for --terraform-plan-json."
        ),
    )
    p.add_argument(
        "--source-revision",
        default=None,
        metavar="COMMIT_SHA",
        help="VCS commit SHA or ref for the plan source (e.g. $GITHUB_SHA).",
    )
    p.add_argument(
        "--terraform-root-id",
        type=_terraform_root_id,
        default=None,
        metavar="UUID",
        help=(
            "UUID of the managed Terraform root this analysis belongs to. "
            "Used to distinguish multiple roots in a monorepo. Omit for "
            "unmanaged/single-root setups (e.g. dogfood self-scan)."
        ),
    )
    p.add_argument(
        "--require-infrastructure-analysis",
        action="store_true",
        default=False,
        help=(
            "Exit with a non-zero code if infrastructure analysis fails or is "
            "skipped (neither --terraform-plan-json nor --terraform-root supplied). Ordinary scanner "
            "failures are unaffected by this flag."
        ),
    )
    p.add_argument(
        "--iac-only",
        action="store_true",
        default=False,
        help=(
            "Run only the Terraform IaC policy/topology path. Checkov is always included; "
            "general SAST/SCA scanners are skipped to avoid duplicate whole-repository scans."
        ),
    )


def _resolve_active_scanners(
    api_url: str, api_key: str, project_id: str
) -> list[dict]:
    """Decide which scanners to run on this invocation.

    Source of truth is the SecureObs API — whatever the user toggled in the
    dashboard takes effect on the next pipeline run with zero YAML edits. If
    that lookup is degraded (transient 5xx, network blip), we fall back to a
    safe default set so the user still gets *some* scan rather than a broken
    pipeline. Auth/permission failures are NOT silently masked here — those
    bubble out of ``api_client.get_active_scanners`` as ``sys.exit(1)``.
    """
    active = api_client.get_active_scanners(api_url, api_key, project_id)
    if active is None:
        log.warning(
            "Falling back to default scanners: %s. Toggle scanners in the "
            "SecureObs dashboard to override on the next run.",
            ", ".join(DEFAULT_KEYS),
        )
        return [{"key": k, "config": None} for k in DEFAULT_KEYS]
    return active


def cmd_scan(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")

    require_iac = getattr(args, "require_infrastructure_analysis", False)
    plan_path = getattr(args, "terraform_plan_json", None)
    terraform_root = getattr(args, "terraform_root", None)
    terraform_var_files = getattr(args, "terraform_var_files", None) or []
    source_revision = getattr(args, "source_revision", None)
    terraform_root_id = getattr(args, "terraform_root_id", None)
    iac_only = getattr(args, "iac_only", False)
    resolved_terraform_root = (
        _resolve_workspace_dir(terraform_root)
        if terraform_root is not None
        else None
    )
    resolved_plan_path = (
        _resolve_workspace_file(plan_path)
        if plan_path
        else None
    )

    active = _resolve_active_scanners(api_url, api_key, args.project_id)
    if iac_only:
        active = [entry for entry in active if entry.get("key") == "checkov"]
    # Checkov is part of the IaC analysis contract, not an optional side scan. It
    # runs exactly once even when the project scanner catalog has it disabled.
    if (plan_path or terraform_root is not None) and not any(
        entry.get("key") == "checkov" for entry in active
    ):
        active.append({"key": "checkov", "config": None})

    if not active:
        log.warning(
            "No scanners are enabled for this project. Enable at least one "
            "in the SecureObs dashboard, then re-run the pipeline."
        )
        # Do NOT return here — infrastructure analysis must still run when
        # --terraform-plan-json is provided even if no ordinary scanners are enabled.
    else:
        enabled_keys = [str(entry.get("key", "?")) for entry in active]
        log.info("Active scanners for this run: %s", ", ".join(enabled_keys))

        executions: list[execution.Execution] = []
        iac_checkov_failed = False
        # Mark every active scanner as running first, so a scan that dies midway
        # leaves "running" (never "completed") behind for the gate to see.
        api_client.post_scan_executions(
            api_url, api_key, args.project_id, args.pipeline_run_id,
            [execution.running(e["key"]).to_api() for e in active if isinstance(e.get("key"), str)])

        for entry in active:
            key = entry.get("key")
            cfg = entry.get("config") or None

            if not key or not isinstance(key, str):
                log.warning("Skipping malformed active-scanner entry: %r", entry)
                continue

            driver = REGISTRY.get(key)
            if driver is None:
                log.warning(
                    "Unknown scanner key '%s' returned by the API; skipping. "
                    "(This usually means the SecureObs catalog is ahead of this "
                    "image — pin to a newer tag once the driver ships.)",
                    key,
                )
                executions.append(execution.driver_unavailable(key))
                continue

            try:
                if key == "checkov" and (plan_path or resolved_terraform_root is not None):
                    cfg = dict(cfg or {})
                    if resolved_terraform_root is not None:
                        cfg["terraform_root"] = resolved_terraform_root
                    if resolved_plan_path is not None:
                        cfg["terraform_plan_json"] = resolved_plan_path
                result = driver.runner(
                    _WORKSPACE, args.project_id, args.pipeline_run_id, cfg
                )
            except RuntimeError as exc:
                # Drivers raise RuntimeError for operational tool failures (bad exit code,
                # timeout, unreadable output): report the reason, not a traceback.
                log.error("Scanner '%s' failed: %s — continuing with the remaining scanners.", key, exc)
                executions.append(execution.from_exception(key, exc))
                if key == "checkov" and (plan_path or terraform_root is not None):
                    iac_checkov_failed = True
                continue
            except Exception as exc:
                log.exception(
                    "Scanner '%s' raised an unexpected error; continuing with the "
                    "remaining scanners.",
                    key,
                )
                executions.append(execution.from_exception(key, exc))
                if key == "checkov" and (plan_path or terraform_root is not None):
                    iac_checkov_failed = True
                continue

            row = execution.from_result(key, result)
            if result.skipped:
                reason = result.skip_reason or "(no reason given)"
                if result.exit_code is not None:
                    log.error(
                        "%s skipped due to non-zero exit (code %d): %s. stderr: %s",
                        key,
                        result.exit_code,
                        reason,
                        result.stderr_tail or "(none)",
                    )
                elif result.not_applicable:
                    log.info("%s: not applicable (%s).", key, reason)
                else:
                    log.error("%s did not complete: %s", key, reason)
                executions.append(row)
                if key == "checkov" and (plan_path or terraform_root is not None):
                    iac_checkov_failed = True
                continue

            if not result.findings:
                log.info("%s: no findings.", key)
                executions.append(row)
                continue

            data = api_client.post_findings(api_url, api_key, driver.bulk_endpoint, result.findings)
            ingested = data.get("ingested", len(result.findings))
            deduped = data.get("deduplicated")
            row.finding_count = ingested
            # The ingestion API merges duplicates server-side; a "new" count is shown only
            # when the API reports how many were merged.
            row.new_after_dedup = None if deduped is None else max(ingested - deduped, 0)
            if row.new_after_dedup is None:
                log.info("%s: %d finding(s) uploaded.", key, ingested)
            else:
                log.info("%s: %d finding(s) uploaded (%d new after dedup).", key, ingested, row.new_after_dedup)
            executions.append(row)

        execution.print_summary(executions)
        api_client.post_scan_executions(
            api_url, api_key, args.project_id, args.pipeline_run_id,
            [e.to_api() for e in executions])

        if iac_checkov_failed and require_iac:
            log.error(
                "Infrastructure analysis requires Checkov, but the Checkov Terraform scan failed.")
            sys.exit(2)

    # ── Infrastructure analysis — runs independently of ordinary scanners ──
    # Two sources of the topology: a pre-generated plan JSON (--terraform-plan-json,
    # highest fidelity, needs the user's CI to run terraform plan with cloud creds) or
    # CREDENTIAL-FREE static HCL analysis (--terraform-root, no plan, no creds).
    iac_result = None
    if plan_path:
        log.info("Running infrastructure analysis on plan: %s", plan_path)
        iac_result = iac_plan.run(
            workspace=_WORKSPACE,
            project_id=args.project_id,
            pipeline_run_id=args.pipeline_run_id,
            plan_json_relative_path=plan_path,
            source_revision=source_revision,
            terraform_root_id=terraform_root_id,
            api_url=api_url,
            api_key=api_key,
            require_submission=require_iac,
        )
    elif terraform_root is not None:
        root_dir = resolved_terraform_root or _resolve_workspace_dir(terraform_root)
        log.info("Running credential-free static infrastructure analysis on: %s",
                 terraform_root or "<workspace root>")
        iac_result = iac_config.run(
            root_dir=root_dir,
            project_id=args.project_id,
            pipeline_run_id=args.pipeline_run_id,
            source_revision=source_revision,
            terraform_root_id=terraform_root_id,
            var_files=terraform_var_files,
            api_url=api_url,
            api_key=api_key,
            require_submission=require_iac,
        )

    if iac_result is not None:
        if iac_result.success:
            log.info(
                "Infrastructure analysis: %d resource(s), %d edge(s), "
                "%d potential path(s), %d unsupported resource(s)",
                iac_result.resource_count,
                iac_result.edge_count,
                iac_result.path_count,
                iac_result.unsupported_count,
            )
        else:
            log.error(
                "Infrastructure analysis FAILED: %s",
                iac_result.error or "unknown error",
            )
            if require_iac:
                sys.exit(2)
    elif require_iac:
        log.error(
            "Infrastructure analysis required (--require-infrastructure-analysis) "
            "but neither --terraform-plan-json nor --terraform-root was supplied."
        )
        sys.exit(2)
    else:
        log.info(
            "Infrastructure analysis skipped: neither --terraform-plan-json nor "
            "--terraform-root was supplied.")

    sbom_output = getattr(args, "sbom_output", None)
    if sbom_output:
        sbom_path = _resolve_output_file(sbom_output, "--sbom-output")
        try:
            sbom.generate(_WORKSPACE, sbom_path)
        except Exception as exc:
            log.error("SBOM generation FAILED: %s", exc)
            sys.exit(2)

    log.info("Scan complete.")


def cmd_gate(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")
    gate_module.run(api_url, api_key, args.project_id, args.pipeline_run_id)


def cmd_import_iast(args: argparse.Namespace) -> int:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")
    return iast_command.run(args, api_url, api_key)


def cmd_pr_comment(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")

    if args.platform == "azuredevops":
        azuredevops.post_or_update(api_url, api_key, args.pipeline_run_id, args.project_id)
    elif args.platform == "github":
        github.post_or_update(api_url, api_key, args.pipeline_run_id, args.project_id)
    else:
        log.error("Unknown platform: %s", args.platform)
        sys.exit(1)


def main() -> None:
    config.setup_logging()

    parser = argparse.ArgumentParser(
        prog="secureobs-scanner",
        description="SecureObs security scanner for CI pipelines.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser(
        "scan",
        help="Run the scanners enabled for this project in the SecureObs dashboard, then post findings.",
    )
    _add_common_args(scan_p)
    _add_iac_args(scan_p)
    scan_p.add_argument(
        "--sbom-output",
        default=None,
        metavar="PATH",
        help=(
            "Also write a CycloneDX SBOM (inventory of every dependency Trivy finds) to this "
            "path — relative to /workspace, or absolute under /workspace or /output. The SBOM "
            "stays in the CI job; SecureObs never uploads or stores it."
        ),
    )

    gate_p = sub.add_parser(
        "gate",
        help="Evaluate the build gate. Exits 3 on blocking findings, 4 when a required "
             "security check did not complete.")
    _add_common_args(gate_p)

    iast_p = sub.add_parser(
        "import-iast",
        help=(
            "Import a report produced by an IAST agent while your tests exercised an "
            "instrumented application. This command does not run or instrument anything."
        ),
    )
    _add_common_args(iast_p)
    iast_p.add_argument("--file", required=True, metavar="PATH",
                        help="Report path inside the container, e.g. /reports/iast.sarif (mount it read-only).")
    iast_p.add_argument("--format", required=True, choices=["sarif"],
                        help="Report format. SARIF 2.1.0 is the supported interchange format.")
    iast_p.add_argument("--provider", required=True, choices=sorted(iast_providers.PROVIDERS),
                        help="IAST engine that produced the report: 'sarif' (generic SARIF 2.1.0 "
                             "IAST export) or 'contrast' (unverified).")
    iast_p.add_argument("--test-session-id", default=None, metavar="ID",
                        help="Test session to record (defaults to the report's automationDetails.id).")
    iast_p.add_argument("--environment", default=None, metavar="NAME",
                        help="Short label for the test environment, e.g. 'ci' or 'staging'.")
    iast_p.add_argument("--max-report-bytes", type=int, default=iast_sarif.DEFAULT_MAX_REPORT_BYTES,
                        metavar="BYTES", help="Reject larger reports (default 10 MiB, maximum 50 MiB).")

    pr_p = sub.add_parser("pr-comment", help="Post or update a PR comment with scan results.")
    _add_common_args(pr_p)
    pr_p.add_argument(
        "--platform",
        required=True,
        choices=["azuredevops", "github"],
        help="CI platform for PR comment posting.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "gate":
        cmd_gate(args)
    elif args.command == "import-iast":
        sys.exit(cmd_import_iast(args))
    elif args.command == "pr-comment":
        cmd_pr_comment(args)


if __name__ == "__main__":
    main()
