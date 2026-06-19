#!/usr/bin/env python3
import argparse
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

import config
import api_client
import build_gate as gate_module
from scanners.registry import DEFAULT_KEYS, REGISTRY
from pr_comments import azuredevops, github
from infrastructure import terraform_plan as iac_plan

log = logging.getLogger(__name__)


@dataclass
class _ScanRow:
    key: str
    status: str = "ok"          # ok | skipped | error | unknown
    findings: int = 0
    ingested: int = 0
    new_after_dedup: int = 0
    skip_reason: Optional[str] = None


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
            "plan is never transmitted. Omit to skip infrastructure analysis."
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
        default=None,
        metavar="STABLE_ID",
        help=(
            "Stable configuration ID for the Terraform root being analysed. "
            "Used to distinguish multiple roots in a monorepo."
        ),
    )
    p.add_argument(
        "--require-infrastructure-analysis",
        action="store_true",
        default=False,
        help=(
            "Exit with a non-zero code if infrastructure analysis fails or is "
            "skipped (no --terraform-plan-json supplied). Ordinary scanner "
            "failures are unaffected by this flag."
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


def _print_scan_summary(rows: list[_ScanRow]) -> None:
    """Print a formatted per-scanner summary table to the log."""
    if not rows:
        return

    col_w = max(len(r.key) for r in rows) + 2
    sep = "─" * (col_w + 36)

    lines = [f"\n{sep}"]
    for r in rows:
        label = r.key.ljust(col_w)
        if r.status == "skipped":
            reason = r.skip_reason or "no_reason"
            lines.append(f"  {label}SKIPPED  ({reason})")
        elif r.status == "error":
            lines.append(f"  {label}ERROR    (see above)")
        elif r.status == "unknown":
            lines.append(f"  {label}UNKNOWN  (driver not in catalog)")
        else:
            if r.findings == 0:
                lines.append(f"  {label}0 findings")
            else:
                lines.append(
                    f"  {label}{r.findings} finding(s)  "
                    f"({r.new_after_dedup} new after dedup)"
                )

    total_findings = sum(r.findings for r in rows)
    total_new = sum(r.new_after_dedup for r in rows)
    lines.append(sep)
    total_label = "Total".ljust(col_w)
    lines.append(f"  {total_label}{total_findings} finding(s)  ({total_new} new after dedup)")
    lines.append(sep)

    log.info("\n".join(lines))


def cmd_scan(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")

    require_iac = getattr(args, "require_infrastructure_analysis", False)
    plan_path = getattr(args, "terraform_plan_json", None)
    source_revision = getattr(args, "source_revision", None)
    terraform_root_id = getattr(args, "terraform_root_id", None)

    active = _resolve_active_scanners(api_url, api_key, args.project_id)

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

        summary_rows: list[_ScanRow] = []

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
                summary_rows.append(_ScanRow(key=key, status="unknown"))
                continue

            try:
                result = driver.runner(
                    "/workspace", args.project_id, args.pipeline_run_id, cfg
                )
            except Exception:
                log.exception(
                    "Scanner '%s' raised an unexpected error; continuing with the "
                    "remaining scanners.",
                    key,
                )
                summary_rows.append(_ScanRow(key=key, status="error"))
                continue

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
                else:
                    log.info("%s skipped: %s", key, reason)
                summary_rows.append(_ScanRow(key=key, status="skipped", skip_reason=reason))
                continue

            if not result.findings:
                log.info("%s: no findings.", key)
                summary_rows.append(_ScanRow(key=key, status="ok"))
                continue

            data = api_client.post_findings(api_url, api_key, driver.bulk_endpoint, result.findings)
            ingested = data.get("ingested", len(result.findings))
            deduped = data.get("deduplicated", 0)
            new_count = ingested - deduped
            log.info("%s: %d finding(s) ingested (%d new after dedup).", key, ingested, deduped)
            summary_rows.append(
                _ScanRow(
                    key=key,
                    status="ok",
                    findings=ingested,
                    ingested=ingested,
                    new_after_dedup=new_count,
                )
            )

        _print_scan_summary(summary_rows)

    # ── Infrastructure analysis — runs independently of ordinary scanners ──
    if plan_path:
        log.info("Running infrastructure analysis on plan: %s", plan_path)
        iac_result = iac_plan.run(
            workspace="/workspace",
            project_id=args.project_id,
            pipeline_run_id=args.pipeline_run_id,
            plan_json_relative_path=plan_path,
            source_revision=source_revision,
            terraform_root_id=terraform_root_id,
            api_url=api_url,
            api_key=api_key,
            require_submission=require_iac,
        )
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
            "but no --terraform-plan-json was supplied."
        )
        sys.exit(2)
    else:
        log.info("Infrastructure analysis skipped: no --terraform-plan-json supplied.")

    log.info("Scan complete.")


def cmd_gate(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")
    gate_module.run(api_url, api_key, args.pipeline_run_id)


def cmd_pr_comment(args: argparse.Namespace) -> None:
    api_url = config.get_api_url()
    api_key = config.require_env("SECUREOBS_API_KEY")

    if args.platform == "azuredevops":
        azuredevops.post_or_update(api_url, api_key, args.pipeline_run_id)
    elif args.platform == "github":
        github.post_or_update(api_url, api_key, args.pipeline_run_id)
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

    gate_p = sub.add_parser("gate", help="Check for blocking findings. Exits 3 if blocked.")
    _add_common_args(gate_p)

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
    elif args.command == "pr-comment":
        cmd_pr_comment(args)


if __name__ == "__main__":
    main()
