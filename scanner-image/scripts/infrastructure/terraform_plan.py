"""Terraform plan analyser for the SecureObs scanner image.

Security contract
-----------------
* NEVER print or log plan file contents.
* NEVER include variable values, output values, provider config, or
  provisioner commands in the normalized payload.
* NEVER accept an absolute path, a path containing ``..``, or a symlink
  that escapes the workspace root.
* NEVER guess values that are marked ``after_unknown`` — record them as
  unknown instead.
* ALLOWLIST-first extraction: only named attributes per resource type are
  kept; everything else is silently dropped.
* DENYLIST as defense-in-depth: any remaining key whose name matches a
  known-sensitive stem is removed even if it slipped through the allowlist.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WORKSPACE_ROOT = "/workspace"
MAX_PLAN_FILE_BYTES = 50 * 1024 * 1024  # 50 MiB

SENSITIVE_KEY_DENYLIST: frozenset[str] = frozenset(
    {
        "secret",
        "password",
        "token",
        "private_key",
        "access_key",
        "connection_string",
        "certificate",
        "client_secret",
        "sas",
        "credential",
        "passwd",
        "pass",
        "pwd",
        "auth",
        "key_data",
        "ssh_key",
        "private_key_pem",
        "client_certificate",
    }
)

# Keys that look sensitive by name but carry safe topology data.
# Azure permission lists ("Get", "List", etc.) are required for rule evaluation
# and must not be silently dropped by the denylist.
SAFE_PERMISSION_KEYS: frozenset[str] = frozenset(
    {
        "secret_permissions",
        "key_permissions",
        "certificate_permissions",
        "storage_permissions",
    }
)

# Recursion / size limits applied before serialisation.
_MAX_NESTED_DEPTH = 3
_MAX_STRING_VALUE_LEN = 4096
_MAX_ARRAY_ITEMS = 256
_MAX_KEY_LEN = 128

# ---------------------------------------------------------------------------
# Per-type attribute allowlists
# ---------------------------------------------------------------------------

_RESOURCE_ALLOWLIST: dict[str, list[str]] = {
    # Resource group (container header for the topology hierarchy)
    "azurerm_resource_group": ["name", "location"],
    # Network
    "azurerm_virtual_network": [
        "name",
        "location",
        "resource_group_name",
        "address_space",
        "dns_servers",
    ],
    "azurerm_subnet": [
        "name",
        "resource_group_name",
        "address_prefixes",
        "virtual_network_name",
        "service_endpoints",
    ],
    "azurerm_network_security_group": ["name", "location", "resource_group_name"],
    "azurerm_network_security_rule": [
        "name",
        "resource_group_name",
        "network_security_group_name",
        "direction",
        "access",
        "protocol",
        "source_port_range",
        "source_port_ranges",
        "destination_port_range",
        "destination_port_ranges",
        "source_address_prefix",
        "source_address_prefixes",
        "destination_address_prefix",
        "destination_address_prefixes",
        "priority",
    ],
    "azurerm_subnet_network_security_group_association": [
        "subnet_id",
        "network_security_group_id",
    ],
    "azurerm_network_interface": [
        "name",
        "location",
        "resource_group_name",
        "ip_configuration",
    ],
    "azurerm_network_interface_security_group_association": [
        "network_interface_id",
        "network_security_group_id",
    ],
    "azurerm_public_ip": [
        "name",
        "location",
        "resource_group_name",
        "allocation_method",
        "sku",
    ],
    "azurerm_private_endpoint": [
        "name",
        "location",
        "resource_group_name",
        "subnet_id",
        "private_service_connection",
    ],
    # Compute
    "azurerm_linux_virtual_machine": [
        "name",
        "location",
        "resource_group_name",
        "size",
        "identity",
        "network_interface_ids",
        "disable_password_authentication",
        "patch_mode",
    ],
    "azurerm_windows_virtual_machine": [
        "name",
        "location",
        "resource_group_name",
        "size",
        "identity",
        "network_interface_ids",
        "patch_mode",
    ],
    "azurerm_linux_web_app": [
        "name",
        "location",
        "resource_group_name",
        "identity",
        "site_config",
        "public_network_access_enabled",
        "https_only",
    ],
    "azurerm_windows_web_app": [
        "name",
        "location",
        "resource_group_name",
        "identity",
        "site_config",
        "public_network_access_enabled",
        "https_only",
    ],
    "azurerm_container_app": [
        "name",
        "location",
        "identity",
        "ingress",
        "resource_group_name",
    ],
    # Identity
    "azurerm_user_assigned_identity": ["name", "location", "resource_group_name"],
    "azurerm_role_assignment": [
        "scope",
        "role_definition_name",
        "role_definition_id",
        "principal_id",
        "principal_type",
    ],
    "azurerm_key_vault_access_policy": [
        "key_vault_id",
        "tenant_id",
        "object_id",
        "key_permissions",
        "secret_permissions",
        "certificate_permissions",
    ],
    # Secret stores / storage
    "azurerm_key_vault": [
        "name",
        "location",
        "resource_group_name",
        "sku_name",
        "enable_rbac_authorization",
        "public_network_access_enabled",
        "network_acls",
    ],
    "azurerm_storage_account": [
        "name",
        "location",
        "resource_group_name",
        "account_tier",
        "account_replication_type",
        "public_network_access_enabled",
        "allow_nested_items_to_be_public",
        "min_tls_version",
    ],
    "azurerm_storage_container": [
        "name",
        "storage_account_name",
        "container_access_type",
    ],
    # Databases
    "azurerm_mssql_server": [
        "name",
        "location",
        "resource_group_name",
        "public_network_access_enabled",
        "minimum_tls_version",
    ],
    "azurerm_mssql_database": ["name", "server_id"],
    "azurerm_mssql_firewall_rule": [
        "name",
        "server_id",
        "start_ip_address",
        "end_ip_address",
    ],
    "azurerm_postgresql_flexible_server": [
        "name",
        "location",
        "resource_group_name",
        "public_network_access_enabled",
        "delegated_subnet_id",
    ],
    "azurerm_postgresql_flexible_server_firewall_rule": [
        "name",
        "server_id",
        "start_ip_address",
        "end_ip_address",
    ],
}

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class InfrastructureAnalysisResult:
    success: bool
    resource_count: int = 0
    edge_count: int = 0
    path_count: int = 0
    unsupported_count: int = 0
    error: str | None = None


# ---------------------------------------------------------------------------
# API submission result
# ---------------------------------------------------------------------------

@dataclass
class _ApiSubmitResult:
    ok: bool
    resource_count: int = 0
    edge_count: int = 0
    path_count: int = 0
    error: str | None = None


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def _validate_plan_path(relative_path: str) -> pathlib.Path:
    """Validate and resolve a relative plan path inside WORKSPACE_ROOT.

    Raises ``ValueError`` with a safe (non-leaking) message on any violation.
    """
    if not relative_path:
        raise ValueError("Plan path must not be empty.")

    if os.path.isabs(relative_path):
        raise ValueError("Plan path must be relative, not absolute.")

    # Reject literal '..' components before any resolution.
    parts = pathlib.PurePosixPath(relative_path).parts
    if ".." in parts:
        raise ValueError("Plan path must not contain '..'.")

    workspace = pathlib.Path(WORKSPACE_ROOT).resolve()
    candidate = (workspace / relative_path).resolve()

    # Ensure the resolved path is actually inside the workspace.
    try:
        candidate.relative_to(workspace)
    except ValueError:
        raise ValueError("Plan path resolves outside the workspace root.")

    # Reject symlinks that point outside the workspace.
    if candidate.is_symlink():
        link_target = pathlib.Path(os.path.realpath(str(candidate)))
        try:
            link_target.relative_to(workspace)
        except ValueError:
            raise ValueError("Plan path symlink escapes the workspace root.")

    if not candidate.is_file():
        raise ValueError("Plan path does not point to a regular file.")

    return candidate


# ---------------------------------------------------------------------------
# Format-version validation
# ---------------------------------------------------------------------------


def _validate_format_version(format_version: str) -> None:
    """Accept ``1.x`` only; raise ``ValueError`` for other major versions."""
    try:
        major = int(str(format_version).split(".")[0])
    except (ValueError, IndexError):
        raise ValueError(
            f"Unrecognised format_version: {format_version!r}"
        )
    if major != 1:
        raise ValueError(
            f"Unsupported format_version major: {major!r} (only '1.x' accepted)."
        )


# ---------------------------------------------------------------------------
# Recursive module extraction helpers
# ---------------------------------------------------------------------------


def _iter_module_resources(module: dict) -> list[dict]:
    """Yield all resources from a module and its child_modules recursively."""
    out: list[dict] = []
    for res in module.get("resources") or []:
        if isinstance(res, dict):
            out.append(res)
    for child in module.get("child_modules") or []:
        if isinstance(child, dict):
            out.extend(_iter_module_resources(child))
    return out


def _iter_module_resources_cfg(module: dict) -> list[dict]:
    """Yield configuration resources from a module recursively."""
    out: list[dict] = []
    for res in module.get("resources") or []:
        if isinstance(res, dict):
            out.append(res)
    for child in (module.get("module_calls") or {}).values():
        if isinstance(child, dict):
            inner = child.get("module") or {}
            if isinstance(inner, dict):
                out.extend(_iter_module_resources_cfg(inner))
    return out


def _iter_references(module: dict, source_address: str = "") -> list[dict]:
    """Extract expression references from a configuration module recursively."""
    refs: list[dict] = []

    for res in module.get("resources") or []:
        if not isinstance(res, dict):
            continue
        addr = res.get("address") or source_address
        _collect_expression_refs(res.get("expressions") or {}, addr, refs, attr_path="")

    for call_name, call in (module.get("module_calls") or {}).items():
        if not isinstance(call, dict):
            continue
        inner_module = call.get("module") or {}
        if isinstance(inner_module, dict):
            refs.extend(_iter_references(inner_module, call_name))

    return refs


def _collect_expression_refs(
    expressions: dict,
    source_address: str,
    out: list[dict],
    attr_path: str,
) -> None:
    """Walk an expressions dict and emit references with their attribute paths."""
    if not isinstance(expressions, dict):
        return
    for key, expr in expressions.items():
        if not isinstance(expr, dict):
            continue
        current_path = f"{attr_path}.{key}" if attr_path else key
        for ref in expr.get("references") or []:
            if not isinstance(ref, str):
                continue
            # Skip meta-references like "var.*", "each.*", "path.*",
            # "module.*" (module-level), "data.*" raw, "local.*", "self"
            if _is_resource_reference(ref):
                # Canonicalise the target address: strip trailing attribute
                # accessors (.id, .principal_id, [0].id, etc.) so the target
                # is a Terraform resource address that will appear in the plan.
                canonical = _canonicalise_reference(ref)
                out.append(
                    {
                        "sourceAddress": source_address,
                        "targetAddress": canonical,
                        "referenceType": "terraform",
                        "attributePath": current_path,
                    }
                )
        # Recurse into nested expression blocks (e.g. ip_configuration)
        _collect_expression_refs(expr, source_address, out, current_path)


def _canonicalise_reference(ref: str) -> str:
    """Strip trailing attribute accessors from a Terraform expression reference.

    Terraform configuration references look like:
      ``azurerm_subnet.main.id``
      ``module.networking.azurerm_subnet.main[0].id``
      ``azurerm_user_assigned_identity.app.principal_id``

    The graph builder needs the *resource address* part, not the attribute suffix.
    We strip everything after the last ``[...]`` index or after the second-last
    dot segment that is not a module component.

    Examples
    --------
    ``azurerm_subnet.main.id``              → ``azurerm_subnet.main``
    ``module.net.azurerm_subnet.main[0].id``→ ``module.net.azurerm_subnet.main[0]``
    ``azurerm_x.y``                         → ``azurerm_x.y``  (no change, no suffix)
    """
    import re as _re

    # Strip a trailing .attr_name after an optional [index].
    # Pattern: strip the last .something that is NOT an index expression.
    stripped = _re.sub(r"\.[a-zA-Z_][a-zA-Z0-9_]*$", "", ref)
    # If stripping left us with something that still ends in [n], keep it.
    # If we over-stripped (e.g. "azurerm_x" with no dot left), restore original.
    if "." not in stripped and "[" not in stripped:
        return ref
    return stripped


def _is_resource_reference(ref: str) -> bool:
    """Return True if the reference string looks like a managed/data resource."""
    if "." not in ref:
        return False
    skip_prefixes = ("var.", "local.", "each.", "path.", "self", "data.")
    for pfx in skip_prefixes:
        if ref.startswith(pfx):
            return False
    # Terraform resource references look like "azurerm_vnet.main" or
    # "module.networking.azurerm_vnet.main"
    return True


# ---------------------------------------------------------------------------
# Attribute sanitisation
# ---------------------------------------------------------------------------


def _is_sensitive(sensitive_values: Any, key: str) -> bool:
    """Return True if the attribute key is flagged as sensitive at the top level."""
    if sensitive_values is True:
        return True
    if isinstance(sensitive_values, dict):
        val = sensitive_values.get(key)
        if val is True:
            return True
        if isinstance(val, list) and any(v is True for v in val):
            return True
    return False


def _is_unknown(after_unknown: Any, key: str) -> bool:
    """Return True if the attribute value is not yet known (after_unknown) at the top level."""
    if after_unknown is True:
        return True
    if isinstance(after_unknown, dict):
        val = after_unknown.get(key)
        if val is True:
            return True
        if isinstance(val, list) and any(v is True for v in val):
            return True
    return False


def _key_matches_denylist(key: str) -> bool:
    """Return True if the key name is or contains a sensitive stem."""
    lower = key.lower()
    for stem in SENSITIVE_KEY_DENYLIST:
        if stem in lower:
            return True
    return False


def _get_ctx_flag(ctx: Any, key: str) -> bool:
    """Check whether *key* is flagged True in a sensitivity/unknown context dict."""
    if ctx is True:
        return True
    if isinstance(ctx, dict):
        v = ctx.get(key)
        if v is True:
            return True
        if isinstance(v, list) and any(x is True for x in v):
            return True
    return False


def _nested_ctx(ctx: Any, key: str) -> Any:
    """Descend one level into a sensitivity/unknown context dict for *key*."""
    if ctx is True:
        return True
    if isinstance(ctx, dict):
        return ctx.get(key, {})
    return {}


def _sanitise_value_recursive(
    value: Any,
    sensitive_ctx: Any,
    unknown_ctx: Any,
    depth: int,
    path: str,
    unknown_paths: list[str],
    redacted_paths: list[str],
) -> Any:
    """Recursively sanitise *value*, enforcing bounds and sensitivity masks."""
    if depth >= _MAX_NESTED_DEPTH:
        # At the depth limit: pass through primitives, drop containers.
        if isinstance(value, str):
            return value[:_MAX_STRING_VALUE_LEN]
        if isinstance(value, (bool, int, float, type(None))):
            return value
        return None

    if isinstance(value, str):
        return value[:_MAX_STRING_VALUE_LEN]

    if isinstance(value, (bool, int, float, type(None))):
        return value

    if isinstance(value, dict):
        safe: dict = {}
        for k, v in value.items():
            if len(k) > _MAX_KEY_LEN:
                continue
            child_path = f"{path}.{k}"
            if _get_ctx_flag(sensitive_ctx, k):
                redacted_paths.append(child_path)
                continue
            if _get_ctx_flag(unknown_ctx, k):
                unknown_paths.append(child_path)
                continue
            if k not in SAFE_PERMISSION_KEYS and _key_matches_denylist(k):
                redacted_paths.append(child_path)
                continue
            safe_v = _sanitise_value_recursive(
                v,
                _nested_ctx(sensitive_ctx, k),
                _nested_ctx(unknown_ctx, k),
                depth + 1,
                child_path,
                unknown_paths,
                redacted_paths,
            )
            if safe_v is not None or v is None:
                safe[k] = safe_v
        return safe

    if isinstance(value, list):
        if sensitive_ctx is True:
            redacted_paths.append(path)
            return []
        if unknown_ctx is True:
            unknown_paths.append(path)
            return []

        items = value[:_MAX_ARRAY_ITEMS]
        result: list = []
        for i, item in enumerate(items):
            item_sens = (
                sensitive_ctx[i]
                if isinstance(sensitive_ctx, list) and i < len(sensitive_ctx)
                else (True if sensitive_ctx is True else {})
            )
            item_unk = (
                unknown_ctx[i]
                if isinstance(unknown_ctx, list) and i < len(unknown_ctx)
                else (True if unknown_ctx is True else {})
            )
            item_path = f"{path}[{i}]"
            if item_sens is True:
                redacted_paths.append(item_path)
                continue
            if item_unk is True:
                unknown_paths.append(item_path)
                continue
            safe_item = _sanitise_value_recursive(
                item,
                item_sens,
                item_unk,
                depth + 1,
                item_path,
                unknown_paths,
                redacted_paths,
            )
            if safe_item is not None or item is None:
                result.append(safe_item)
        return result

    return None


def _sanitise_resource(
    resource_type: str,
    values: dict,
    sensitive_values: Any,
    after_unknown: Any,
) -> tuple[dict, list[str], list[str]]:
    """Return (safe_attributes, unknown_paths, redacted_paths).

    Applies allowlist-first extraction with recursive sensitivity/unknown checking
    and denylist defense-in-depth at every nesting level.
    """
    safe: dict = {}
    unknown_paths: list[str] = []
    redacted_paths: list[str] = []

    allowed_keys = _RESOURCE_ALLOWLIST.get(resource_type)
    if allowed_keys is None:
        return safe, unknown_paths, redacted_paths

    for key in allowed_keys:
        if key not in values:
            continue

        if _is_sensitive(sensitive_values, key):
            redacted_paths.append(key)
            continue

        if _is_unknown(after_unknown, key):
            unknown_paths.append(key)
            continue

        # Defense-in-depth: top-level denylist (SAFE_PERMISSION_KEYS bypass).
        if key not in SAFE_PERMISSION_KEYS and _key_matches_denylist(key):
            redacted_paths.append(key)
            continue

        # Recursively sanitise nested value, walking sensitivity/unknown masks.
        safe_v = _sanitise_value_recursive(
            values[key],
            _nested_ctx(sensitive_values, key),
            _nested_ctx(after_unknown, key),
            depth=1,
            path=key,
            unknown_paths=unknown_paths,
            redacted_paths=redacted_paths,
        )
        if safe_v is not None or values[key] is None:
            safe[key] = safe_v

    return safe, unknown_paths, redacted_paths


# ---------------------------------------------------------------------------
# Resource change action helpers
# ---------------------------------------------------------------------------


def _extract_change_actions(change: dict | None) -> list[str]:
    if not isinstance(change, dict):
        return []
    actions = change.get("actions") or []
    if not isinstance(actions, list):
        return []
    valid = {"create", "update", "no-op", "delete", "read"}
    return [str(a) for a in actions if str(a) in valid]


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------


def _parse_plan(raw_bytes: bytes) -> dict:
    """Parse and return the plan dict; raises ValueError on bad JSON."""
    try:
        return json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Plan file is not valid JSON: {exc}") from exc


def _build_resource_index(
    planned_root: dict,
    resource_changes: list[dict],
) -> dict[str, dict]:
    """Build an address-keyed index combining planned values and changes."""
    index: dict[str, dict] = {}

    # Walk planned_values.root_module recursively.
    for res in _iter_module_resources(planned_root):
        addr = res.get("address") or ""
        if addr:
            index[addr] = {
                "planned": res,
                "change": None,
            }

    # Overlay resource_changes (may introduce addresses not in planned_values
    # for delete-only operations where no "after" state exists).
    for rc in resource_changes:
        if not isinstance(rc, dict):
            continue
        addr = rc.get("address") or ""
        if not addr:
            continue
        if addr in index:
            index[addr]["change"] = rc
        else:
            index[addr] = {"planned": None, "change": rc}

    return index


def _normalize_resources(
    index: dict[str, dict],
    cfg_resources: dict[str, dict],
) -> tuple[list[dict], int]:
    """Build the normalized resource list; return (resources, unsupported_count)."""
    results: list[dict] = []
    unsupported_count = 0

    for address, entry in index.items():
        planned = entry.get("planned") or {}
        change = entry.get("change") or {}

        # Prefer data from planned_values; fall back to resource_changes.
        res_type = planned.get("type") or change.get("type") or ""
        res_name = planned.get("name") or change.get("name") or ""
        module_address = (
            planned.get("module_address")
            or change.get("module_address")
            or None
        )
        mode = planned.get("mode") or change.get("mode") or "managed"

        # Provider comes from planned_values resource or change.
        provider_name = (
            planned.get("provider_name")
            or change.get("provider_name")
            or change.get("provider_config_key")
            or None
        )

        change_actions = _extract_change_actions(change.get("change"))

        # Values for attribute extraction come from planned_values.
        values: dict = {}
        sensitive_values: Any = {}
        after_unknown: Any = {}

        if planned:
            values = planned.get("values") or {}
            sensitive_values = planned.get("sensitive_values") or {}

        if isinstance(change.get("change"), dict):
            chg = change["change"]
            # after_unknown is only meaningful for creates/updates.
            after_unknown = chg.get("after_unknown") or {}
            # Merge before_sensitive and after_sensitive for redaction.
            for sens_key in ("before_sensitive", "after_sensitive"):
                sv = chg.get(sens_key)
                if sv is True:
                    sensitive_values = True
                elif isinstance(sv, dict) and isinstance(sensitive_values, dict):
                    for k, v in sv.items():
                        if v:
                            sensitive_values[k] = v

        is_known_type = res_type in _RESOURCE_ALLOWLIST

        if is_known_type:
            safe_attrs, unknown_paths, redacted_paths = _sanitise_resource(
                res_type, values, sensitive_values, after_unknown
            )
        else:
            unsupported_count += 1
            safe_attrs = {}
            unknown_paths = []
            redacted_paths = []

        resource_node: dict = {
            "address": address,
            "moduleAddress": module_address,
            "mode": mode,
            "type": res_type,
            "name": res_name,
            "providerName": provider_name,
            "changeActions": change_actions,
            "safeAttributes": safe_attrs,
            "unknownAttributePaths": unknown_paths,
            "redactedAttributePaths": redacted_paths,
        }
        results.append(resource_node)

    return results, unsupported_count


def _normalize_references(plan: dict) -> list[dict]:
    """Extract references from configuration.root_module recursively."""
    cfg = plan.get("configuration") or {}
    if not isinstance(cfg, dict):
        return []
    root_module = cfg.get("root_module") or {}
    if not isinstance(root_module, dict):
        return []
    return _iter_references(root_module)


# ---------------------------------------------------------------------------
# API submission
# ---------------------------------------------------------------------------


def _post_analysis(
    api_url: str,
    api_key: str,
    payload: dict,
) -> _ApiSubmitResult:
    """Post the infrastructure analysis payload; return a structured result."""
    try:
        import api_client  # local import to keep module importable in tests

        ok, result = api_client.post_infrastructure_analysis(api_url, api_key, payload)
        if not ok:
            log.error("Infrastructure analysis submission failed: %s", result)
            return _ApiSubmitResult(ok=False, error=str(result))

        # Populate counts from the API response so we report real graph metrics,
        # not raw Terraform reference counts.
        resource_count = int(result.get("resourceCount", 0)) if isinstance(result, dict) else 0
        edge_count = int(result.get("edgeCount", 0)) if isinstance(result, dict) else 0
        path_count = int(result.get("potentialAttackPathCount", 0)) if isinstance(result, dict) else 0
        return _ApiSubmitResult(
            ok=True,
            resource_count=resource_count,
            edge_count=edge_count,
            path_count=path_count,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error posting infrastructure analysis: %s", exc)
        return _ApiSubmitResult(ok=False, error=str(exc))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(
    workspace: str,
    project_id: str,
    pipeline_run_id: str,
    plan_json_relative_path: str,
    *,
    source_revision: str | None = None,
    terraform_root_id: str | None = None,
    api_url: str | None = None,
    api_key: str | None = None,
    require_submission: bool = False,
) -> InfrastructureAnalysisResult:
    """Analyse a Terraform plan JSON file and post the sanitized payload.

    Never raises.  All errors are logged and returned as an
    ``InfrastructureAnalysisResult`` with ``success=False``.

    Parameters
    ----------
    workspace:
        The workspace root (must equal ``WORKSPACE_ROOT`` in production;
        exposed as a parameter so tests can supply a temp dir).
    project_id:
        SecureObs project identifier.
    pipeline_run_id:
        Unique identifier for this pipeline invocation.
    plan_json_relative_path:
        Path to the Terraform plan JSON file, relative to ``workspace``.
    source_revision:
        VCS commit SHA or ref for the plan source (from ``--source-revision``).
    terraform_root_id:
        Stable configuration ID for the Terraform root being analysed.
    api_url:
        Override the SecureObs API URL (defaults to env var).
    api_key:
        Override the API key (defaults to env var).
    require_submission:
        Return failure instead of silently performing a local-only parse when API
        submission credentials are unavailable.
    """
    effective_workspace = workspace or WORKSPACE_ROOT

    try:
        return _run_inner(
            effective_workspace,
            project_id,
            pipeline_run_id,
            plan_json_relative_path,
            source_revision=source_revision,
            terraform_root_id=terraform_root_id,
            api_url=api_url,
            api_key=api_key,
            require_submission=require_submission,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("terraform_plan.run raised unexpectedly: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))


def _run_inner(
    workspace: str,
    project_id: str,
    pipeline_run_id: str,
    plan_json_relative_path: str,
    *,
    source_revision: str | None,
    terraform_root_id: str | None,
    api_url: str | None,
    api_key: str | None,
    require_submission: bool,
) -> InfrastructureAnalysisResult:
    # ------------------------------------------------------------------
    # 1. Validate the path
    # ------------------------------------------------------------------
    try:
        plan_path = _validate_plan_path_in_workspace(
            workspace, plan_json_relative_path
        )
    except ValueError as exc:
        log.error("Invalid plan path: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # 2. Size check
    # ------------------------------------------------------------------
    try:
        file_size = plan_path.stat().st_size
    except OSError as exc:
        log.error("Cannot stat plan file: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))

    if file_size > MAX_PLAN_FILE_BYTES:
        msg = (
            f"Plan file exceeds maximum size "
            f"({file_size} > {MAX_PLAN_FILE_BYTES} bytes)."
        )
        log.error(msg)
        return InfrastructureAnalysisResult(success=False, error=msg)

    # ------------------------------------------------------------------
    # 3. Read + digest
    # ------------------------------------------------------------------
    try:
        raw_bytes = plan_path.read_bytes()
    except OSError as exc:
        log.error("Cannot read plan file: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))

    hex_digest = hashlib.sha256(raw_bytes).hexdigest()

    # ------------------------------------------------------------------
    # 4. Parse JSON
    # ------------------------------------------------------------------
    try:
        plan = _parse_plan(raw_bytes)
    except ValueError as exc:
        log.error("Plan parse error: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))

    if not isinstance(plan, dict):
        msg = "Plan JSON root is not an object."
        log.error(msg)
        return InfrastructureAnalysisResult(success=False, error=msg)

    # ------------------------------------------------------------------
    # 5. Validate format_version
    # ------------------------------------------------------------------
    format_version = plan.get("format_version", "")
    try:
        _validate_format_version(format_version)
    except ValueError as exc:
        log.error("Unsupported plan format: %s", exc)
        return InfrastructureAnalysisResult(success=False, error=str(exc))

    terraform_version = plan.get("terraform_version")  # may be None

    # ------------------------------------------------------------------
    # 6. Build resource index
    # ------------------------------------------------------------------
    planned_values = plan.get("planned_values") or {}
    root_module = planned_values.get("root_module") or {}

    resource_changes_raw = plan.get("resource_changes") or []
    if not isinstance(resource_changes_raw, list):
        resource_changes_raw = []

    resource_index = _build_resource_index(root_module, resource_changes_raw)

    # ------------------------------------------------------------------
    # 7. Build configuration resource lookup (for provider/module info)
    # ------------------------------------------------------------------
    cfg = plan.get("configuration") or {}
    cfg_root = cfg.get("root_module") or {}
    cfg_resources: dict[str, dict] = {}
    for res in _iter_module_resources_cfg(cfg_root):
        addr = res.get("address") or ""
        if addr:
            cfg_resources[addr] = res

    # ------------------------------------------------------------------
    # 8. Normalize resources
    # ------------------------------------------------------------------
    resources, unsupported_count = _normalize_resources(resource_index, cfg_resources)

    # ------------------------------------------------------------------
    # 9. Extract references
    # ------------------------------------------------------------------
    references = _normalize_references(plan)

    # ------------------------------------------------------------------
    # 10. Build payload
    # ------------------------------------------------------------------
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "planDigest": hex_digest,
        "formatVersion": format_version,
        "terraformVersion": terraform_version,
        "sourceRevision": source_revision,
        "terraformRootId": terraform_root_id,
        "resources": resources,
        "references": references,
        "warnings": _collect_warnings(plan, unsupported_count),
    }

    log.info(
        "Terraform plan analysed: %d resource(s) (%d unsupported), "
        "%d reference(s), digest=%s",
        len(resources),
        unsupported_count,
        len(references),
        hex_digest,
    )

    # ------------------------------------------------------------------
    # 11. Post — failure is an infrastructure-analysis failure.
    # ------------------------------------------------------------------
    effective_url = api_url or os.environ.get("SECUREOBS_API_URL", "")
    effective_key = api_key or os.environ.get("SECUREOBS_API_KEY", "")

    if not (effective_url and effective_key):
        if require_submission:
            return InfrastructureAnalysisResult(
                success=False,
                resource_count=len(resources),
                unsupported_count=unsupported_count,
                error="API URL and API key are required for infrastructure analysis submission",
            )
        log.debug(
            "No API URL/key available; skipping infrastructure analysis submission."
        )
        return InfrastructureAnalysisResult(
            success=True,
            resource_count=len(resources),
            edge_count=0,
            path_count=0,
            unsupported_count=unsupported_count,
        )

    submit = _post_analysis(effective_url, effective_key, payload)
    if not submit.ok:
        return InfrastructureAnalysisResult(
            success=False,
            resource_count=len(resources),
            unsupported_count=unsupported_count,
            error=submit.error or "API submission failed",
        )

    return InfrastructureAnalysisResult(
        success=True,
        resource_count=submit.resource_count or len(resources),
        edge_count=submit.edge_count,
        path_count=submit.path_count,
        unsupported_count=unsupported_count,
    )


def _collect_warnings(plan: dict, unsupported_count: int) -> list[str]:
    warnings: list[str] = []
    if unsupported_count:
        warnings.append(
            f"{unsupported_count} resource type(s) not in the allowlist; "
            "only address/type/name/changeActions are recorded for those."
        )
    # Warn if the plan contains outputs or variables (we intentionally skip them).
    if plan.get("output_changes") or (plan.get("planned_values") or {}).get("outputs"):
        warnings.append(
            "Plan contains output values; they are intentionally excluded from analysis."
        )
    if plan.get("variables"):
        warnings.append(
            "Plan contains variable values; they are intentionally excluded from analysis."
        )
    return warnings


# ---------------------------------------------------------------------------
# Workspace-relative path validation (accepts custom workspace for tests)
# ---------------------------------------------------------------------------


def _validate_plan_path_in_workspace(
    workspace: str, relative_path: str
) -> pathlib.Path:
    """Validate *relative_path* relative to *workspace*.

    This is the internal variant used by ``_run_inner``; it takes an explicit
    workspace so tests can pass a temp dir without mutating the global constant.
    """
    if not relative_path:
        raise ValueError("Plan path must not be empty.")

    if os.path.isabs(relative_path):
        raise ValueError("Plan path must be relative, not absolute.")

    parts = pathlib.PurePosixPath(relative_path).parts
    if ".." in parts:
        raise ValueError("Plan path must not contain '..'.")

    workspace_path = pathlib.Path(workspace).resolve()
    candidate = (workspace_path / relative_path).resolve()

    try:
        candidate.relative_to(workspace_path)
    except ValueError:
        raise ValueError("Plan path resolves outside the workspace root.")

    if candidate.is_symlink():
        link_target = pathlib.Path(os.path.realpath(str(candidate)))
        try:
            link_target.relative_to(workspace_path)
        except ValueError:
            raise ValueError("Plan path symlink escapes the workspace root.")

    if not candidate.is_file():
        raise ValueError("Plan path does not point to a regular file.")

    return candidate
