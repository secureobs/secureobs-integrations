"""Static, credential-free Terraform topology extractor.

Parses HCL with ``python-hcl2`` — no ``terraform plan``, no provider initialization,
no cloud credentials — and produces the same ingestion schema as
``terraform_plan.py`` (reusing its allowlist + sanitizer), so the server-side graph
builder and attack-path rules can consume either source while preserving the
analysis-mode fidelity warning.

Fidelity vs. a real plan
------------------------
A real plan resolves every expression; this extractor resolves variable and local
references best-effort and marks unresolved expressions as unknown. ``count`` /
``for_each`` resources are represented once unless statically disabled. Local modules
are followed; remote modules are skipped with a warning.

Security contract (same as terraform_plan)
------------------------------------------
* Allowlist-first attribute extraction; denylist defense-in-depth.
* Never emits variable values, provider config, or secret-stemmed keys.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any

import hcl2

from . import terraform_plan as tp

log = logging.getLogger(__name__)

MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 50 * 1024 * 1024
MAX_MODULE_DEPTH = 8
MAX_RESOURCES = 2_000
MAX_REFERENCES = 10_000
MAX_WARNINGS = 200
MAX_WARNING_LENGTH = 1024
_FORMAT_VERSION = "1.0"  # satisfies the ingestion validator's "1.x" requirement

# A reference like azurerm_subnet.main / azurerm_subnet.main.id / module.x[0].
# First segment must look like a managed-resource type (lowercase, has an underscore).
_REF_RE = re.compile(
    r"\b([a-z][a-z0-9]*_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[[^\]]*\])?(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)
_VAR_RE = re.compile(r"\$\{\s*var\.([A-Za-z_][A-Za-z0-9_]*)\s*\}")
_LOCAL_RE = re.compile(r"\$\{\s*local\.([A-Za-z_][A-Za-z0-9_]*)\s*\}")
_SKIP_REF_PREFIXES = ("var.", "local.", "each.", "count.", "path.", "self.", "data.", "module.")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _is_within(path: str, boundary: str) -> bool:
    real = os.path.realpath(path)
    base = os.path.realpath(boundary)
    return real == base or real.startswith(base + os.sep)


def _repository_boundary(root_dir: str) -> str:
    """Find the checkout root so ../shared modules work without escaping the repo."""
    current = os.path.realpath(root_dir)
    while True:
        if os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return os.path.realpath(root_dir)
        current = parent


def _list_tf_files(
    directory: str,
    repository_root: str,
    warnings: list[str],
    budget: dict[str, int],
) -> list[str]:
    out: list[str] = []
    if not _is_within(directory, repository_root):
        warnings.append("A local module resolved outside the repository and was skipped.")
        return out
    try:
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".tf"):
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            if not _is_within(path, repository_root):
                warnings.append(
                    f"Terraform file '{name}' resolves outside the repository and was skipped.")
                continue
            if budget["files"] >= MAX_FILES:
                warnings.append(
                    f"Static analysis stopped after the {MAX_FILES}-file safety limit.")
                break
            try:
                file_size = os.path.getsize(path)
                if file_size > MAX_FILE_BYTES:
                    warnings.append(
                        f"Terraform file '{name}' exceeds the {MAX_FILE_BYTES}-byte safety limit and was skipped.")
                    continue
                if budget["bytes"] + file_size > MAX_TOTAL_INPUT_BYTES:
                    warnings.append(
                        f"Static analysis stopped at the {MAX_TOTAL_INPUT_BYTES}-byte input safety limit.")
                    break
            except OSError:
                continue
            budget["files"] += 1
            budget["bytes"] += file_size
            out.append(path)
    except OSError:
        return []
    return out


def _parse_dir(
    directory: str,
    warnings: list[str],
    repository_root: str,
    budget: dict[str, int],
) -> dict[str, list]:
    """Merge all .tf blocks in a directory into one dict of block lists."""
    merged: dict[str, list] = {}
    for path in _list_tf_files(directory, repository_root, warnings, budget):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                parsed = hcl2.load(fh)
        except Exception as exc:  # noqa: BLE001 — malformed .tf must not abort the whole root
            log.warning("Skipping unparseable file %s: %s", path, str(exc)[:160])
            warnings.append(
                f"Terraform file '{os.path.basename(path)}' could not be parsed and was skipped.")
            continue
        for key, blocks in parsed.items():
            if isinstance(blocks, list):
                merged.setdefault(key, []).extend(blocks)
    return merged


def _load_tfvars(
    root_dir: str,
    var_files: list[str],
    repository_root: str,
    budget: dict[str, int],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    # Auto-loaded files first, then explicitly requested ones (which win).
    candidates: list[str] = []
    p = os.path.join(root_dir, "terraform.tfvars")
    if os.path.isfile(p):
        candidates.append(p)
    p_json = os.path.join(root_dir, "terraform.tfvars.json")
    if os.path.isfile(p_json):
        candidates.append(p_json)
    try:
        for name in sorted(os.listdir(root_dir)):
            if name.endswith((".auto.tfvars", ".auto.tfvars.json")):
                candidates.append(os.path.join(root_dir, name))
    except OSError:
        pass
    explicit_paths: list[str] = []
    root_real = os.path.realpath(root_dir)
    for vf in var_files or []:
        candidate = os.path.realpath(os.path.join(root_real, vf))
        if candidate != root_real and not candidate.startswith(root_real + os.sep):
            if warnings is not None:
                warnings.append(
                    f"Variable file '{vf}' resolves outside the Terraform root and was skipped.")
            continue
        explicit_paths.append(candidate)
    candidates.extend(explicit_paths)
    for path in dict.fromkeys(candidates):
        if budget["files"] >= MAX_FILES:
            if warnings is not None:
                warnings.append(
                    f"Variable inputs exceeded the {MAX_FILES}-file safety limit and were skipped.")
            break
        if not _is_within(path, repository_root):
            if warnings is not None:
                warnings.append(
                    f"Variable file '{os.path.basename(path)}' resolves outside the repository and was skipped.")
            continue
        if not os.path.isfile(path):
            if warnings is not None and path in explicit_paths:
                warnings.append(
                    f"Variable file '{os.path.relpath(path, root_dir)}' was not found and was skipped.")
            continue
        try:
            file_size = os.path.getsize(path)
        except OSError:
            continue
        if file_size > MAX_FILE_BYTES:
            if warnings is not None:
                warnings.append(
                    f"Variable file '{os.path.basename(path)}' exceeds the file-size safety limit and was skipped.")
            continue
        if budget["bytes"] + file_size > MAX_TOTAL_INPUT_BYTES:
            if warnings is not None:
                warnings.append(
                    f"Variable inputs exceeded the {MAX_TOTAL_INPUT_BYTES}-byte safety limit and were skipped.")
            continue
        budget["files"] += 1
        budget["bytes"] += file_size
        try:
            with open(path, "r", encoding="utf-8") as fh:
                parsed = json.load(fh) if path.endswith(".json") else hcl2.load(fh)
        except Exception as exc:  # noqa: BLE001
            if warnings is not None:
                warnings.append(
                    f"Variable file '{os.path.relpath(path, root_dir)}' could not be parsed and was skipped.")
            log.warning("Skipping unparseable variable file %s: %s", path, str(exc)[:160])
            continue
        # tfvars are flat key = value; hcl2 returns them as top-level keys.
        for key, val in parsed.items():
            if key not in ("resource", "variable", "module", "locals", "provider", "terraform", "data", "output"):
                values[key] = val
    return values


# ---------------------------------------------------------------------------
# Variable / local resolution (best-effort)
# ---------------------------------------------------------------------------


def _build_var_map(parsed: dict[str, list], tfvars: dict[str, Any]) -> dict[str, Any]:
    var_map: dict[str, Any] = {}
    for block in parsed.get("variable", []) or []:
        if not isinstance(block, dict):
            continue
        for name, body in block.items():
            if isinstance(body, dict) and "default" in body:
                var_map[name] = body["default"]
    var_map.update(tfvars)  # tfvars override defaults
    return var_map


def _build_local_map(parsed: dict[str, list], var_map: dict[str, Any]) -> dict[str, Any]:
    expressions: dict[str, Any] = {}
    for block in parsed.get("locals", []) or []:
        if not isinstance(block, dict):
            continue
        for name, expr in block.items():
            expressions[name] = expr
    local_map: dict[str, Any] = {}
    for _ in range(min(16, max(1, len(expressions)))):
        updated = {
            name: _resolve(expr, var_map, local_map)
            for name, expr in expressions.items()
        }
        if updated == local_map:
            break
        local_map = updated
    return local_map


def _resolve(value: Any, var_map: dict[str, Any], local_map: dict[str, Any]) -> Any:
    """Replace ${var.x} / ${local.x} references best-effort, preserving types."""
    if isinstance(value, str):
        # Exact single reference → substitute the typed value.
        m = _VAR_RE.fullmatch(value.strip())
        if m and m.group(1) in var_map:
            return var_map[m.group(1)]
        m = _LOCAL_RE.fullmatch(value.strip())
        if m and m.group(1) in local_map:
            return local_map[m.group(1)]
        # Embedded references → string substitution where known.
        def _sub_var(match: re.Match) -> str:
            name = match.group(1)
            return str(var_map[name]) if name in var_map else match.group(0)
        def _sub_local(match: re.Match) -> str:
            name = match.group(1)
            return str(local_map[name]) if name in local_map else match.group(0)
        return _LOCAL_RE.sub(_sub_local, _VAR_RE.sub(_sub_var, value))
    if isinstance(value, list):
        return [_resolve(v, var_map, local_map) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, var_map, local_map) for k, v in value.items()}
    return value


def _unknown_mask(value: Any) -> Any:
    """Build a Terraform-style unknown mask for expressions static analysis cannot resolve."""
    if isinstance(value, str):
        return "${" in value
    if isinstance(value, list):
        return [_unknown_mask(v) for v in value]
    if isinstance(value, dict):
        return {k: _unknown_mask(v) for k, v in value.items()}
    return False


# ---------------------------------------------------------------------------
# Reference extraction
# ---------------------------------------------------------------------------


def _collect_references(
    value: Any,
    source_address: str,
    attr_path: str,
    out: list[dict],
    module_address: str | None = None,
) -> None:
    if len(out) >= MAX_REFERENCES:
        return
    if isinstance(value, str):
        for match in _REF_RE.finditer(value):
            if len(out) >= MAX_REFERENCES:
                return
            target = match.group(1)  # type.name
            if any(target.startswith(p) for p in _SKIP_REF_PREFIXES):
                continue
            if module_address:
                target = f"{module_address}.{target}"
            if (
                len(source_address) > 512 or
                len(target) > 512 or
                len(attr_path) > 512
            ):
                continue
            out.append({
                "sourceAddress": source_address,
                "targetAddress": target,
                "referenceType": "terraform",
                "attributePath": attr_path,
            })
    elif isinstance(value, list):
        for item in value:
            _collect_references(item, source_address, attr_path, out, module_address)
    elif isinstance(value, dict):
        for k, v in value.items():
            child = f"{attr_path}.{k}" if attr_path else k
            _collect_references(v, source_address, child, out, module_address)


# ---------------------------------------------------------------------------
# Resource extraction
# ---------------------------------------------------------------------------


def _provider_name(res_type: str) -> str:
    prefix = res_type.split("_", 1)[0] if "_" in res_type else res_type
    return f"registry.terraform.io/hashicorp/{prefix}"


def _extract_resources(
    parsed: dict[str, list],
    module_address: str | None,
    var_map: dict[str, Any],
    local_map: dict[str, Any],
    resources: list[dict],
    references: list[dict],
    unsupported: list[int],
    warnings: list[str] | None = None,
) -> None:
    for block in parsed.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for res_type, named in block.items():
            if not isinstance(named, dict):
                continue
            for res_name, body in named.items():
                if len(resources) >= MAX_RESOURCES:
                    if warnings is not None and not any(
                        "resource safety limit" in warning for warning in warnings
                    ):
                        warnings.append(
                            f"Static analysis stopped after the {MAX_RESOURCES}-resource safety limit.")
                    return
                if not isinstance(body, dict):
                    continue
                local_addr = f"{res_type}.{res_name}"
                address = f"{module_address}.{local_addr}" if module_address else local_addr
                if (
                    len(address) > 512 or
                    len(res_type) > 128 or
                    len(res_name) > 256 or
                    (module_address is not None and len(module_address) > 512)
                ):
                    if warnings is not None:
                        warnings.append(
                            "A Terraform resource with overlong address metadata was skipped.")
                    continue
                values = _resolve(body, var_map, local_map)
                if not isinstance(values, dict):
                    values = {}

                count_value = values.get("count")
                for_each_value = values.get("for_each")
                if count_value in (0, False) or for_each_value in ({}, []):
                    if warnings is not None:
                        warnings.append(
                            f"Resource '{address}' is disabled by an empty count/for_each and was omitted.")
                    continue
                if (
                    ("count" in values and not isinstance(count_value, int)) or
                    ("count" in values and isinstance(count_value, int) and count_value > 1) or
                    ("for_each" in values and for_each_value not in ({}, []))
                ) and warnings is not None:
                    warnings.append(
                        f"Resource '{address}' uses count/for_each; static analysis represents it once.")

                # References are extracted from the RAW body (pre-resolution keeps the
                # resource expressions intact even when a value also embeds a var).
                _collect_references(body, address, "", references, module_address)

                if res_type in tp._RESOURCE_ALLOWLIST:
                    safe_attrs, unknown_paths, redacted = tp._sanitise_resource(
                        res_type, values, {}, _unknown_mask(values))
                else:
                    unsupported.append(1)
                    safe_attrs, unknown_paths, redacted = {}, [], []

                resources.append({
                    "address": address,
                    "moduleAddress": module_address,
                    "mode": "managed",
                    "type": res_type,
                    "name": res_name,
                    "providerName": _provider_name(res_type),
                    "changeActions": [],
                    "safeAttributes": safe_attrs,
                    "unknownAttributePaths": unknown_paths,
                    "redactedAttributePaths": redacted,
                })


def _follow_local_modules(
    parsed: dict[str, list],
    base_dir: str,
    module_address: str | None,
    parent_var_map: dict[str, Any],
    parent_local_map: dict[str, Any],
    depth: int,
    resources: list[dict],
    references: list[dict],
    unsupported: list[int],
    warnings: list[str],
    seen: set[str],
    repository_root: str,
    budget: dict[str, int],
) -> None:
    if depth >= MAX_MODULE_DEPTH:
        warnings.append(
            f"Local module traversal stopped at the maximum depth of {MAX_MODULE_DEPTH}.")
        return
    for block in parsed.get("module", []) or []:
        if not isinstance(block, dict):
            continue
        for mod_name, body in block.items():
            if not isinstance(body, dict):
                continue
            source = body.get("source")
            if not isinstance(source, str):
                continue
            if not source.startswith(("./", "../")):
                warnings.append(
                    f"Module '{mod_name}' uses a non-local source; its resources are not analysed.")
                continue
            mod_dir = os.path.normpath(os.path.join(base_dir, source))
            child_addr = f"{module_address}.module.{mod_name}" if module_address else f"module.{mod_name}"
            resolved_call = _resolve(body, parent_var_map, parent_local_map)
            if isinstance(resolved_call, dict):
                count_value = resolved_call.get("count")
                for_each_value = resolved_call.get("for_each")
                if count_value in (0, False) or for_each_value in ({}, []):
                    warnings.append(
                        f"Module '{child_addr}' is disabled by an empty count/for_each and was omitted.")
                    continue
                if (
                    ("count" in resolved_call and
                     (not isinstance(count_value, int) or count_value > 1)) or
                    ("for_each" in resolved_call and for_each_value not in ({}, []))
                ):
                    warnings.append(
                        f"Module '{child_addr}' uses count/for_each; static analysis represents it once.")
            if not _is_within(mod_dir, repository_root):
                warnings.append(
                    f"Local module '{child_addr}' resolves outside the repository and was skipped.")
                continue
            key = f"{child_addr}:{os.path.realpath(mod_dir)}"
            if key in seen:
                continue
            seen.add(key)
            child_parsed = _parse_dir(
                mod_dir, warnings, repository_root, budget)
            if not child_parsed:
                continue
            # Module input variables come from the call body; merge over the module's own defaults.
            resolved_inputs = {
                k: _resolve(v, parent_var_map, parent_local_map)
                for k, v in body.items()
                if k not in ("source", "version", "providers", "count", "for_each", "depends_on")
            }
            child_var_map = _build_var_map(child_parsed, {
                **resolved_inputs
            })
            child_local_map = _build_local_map(child_parsed, child_var_map)
            _extract_resources(
                child_parsed, child_addr, child_var_map, child_local_map,
                resources, references, unsupported, warnings)
            _follow_local_modules(
                child_parsed, mod_dir, child_addr, child_var_map, child_local_map, depth + 1,
                resources, references, unsupported, warnings, seen, repository_root, budget)


# ---------------------------------------------------------------------------
# Payload + entry point
# ---------------------------------------------------------------------------


def _digest(resources: list[dict], references: list[dict]) -> str:
    """Digest the normalized topology so module and variable changes are represented."""
    canonical = json.dumps(
        {"resources": resources, "references": references},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _deduplicate_topology(
    resources: list[dict],
    references: list[dict],
    warnings: list[str],
) -> tuple[list[dict], list[dict]]:
    unique_resources: list[dict] = []
    addresses: set[str] = set()
    for resource in resources:
        address = str(resource.get("address") or "")
        if not address or address in addresses:
            if address:
                warnings.append(
                    f"Duplicate Terraform address '{address}' was represented once.")
            continue
        addresses.add(address)
        unique_resources.append(resource)

    unique_references: list[dict] = []
    reference_keys: set[tuple[str, str, str]] = set()
    for reference in references:
        source = str(reference.get("sourceAddress") or "")
        target = str(reference.get("targetAddress") or "")
        attribute = str(reference.get("attributePath") or "")
        key = (source, target, attribute)
        if source not in addresses or not target or key in reference_keys:
            continue
        reference_keys.add(key)
        unique_references.append(reference)
    return unique_resources, unique_references


def _bounded_warnings(warnings: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for warning in warnings:
        safe = str(warning)[:MAX_WARNING_LENGTH]
        if safe in seen:
            continue
        seen.add(safe)
        unique.append(safe)
        if len(unique) >= MAX_WARNINGS:
            break
    return unique


def build_payload(
    root_dir: str,
    project_id: str,
    pipeline_run_id: str,
    *,
    source_revision: str | None,
    terraform_root_id: str | None,
    var_files: list[str] | None = None,
) -> tuple[dict, int]:
    warnings: list[str] = []
    repository_root = _repository_boundary(root_dir)
    budget = {"files": 0, "bytes": 0}
    parsed = _parse_dir(root_dir, warnings, repository_root, budget)
    tfvars = _load_tfvars(
        root_dir, var_files or [], repository_root, budget, warnings)
    var_map = _build_var_map(parsed, tfvars)
    local_map = _build_local_map(parsed, var_map)

    resources: list[dict] = []
    references: list[dict] = []
    unsupported: list[int] = []
    _extract_resources(
        parsed, None, var_map, local_map, resources, references, unsupported, warnings)
    _follow_local_modules(
        parsed, root_dir, None, var_map, local_map, 0,
        resources, references, unsupported, warnings, set(), repository_root, budget)
    if len(references) >= MAX_REFERENCES:
        warnings.append(
            f"Static analysis stopped recording references at the {MAX_REFERENCES}-edge safety limit.")
    resources, references = _deduplicate_topology(resources, references, warnings)

    warnings.insert(0, "Topology extracted by static HCL analysis (no terraform plan).")
    if unsupported:
        warnings.append(
            f"{len(unsupported)} resource type(s) not in the allowlist; only "
            "address/type/name recorded for those.")
    warnings = _bounded_warnings(warnings)

    payload = {
        "schemaVersion": 1,
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "planDigest": _digest(resources, references),
        "formatVersion": _FORMAT_VERSION,
        "terraformVersion": None,
        "sourceRevision": source_revision,
        "terraformRootId": terraform_root_id,
        "resources": resources,
        "references": references,
        "warnings": warnings,
    }
    return payload, len(unsupported)


def run(
    root_dir: str,
    project_id: str,
    pipeline_run_id: str,
    *,
    source_revision: str | None = None,
    terraform_root_id: str | None = None,
    var_files: list[str] | None = None,
    api_url: str | None = None,
    api_key: str | None = None,
    require_submission: bool = False,
) -> tp.InfrastructureAnalysisResult:
    """Statically analyse a Terraform root and submit the sanitized topology.

    Mirrors ``terraform_plan.run`` but needs no plan file and no credentials. Never raises.
    """
    try:
        payload, unsupported = build_payload(
            root_dir, project_id, pipeline_run_id,
            source_revision=source_revision, terraform_root_id=terraform_root_id,
            var_files=var_files)
    except Exception as exc:  # noqa: BLE001
        log.error("Static extraction failed: %s", exc)
        return tp.InfrastructureAnalysisResult(success=False, error=str(exc))

    if not payload["resources"]:
        return tp.InfrastructureAnalysisResult(
            success=False, error="No Terraform resources found in the selected root.")

    log.info(
        "Static analysis: %d resource(s) (%d unsupported), %d reference(s).",
        len(payload["resources"]), unsupported, len(payload["references"]))

    effective_url = api_url or os.environ.get("SECUREOBS_API_URL", "")
    effective_key = api_key or os.environ.get("SECUREOBS_API_KEY", "")
    if not (effective_url and effective_key):
        if require_submission:
            return tp.InfrastructureAnalysisResult(
                success=False,
                resource_count=len(payload["resources"]),
                unsupported_count=unsupported,
                error="API URL and API key are required for infrastructure analysis submission")
        return tp.InfrastructureAnalysisResult(
            success=True,
            resource_count=len(payload["resources"]),
            unsupported_count=unsupported)

    submit = tp._post_analysis(effective_url, effective_key, payload)
    if not submit.ok:
        return tp.InfrastructureAnalysisResult(
            success=False,
            resource_count=len(payload["resources"]),
            unsupported_count=unsupported,
            error=submit.error or "API submission failed")

    return tp.InfrastructureAnalysisResult(
        success=True,
        resource_count=submit.resource_count or len(payload["resources"]),
        edge_count=submit.edge_count,
        path_count=submit.path_count,
        unsupported_count=unsupported)
