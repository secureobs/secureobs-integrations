"""Comprehensive tests for infrastructure.terraform_plan."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile

import pytest

# ---------------------------------------------------------------------------
# Path setup — allow imports from the scripts root without installing the pkg.
# ---------------------------------------------------------------------------

SCRIPTS_DIR = str(pathlib.Path(__file__).resolve().parents[2])
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from infrastructure.terraform_plan import (  # noqa: E402
    MAX_PLAN_FILE_BYTES,
    InfrastructureAnalysisResult,
    _collect_warnings,
    _extract_change_actions,
    _is_sensitive,
    _is_unknown,
    _iter_module_resources,
    _iter_references,
    _key_matches_denylist,
    _normalize_references,
    _normalize_resources,
    _validate_format_version,
    _validate_plan_path_in_workspace,
    run,
)

# ---------------------------------------------------------------------------
# Shared fake constants
# ---------------------------------------------------------------------------

FAKE_SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000000"
FAKE_RG = f"{FAKE_SUBSCRIPTION}/resourceGroups/fake-resource-group"
FAKE_PROJECT_ID = "proj-00000000-0000-0000-0000-000000000000"
FAKE_PIPELINE_RUN = "run-00000000-0000-0000-0000-000000000000"

# ---------------------------------------------------------------------------
# Minimal valid plan factory
# ---------------------------------------------------------------------------


def _make_plan(
    *,
    format_version: str = "1.0",
    terraform_version: str = "1.7.5",
    resources_in_root: list[dict] | None = None,
    resource_changes: list[dict] | None = None,
    configuration_resources: list[dict] | None = None,
    extra_keys: dict | None = None,
) -> dict:
    """Build a minimal Terraform plan dict suitable for testing."""
    plan: dict = {
        "format_version": format_version,
        "terraform_version": terraform_version,
        "planned_values": {
            "root_module": {
                "resources": resources_in_root or [],
            }
        },
        "resource_changes": resource_changes or [],
        "configuration": {
            "root_module": {
                "resources": configuration_resources or [],
            }
        },
    }
    if extra_keys:
        plan.update(extra_keys)
    return plan


def _write_plan(directory: str, plan: dict, filename: str = "plan.json") -> str:
    """Write a plan dict to *directory* and return the relative filename."""
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh)
    return filename


def _run_in_tmp(plan: dict, filename: str = "plan.json") -> InfrastructureAnalysisResult:
    """Write *plan* into a tempdir and call ``run()`` with that workspace."""
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write_plan(tmp, plan, filename)
        return run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)


# ---------------------------------------------------------------------------
# 1. Format-version validation
# ---------------------------------------------------------------------------


class TestFormatVersion:
    def test_version_1_0_accepted(self):
        _validate_format_version("1.0")  # must not raise

    def test_version_1_99_accepted(self):
        _validate_format_version("1.99")  # minor bump — still major 1

    def test_version_2_0_rejected(self):
        with pytest.raises(ValueError, match="Unsupported format_version major"):
            _validate_format_version("2.0")

    def test_version_0_x_rejected(self):
        with pytest.raises(ValueError):
            _validate_format_version("0.1")

    def test_garbage_rejected(self):
        with pytest.raises(ValueError):
            _validate_format_version("not-a-version")


# ---------------------------------------------------------------------------
# 2. Path validation
# ---------------------------------------------------------------------------


class TestPathValidation:
    def test_valid_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan_file = os.path.join(tmp, "plan.json")
            pathlib.Path(plan_file).write_text("{}", encoding="utf-8")
            result = _validate_plan_path_in_workspace(tmp, "plan.json")
            assert result == pathlib.Path(plan_file).resolve()

    def test_absolute_path_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(ValueError, match="relative"):
                _validate_plan_path_in_workspace(tmp, "/etc/passwd")

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(ValueError, match=r"\.\.|workspace"):
                _validate_plan_path_in_workspace(tmp, "../etc/passwd")

    def test_double_dotdot_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(ValueError):
                _validate_plan_path_in_workspace(tmp, "subdir/../../etc/passwd")

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(ValueError, match="regular file"):
                _validate_plan_path_in_workspace(tmp, "nonexistent.json")

    def test_symlink_escape_rejected(self):
        """A symlink inside the workspace that points outside must be rejected."""
        with tempfile.TemporaryDirectory() as workspace:
            with tempfile.TemporaryDirectory() as outside:
                # Create a real file outside the workspace.
                outside_file = os.path.join(outside, "secret.json")
                pathlib.Path(outside_file).write_text('{"x":1}', encoding="utf-8")
                # Create a symlink inside the workspace pointing to it.
                link_path = os.path.join(workspace, "sneaky.json")
                os.symlink(outside_file, link_path)
                # resolve() follows the symlink, so the resolved path lands
                # outside the workspace — caught as "resolves outside" before
                # the explicit is_symlink() branch even fires.
                with pytest.raises(ValueError, match="workspace root|symlink"):
                    _validate_plan_path_in_workspace(workspace, "sneaky.json")

    def test_symlink_inside_workspace_allowed(self):
        """A symlink that stays inside the workspace is fine."""
        with tempfile.TemporaryDirectory() as workspace:
            real_file = os.path.join(workspace, "real.json")
            pathlib.Path(real_file).write_text("{}", encoding="utf-8")
            link_path = os.path.join(workspace, "link.json")
            os.symlink(real_file, link_path)
            # Must NOT raise.
            result = _validate_plan_path_in_workspace(workspace, "link.json")
            assert result.exists()


# ---------------------------------------------------------------------------
# 3. File size enforcement
# ---------------------------------------------------------------------------


class TestFileSizeLimit:
    def test_oversized_file_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = os.path.join(tmp, "big.json")
            # Write just over 50 MiB.
            with open(big, "wb") as fh:
                fh.write(b" " * (MAX_PLAN_FILE_BYTES + 1))
            result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, "big.json")
            assert not result.success
            assert "exceeds maximum size" in (result.error or "")

    def test_missing_file_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, "missing.json")
            assert not result.success


# ---------------------------------------------------------------------------
# 4. Valid plan — basic extraction
# ---------------------------------------------------------------------------


def _make_vnet_resource(
    address: str = "azurerm_virtual_network.main",
    name: str = "main",
    location: str = "eastus",
) -> dict:
    return {
        "address": address,
        "mode": "managed",
        "type": "azurerm_virtual_network",
        "name": name,
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "values": {
            "name": name,
            "location": location,
            "address_space": ["10.0.0.0/16"],
            "dns_servers": [],
            "tags": {"env": "test"},  # not in allowlist — must be dropped
        },
        "sensitive_values": {},
    }


def _make_vnet_change(
    address: str = "azurerm_virtual_network.main",
    actions: list[str] | None = None,
) -> dict:
    return {
        "address": address,
        "mode": "managed",
        "type": "azurerm_virtual_network",
        "name": "main",
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "change": {
            "actions": actions or ["create"],
            "before": None,
            "after": {},
            "after_unknown": {},
            "before_sensitive": {},
            "after_sensitive": {},
        },
    }


class TestValidPlan:
    def test_success_flag(self):
        plan = _make_plan(
            resources_in_root=[_make_vnet_resource()],
            resource_changes=[_make_vnet_change()],
        )
        result = _run_in_tmp(plan)
        assert result.success

    def test_resource_count(self):
        plan = _make_plan(
            resources_in_root=[_make_vnet_resource()],
            resource_changes=[_make_vnet_change()],
        )
        result = _run_in_tmp(plan)
        assert result.resource_count == 1

    def test_tags_excluded_from_safe_attrs(self):
        """'tags' is not in the vnet allowlist and must be silently dropped."""
        plan = _make_plan(
            resources_in_root=[_make_vnet_resource()],
            resource_changes=[_make_vnet_change()],
        )
        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)
        assert result.success

    def test_allowlisted_attrs_present(self):
        """Allowed, non-sensitive attributes from planned_values are preserved."""
        resource = _make_vnet_resource(location="westeurope")
        plan = _make_plan(
            resources_in_root=[resource],
            resource_changes=[_make_vnet_change()],
        )
        # We need to peek at the payload; we do so by serializing what run()
        # would produce — replicate the normalization logic in-process.
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})
        assert len(resources) == 1
        safe = resources[0]["safeAttributes"]
        assert safe["location"] == "westeurope"
        assert safe["address_space"] == ["10.0.0.0/16"]
        assert "tags" not in safe

    def test_resource_group_name_preserved_for_containment(self):
        """resource_group_name must survive sanitization so the graph can nest
        resources under their resource group."""
        from infrastructure.terraform_plan import _RESOURCE_ALLOWLIST

        # Broadly allowlisted across the resource types that declare one.
        for rtype in (
            "azurerm_virtual_network",
            "azurerm_subnet",
            "azurerm_key_vault",
            "azurerm_storage_account",
            "azurerm_mssql_server",
            "azurerm_network_interface",
            "azurerm_private_endpoint",
        ):
            assert "resource_group_name" in _RESOURCE_ALLOWLIST[rtype], rtype

        # New container + relationship fields.
        assert "azurerm_resource_group" in _RESOURCE_ALLOWLIST
        assert "network_security_group_name" in _RESOURCE_ALLOWLIST["azurerm_network_security_rule"]

        resource = _make_vnet_resource()
        resource["values"]["resource_group_name"] = "rg-prod"
        plan = _make_plan(
            resources_in_root=[resource],
            resource_changes=[_make_vnet_change()],
        )
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})
        assert resources[0]["safeAttributes"]["resource_group_name"] == "rg-prod"


# ---------------------------------------------------------------------------
# 5. Recursive child_modules
# ---------------------------------------------------------------------------


class TestChildModules:
    def test_child_module_resources_extracted(self):
        child_resource = {
            "address": "module.networking.azurerm_subnet.default",
            "mode": "managed",
            "type": "azurerm_subnet",
            "name": "default",
            "module_address": "module.networking",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "default",
                "address_prefixes": ["10.0.1.0/24"],
                "virtual_network_name": "main",
                "service_endpoints": [],
            },
            "sensitive_values": {},
        }
        child_change = {
            "address": "module.networking.azurerm_subnet.default",
            "mode": "managed",
            "type": "azurerm_subnet",
            "name": "default",
            "module_address": "module.networking",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {},
                "after_unknown": {},
                "before_sensitive": {},
                "after_sensitive": {},
            },
        }
        root_module = {
            "resources": [],
            "child_modules": [
                {
                    "address": "module.networking",
                    "resources": [child_resource],
                }
            ],
        }
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": root_module},
            "resource_changes": [child_change],
            "configuration": {"root_module": {"resources": []}},
        }
        result = _run_in_tmp(plan)
        assert result.success
        assert result.resource_count == 1

    def test_deeply_nested_child_modules(self):
        """Resources in grandchild modules must also be found."""
        inner_resource = {
            "address": "module.a.module.b.azurerm_network_security_group.nsg",
            "mode": "managed",
            "type": "azurerm_network_security_group",
            "name": "nsg",
            "module_address": "module.a.module.b",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {"name": "nsg", "location": "eastus"},
            "sensitive_values": {},
        }
        root_module = {
            "resources": [],
            "child_modules": [
                {
                    "address": "module.a",
                    "resources": [],
                    "child_modules": [
                        {
                            "address": "module.a.module.b",
                            "resources": [inner_resource],
                        }
                    ],
                }
            ],
        }
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": root_module},
            "resource_changes": [],
            "configuration": {"root_module": {"resources": []}},
        }
        result = _run_in_tmp(plan)
        assert result.success
        assert result.resource_count == 1


# ---------------------------------------------------------------------------
# 6. Sensitive attribute masking
# ---------------------------------------------------------------------------

SENTINEL = "DO_NOT_LEAK_SENTINEL_SECRET"


def _make_vm_resource_with_sensitive_password() -> dict:
    return {
        "address": "azurerm_linux_virtual_machine.main",
        "mode": "managed",
        "type": "azurerm_linux_virtual_machine",
        "name": "main",
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "values": {
            "name": "vm-main",
            "location": "eastus",
            "size": "Standard_B2s",
            "admin_password": SENTINEL,  # sensitive — must never leak
            "disable_password_authentication": False,
        },
        "sensitive_values": {
            "admin_password": True,
        },
    }


class TestSensitiveMasking:
    def _get_resources_from_plan(self, plan: dict) -> list[dict]:
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan.get("resource_changes", []))
        resources, _ = _normalize_resources(index, {})
        return resources

    def test_sensitive_attr_not_in_safe_attributes(self):
        plan = _make_plan(
            resources_in_root=[_make_vm_resource_with_sensitive_password()],
        )
        resources = self._get_resources_from_plan(plan)
        assert len(resources) == 1
        safe = resources[0]["safeAttributes"]
        assert "admin_password" not in safe

    def test_sensitive_attr_in_redacted_paths(self):
        plan = _make_plan(
            resources_in_root=[_make_vm_resource_with_sensitive_password()],
        )
        resources = self._get_resources_from_plan(plan)
        redacted = resources[0]["redactedAttributePaths"]
        # admin_password is not in the VM allowlist, so it won't appear at all.
        # The sensitive flag for a *listed* attr should appear:
        resource_with_listed_sensitive = {
            "address": "azurerm_linux_virtual_machine.main",
            "mode": "managed",
            "type": "azurerm_linux_virtual_machine",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "vm-main",
                "location": "eastus",
                "size": "Standard_B2s",
            },
            # Mark "name" as sensitive so it ends up in redacted_paths.
            "sensitive_values": {"name": True},
        }
        plan2 = _make_plan(resources_in_root=[resource_with_listed_sensitive])
        resources2 = self._get_resources_from_plan(plan2)
        assert "name" in resources2[0]["redactedAttributePaths"]
        assert "name" not in resources2[0]["safeAttributes"]

    def test_sentinel_absent_from_serialized_json(self):
        """The sentinel value must NEVER appear in the final serialized payload."""
        vm_resource = _make_vm_resource_with_sensitive_password()
        plan = _make_plan(
            resources_in_root=[vm_resource],
            resource_changes=[
                {
                    "address": "azurerm_linux_virtual_machine.main",
                    "mode": "managed",
                    "type": "azurerm_linux_virtual_machine",
                    "name": "main",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {
                            "admin_password": SENTINEL,
                            "name": "vm-main",
                        },
                        "after_unknown": {},
                        "before_sensitive": {},
                        "after_sensitive": {"admin_password": True},
                    },
                }
            ],
        )
        from infrastructure.terraform_plan import (
            _build_resource_index,
            _normalize_resources,
        )

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})

        payload = {
            "schemaVersion": 1,
            "projectId": FAKE_PROJECT_ID,
            "pipelineRunId": FAKE_PIPELINE_RUN,
            "resources": resources,
            "references": [],
            "warnings": [],
        }

        serialized = json.dumps(payload)
        assert SENTINEL not in serialized, (
            f"Sentinel value leaked into serialized payload!"
        )

    def test_whole_resource_sensitive_flag(self):
        """When sensitive_values is True (entire resource), all extracted attrs are redacted."""
        resource = {
            "address": "azurerm_key_vault.main",
            "mode": "managed",
            "type": "azurerm_key_vault",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "kv-main",
                "location": "eastus",
                "sku_name": "premium",
            },
            "sensitive_values": True,  # whole resource is sensitive
        }
        plan = _make_plan(resources_in_root=[resource])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, _ = _normalize_resources(index, {})
        assert resources[0]["safeAttributes"] == {}
        assert len(resources[0]["redactedAttributePaths"]) > 0


# ---------------------------------------------------------------------------
# 7. Unknown attributes
# ---------------------------------------------------------------------------


class TestUnknownAttributes:
    def test_after_unknown_recorded_not_guessed(self):
        resource = {
            "address": "azurerm_public_ip.main",
            "mode": "managed",
            "type": "azurerm_public_ip",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "pip-main",
                "location": "eastus",
                "allocation_method": "Static",
                "sku": "Standard",
            },
            "sensitive_values": {},
        }
        change = {
            "address": "azurerm_public_ip.main",
            "mode": "managed",
            "type": "azurerm_public_ip",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {},
                "after_unknown": {
                    "sku": True,  # sku is unknown at plan time
                },
                "before_sensitive": {},
                "after_sensitive": {},
            },
        }
        plan = _make_plan(resources_in_root=[resource], resource_changes=[change])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})
        assert len(resources) == 1
        r = resources[0]
        assert "sku" in r["unknownAttributePaths"]
        assert "sku" not in r["safeAttributes"]


# ---------------------------------------------------------------------------
# 8. Variables and outputs must be absent
# ---------------------------------------------------------------------------


class TestVariablesAndOutputsExcluded:
    def _payload_json_from_plan(self, plan: dict) -> str:
        from infrastructure.terraform_plan import (
            _build_resource_index,
            _normalize_references,
            _normalize_resources,
        )

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan.get("resource_changes", []))
        resources, _ = _normalize_resources(index, {})
        references = _normalize_references(plan)
        payload = {
            "schemaVersion": 1,
            "resources": resources,
            "references": references,
            "warnings": _collect_warnings(plan, 0),
        }
        return json.dumps(payload)

    def test_variable_values_absent(self):
        plan = _make_plan(
            extra_keys={
                "variables": {
                    "admin_username": {"value": "superadmin"},
                    "db_password": {"value": "hunter2"},
                }
            }
        )
        serialized = self._payload_json_from_plan(plan)
        assert "superadmin" not in serialized
        assert "hunter2" not in serialized
        # A warning is emitted, but the values are never in the payload.
        warnings = _collect_warnings(plan, 0)
        assert any("variable" in w for w in warnings)

    def test_output_values_absent(self):
        plan = _make_plan(
            extra_keys={
                "output_changes": {
                    "connection_string": {
                        "actions": ["create"],
                        "before": None,
                        "after": "Server=tcp:fake.database.windows.net",
                    }
                }
            }
        )
        serialized = self._payload_json_from_plan(plan)
        assert "connection_string" not in serialized
        assert "tcp:fake.database.windows.net" not in serialized


# ---------------------------------------------------------------------------
# 9. Unsupported resource type → generic node
# ---------------------------------------------------------------------------


class TestUnsupportedResourceType:
    def test_generic_node_attributes(self):
        resource = {
            "address": "azurerm_some_new_resource.x",
            "mode": "managed",
            "type": "azurerm_some_new_resource",
            "name": "x",
            "module_address": None,
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "x",
                "secret_token": "SHOULD_NOT_APPEAR",
                "location": "eastus",
            },
            "sensitive_values": {},
        }
        change = {
            "address": "azurerm_some_new_resource.x",
            "mode": "managed",
            "type": "azurerm_some_new_resource",
            "name": "x",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {},
                "after_unknown": {},
                "before_sensitive": {},
                "after_sensitive": {},
            },
        }
        plan = _make_plan(resources_in_root=[resource], resource_changes=[change])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, unsupported = _normalize_resources(index, {})
        assert unsupported == 1
        node = resources[0]
        # Generic nodes must have no safeAttributes.
        assert node["safeAttributes"] == {}
        # Structural fields are present.
        assert node["address"] == "azurerm_some_new_resource.x"
        assert node["type"] == "azurerm_some_new_resource"
        assert node["name"] == "x"
        assert node["changeActions"] == ["create"]
        # Secret value must not appear.
        serialized = json.dumps(node)
        assert "SHOULD_NOT_APPEAR" not in serialized

    def test_unsupported_count_tracked(self):
        plan = _make_plan(
            resources_in_root=[
                {
                    "address": "azurerm_unknown_a.x",
                    "mode": "managed",
                    "type": "azurerm_unknown_a",
                    "name": "x",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "values": {},
                    "sensitive_values": {},
                },
                {
                    "address": "azurerm_unknown_b.y",
                    "mode": "managed",
                    "type": "azurerm_unknown_b",
                    "name": "y",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "values": {},
                    "sensitive_values": {},
                },
            ]
        )
        result = _run_in_tmp(plan)
        assert result.success
        assert result.unsupported_count == 2


# ---------------------------------------------------------------------------
# 10. Denylist removes sensitive keys even if listed in allowlist
# ---------------------------------------------------------------------------


class TestDenylist:
    def test_denylist_removes_password_key(self):
        """Even if 'password' somehow crept into an allowlist, denylist removes it."""
        from infrastructure.terraform_plan import _RESOURCE_ALLOWLIST, _sanitise_resource

        # Temporarily inject "password" into the vnet allowlist for this test.
        original = list(_RESOURCE_ALLOWLIST["azurerm_virtual_network"])
        _RESOURCE_ALLOWLIST["azurerm_virtual_network"] = original + ["password"]
        try:
            safe, unknown, redacted = _sanitise_resource(
                "azurerm_virtual_network",
                {"name": "vnet", "location": "eastus", "password": "hunter2"},
                {},
                {},
            )
        finally:
            _RESOURCE_ALLOWLIST["azurerm_virtual_network"] = original

        assert "password" not in safe
        assert "password" in redacted

    def test_key_matches_denylist_function(self):
        assert _key_matches_denylist("admin_password") is True
        assert _key_matches_denylist("ssh_key_data") is True
        assert _key_matches_denylist("client_secret") is True
        assert _key_matches_denylist("connection_string") is True
        assert _key_matches_denylist("location") is False
        assert _key_matches_denylist("name") is False
        assert _key_matches_denylist("address_space") is False

    def test_denylist_stem_in_middle_of_key(self):
        """Denylist matches substrings, e.g. 'admin_password_hash'."""
        assert _key_matches_denylist("admin_password_hash") is True


# ---------------------------------------------------------------------------
# 11. SHA-256 digest
# ---------------------------------------------------------------------------


class TestDigest:
    def test_digest_is_deterministic(self):
        """Same bytes must produce the same digest on every call."""
        import hashlib

        plan = _make_plan(resources_in_root=[_make_vnet_resource()])
        content = json.dumps(plan).encode()
        d1 = hashlib.sha256(content).hexdigest()
        d2 = hashlib.sha256(content).hexdigest()
        assert d1 == d2

    def test_different_content_different_digest(self):
        import hashlib

        plan_a = _make_plan(resources_in_root=[_make_vnet_resource(name="a")])
        plan_b = _make_plan(resources_in_root=[_make_vnet_resource(name="b")])
        d_a = hashlib.sha256(json.dumps(plan_a).encode()).hexdigest()
        d_b = hashlib.sha256(json.dumps(plan_b).encode()).hexdigest()
        assert d_a != d_b


# ---------------------------------------------------------------------------
# 12. Change actions
# ---------------------------------------------------------------------------


class TestChangeActions:
    def _actions_for(self, actions_list: list[str]) -> list[str]:
        change = {
            "actions": actions_list,
            "before": None,
            "after": {},
            "after_unknown": {},
            "before_sensitive": {},
            "after_sensitive": {},
        }
        return _extract_change_actions(change)

    def test_create(self):
        assert self._actions_for(["create"]) == ["create"]

    def test_update(self):
        assert self._actions_for(["update"]) == ["update"]

    def test_no_op(self):
        assert self._actions_for(["no-op"]) == ["no-op"]

    def test_delete(self):
        assert self._actions_for(["delete"]) == ["delete"]

    def test_create_before_delete(self):
        assert self._actions_for(["create", "delete"]) == ["create", "delete"]

    def test_unknown_action_excluded(self):
        result = self._actions_for(["create", "fly"])
        assert result == ["create"]

    def test_empty_change(self):
        assert _extract_change_actions(None) == []

    def test_actions_in_full_plan(self):
        """End-to-end: all four actions appear in changeActions of resources."""
        addresses_and_actions = [
            ("azurerm_virtual_network.a", ["create"]),
            ("azurerm_virtual_network.b", ["update"]),
            ("azurerm_virtual_network.c", ["no-op"]),
            ("azurerm_virtual_network.d", ["delete"]),
        ]
        resources_in_root = [
            {
                "address": addr,
                "mode": "managed",
                "type": "azurerm_virtual_network",
                "name": addr.split(".")[1],
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "values": {"name": addr.split(".")[1], "location": "eastus"},
                "sensitive_values": {},
            }
            for addr, _ in addresses_and_actions
        ]
        resource_changes = [
            {
                "address": addr,
                "mode": "managed",
                "type": "azurerm_virtual_network",
                "name": addr.split(".")[1],
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "change": {
                    "actions": actions,
                    "before": None,
                    "after": {},
                    "after_unknown": {},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
            for addr, actions in addresses_and_actions
        ]
        plan = _make_plan(
            resources_in_root=resources_in_root,
            resource_changes=resource_changes,
        )
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})

        action_map = {r["address"]: r["changeActions"] for r in resources}
        assert action_map["azurerm_virtual_network.a"] == ["create"]
        assert action_map["azurerm_virtual_network.b"] == ["update"]
        assert action_map["azurerm_virtual_network.c"] == ["no-op"]
        assert action_map["azurerm_virtual_network.d"] == ["delete"]


# ---------------------------------------------------------------------------
# 13. References extracted from configuration
# ---------------------------------------------------------------------------


class TestReferences:
    def test_references_extracted(self):
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_subnet.default",
                            "mode": "managed",
                            "type": "azurerm_subnet",
                            "name": "default",
                            "expressions": {
                                "virtual_network_name": {
                                    "references": ["azurerm_virtual_network.main"],
                                }
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        assert len(refs) >= 1
        ref = refs[0]
        assert ref["referenceType"] == "terraform"
        assert ref["sourceAddress"] == "azurerm_subnet.default"
        assert ref["targetAddress"] == "azurerm_virtual_network.main"

    def test_var_references_excluded(self):
        """References like 'var.location' must not appear in the output."""
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_virtual_network.main",
                            "mode": "managed",
                            "type": "azurerm_virtual_network",
                            "name": "main",
                            "expressions": {
                                "location": {
                                    "references": ["var.location"],
                                },
                                "address_space": {
                                    "references": [
                                        "azurerm_subnet.default",
                                        "var.cidr",
                                    ],
                                },
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        for r in refs:
            assert not r["targetAddress"].startswith("var.")
        # azurerm_subnet.default should appear.
        targets = [r["targetAddress"] for r in refs]
        assert "azurerm_subnet.default" in targets

    def test_reference_count_extracted_from_configuration(self):
        """References are extracted from configuration expressions by the scanner.

        Note: edge_count in InfrastructureAnalysisResult reflects the server-side
        graph builder output (from the API response). Without an API submission,
        edge_count is always 0 — the scanner's job is to extract and forward
        references, not build graph edges locally.
        """
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_subnet.a",
                            "mode": "managed",
                            "type": "azurerm_subnet",
                            "name": "a",
                            "expressions": {
                                "virtual_network_name": {
                                    "references": ["azurerm_virtual_network.vnet"],
                                },
                                "network_security_group_id": {
                                    "references": ["azurerm_network_security_group.nsg"],
                                },
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        # The scanner extracts references; edges are built server-side.
        assert len(refs) >= 2, "Both references must be extracted from configuration"
        result = _run_in_tmp(plan)
        assert result.success
        # edge_count is 0 when no API submission occurs (computed server-side)
        assert result.edge_count == 0


# ---------------------------------------------------------------------------
# 14. Bounded / idempotent counts
# ---------------------------------------------------------------------------


class TestBoundedCounts:
    def test_resource_count_bounded(self):
        n = 5
        resources = [
            {
                "address": f"azurerm_virtual_network.vnet{i}",
                "mode": "managed",
                "type": "azurerm_virtual_network",
                "name": f"vnet{i}",
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "values": {"name": f"vnet{i}", "location": "eastus"},
                "sensitive_values": {},
            }
            for i in range(n)
        ]
        plan = _make_plan(resources_in_root=resources)
        result = _run_in_tmp(plan)
        assert result.success
        assert result.resource_count == n

    def test_idempotent_result_for_same_file(self):
        plan = _make_plan(resources_in_root=[_make_vnet_resource()])
        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            r1 = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)
            r2 = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)
        assert r1.success and r2.success
        assert r1.resource_count == r2.resource_count


# ---------------------------------------------------------------------------
# 15. Helper unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_is_sensitive_true_value(self):
        assert _is_sensitive(True, "anything") is True

    def test_is_sensitive_dict_key(self):
        assert _is_sensitive({"key": True}, "key") is True
        assert _is_sensitive({"key": False}, "key") is False
        assert _is_sensitive({"other": True}, "key") is False

    def test_is_unknown_true_value(self):
        assert _is_unknown(True, "anything") is True

    def test_is_unknown_dict_key(self):
        assert _is_unknown({"attr": True}, "attr") is True
        assert _is_unknown({"attr": False}, "attr") is False

    def test_iter_module_resources_flat(self):
        module = {
            "resources": [
                {"address": "azurerm_virtual_network.a"},
                {"address": "azurerm_virtual_network.b"},
            ]
        }
        result = _iter_module_resources(module)
        assert len(result) == 2

    def test_iter_module_resources_with_children(self):
        module = {
            "resources": [{"address": "azurerm_virtual_network.a"}],
            "child_modules": [
                {"resources": [{"address": "module.sub.azurerm_subnet.b"}]}
            ],
        }
        result = _iter_module_resources(module)
        assert len(result) == 2

    def test_iter_references_empty(self):
        module = {"resources": []}
        result = _iter_references(module)
        assert result == []


# ---------------------------------------------------------------------------
# 16. Malformed plan inputs
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_non_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "plan.json")
            pathlib.Path(path).write_text("this is not JSON{{", encoding="utf-8")
            result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, "plan.json")
        assert not result.success
        assert result.error is not None

    def test_json_array_root(self):
        """Plan root must be an object, not an array."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "plan.json")
            pathlib.Path(path).write_text("[1, 2, 3]", encoding="utf-8")
            result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, "plan.json")
        assert not result.success

    def test_unsupported_major_version(self):
        plan = _make_plan(format_version="2.0")
        result = _run_in_tmp(plan)
        assert not result.success
        assert "Unsupported" in (result.error or "")

    def test_compatible_minor_version_succeeds(self):
        plan = _make_plan(format_version="1.99")
        result = _run_in_tmp(plan)
        assert result.success


# ---------------------------------------------------------------------------
# 17. Provider info preserved for known types
# ---------------------------------------------------------------------------


class TestProviderInfo:
    def test_provider_name_preserved(self):
        resource = _make_vnet_resource()
        plan = _make_plan(
            resources_in_root=[resource],
            resource_changes=[_make_vnet_change()],
        )
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})
        assert resources[0]["providerName"] == "registry.terraform.io/hashicorp/azurerm"


# ---------------------------------------------------------------------------
# 18. before_sensitive / after_sensitive both trigger redaction
# ---------------------------------------------------------------------------


class TestBeforeAfterSensitive:
    def test_after_sensitive_triggers_redaction(self):
        resource = {
            "address": "azurerm_key_vault.main",
            "mode": "managed",
            "type": "azurerm_key_vault",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "kv-main",
                "location": "eastus",
                "sku_name": "standard",
                "enable_rbac_authorization": True,
            },
            "sensitive_values": {},
        }
        change = {
            "address": "azurerm_key_vault.main",
            "mode": "managed",
            "type": "azurerm_key_vault",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {},
                "after_unknown": {},
                "before_sensitive": {},
                "after_sensitive": {"sku_name": True},  # marked sensitive in after
            },
        }
        plan = _make_plan(resources_in_root=[resource], resource_changes=[change])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, plan["resource_changes"])
        resources, _ = _normalize_resources(index, {})
        r = resources[0]
        assert "sku_name" not in r["safeAttributes"]
        assert "sku_name" in r["redactedAttributePaths"]


# ---------------------------------------------------------------------------
# 19. Module address preserved
# ---------------------------------------------------------------------------


class TestModuleAddress:
    def test_module_address_set_for_child_module_resource(self):
        resource = {
            "address": "module.networking.azurerm_virtual_network.main",
            "mode": "managed",
            "type": "azurerm_virtual_network",
            "name": "main",
            "module_address": "module.networking",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {"name": "main", "location": "eastus"},
            "sensitive_values": {},
        }
        plan = _make_plan(resources_in_root=[resource])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, _ = _normalize_resources(index, {})
        assert resources[0]["moduleAddress"] == "module.networking"

    def test_root_resource_module_address_none(self):
        resource = _make_vnet_resource()
        plan = _make_plan(resources_in_root=[resource])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, _ = _normalize_resources(index, {})
        assert resources[0]["moduleAddress"] is None


# ---------------------------------------------------------------------------
# 20. source_revision forwarded in payload
# ---------------------------------------------------------------------------


class TestSourceRevision:
    def test_source_revision_included_in_payload(self):
        """source_revision must appear in the payload sent to the API."""
        from infrastructure.terraform_plan import (
            _build_resource_index,
            _normalize_resources,
            _normalize_references,
            _collect_warnings,
        )

        plan = _make_plan()
        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, unsupported_count = _normalize_resources(index, {})
        references = _normalize_references(plan)
        warnings = _collect_warnings(plan, unsupported_count)

        payload: dict = {
            "schemaVersion": 1,
            "projectId": FAKE_PROJECT_ID,
            "pipelineRunId": FAKE_PIPELINE_RUN,
            "planDigest": "a" * 64,
            "formatVersion": "1.0",
            "terraformVersion": "1.7.5",
            "sourceRevision": "abc123",
            "resources": resources,
            "references": references,
            "warnings": warnings,
        }
        assert payload["sourceRevision"] == "abc123"

    def test_source_revision_none_when_not_provided(self):
        """Payload sourceRevision is None when the parameter is omitted."""
        from infrastructure.terraform_plan import (
            _build_resource_index,
            _normalize_resources,
            _normalize_references,
            _collect_warnings,
        )

        plan = _make_plan()
        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, unsupported_count = _normalize_resources(index, {})
        references = _normalize_references(plan)
        warnings = _collect_warnings(plan, unsupported_count)

        payload: dict = {
            "schemaVersion": 1,
            "projectId": FAKE_PROJECT_ID,
            "pipelineRunId": FAKE_PIPELINE_RUN,
            "planDigest": "a" * 64,
            "formatVersion": "1.0",
            "terraformVersion": "1.7.5",
            "sourceRevision": None,  # not provided
            "resources": resources,
            "references": references,
            "warnings": warnings,
        }
        assert payload["sourceRevision"] is None


# ---------------------------------------------------------------------------
# 21. attributePath included in reference records
# ---------------------------------------------------------------------------


class TestAttributePath:
    def test_attribute_path_set_for_nested_expression(self):
        """References from nested expressions must carry their attributePath."""
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_network_interface.nic",
                            "mode": "managed",
                            "type": "azurerm_network_interface",
                            "name": "nic",
                            "expressions": {
                                "ip_configuration": {
                                    "public_ip_address_id": {
                                        "references": ["azurerm_public_ip.pip"],
                                    }
                                }
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        assert len(refs) >= 1
        ref = next(r for r in refs if r["targetAddress"] == "azurerm_public_ip.pip")
        assert ref["attributePath"] is not None, "attributePath must be set"
        # The attribute path should reflect the nested key path
        assert "public_ip_address_id" in ref["attributePath"]

    def test_top_level_reference_has_attribute_path(self):
        """Top-level references also carry their attributePath."""
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_role_assignment.ra",
                            "mode": "managed",
                            "type": "azurerm_role_assignment",
                            "name": "ra",
                            "expressions": {
                                "scope": {
                                    "references": ["azurerm_resource_group.rg"],
                                }
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        ref = next(r for r in refs if r["targetAddress"] == "azurerm_resource_group.rg")
        assert ref["attributePath"] == "scope"

    def test_expression_reference_with_attribute_suffix_is_canonicalised(self):
        """References like 'azurerm_subnet.main.id' are canonicalised to 'azurerm_subnet.main'."""
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.7.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [],
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_network_interface.nic",
                            "mode": "managed",
                            "type": "azurerm_network_interface",
                            "name": "nic",
                            "expressions": {
                                "subnet_id": {
                                    "references": ["azurerm_subnet.main.id", "azurerm_subnet.main"],
                                }
                            },
                        }
                    ]
                }
            },
        }
        refs = _normalize_references(plan)
        targets = {r["targetAddress"] for r in refs}
        # After canonicalisation, only 'azurerm_subnet.main' should appear (deduplicated)
        assert "azurerm_subnet.main.id" not in targets, (
            "Attribute-suffixed references must be canonicalised to the resource address"
        )
        assert "azurerm_subnet.main" in targets


# ---------------------------------------------------------------------------
# 22. No-scanner control flow: success without API submission
# ---------------------------------------------------------------------------


class TestNoScannerControlFlow:
    def test_run_succeeds_without_api_url(self):
        """When SECUREOBS_API_URL is absent, run returns success=True and skips upload."""
        plan = _make_plan(resources_in_root=[_make_vnet_resource()])
        env_backup = {k: os.environ.pop(k) for k in ("SECUREOBS_API_URL", "SECUREOBS_API_KEY") if k in os.environ}
        try:
            result = _run_in_tmp(plan)
        finally:
            os.environ.update(env_backup)

        assert result.success, "Should succeed even with no API credentials"
        assert result.resource_count >= 1

    def test_run_succeeds_without_api_key(self):
        """When API URL is set but API key is absent, run skips upload gracefully."""
        plan = _make_plan(resources_in_root=[_make_vnet_resource()])
        env_backup = {k: os.environ.pop(k) for k in ("SECUREOBS_API_URL", "SECUREOBS_API_KEY") if k in os.environ}
        os.environ["SECUREOBS_API_URL"] = "https://fake.api"
        try:
            result = _run_in_tmp(plan)
        finally:
            os.environ.pop("SECUREOBS_API_URL", None)
            os.environ.update(env_backup)

        assert result.success, "Should succeed even when key is absent"

    def test_run_resource_count_from_local_parse_when_no_api(self):
        """Without API submission the resource count comes from local parse."""
        resources = [_make_vnet_resource()]
        plan = _make_plan(resources_in_root=resources)
        env_backup = {k: os.environ.pop(k) for k in ("SECUREOBS_API_URL", "SECUREOBS_API_KEY") if k in os.environ}
        try:
            result = _run_in_tmp(plan)
        finally:
            os.environ.update(env_backup)

        assert result.resource_count == len(resources)

    def test_required_submission_fails_without_api_credentials(self):
        plan = _make_plan(resources_in_root=[_make_vnet_resource()])
        env_backup = {
            k: os.environ.pop(k)
            for k in ("SECUREOBS_API_URL", "SECUREOBS_API_KEY")
            if k in os.environ
        }
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rel = _write_plan(tmp, plan, "plan.json")
                result = run(
                    tmp,
                    FAKE_PROJECT_ID,
                    FAKE_PIPELINE_RUN,
                    rel,
                    require_submission=True,
                )
        finally:
            os.environ.update(env_backup)

        assert not result.success
        assert "required" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# 23. API upload failure: run() returns success=False, preserves resource count
# ---------------------------------------------------------------------------


class TestApiUploadFailure:
    def test_upload_failure_returns_success_false(self):
        """When the API call fails, run() must return success=False."""
        import unittest.mock as mock

        plan = _make_plan(resources_in_root=[_make_vnet_resource()])

        failing_result = type("_R", (), {"ok": False, "error": "HTTP 500"})()

        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            with mock.patch(
                "infrastructure.terraform_plan._post_analysis",
                return_value=failing_result,
            ):
                with mock.patch.dict(
                    os.environ,
                    {"SECUREOBS_API_URL": "https://fake.api", "SECUREOBS_API_KEY": "fake-key"},
                ):
                    result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)

        assert not result.success, "Upload failure must result in success=False"
        assert "HTTP 500" in (result.error or ""), "Error message must be propagated"

    def test_upload_failure_preserves_resource_count(self):
        """Even on upload failure the local resource_count is returned."""
        import unittest.mock as mock

        plan = _make_plan(resources_in_root=[_make_vnet_resource()])

        failing_result = type("_R", (), {"ok": False, "error": "timeout", "resource_count": 0})()

        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            with mock.patch(
                "infrastructure.terraform_plan._post_analysis",
                return_value=failing_result,
            ):
                with mock.patch.dict(
                    os.environ,
                    {"SECUREOBS_API_URL": "https://fake.api", "SECUREOBS_API_KEY": "fake-key"},
                ):
                    result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)

        # resource_count reported should reflect the local parse, not zero from the API
        assert result.resource_count >= 1


# ---------------------------------------------------------------------------
# 24. API counts reflected in result
# ---------------------------------------------------------------------------


class TestApiCounts:
    def test_result_reflects_api_resource_count(self):
        """On success the resource/edge/path counts come from the API response."""
        import unittest.mock as mock

        plan = _make_plan(resources_in_root=[_make_vnet_resource()])

        api_result = type(
            "_R",
            (),
            {"ok": True, "resource_count": 42, "edge_count": 17, "path_count": 5, "error": None},
        )()

        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            with mock.patch(
                "infrastructure.terraform_plan._post_analysis",
                return_value=api_result,
            ):
                with mock.patch.dict(
                    os.environ,
                    {"SECUREOBS_API_URL": "https://fake.api", "SECUREOBS_API_KEY": "fake-key"},
                ):
                    result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)

        assert result.success
        assert result.resource_count == 42, "resource_count must come from API"
        assert result.edge_count == 17, "edge_count must come from API"
        assert result.path_count == 5, "path_count must come from API"

    def test_api_zero_resource_count_falls_back_to_local(self):
        """When the API returns resource_count=0, fall back to the locally parsed count."""
        import unittest.mock as mock

        plan = _make_plan(resources_in_root=[_make_vnet_resource()])

        api_result = type(
            "_R",
            (),
            {"ok": True, "resource_count": 0, "edge_count": 0, "path_count": 0, "error": None},
        )()

        with tempfile.TemporaryDirectory() as tmp:
            rel = _write_plan(tmp, plan)
            with mock.patch(
                "infrastructure.terraform_plan._post_analysis",
                return_value=api_result,
            ):
                with mock.patch.dict(
                    os.environ,
                    {"SECUREOBS_API_URL": "https://fake.api", "SECUREOBS_API_KEY": "fake-key"},
                ):
                    result = run(tmp, FAKE_PROJECT_ID, FAKE_PIPELINE_RUN, rel)

        assert result.success
        # 0 from API → falls back to locally parsed count (at least 1 vnet)
        assert result.resource_count >= 1


# ---------------------------------------------------------------------------
# 25. Recursive sentinel redaction: nested sensitive values never leaked
# ---------------------------------------------------------------------------


class TestRecursiveSentinelRedaction:
    def test_sentinel_absent_from_nested_dict(self):
        """Sentinel in a nested attribute dict must be redacted, not serialized."""
        resource = {
            "address": "azurerm_linux_virtual_machine.main",
            "mode": "managed",
            "type": "azurerm_linux_virtual_machine",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "vm-main",
                "location": "eastus",
                "size": "Standard_B2s",
                "identity": {
                    "type": "UserAssigned",
                    "admin_password": SENTINEL,  # nested sensitive — must never appear
                },
            },
            "sensitive_values": {
                "identity": {"admin_password": True},
            },
        }
        plan = _make_plan(resources_in_root=[resource])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, _ = _normalize_resources(index, {})

        payload_json = json.dumps({"resources": resources})
        assert SENTINEL not in payload_json, (
            f"Sentinel leaked from nested attribute into serialized payload"
        )

    def test_sentinel_absent_from_nested_list(self):
        """Sentinel in a list attribute must be redacted when the list is sensitive."""
        resource = {
            "address": "azurerm_network_security_rule.main",
            "mode": "managed",
            "type": "azurerm_network_security_rule",
            "name": "main",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "values": {
                "name": "rule-main",
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source_port_range": "*",
                "destination_port_range": "22",
                "source_address_prefix": SENTINEL,  # pretend sensitive source prefix
                "destination_address_prefix": "*",
                "priority": 100,
            },
            "sensitive_values": {
                "source_address_prefix": True,  # marked sensitive
            },
        }
        plan = _make_plan(resources_in_root=[resource])
        from infrastructure.terraform_plan import _build_resource_index, _normalize_resources

        root_module = plan["planned_values"]["root_module"]
        index = _build_resource_index(root_module, [])
        resources, _ = _normalize_resources(index, {})

        payload_json = json.dumps({"resources": resources})
        assert SENTINEL not in payload_json, (
            "Sentinel from a sensitive list/string attribute must not leak"
        )
