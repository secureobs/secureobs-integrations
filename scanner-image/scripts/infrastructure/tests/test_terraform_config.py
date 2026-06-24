"""Tests for the static (credential-free) Terraform topology extractor."""

from __future__ import annotations

import os

from infrastructure import terraform_config as tc


def _write(tmp_path, rel, content):
    path = os.path.join(str(tmp_path), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _addresses(payload):
    return {r["address"] for r in payload["resources"]}


def _by_address(payload, address):
    return next(r for r in payload["resources"] if r["address"] == address)


def test_resolves_variable_defaults(tmp_path):
    _write(tmp_path, "variables.tf", 'variable "public" { default = true }\n')
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
  account_replication_type = "LRS"
}
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    attrs = _by_address(payload, "azurerm_storage_account.main")["safeAttributes"]
    assert attrs["public_network_access_enabled"] is True


def test_tfvars_override_defaults(tmp_path):
    _write(tmp_path, "variables.tf", 'variable "public" { default = true }\n')
    _write(tmp_path, "terraform.tfvars", "public = false\n")
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
}
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    attrs = _by_address(payload, "azurerm_storage_account.main")["safeAttributes"]
    assert attrs["public_network_access_enabled"] is False


def test_tfvars_json_is_auto_loaded(tmp_path):
    _write(tmp_path, "variables.tf", 'variable "public" { default = true }\n')
    _write(tmp_path, "terraform.tfvars.json", '{"public": false}\n')
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    attrs = _by_address(payload, "azurerm_storage_account.main")["safeAttributes"]
    assert attrs["public_network_access_enabled"] is False


def test_explicit_tfvars_cannot_escape_root(tmp_path):
    root = tmp_path / "infra"
    _write(root, "variables.tf", 'variable "public" { default = false }\n')
    _write(root, "main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
}
''')
    _write(tmp_path, "outside.tfvars", "public = true\n")

    payload, _ = tc.build_payload(
        str(root), "p", "r", source_revision=None, terraform_root_id=None,
        var_files=["../outside.tfvars"])

    attrs = _by_address(payload, "azurerm_storage_account.main")["safeAttributes"]
    assert attrs["public_network_access_enabled"] is False
    assert any("outside the Terraform root" in warning for warning in payload["warnings"])


def test_auto_tfvars_symlink_cannot_escape_repository(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo, "infra/variables.tf", 'variable "public" { default = false }\n')
    _write(repo, "infra/main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
}
''')
    _write(tmp_path, "outside.tfvars", "public = true\n")
    os.symlink(tmp_path / "outside.tfvars", repo / "infra" / "terraform.tfvars")

    payload, _ = tc.build_payload(
        str(repo / "infra"), "p", "r", source_revision=None, terraform_root_id=None)

    attrs = _by_address(payload, "azurerm_storage_account.main")["safeAttributes"]
    assert attrs["public_network_access_enabled"] is False
    assert any("outside the repository" in warning for warning in payload["warnings"])


def test_unresolved_security_value_is_marked_unknown_not_uploaded(tmp_path):
    _write(tmp_path, "variables.tf", 'variable "public" { type = bool }\n')
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" {
  name = "sa"
  public_network_access_enabled = var.public
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    node = _by_address(payload, "azurerm_storage_account.main")
    assert "public_network_access_enabled" not in node["safeAttributes"]
    assert "public_network_access_enabled" in node["unknownAttributePaths"]


def test_resource_reference_value_is_unknown_but_reference_edge_is_preserved(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "azurerm_virtual_network" "vnet" { name = "vnet" address_space = ["10.0.0.0/16"] }
resource "azurerm_subnet" "subnet" {
  name = "subnet"
  virtual_network_name = azurerm_virtual_network.vnet.name
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    subnet = _by_address(payload, "azurerm_subnet.subnet")
    assert "virtual_network_name" not in subnet["safeAttributes"]
    assert "virtual_network_name" in subnet["unknownAttributePaths"]
    assert any(
        edge["targetAddress"] == "azurerm_virtual_network.vnet"
        for edge in payload["references"]
    )


def test_local_module_cannot_escape_repository(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo, "infra/main.tf", 'module "outside" { source = "../../outside" }\n'
           'resource "azurerm_subnet" "inside" { name = "inside" }\n')
    _write(tmp_path, "outside/main.tf",
           'resource "azurerm_subnet" "outside" { name = "outside" }\n')

    payload, _ = tc.build_payload(
        str(repo / "infra"), "p", "r", source_revision=None, terraform_root_id=None)

    assert "azurerm_subnet.inside" in _addresses(payload)
    assert "module.outside.azurerm_subnet.outside" not in _addresses(payload)
    assert any("outside the repository" in warning for warning in payload["warnings"])


def test_extracts_references_between_resources(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" { name = "sa" }
resource "azurerm_storage_container" "c" {
  name = "data"
  storage_account_name = azurerm_storage_account.main.name
}
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    edge = next(e for e in payload["references"]
                if e["sourceAddress"] == "azurerm_storage_container.c")
    assert edge["targetAddress"] == "azurerm_storage_account.main"
    assert edge["attributePath"] == "storage_account_name"


def test_duplicate_reference_edges_are_emitted_once(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_account" "main" { name = "sa" }
resource "azurerm_linux_virtual_machine" "vm" {
  name = "vm"
  network_interface_ids = [
    azurerm_storage_account.main.id,
    azurerm_storage_account.main.id
  ]
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    matching = [
        edge for edge in payload["references"]
        if edge["sourceAddress"] == "azurerm_linux_virtual_machine.vm" and
        edge["targetAddress"] == "azurerm_storage_account.main"
    ]
    assert len(matching) == 1


def test_reference_ignores_var_local_data(tmp_path):
    _write(tmp_path, "main.tf", '''
variable "x" { default = "v" }
locals { y = "z" }
resource "azurerm_subnet" "s" {
  name = var.x
  virtual_network_name = local.y
}
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert payload["references"] == []


def test_follows_local_modules(tmp_path):
    _write(tmp_path, "main.tf", 'module "net" { source = "./modules/net" }\n')
    _write(tmp_path, "modules/net/net.tf", '''
resource "azurerm_virtual_network" "vnet" { name = "vnet" address_space = ["10.0.0.0/16"] }
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert "module.net.azurerm_virtual_network.vnet" in _addresses(payload)


def test_local_module_references_keep_module_prefix(tmp_path):
    _write(tmp_path, "main.tf", 'module "net" { source = "./modules/net" }\n')
    _write(tmp_path, "modules/net/net.tf", '''
resource "azurerm_public_ip" "pip" { name = "pip" }
resource "azurerm_network_interface" "nic" {
  name = "nic"
  ip_configuration {
    name = "main"
    public_ip_address_id = azurerm_public_ip.pip.id
  }
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    edge = next(e for e in payload["references"]
                if e["sourceAddress"] == "module.net.azurerm_network_interface.nic")
    assert edge["targetAddress"] == "module.net.azurerm_public_ip.pip"


def test_same_local_module_can_be_instantiated_twice(tmp_path):
    _write(tmp_path, "main.tf", '''
module "east" { source = "./modules/net" }
module "west" { source = "./modules/net" }
''')
    _write(tmp_path, "modules/net/net.tf",
           'resource "azurerm_virtual_network" "vnet" { name = "vnet" }\n')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert "module.east.azurerm_virtual_network.vnet" in _addresses(payload)
    assert "module.west.azurerm_virtual_network.vnet" in _addresses(payload)


def test_count_zero_resource_is_omitted(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "azurerm_storage_container" "disabled" {
  count = 0
  name = "public"
  container_access_type = "blob"
}
''')
    payload, _ = tc.build_payload(
        str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert "azurerm_storage_container.disabled" not in _addresses(payload)


def test_remote_module_is_skipped_with_warning(tmp_path):
    _write(tmp_path, "main.tf",
           'module "x" { source = "Azure/network/azurerm" version = "5.0.0" }\n'
           'resource "azurerm_subnet" "s" { name = "snet" }\n')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert any("non-local source" in w for w in payload["warnings"])
    assert "azurerm_subnet.s" in _addresses(payload)


def test_unsupported_type_recorded_without_attributes(tmp_path):
    _write(tmp_path, "main.tf",
           'resource "some_unknown_thing" "x" { secret = "shh" foo = "bar" }\n')
    payload, unsupported = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    node = _by_address(payload, "some_unknown_thing.x")
    assert node["safeAttributes"] == {}
    assert unsupported == 1


def test_denylisted_keys_are_dropped(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "azurerm_key_vault" "kv" {
  name = "kv"
  sku_name = "standard"
  public_network_access_enabled = false
}
''')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    attrs = _by_address(payload, "azurerm_key_vault.kv")["safeAttributes"]
    assert "sku_name" in attrs
    assert attrs["public_network_access_enabled"] is False


def test_digest_is_sha256_hex(tmp_path):
    _write(tmp_path, "main.tf", 'resource "azurerm_subnet" "s" { name = "snet" }\n')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert len(payload["planDigest"]) == 64
    assert all(c in "0123456789abcdef" for c in payload["planDigest"])
    assert payload["formatVersion"] == "1.0"


def test_empty_root_returns_no_resources(tmp_path):
    _write(tmp_path, "providers.tf", 'provider "azurerm" { features {} }\n')
    payload, _ = tc.build_payload(str(tmp_path), "p", "r", source_revision=None, terraform_root_id=None)
    assert payload["resources"] == []
