import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from veritee import cli


@pytest.fixture
def incomplete(tmp_path):
    state = {"resources": [{"type": "azurerm_resource_group", "instances": [{
        "attributes": {"id": "/subscriptions/test-sub/resourceGroups/test-rg"},
    }]}]}
    (tmp_path / "terraform.tfstate").write_text(json.dumps(state))
    group = {"tags": {"temenos_managed": "true", "temenos_deployment_id": "demo-123",
                      "temenos_app_name": "Demo"}}
    return tmp_path, state, group


def resume(work_dir):
    return cli.validate_incomplete_deployment_resume(work_dir, "test-rg", "test-sub", "demo-123", "Demo")


def test_accepts_owned_partial_deployment_without_a_vm(incomplete):
    work_dir, _, group = incomplete
    with (mock.patch.object(cli, "query_resource_group", return_value=group),
          mock.patch.object(cli, "run_checked", return_value=SimpleNamespace(stdout="[]"))):
        assert resume(work_dir) == group


def test_missing_local_state_cannot_adopt_azure_resources(tmp_path):
    with pytest.raises(cli.DeployerException, match="original local Terraform state"):
        resume(tmp_path)


def test_state_from_another_subscription_is_rejected(incomplete):
    work_dir, state, _ = incomplete
    state["resources"][0]["instances"][0]["attributes"]["id"] = "/subscriptions/other/resourceGroups/test-rg"
    (work_dir / "terraform.tfstate").write_text(json.dumps(state))
    with pytest.raises(cli.DeployerException, match="does not match"):
        resume(work_dir)


@pytest.mark.parametrize("key,value", [("temenos_managed", "false"),
    ("temenos_deployment_id", "another-deployment"), ("temenos_app_name", "Another app")])
def test_unrelated_azure_group_is_rejected(incomplete, key, value):
    work_dir, _, group = incomplete
    group["tags"][key] = value
    with (mock.patch.object(cli, "query_resource_group", return_value=group),
          pytest.raises(cli.DeployerException, match="does not belong")):
        resume(work_dir)


def test_existing_vm_in_state_is_rejected_even_if_deleted_from_azure(incomplete):
    work_dir, state, _ = incomplete
    state["resources"].append({"type": "azurerm_linux_virtual_machine", "instances": [{"attributes": {}}]})
    (work_dir / "terraform.tfstate").write_text(json.dumps(state))
    with pytest.raises(cli.DeployerException, match="VM already entered"):
        resume(work_dir)


def test_existing_azure_vm_is_rejected_even_if_missing_from_state(incomplete):
    work_dir, _, group = incomplete
    with (mock.patch.object(cli, "query_resource_group", return_value=group),
          mock.patch.object(cli, "run_checked", return_value=SimpleNamespace(stdout='[{"name":"live-vm"}]')),
          pytest.raises(cli.DeployerException, match="containing a VM")):
        resume(work_dir)
