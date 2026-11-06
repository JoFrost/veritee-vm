# Immutable VM Inventory

Veritee treats each measured Azure CVM as immutable. A new image creates a new
deployment id and resource group; there is no update-in-place path.

## Prerequisites

Set the Azure subscription and initialize the shared inventory infrastructure
once:

```bash
export ARM_SUBSCRIPTION_ID=<subscription-id>
veritee init-inventory --location <azure-region>
```

The command is idempotent. It creates or reuses a private Storage account in
`temenos-inventory-rg`, grants the current Azure identity Blob Data access, and
creates the `temenos-inventory` container. The account is tagged so later
commands discover it without local configuration.

`VERITEE_INVENTORY_STORAGE_ACCOUNT` overrides account discovery when an estate
uses a separately managed account. `VERITEE_INVENTORY_CONTAINER` optionally
changes the container name from `temenos-inventory`.

The operator needs permission to create the shared resource group and Storage
account and to assign itself Blob Data access. Configure an Azure
immutability/WORM policy on the inventory container so its uniquely named audit
records cannot be changed or deleted outside Veritee.

## Deploy

Interactive deployment prompts for the resource group, location, VM name, and
Compute Gallery name:

```bash
veritee create-vm --azuresnp
```

Automation must provide those values explicitly:

```bash
veritee create-vm --azuresnp \
  --resource-group <new-resource-group> \
  --location <azure-region> \
  --vm-name <vm-name> \
  --gallery-name <gallery-name>
```

The command refuses an existing resource group. On success it prints the
deployment id and records:

- live inventory tags on the resource group;
- a creation event under
  `records/<deployment-id>/...-created-<random>.json` in the inventory container;
- Terraform scratch state under
  `.temenos/deploy-azure-snp/<deployment-id>/`.

The Terraform directory is mode `0700` because its state and debug output may
contain deployment credentials. It is local recovery material, not the fleet
inventory; Azure tags remain authoritative for live deployments.

Tags are operational inventory. Attestation and the registered policy remain
the source of trust for the measured workload.

## List

```bash
veritee list-deployments
veritee list-deployments --all
veritee list-deployments --json
```

Without `--all`, the command queries live Azure resource groups tagged
`temenos_managed=true`. With `--all`, it merges those live resources with the
durable inventory records, including deployments whose resource groups have
already been deleted. The JSON output includes the complete DApp and base OS
image references alongside their available digest tags. For older records that
end at `destroy_requested`, the command checks whether the resource group still
exists and reports it as destroyed when Azure confirms it is gone; the stored
event history itself is not rewritten.

Inspect the audit events and their Azure blob paths for one deployment with:

```bash
veritee deployment-history <deployment-id>
veritee deployment-history <deployment-id> --json
```

## Destroy

Select exactly one deployment:

```bash
veritee destroy-vm --deployment-id <deployment-id>
veritee destroy-vm --resource-group <resource-group>
```

The command refuses untagged resource groups and asks for confirmation. In
non-interactive environments, pass `--yes`. For `azure_vault` deployments it
removes the VM identity's role on the external Key Vault, but never deletes the
vault.

The entire deployment resource group, including its uploaded VHD, is deleted by
default. To retain the measured image explicitly:

```bash
veritee destroy-vm --deployment-id <deployment-id> --keep-image
```

The VHD is copied server-side to
`retained-images/<deployment-id>/...-temen-os.vhd` before the destroy audit event
is appended and before Azure resource-group deletion begins. The CLI records
`destroy_requested` before issuing the deletion and records `destroyed` only
after Azure confirms that the resource group no longer exists.

## Rehearsal

Run this once in the development subscription before relying on the teardown
path operationally:

1. Deploy with all non-interactive flags.
2. Confirm `veritee list-deployments` shows the deployment.
3. Compare the live resource-group tags with `local-azure-snp/pcrs.json` and the
   pinned images in `local-azure-snp/metadata.json`.
4. Run `veritee destroy-vm --deployment-id <id> --yes`.
5. Confirm the resource group and its VHD no longer exist.
6. Confirm the inventory container contains both the creation and
   `destroy_requested` records.
7. For `azure_vault`, confirm the shared vault remains and the deleted VM
   principal has no remaining `Key Vault Secrets User` assignment.
