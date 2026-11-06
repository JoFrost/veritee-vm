# `destroy-vm` output example

This example uses the deployment details from the completed `inv-test` Azure
rehearsal. Repeated Azure deletion heartbeat lines are abbreviated, and blob
suffixes marked `<generated>` are generated independently for every event.

```text
$ veritee destroy-vm \
    --deployment-id midnight-proof-server-preprod-20260918t151435z-d18bab5e \
    --yes

 _____
|_   _|__ _ __ ___   ___ _ __   ___  ___
  | |/ _ \ '_ ` _ \ / _ \ '_ \ / _ \/ __|      [ TEE PACKAGER ]
  | |  __/ | | | | |  __/ | | | (_) \__ \
  |_|\___|_| |_| |_|\___|_| |_|\___/|___/
  version 0.2.0 · network preprod · started 2026-09-18T18:35:44+03:00

════════════════════════════════════════════════════════════════════════════════
PHASE 1/4: VALIDATE DEPLOYMENT DESTRUCTION REQUEST
════════════════════════════════════════════════════════════════════════════════
Deployment ID         : midnight-proof-server-preprod-20260918t151435z-d18bab5e
DApp                  : Midnight Proof Server - preprod
Resource group        : inv-test
VM                    : inventory-vm-64
Created               : 2026-09-18T15:14:35Z
TLS mode              : internal
Base OS               : temenostest.azurecr.io/temenos/base-os:0.3.1-raw-sev-snp
DApp image            : docker.io/midnightntwrk/proof-server:8.1.0-amd64@sha256:829d02876b346fe773d3d17419a38aadb9fafc6653603afbb3f16672bc122bd4
Application root hash : 8d857d91009b28b1b712cd84c2b10de2c3b5fec22f7a71571b4a1057d5d0368a

════════════════════════════════════════════════════════════════════════════════
PHASE 2/4: PRESERVE DEPLOYMENT AUDIT RECORD
════════════════════════════════════════════════════════════════════════════════
veritee       | 2026-09-18T18:35:53+03:00 INFO  Measured VHD retention was not requested.
veritee       | 2026-09-18T18:35:53+03:00 INFO  Appended deployment audit record: temenosinventorywus/temenos-inventory/records/midnight-proof-server-preprod-20260918t151435z-d18bab5e/20260918T153551Z-destroy_requested-721508f9.json
veritee       | 2026-09-18T18:35:53+03:00 INFO   ✓ Destroy request recorded in durable inventory.

════════════════════════════════════════════════════════════════════════════════
PHASE 3/4: CLEAN UP EXTERNAL ACCESS
════════════════════════════════════════════════════════════════════════════════
veritee       | 2026-09-18T18:35:53+03:00 INFO  No external TLS Key Vault access to remove.

════════════════════════════════════════════════════════════════════════════════
PHASE 4/4: DELETE AZURE DEPLOYMENT
════════════════════════════════════════════════════════════════════════════════
veritee       | 2026-09-18T18:35:53+03:00 INFO  Deleting Azure resource group inv-test and all deployment resources...
veritee       | 2026-09-18T18:35:54+03:00 INFO  Azure accepted the deletion request. Waiting for completion...
veritee       | 2026-09-18T18:36:24+03:00 INFO  Azure resource group inv-test is still deleting (elapsed=30s)...
veritee       | 2026-09-18T18:36:54+03:00 INFO  Azure resource group inv-test is still deleting (elapsed=60s)...
...
veritee       | 2026-09-18T18:41:59+03:00 INFO  Appended deployment audit record: temenosinventorywus/temenos-inventory/records/midnight-proof-server-preprod-20260918t151435z-d18bab5e/20260918T154159Z-destroyed-<generated>.json
veritee       | 2026-09-18T18:41:59+03:00 INFO   ✓ Destroyed Veritee deployment midnight-proof-server-preprod-20260918t151435z-d18bab5e.
```

The deployment remains discoverable after its Azure resource group is gone:

```text
$ veritee list-deployments --all
veritee       | 2026-09-18T19:04:57+03:00 INFO  Querying Azure for live Veritee deployments...
veritee       | 2026-09-18T19:05:00+03:00 INFO  Querying deployment history from temenosinventorywus/temenos-inventory...
veritee       | 2026-09-18T19:05:02+03:00 INFO  Downloading 2 deployment audit records...
veritee       | 2026-09-18T19:05:05+03:00 INFO  Checking Azure state for 1 pending deletion...

DEPLOYMENT ID                                            RESOURCE GROUP  STATUS     DAPP                             VM               CREATED               BASE OS                                                   APPLICATION ROOT HASH
midnight-proof-server-preprod-20260918t151435z-d18bab5e  inv-test        destroyed  Midnight Proof Server - preprod  inventory-vm-64  2026-09-18T15:14:35Z  temenostest.azurecr.io/temenos/base-os:0.3.1-raw-sev-snp  8d857d91009b28b1b712cd84c2b10de2c3b5fec22f7a71571b4a1057d5d0368a
```

For deployments destroyed by the current CLI, the explicit `destroyed` event
means subsequent listings do not need the Azure state reconciliation shown in
this older rehearsal.
