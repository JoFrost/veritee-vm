# Working in this repository

This repository builds Veritee application disks, packages deployable VM images,
deploys Azure confidential VMs, and registers DApps with Warden.

## Deployment workflow

- Use the Veritee CLI for packaging, deployment, policy hydration, registration,
  and verification. Inspect the CLI implementation and app source when resolving
  problems instead of replacing the workflow with manual steps.
  The packaging command pulls its pinned base OS automatically; a separate
  pull is only useful when inspecting OS artifacts independently.
- Read the selected application's metadata and runtime files before building.
  Exercise actual container startup with the intended configuration and isolated
  scratch state before packaging; toolchain checks alone do not establish that
  the application will start.
  Check the host's local proxy hop as well as requests between containers;
  publishing a port from an internal Docker network may leave it unreachable.
  Preserve user-selected image pins and configuration. Subscription, region,
  VM size, hostnames, TLS vault, persistence size, and Warden endpoint are choices
  for each deployment; do not inherit them from another application's notes.
- Verify regional SKU availability, quota, required Azure components, TLS
  certificates, and permissions before provisioning. Reuse shared resources
  when appropriate, and preserve them during deployment teardown.
- Verify the deployed service over HTTPS and check application readiness
  separately from API availability. For indexers, verify stored block heights
  advance and check protocol compatibility with the upstream node.
  When changing the OS image, check attested proxy protocol compatibility and
  exercise the application request with a matching client.
  Check that the deployed Warden's trusted OS measurements include the pinned
  release before registration. A source policy change compiled into the binary
  requires an updated runtime; verify the published measurement before adding it.
- Fetch fresh nonce-bound attestation, verify the TPM quote, compare PCR4 with
  the packaged base OS value, and hydrate the actual platform policy/PCRs.
  A different VM generation requires live attestation checks.
- When registration is requested, use packaged metadata and the exact app source
  files used for the build. Poll the Warden job through root hash verification
  and on-chain completion, then verify fresh evidence against the registration.
- Keep new documentation and test harnesses outside the measured application
  source tree. Adding files there can change the packaged root hash; packaging
  and registration must use the same file set.
- Check existing Azure resources, inventory records, and Warden job status
  before retrying a long operation. Avoid duplicate deployments or registrations.

## Local tooling and care

- A local editable CLI environment may be available at `cli/env/bin/veritee`.
  Downloaded tools may be under `.temenos/tools/bin`; add that directory to PATH
  as needed. Check installed tool versions and dependencies before building.
- `local-azure-snp/` contains packaged artifacts and generated security files.
  `.temenos/` contains deployment work directories, Terraform state, and logs.
- Keep credentials, private keys, and generated `temenos_app_key` files secret.
  Preserve application keys securely; never print or commit them.
  Store supplied application keys in a private ignored file and reuse them for
  registration instead of generating a replacement identity.
  Archive keys and packaged artifacts per application. When switching applications,
  seed the correct key explicitly; a shared output directory can retain another
  application's identity.
  Process arguments can contain tool credentials. Report process names, IDs,
  status, and elapsed time without printing unfiltered command arguments.
- Check disk space before large builds and exports. Cleanup should stay within
  the user's authorization and preserve running containers and data volumes.
- Preserve unrelated work and pre-existing local repositories/files. Record
  code changes and relevant validation; do not imply an app is ready merely
  because infrastructure deployment or attestation succeeded.
- A job phase can remain unchanged throughout wallet synchronization. Use
  measured checkpoint counters or a confirmed contract entry as evidence of
  progress; do not assume a failure from elapsed time alone.
- Guest lockdown does not establish confidentiality of persisted data. Treat
  authorized disk exports and saved checkpoints as sensitive. A running-disk
  snapshot may intersect a checkpoint write; validate recovery files before
  using them, and revoke temporary export access after diagnostics.
  For wallet replacement, validate the provider, SDK versions, all sub-wallet
  files and the exact pinned archive before starting the new writer. Stop the
  previous writer before starting its replacement.

## Notes

Keep deployment-specific decisions, identifiers, hashes, paths, job status,
verification results, and remaining work in dated files under
`docs/deployment-notes/`. Update those notes as work progresses. Keep this file
generic and check live state before acting on historical notes.
