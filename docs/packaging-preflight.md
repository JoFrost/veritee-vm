# Validate before packaging

`package-dapp-deployable-vm-image` validates registration inputs before pulling
the base OS or starting Earthly. Run the same checks independently:

First configure the application metadata with digest-pinned app and approved
base OS image references. The reference app's tag-only placeholders are rejected.

```sh
veritee validate-dapp --app-dir projects/my-app --tls-mode internal

veritee validate-dapp --app-dir projects/my-app --tls-mode azure_vault \
  --tls-keyvault-name <runtime-tls-vault>
```

Validation is local, even when `VERITEE_WARDEN_URL` is configured. It does not
contact Warden, query the OS registry, build a disk, generate an app key or
provision Azure resources. Normal packaging subsequently performs its existing
accepted-OS lookup and image retrieval. Container startup, readiness and live
attestation still need their normal checks.

## What is checked

The CLI uses its bundled rebuild recipe and `registration-limits-v1.json`.
These encoded-byte budgets match Warden's native app projection validator.
They do not require a validation endpoint or a startup call to Warden.

| Input | Pack-time rule |
|---|---|
| App details | Compact JSON UTF-8 byte budgets, including quotes and escapes; the complete projection must fit 1,024 bytes |
| `name`, `description` | At most 34 / 130 encoded bytes; equivalent to 32 / 128 unescaped ASCII characters |
| Attestation domain / API address | Domain at most 82 encoded bytes; normalized API address and duplicated deployment URL each at most 74; attestation base URL at most 90 |
| OS version | Use the selected release's version, at most 34 encoded bytes; reject a conflicting authored version hint |
| Images | App, base OS and guest attestation references must be digest-pinned; a tag alone is rejected, not silently resolved or rewritten |
| Rebuild | Helper image, fixed template files, default scripts and repart definitions must match the bundled registration builder's recipe |
| Source files | Warden receives only metadata, Caddyfile and Compose. Extra files/directories or changed startup scripts that it cannot reproduce are rejected |
| Egress | Existing metadata/Compose validation applies. A Warden-only egress profile cannot be submitted to the ordinary registration builder; an unused opt-in flag does not change an otherwise ordinary app |
| Caddy | The default guest launcher needs two separate sites, attestation first and API second. Check its actual parser against CLI host inference; use bare DNS names and LF site headers |
| Azure tags | Name and image references used in deployment tags must fit the 256-character value limit |

Runtime addresses supplied later, especially an IP in internal-TLS mode, cannot
be known during packaging. Registration checks the actual normalized address
against bundled limits before sending the request. Warden enforces its own
limits during normal registration, before queuing an expensive job.

Use the matching CLI/recipe in Warden when registering a new package. Local
preflight cannot establish what a running Warden currently accepts.
For an operator image that will not be registered, such as Warden's own custom
runtime, use `--no-registration-preflight`. Explicit egress opt-ins are still
required; digest pins and Azure tag limits remain checked. This flag does not
weaken any Warden admission check.

## Frozen inputs and runtime certificates

New packages write `local-azure-snp/packaged-inputs.json` beside their measurements
and include it when publishing deployable artifacts. It records source file
hashes, exact prepared metadata identity, TLS mode, helper image, OS reference,
application root/PCR4 and the local build recipe. It is outside the measured
disk, contains no app key, and is a local consistency record, not signed
provenance or an admission receipt.

`register-app` detects changed metadata, Caddyfile, Compose, extra files and
measurements before reading the app key or posting a registration. It preserves
the actual UTF-8 file bytes, including Compose CRLF. Changed limits are rechecked
against local rules. No extra validation or OS-registry requests are made before
the normal registration POST. Restore the original inputs or repackage after an
intentional change. Warden remains responsible for its current recipe and OS
registry; local validation is not a guarantee of admission by an arbitrary server.
Older packages without a snapshot retain legacy registration behavior without
a claim that source drift was checked.

`run.d/certs/`, including its README, is excluded before staging and removed in
all Earthly app-copy targets. It is never an app-disk input. The launcher creates
the runtime directory; Azure Vault TLS still fetches its certificate/key at boot.
Source certificate files are left untouched. Certificate renewal therefore does
not change this input snapshot or require repackaging.

Excluding previously embedded certificate directories changes the application
root for new packages. Use the matching Warden builder for new registrations;
existing registered images continue to verify against their existing roots.
This changes the app recipe, not the base-OS release or PCR4.

## Checks that remain live

The existing accepted-OS resolution during packaging checks the configured OS
ledger against the signed manifest returned by the configured Warden. That
pre-existing lookup is separate from preflight. During registration, Warden
resolves and validates OS acceptance itself; the client does not need a local
contract CLI or a separate validation request.

Key Vault availability requires the intended Azure subscription/tenant and
permissions. An existing name may be the vault deliberately being reused;
soft-deleted and inaccessible vaults need different recovery actions. Format
validation cannot establish availability, and a live lookup cannot reserve a
name. Use `upload-tls-certs` to prepare or recover the intended vault before
packaging. Preflight explicitly reports that vault availability was not checked.
`create-vm` enforces the vault name already bound into packaged metadata.

Cloud quota, allocation, permissions and TLS-secret readiness still require
deployment preflight. Warden independently enforces admission, attestation,
revocation, reproduction and confirmed publication; a successful input check
does not replace them.
