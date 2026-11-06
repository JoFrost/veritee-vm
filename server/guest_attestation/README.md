# Guest attestation image

The two build stages use the same pinned `linux/amd64` Python 3.11.15 image.
Debian packages come only from the `20260928T000000Z` Bookworm and security
snapshots; `tpm2-tools` is pinned to `5.4-1`. APT still verifies repository
signatures; disabling snapshot expiry does not disable signature checking.

`requirements.lock` is the hash-bearing export of the existing `poetry.lock`
(Poetry 2.2.1, export plugin 1.10.0). Docker does not install Poetry or its
plugins. The dependency stage verifies the source/export checksums and installs
only listed, hash-checked wheels into a virtual environment. No source builds
or additional dependency resolution are allowed. Both stages run `pip check`.

After an intentional dependency change, regenerate and review the export:

```sh
cd server/guest_attestation
poetry export --format requirements.txt --output requirements.lock --only main
sha256sum pyproject.toml poetry.lock requirements.lock > requirements.sources.sha256
python3.11 -m unittest discover -s tests -v
```

Build from the repository root. The BuildKit epoch argument and exporter option
normalize OCI timestamps; the Dockerfile also removes package-install logs and
the inode-dependent `ldconfig` auxiliary cache. Retain the dpkg package database
for dependency inspection.

```sh
docker buildx build --platform linux/amd64 \
  --build-arg SOURCE_DATE_EPOCH=946684800 --provenance=false --sbom=false \
  --output type=docker,rewrite-timestamp=true \
  -t guest-attestation:pinning-test server/guest_attestation
docker run --rm --entrypoint python guest-attestation:pinning-test -m pip check
docker run --rm --entrypoint tpm2_quote guest-attestation:pinning-test --version
```

For a clean-output comparison, build twice with `--no-cache`, using a
docker-container Buildx builder and `--output
type=oci,dest=/path/to/build-a.oci.tar,rewrite-timestamp=true` (use a different
destination for the second build). Compare the referenced OCI manifest, config
and layer blobs; do not treat cached rebuilds as evidence of reproducibility.

Inspect Python packages and Debian package records (`ii` marks installed Debian packages):

```sh
docker run --rm --entrypoint python guest-attestation:pinning-test -m pip list --format=json
docker run --rm --entrypoint dpkg-query guest-attestation:pinning-test -W '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n'
```

These are inventory inputs, not an authenticated dependency manifest or proof
that the Warden validated them.

## Building the guest helper

From the repository root:

```sh
veritee build-guest-attestation
```

This produces `guest-attestation:local`. Packaging retains the existing
published helper digest below. To use a newly published helper image, pass
`--guest-attestation-image` or set `VERITEE_GUEST_ATTESTATION_IMAGE`. Warden must
use the same image when reproducing the app disk.

DApps run the helper as `guest-attestation`, load `.guest-attestation.env`, and
reach Caddy through the existing private DNS alias on the
`constrained-attestation` network. The alias remains
`caddy-in-constrained-attestation-generator-network` because the published
helper uses that name. Caddy's admin API on port 2019 provides its local TLS root CA to the
helper. It is not published as a host port.

## Current published image

The current pinned helper was published on 8 October 2026 as
`20261008-pinned`. Its private Caddy hostname remains supported by the renamed
DApp services:

On 2 November 2026, the existing image was also tagged under
`veritee/guest-attestation:20261008-pinned` in the same registry. The manifest
digest is unchanged. This alias does not contain the newer source changes in
this checkout; publishing a rebuilt helper is a separate release step.

```text
temenostest.azurecr.io/veritee/guest-attestation@sha256:9426ac1dce1c3501c70252ab37d9d591ebfaca252f853e31da747acf541d6b1a
```

Two uncached `linux/amd64` builds with BuildKit `v0.32.2`, the epoch argument and
timestamp-rewriting exporter above produced byte-identical OCI tar files.
Their manifest, config and all layer blobs matched. OCI tar SHA-256:
`9a92d96eb8aa954fbb46425538626cec4ea0769b89c152b3549603409fe70963`.
Image config SHA-256:
`acdf7b3e49cac8c9f438de12ce949d065dcabdbcc22e0d39abcd5604c36c9538`.
This is a same-builder clean-build result, not independent-builder certification.

The published digest was pulled without registry credentials and smoke-tested:
`pip check`, Python 3.11.15, cryptography/requests imports, `tpm2_quote` 5.4,
source compilation and parsing of both public certificates passed. Eight
build-input/default-pin tests passed. No OS image was rebuilt or deployed.

These smoke tests do not access a TPM or produce an attestation. Full TPM/TLS
validation requires the guest runtime. The canonical provenance manifests
proposed in temenos-spec#24 are not implemented here. Docker APT package
archiving is separate work.
