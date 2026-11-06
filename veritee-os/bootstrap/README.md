# Debian CA bootstrap

`ca-certificates_20250419_all.deb` is copied unchanged from the pinned Debian
snapshot used by the Earthfile:

```text
https://snapshot.debian.org/archive/debian/20251208T000000Z/pool/main/c/ca-certificates/ca-certificates_20250419_all.deb
```

Expected size: `161704` bytes.

Expected SHA-256:

```text
ef590f89563aa4b46c8260d49d1cea0fc1b181d19e8df3782694706adf05c184
```

The pinned Debian slim base does not contain a CA bundle. The build extracts
the roots from this package only long enough to authenticate the HTTPS snapshot,
then installs the same pinned package normally and removes the temporary trust
configuration.
