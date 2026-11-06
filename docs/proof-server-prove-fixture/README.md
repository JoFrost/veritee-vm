# Proof-server fixtures

These are synthetic ledger 8.1 fixtures for application tests. They contain no
operator wallet or deployment secrets.

- `zswap-prove-payload.bin`: the existing 481-byte proof-preimage request for
  the built-in `midnight/zswap/output` key. SHA-256:
  `54ca63f4a16a3d99aa8090d98dbbee34a9f560ce02033cf61757e738e94aca15`.
- `zswap-check-payload.bin`: the same preimage encoded for `/check`, 463 bytes.
  SHA-256: `b905ad050547a5f179b60324c806453fae24cce150eadd0a3ae52b67bfd0f45c`.

The check fixture was generated with `createCheckPayload` from the official
`@midnight-ntwrk/ledger-v8` package at exactly 8.1.0. `createProvingPayload`
round-tripped the original prove fixture byte for byte before generation.
The two endpoints take different serialized tuples; a prove request should
not be sent unchanged to `/check`.

Source: [ledger 8.1 proof helpers](https://github.com/midnightntwrk/midnight-ledger/blob/ledger-8.1.0/ledger-wasm/src/lib.rs)
and [proof-server endpoints](https://github.com/midnightntwrk/midnight-ledger/blob/ledger-8.1.0/proof-server/src/endpoints.rs).

`scripts/test-proof-server-proxy.py` tests direct requests and encrypted
requests in the same session, including recovery after an application error.
Use the matching HTTP tunnel client from
[PR #53](https://github.com/input-output-hk/veritee-vm/pull/53), for example:

```sh
PYTHONPATH=/path/to/PR53-checkout/cli cli/env/bin/python \
  scripts/test-proof-server-proxy.py --runs 1
```

`--ip` routes to a replacement VM before DNS changes while preserving TLS
hostname validation. The script checks application and transport behavior;
fresh TPM/SNP evidence and Warden verification remain separate checks.

After registration, add `--dapp-id <entry-id>` to verify the epoch key with
Warden before either encrypted request. This requires the client nonce/payload
binding fix on `feat/warden-dapp` as well as the HTTP client from PR #53.
`--warden-url` selects Warden; `--warden-ip` can override its DNS for testing.
