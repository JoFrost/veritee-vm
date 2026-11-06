# Veritee Egress Proxy

`temenos-egress-proxy` is a small HTTP CONNECT gateway used to enforce measured
outbound policies in Veritee guests. It has no attestation responsibilities.

For hostname entries, the proxy accepts only HTTP/1.1 CONNECT requests, verifies
that the TLS ClientHello SNI exactly matches the requested hostname, resolves the
hostname itself, rejects non-public results, and only then opens the upstream
connection. Literal-IP entries provide a raw TCP tunnel to the exact measured
IP and port.

## Policy

```json
{
  "version": 2,
  "profile": null,
  "outbound": [
    { "host": "downloads.example.com", "port": 443 },
    { "ip": "1.1.1.1", "port": 443 }
  ],
  "platform_outbound": [
    { "host": "example.attest.azure.net", "port": 443 }
  ]
}
```

Run one process for each policy scope:

```sh
cargo run --locked -- \
  --policy-file /run/temenos/egress-policy.json \
  --scope app \
  --allow-client-cidr 172.30.255.0/24 \
  --dns-server 168.63.129.16
```

The `app` scope listens on `0.0.0.0:18080` by default. The `platform` scope
listens on `127.0.0.1:18081`. Both addresses and ports can be overridden with
`--listen-host` and `--listen-port`, although the platform scope refuses to bind
outside loopback. At least one `--allow-client-cidr` is required.

The DNS server is explicit. The proxy does not use the host resolver
configuration or `/etc/hosts`; this lets the guest firewall grant DNS access to
the proxy process without granting it to the DApp.

Each scope accepts at most 256 concurrent tunnels. Excess connections receive
HTTP `503` immediately. Established tunnels are closed after five minutes with
no traffic in either direction; active transfers and long-lived connections
that continue exchanging data are unaffected.

## Security boundary

This process is only one part of the enforcement boundary. The guest must also:

- deny direct application and container egress in the kernel;
- permit outbound connections only for the dedicated proxy user;
- restrict access to the app listener to the intended container bridge;
- keep the platform listener on loopback;
- provide the proxy with policy bytes covered by the measured application state.

The application disk itself is trusted measured input. Veritee currently runs
its `setup.d/main` and `run.d/main` lifecycle hooks as host root. Those hooks are
part of the DApp TCB and can reconfigure the host; the proxy is not intended to
sandbox deliberately malicious lifecycle hooks. Its boundary begins with the
runtime containers produced by a verified application package. Removing
application-supplied host hooks is tracked separately in
[veritee-vm#42](https://github.com/input-output-hk/veritee-vm/issues/42).

The proxy does not terminate TLS and therefore cannot inspect encrypted HTTP
headers. Exact SNI validation prevents a simple CONNECT-host mismatch, but it
cannot prevent domain fronting where an approved TLS endpoint intentionally
routes encrypted requests for another logical service. An approved endpoint is
also an approved exfiltration destination. Policy review therefore remains part
of the security boundary.

For the same reason, the proxy does not validate the upstream certificate. SNI
matching is an authorization check, not server authentication. The DApp's TLS
client must validate WebPKI certificates or measured certificate pins. A
compromised client that disables certificate validation can still be redirected
by a hostile DNS or network path. Enforcing server identity centrally would
require a separate TLS-terminating gateway and a CA trusted by the workload.

Plain HTTP through the proxy is intentionally unsupported. Hostname destinations
must begin with a TLS ClientHello containing SNI. Encrypted ClientHello without a
visible server name is rejected.

## Development

The Rust toolchain, direct dependencies, and full dependency graph are pinned.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release --locked
```
