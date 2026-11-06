# Security Notes

This proxy is part of the Veritee guest TCB. Changes to request parsing, policy
matching, DNS filtering, TLS ClientHello parsing, connection limits, or timeout
behavior require security review and negative tests.

The threat boundary assumes that the measured application package, including
the host-root `setup.d/main` and `run.d/main` lifecycle hooks, has been verified
against the expected registered policy. The proxy constrains runtime container
egress; it does not defend the host against intentionally malicious measured
lifecycle hooks. Replacing those hooks with platform-owned orchestration is
tracked in temenos-vm#42.

Reports should include the policy, CONNECT request, TLS ClientHello behavior,
and the destination reached or denied. Do not include production secrets.

Known architectural limitation: the proxy validates CONNECT authority and TLS
SNI, but it cannot inspect application data encrypted inside the tunnel. Shared
TLS/CDN infrastructure can therefore retain domain-fronting risk. The proxy
also cannot authenticate the upstream certificate without terminating TLS;
certificate validation remains the responsibility of the DApp's TLS client.
