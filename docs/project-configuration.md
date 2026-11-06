# Configuring a DApp project

Copy `projects/dapp` to `projects/<name>` and select it with `--app-dir`.
Set the application name, image and approved base OS in `metadata.json`.
Configure the app's command, environment and volumes in the Compose `app` service.

In `run.d/Caddyfile.template`, replace the attestation and API hostnames.
Set the application's container port once, in the Compose `caddy` service.
For an app listening on port 6300:

```yaml
caddy:
  environment:
    APP_UPSTREAM: "app:6300"
```

The app must listen on its container network interface, for example
`0.0.0.0:6300`, so Caddy can reach it.

Both the public HTTPS API and the attested proxy read this value. There is
one upstream port to maintain; no additional CLI option or shell export is
needed. The template already provides the required routing.

The Compose mapping `127.0.0.1:8080:8080` belongs to Caddy. Port 8080 is the
fixed internal connection from the host attestation server, regardless of the
app's container port. Use the supplied listener and network definitions as-is:
the attestation server decrypts the request, sends it to loopback Caddy, and
Caddy forwards it to the app on its private Docker network.
This hop is needed because a port published directly from an internal Docker
network can be unreachable from the host.

Outbound connections use the separate measured egress policy declared in
`metadata.json`. The loopback listener serves incoming application requests.

Package and register with the same project files. Keep operator notes, test
harnesses and documentation under `docs/` or elsewhere outside the project;
files placed inside a project can change its measured application root.
