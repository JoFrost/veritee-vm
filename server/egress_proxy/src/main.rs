use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use hickory_resolver::config::{
    LookupIpStrategy, ResolveHosts, ResolverConfig, ResolverOpts, ServerGroup,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use ipnet::IpNet;
use rustls::server::Acceptor;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{sleep_until, timeout, Instant};

const OUTBOUND_POLICY_VERSION: u8 = 2;
const APP_PROXY_PORT: u16 = 18_080;
const PLATFORM_PROXY_PORT: u16 = 18_081;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_POLICY_ENTRIES: usize = 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Scope {
    App,
    Platform,
}

impl Scope {
    fn default_host(self) -> &'static str {
        match self {
            Self::App => "0.0.0.0",
            Self::Platform => "127.0.0.1",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::App => APP_PROXY_PORT,
            Self::Platform => PLATFORM_PROXY_PORT,
        }
    }

    fn policy_entries(self, policy: &RawPolicy) -> &[RawEntry] {
        match self {
            Self::App => &policy.outbound,
            Self::Platform => &policy.platform_outbound,
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App => formatter.write_str("app"),
            Self::Platform => formatter.write_str("platform"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "temenos-egress-proxy")]
struct Args {
    #[arg(long)]
    policy_file: PathBuf,
    #[arg(long, value_enum)]
    scope: Scope,
    #[arg(long)]
    listen_host: Option<IpAddr>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long = "allow-client-cidr", required = true)]
    allowed_client_cidrs: Vec<IpNet>,
    #[arg(long)]
    dns_server: IpAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u8,
    profile: Option<String>,
    outbound: Vec<RawEntry>,
    platform_outbound: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<IpAddr>,
    port: u16,
}

#[derive(Debug)]
struct ProxyPolicy {
    scope: Scope,
    warden_profile: bool,
    unrestricted_profile: bool,
    hosts: HashSet<(String, u16)>,
    ips: HashSet<(IpAddr, u16)>,
}

impl ProxyPolicy {
    fn from_json(input: &str, scope: Scope) -> Result<Self> {
        let raw: RawPolicy = serde_json::from_str(input).context("invalid egress policy JSON")?;
        if raw.version != OUTBOUND_POLICY_VERSION {
            bail!(
                "egress policy version must be {OUTBOUND_POLICY_VERSION}, got {}",
                raw.version
            );
        }
        if raw
            .profile
            .as_deref()
            .is_some_and(|value| !matches!(value, "unrestricted" | "warden"))
        {
            bail!("unsupported egress profile");
        }
        if raw.profile.is_some() && !raw.outbound.is_empty() {
            bail!("egress profile and outbound entries are mutually exclusive");
        }

        let mut hosts = HashSet::new();
        let mut ips = HashSet::new();
        let entries = scope.policy_entries(&raw);
        if entries.len() > MAX_POLICY_ENTRIES {
            bail!("egress policy contains too many entries");
        }
        for (index, entry) in entries.iter().enumerate() {
            if entry.port == 0 || entry.host.is_some() == entry.ip.is_some() {
                bail!(
                    "policy entry {index} must contain a non-zero port and exactly one of host or ip"
                );
            }
            if let Some(host) = &entry.host {
                if !hosts.insert((normalize_hostname(host)?, entry.port)) {
                    bail!("policy entry {index} is duplicated");
                }
            } else if let Some(ip) = entry.ip {
                if !is_public_destination_ip(ip) {
                    bail!("policy entry {index} contains a non-public IP address");
                }
                if !ips.insert((ip, entry.port)) {
                    bail!("policy entry {index} is duplicated");
                }
            }
        }

        Ok(Self {
            scope,
            warden_profile: raw.profile.as_deref() == Some("warden") && scope == Scope::App,
            unrestricted_profile: raw.profile.as_deref() == Some("unrestricted")
                && scope == Scope::App,
            hosts,
            ips,
        })
    }

    fn load(path: &PathBuf, scope: Scope) -> Result<Self> {
        let size = fs::metadata(path)
            .with_context(|| format!("could not inspect {}", path.display()))?
            .len();
        if size > MAX_POLICY_BYTES {
            bail!("egress policy exceeds {MAX_POLICY_BYTES} bytes");
        }
        let input = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        Self::from_json(&input, scope)
    }

    fn allows(&self, target: &Target) -> bool {
        if let TargetHost::Ip(ip) = &target.host {
            if !is_public_destination_ip(*ip) {
                return false;
            }
        }
        if self.warden_profile && target.port == 443 {
            return true;
        }
        if self.unrestricted_profile {
            return true;
        }
        match &target.host {
            TargetHost::Name(host) => self.hosts.contains(&(host.clone(), target.port)),
            TargetHost::Ip(ip) => self.ips.contains(&(*ip, target.port)),
        }
    }

    fn allows_client(&self, configured_networks: &[IpNet], client: IpAddr) -> bool {
        client_is_allowed(configured_networks, client)
            || (self.warden_profile && is_private_ipv4(client))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TargetHost {
    Name(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Target {
    host: TargetHost,
    port: u16,
}

impl Target {
    fn display(&self) -> String {
        match &self.host {
            TargetHost::Name(host) => format!("{host}:{}", self.port),
            TargetHost::Ip(IpAddr::V4(ip)) => format!("{ip}:{}", self.port),
            TargetHost::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
        }
    }
}

fn normalize_hostname(input: &str) -> Result<String> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.contains("://")
        || host.contains(['/', ':', '*', '@'])
        || host.parse::<IpAddr>().is_ok()
    {
        bail!("invalid hostname: {input:?}");
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid hostname: {input:?}");
        }
    }
    Ok(host)
}

fn parse_authority(authority: &str) -> Result<Target> {
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        bail!("CONNECT target must be host:port");
    }

    let (host, port_text) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 CONNECT target"))?;
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("CONNECT target must include a port"))?;
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("CONNECT target must be host:port"))?;
        if host.contains(':') {
            bail!("IPv6 CONNECT targets must use brackets");
        }
        (host, port)
    };

    let port: u16 = port_text.parse().context("invalid CONNECT port")?;
    if port == 0 {
        bail!("CONNECT port must be non-zero");
    }
    let host = match host.parse::<IpAddr>() {
        Ok(ip) => TargetHost::Ip(ip),
        Err(_) => TargetHost::Name(normalize_hostname(host)?),
    };
    Ok(Target { host, port })
}

fn parse_connect_request(input: &[u8]) -> Result<Target> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request.parse(input).context("invalid HTTP proxy request")?;
    if !parsed.is_complete() || request.method != Some("CONNECT") || request.version != Some(1) {
        bail!("only complete HTTP/1.1 CONNECT requests are supported");
    }

    let authority = request.path.context("CONNECT target is missing")?;
    let target = parse_authority(authority)?;
    let mut host_headers = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    if let Some(header) = host_headers.next() {
        if host_headers.next().is_some() {
            bail!("multiple Host headers are not allowed");
        }
        let value = std::str::from_utf8(header.value)
            .context("Host header must be ASCII")?
            .trim();
        if parse_authority(value)? != target {
            bail!("Host header does not match CONNECT target");
        }
    } else {
        bail!("HTTP/1.1 CONNECT requires a Host header");
    }
    Ok(target)
}

async fn read_connect_headers(client: &mut TcpStream) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(1024);
    loop {
        if let Some(position) = input.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            if end != input.len() {
                bail!("unexpected bytes before CONNECT was accepted");
            }
            return Ok(input);
        }
        if input.len() >= MAX_HEADER_BYTES {
            bail!("CONNECT headers are too large");
        }

        let remaining = MAX_HEADER_BYTES - input.len();
        let mut buffer = [0u8; 4096];
        let read_capacity = remaining.min(buffer.len());
        let read = client.read(&mut buffer[..read_capacity]).await?;
        if read == 0 {
            bail!("client closed before sending CONNECT headers");
        }
        input.extend_from_slice(&buffer[..read]);
    }
}

async fn read_client_hello(client: &mut TcpStream) -> Result<(Vec<u8>, String)> {
    let mut acceptor = Acceptor::default();
    let mut raw = Vec::with_capacity(4096);
    loop {
        if raw.len() >= MAX_CLIENT_HELLO_BYTES {
            bail!("TLS ClientHello is too large");
        }
        let mut buffer = [0u8; 4096];
        let available = (MAX_CLIENT_HELLO_BYTES - raw.len()).min(buffer.len());
        let read = client.read(&mut buffer[..available]).await?;
        if read == 0 {
            bail!("client closed during TLS ClientHello");
        }
        raw.extend_from_slice(&buffer[..read]);

        let mut cursor = Cursor::new(&buffer[..read]);
        while (cursor.position() as usize) < read {
            if acceptor.read_tls(&mut cursor)? == 0 {
                break;
            }
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let client_hello = accepted.client_hello();
                let server_name = client_hello
                    .server_name()
                    .context("TLS ClientHello does not contain SNI")?;
                return Ok((raw, normalize_hostname(server_name)?));
            }
            Ok(None) => continue,
            Err((error, _alert)) => return Err(anyhow!("invalid TLS ClientHello: {error}")),
        }
    }
}

fn is_public_destination_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn client_is_allowed(networks: &[IpNet], client: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(&client))
}

fn is_private_ipv4(client: IpAddr) -> bool {
    let IpAddr::V4(client) = client else {
        return false;
    };
    let [first, second, ..] = client.octets();
    first == 10 || (first == 172 && (16..=31).contains(&second)) || (first == 192 && second == 168)
}

fn require_matching_sni(expected_name: &str, server_name: &str) -> Result<()> {
    if server_name != expected_name {
        bail!("TLS SNI {server_name:?} does not match CONNECT host {expected_name:?}");
    }
    Ok(())
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = ip.segments();
    // Current globally routed unicast space is 2000::/3. Exclude documentation
    // and the special-purpose 2001::/23 block rather than letting DNS provide a
    // route back into the guest or Azure fabric.
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && segments[0] != 0x2002
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}

async fn resolve_target(target: &Target, resolver: &TokioResolver) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<SocketAddr> = match &target.host {
        TargetHost::Ip(ip) if is_public_destination_ip(*ip) => {
            vec![SocketAddr::new(*ip, target.port)]
        }
        TargetHost::Ip(_) => bail!("destination IP is not public"),
        TargetHost::Name(host) => {
            let lookup = timeout(DNS_TIMEOUT, resolver.lookup_ip(format!("{host}.")))
                .await
                .context("DNS resolution timed out")?
                .with_context(|| format!("{} did not resolve", target.display()))?;
            lookup
                .iter()
                .filter(|ip| is_public_destination_ip(*ip))
                .map(|ip| SocketAddr::new(ip, target.port))
                .take(MAX_RESOLVED_ADDRESSES)
                .collect()
        }
    };
    if addresses.is_empty() {
        bail!("destination resolved only to non-public addresses");
    }
    Ok(addresses)
}

async fn connect_upstream(target: &Target, resolver: &TokioResolver) -> Result<TcpStream> {
    let addresses = resolve_target(target, resolver).await?;
    timeout(CONNECT_TIMEOUT, async {
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        bail!(
            "could not connect to {}: {}",
            target.display(),
            last_error.unwrap_or_else(|| "no destination addresses".to_string())
        )
    })
    .await
    .context("upstream connection timed out")?
}

async fn send_response(client: &mut TcpStream, status: u16, reason: &str) {
    let response = if status == 200 {
        format!("HTTP/1.1 {status} {reason}\r\n\r\n")
    } else {
        format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    };
    let _ = client.write_all(response.as_bytes()).await;
}

struct ActivityStream<T> {
    inner: T,
    activity: mpsc::Sender<()>,
}

impl<T> ActivityStream<T> {
    fn new(inner: T, activity: mpsc::Sender<()>) -> Self {
        Self { inner, activity }
    }

    fn record_activity(&self) {
        let _ = self.activity.try_send(());
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() > filled_before {
            this.record_activity();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(context, buffer);
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            this.record_activity();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
    client: &mut A,
    upstream: &mut B,
    idle_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let mut client = ActivityStream::new(client, activity_tx.clone());
    let mut upstream = ActivityStream::new(upstream, activity_tx);
    let transfer = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    tokio::pin!(transfer);

    let idle_deadline = sleep_until(Instant::now() + idle_timeout);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            result = &mut transfer => return result,
            activity = activity_rx.recv() => {
                if activity.is_none() {
                    return transfer.await;
                }
                while activity_rx.try_recv().is_ok() {}
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            _ = &mut idle_deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "egress tunnel was idle for too long",
                ));
            }
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    policy: Arc<ProxyPolicy>,
    resolver: Arc<TokioResolver>,
) -> Result<()> {
    let headers = timeout(HEADER_TIMEOUT, read_connect_headers(&mut client))
        .await
        .context("CONNECT header timeout")??;
    let target = parse_connect_request(&headers)?;
    if !policy.allows(&target) {
        send_response(&mut client, 403, "Forbidden").await;
        eprintln!(
            "WARN denied scope={} destination={}",
            policy.scope,
            target.display()
        );
        return Ok(());
    }

    match &target.host {
        TargetHost::Name(expected_name) => {
            // The client must receive CONNECT success before it sends its TLS
            // ClientHello. Validate SNI before opening any upstream connection.
            send_response(&mut client, 200, "Connection Established").await;
            let (client_hello, server_name) =
                timeout(CLIENT_HELLO_TIMEOUT, read_client_hello(&mut client))
                    .await
                    .context("TLS ClientHello timeout")??;
            require_matching_sni(expected_name, &server_name)?;
            let mut upstream = connect_upstream(&target, &resolver).await?;
            upstream.write_all(&client_hello).await?;
            eprintln!(
                "INFO allowed scope={} destination={}",
                policy.scope,
                target.display()
            );
            copy_bidirectional_with_idle_timeout(&mut client, &mut upstream, TUNNEL_IDLE_TIMEOUT)
                .await?;
        }
        TargetHost::Ip(_) => {
            let mut upstream = match connect_upstream(&target, &resolver).await {
                Ok(stream) => stream,
                Err(error) => {
                    send_response(&mut client, 502, "Bad Gateway").await;
                    return Err(error);
                }
            };
            send_response(&mut client, 200, "Connection Established").await;
            eprintln!(
                "INFO allowed scope={} destination={}",
                policy.scope,
                target.display()
            );
            copy_bidirectional_with_idle_timeout(&mut client, &mut upstream, TUNNEL_IDLE_TIMEOUT)
                .await?;
        }
    }
    Ok(())
}

fn build_resolver(dns_server: IpAddr) -> Result<TokioResolver> {
    let dns_servers = [dns_server];
    let group = ServerGroup {
        ips: &dns_servers,
        server_name: "",
        path: "",
    };
    let config = ResolverConfig::udp_and_tcp(&group);
    let mut options = ResolverOpts::default();
    options.timeout = DNS_TIMEOUT;
    options.attempts = 1;
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.use_hosts_file = ResolveHosts::Never;
    options.try_tcp_on_error = true;

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .context("could not initialize DNS resolver")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let policy = Arc::new(ProxyPolicy::load(&args.policy_file, args.scope)?);
    let resolver = Arc::new(build_resolver(args.dns_server)?);
    let listen_host = args
        .listen_host
        .unwrap_or_else(|| args.scope.default_host().parse().expect("valid default IP"));
    if args.scope == Scope::Platform && !listen_host.is_loopback() {
        bail!("the platform scope must listen on a loopback address");
    }
    let listen_port = args
        .listen_port
        .unwrap_or_else(|| args.scope.default_port());
    let listener = TcpListener::bind(SocketAddr::new(listen_host, listen_port))
        .await
        .with_context(|| format!("could not bind {listen_host}:{listen_port}"))?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    eprintln!(
        "INFO listening scope={} address={}:{} hosts={} ips={}",
        args.scope,
        listen_host,
        listen_port,
        policy.hosts.len(),
        policy.ips.len()
    );

    loop {
        let (mut client, peer) = listener.accept().await?;
        if !policy.allows_client(&args.allowed_client_cidrs, peer.ip()) {
            eprintln!(
                "WARN denied scope={} peer={} reason=client_address",
                args.scope, peer
            );
            continue;
        }
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                send_response(&mut client, 503, "Service Unavailable").await;
                eprintln!(
                    "WARN denied scope={} peer={} reason=connection_limit",
                    args.scope, peer
                );
                continue;
            }
        };
        let policy = policy.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(client, policy.clone(), resolver).await {
                eprintln!(
                    "WARN rejected scope={} peer={} reason={error:#}",
                    policy.scope, peer
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};

    fn policy_json() -> &'static str {
        r#"{
          "version": 2,
          "profile": null,
          "outbound": [
            {"host": "downloads.example.com", "port": 443},
            {"ip": "1.1.1.1", "port": 5432}
          ],
          "platform_outbound": [
            {"host": "midnightl2.eus.attest.azure.net", "port": 443}
          ]
        }"#
    }

    #[test]
    fn policy_scopes_are_separate() {
        let app = ProxyPolicy::from_json(policy_json(), Scope::App).unwrap();
        let platform = ProxyPolicy::from_json(policy_json(), Scope::Platform).unwrap();
        let app_target = parse_authority("downloads.example.com:443").unwrap();
        let platform_target = parse_authority("midnightl2.eus.attest.azure.net:443").unwrap();

        assert!(app.allows(&app_target));
        assert!(!app.allows(&platform_target));
        assert!(platform.allows(&platform_target));
        assert!(!platform.allows(&app_target));
    }

    #[test]
    fn connect_parser_rejects_ambiguous_requests() {
        assert_eq!(
            parse_connect_request(
                b"CONNECT Downloads.Example.com.:443 HTTP/1.1\r\nHost: downloads.example.com:443\r\n\r\n"
            )
            .unwrap(),
            Target {
                host: TargetHost::Name("downloads.example.com".to_string()),
                port: 443,
            }
        );
        for request in [
            b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: attacker.example:443\r\n\r\n".as_slice(),
            b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n".as_slice(),
            b"CONNECT 2606:4700:4700::1111:443 HTTP/1.1\r\nHost: 2606:4700:4700::1111:443\r\n\r\n"
                .as_slice(),
            b"CONNECT user@example.com:443 HTTP/1.1\r\nHost: user@example.com:443\r\n\r\n"
                .as_slice(),
        ] {
            assert!(parse_connect_request(request).is_err());
        }
    }

    #[test]
    fn hostname_dns_results_cannot_reach_private_or_platform_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert!(!is_public_destination_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_destination_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn client_networks_are_enforced() {
        let networks: Vec<IpNet> = ["172.30.255.0/24", "127.0.0.0/8"]
            .into_iter()
            .map(|network| network.parse().unwrap())
            .collect();

        assert!(client_is_allowed(
            &networks,
            "172.30.255.42".parse().unwrap()
        ));
        assert!(client_is_allowed(&networks, "127.0.0.1".parse().unwrap()));
        assert!(!client_is_allowed(
            &networks,
            "172.30.254.42".parse().unwrap()
        ));
        assert!(!client_is_allowed(
            &networks,
            "203.0.113.1".parse().unwrap()
        ));
    }

    #[test]
    fn warden_policy_accepts_dynamic_private_docker_networks_only() {
        let configured: Vec<IpNet> = ["172.30.255.0/24", "127.0.0.0/8"]
            .into_iter()
            .map(|network| network.parse().unwrap())
            .collect();
        let ordinary = ProxyPolicy::from_json(policy_json(), Scope::App).unwrap();
        let warden = ProxyPolicy::from_json(
            r#"{
              "version": 2,
              "profile": "warden",
              "outbound": [],
              "platform_outbound": []
            }"#,
            Scope::App,
        )
        .unwrap();

        for client in ["10.42.0.2", "172.17.0.2", "172.29.254.2", "192.168.42.2"] {
            let client = client.parse().unwrap();
            assert!(!ordinary.allows_client(&configured, client));
            assert!(warden.allows_client(&configured, client));
        }
        assert!(warden.allows_client(&configured, "127.0.0.1".parse().unwrap()));
        assert!(!warden.allows_client(&configured, "203.0.113.1".parse().unwrap()));
        assert!(!warden.allows_client(&configured, "fd00::1".parse().unwrap()));
    }

    #[test]
    fn policy_rejects_non_public_literal_addresses() {
        let policy = r#"{
          "version": 2,
          "profile": null,
          "outbound": [{"ip": "169.254.169.254", "port": 80}],
          "platform_outbound": []
        }"#;

        assert!(ProxyPolicy::from_json(policy, Scope::App).is_err());
    }

    #[test]
    fn policy_rejects_duplicates_and_profile_overrides() {
        let duplicate = r#"{
          "version": 2,
          "profile": null,
          "outbound": [
            {"host": "downloads.example.com", "port": 443},
            {"host": "DOWNLOADS.EXAMPLE.COM.", "port": 443}
          ],
          "platform_outbound": []
        }"#;
        let profile_with_override = r#"{
          "version": 2,
          "profile": "warden",
          "outbound": [{"host": "downloads.example.com", "port": 443}],
          "platform_outbound": []
        }"#;

        assert!(ProxyPolicy::from_json(duplicate, Scope::App).is_err());
        assert!(ProxyPolicy::from_json(profile_with_override, Scope::App).is_err());
    }

    #[test]
    fn warden_profile_does_not_override_address_filtering() {
        let policy = r#"{
          "version": 2,
          "profile": "warden",
          "outbound": [],
          "platform_outbound": []
        }"#;
        let policy = ProxyPolicy::from_json(policy, Scope::App).unwrap();

        assert!(!policy.allows(&parse_authority("127.0.0.1:443").unwrap()));
        assert!(!policy.allows(&parse_authority("169.254.169.254:443").unwrap()));
        assert!(!policy.allows(&parse_authority("1.1.1.1:80").unwrap()));
        assert!(policy.allows(&parse_authority("1.1.1.1:443").unwrap()));
        assert!(!policy.allows(&parse_authority("1.1.1.1:8000").unwrap()));
    }

    #[test]
    fn unrestricted_profile_allows_public_targets_on_any_tcp_port() {
        let policy = r#"{
          "version": 2,
          "profile": "unrestricted",
          "outbound": [],
          "platform_outbound": []
        }"#;
        let policy = ProxyPolicy::from_json(policy, Scope::App).unwrap();

        assert!(policy.allows(&parse_authority("downloads.example.com:8443").unwrap()));
        assert!(policy.allows(&parse_authority("1.1.1.1:5432").unwrap()));
        assert!(!policy.allows(&parse_authority("127.0.0.1:443").unwrap()));
        assert!(!policy.allows(&parse_authority("169.254.169.254:80").unwrap()));
    }

    #[test]
    fn sni_must_match_the_connect_hostname() {
        assert!(require_matching_sni("downloads.example.com", "downloads.example.com").is_ok());
        assert!(require_matching_sni("downloads.example.com", "attacker.example").is_err());
    }

    fn tls_client_hello(host: &str) -> Vec<u8> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut connection = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut output = Vec::new();
        connection.write_tls(&mut output).unwrap();
        output
    }

    #[tokio::test]
    async fn extracts_sni_from_a_real_tls_client_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = tls_client_hello("downloads.example.com");
        let client_bytes = expected.clone();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&client_bytes).await.unwrap();
        });
        let (mut server, _) = listener.accept().await.unwrap();

        let (observed, server_name) = read_client_hello(&mut server).await.unwrap();

        client.await.unwrap();
        assert_eq!(observed, expected);
        assert_eq!(server_name, "downloads.example.com");
    }

    #[tokio::test]
    async fn rejects_a_tls_client_hello_without_dns_sni() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_bytes = tls_client_hello("127.0.0.1");
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&client_bytes).await.unwrap();
        });
        let (mut server, _) = listener.accept().await.unwrap();

        assert!(read_client_hello(&mut server).await.is_err());
        client.await.unwrap();
    }

    #[tokio::test]
    async fn idle_tunnels_time_out() {
        let (mut proxy_client, _client_peer) = tokio::io::duplex(64);
        let (mut proxy_upstream, _upstream_peer) = tokio::io::duplex(64);

        let error = copy_bidirectional_with_idle_timeout(
            &mut proxy_client,
            &mut proxy_upstream,
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn tunnel_activity_resets_the_idle_deadline() {
        let (mut proxy_client, mut client_peer) = tokio::io::duplex(64);
        let (mut proxy_upstream, mut upstream_peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                &mut proxy_client,
                &mut proxy_upstream,
                Duration::from_millis(200),
            )
            .await
        });

        for byte in b"abc" {
            client_peer.write_all(&[*byte]).await.unwrap();
            let mut observed = [0u8; 1];
            upstream_peer.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed[0], *byte);
            tokio::time::sleep(Duration::from_millis(75)).await;
        }

        drop(client_peer);
        drop(upstream_peer);
        let transferred = relay.await.unwrap().unwrap();
        assert_eq!(transferred.0, 3);
    }
}
