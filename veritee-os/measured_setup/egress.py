from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


OUTBOUND_POLICY_VERSION = 2
EGRESS_PROFILES = frozenset(("unrestricted", "warden"))
HOST_CHAIN = "TEMENOS-APP-OUTBOUND"
CONTAINER_CHAIN = "TEMENOS-CONTAINER-EGRESS"
POLICY_STATE_PATH = Path("/run/temenos/egress-policy.json")
AZURE_DNS_IP = "168.63.129.16"
AZURE_IMDS_IP = "169.254.169.254"
APP_PROXY_USER = "temenos-egress-app"
PLATFORM_PROXY_USER = "temenos-egress-platform"
WARDEN_PLATFORM_NETWORK = "warden-platform"
WARDEN_PLATFORM_SUBNET = "172.30.254.0/28"
WARDEN_PLATFORM_APP_IP = "172.30.254.2"
BUILDER_NETWORK = "temenos-builder"
BUILDER_NETWORK_SUBNET = "172.29.254.0/28"
BUILDER_NETWORK_GATEWAY = "172.29.254.1"
BLOCKED_CAPABILITIES = frozenset(
    ("ALL", "BPF", "NET_ADMIN", "SYS_ADMIN", "SYS_MODULE")
)
CONTAINER_CONTROL_SOCKETS = frozenset(
    (
        "/run/containerd/containerd.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/containerd/containerd.sock",
        "/var/run/docker.sock",
    )
)
NON_PUBLIC_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
NON_PUBLIC_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    )
)


class EgressPolicyError(ValueError):
    pass


Runner = Callable[[list[str], bool], int]
NetworkInspector = Callable[[str], dict[str, Any] | None]


def _compose_network_names(value: Any, field: str) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    if isinstance(value, dict) and all(isinstance(item, str) for item in value):
        return set(value)
    raise EgressPolicyError(f"{field} must be a list or object of network names")


def _compose_mount_paths(value: Any, field: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list):
        raise EgressPolicyError(f"{field} must be an array")

    paths = set()
    for index, mount in enumerate(value):
        if isinstance(mount, str):
            paths.update(part for part in mount.split(":", 2)[:2] if part.startswith("/"))
        elif isinstance(mount, dict):
            for key in ("source", "target"):
                path = mount.get(key)
                if isinstance(path, str) and path.startswith("/"):
                    paths.add(path)
        else:
            raise EgressPolicyError(f"{field}[{index}] must be a string or object")
    return paths


def _compose_control_socket_mounts(
    value: Any,
    field: str,
) -> list[tuple[str | None, str | None]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise EgressPolicyError(f"{field} must be an array")

    mounts = []
    for index, mount in enumerate(value):
        source = None
        target = None
        if isinstance(mount, str):
            parts = mount.split(":", 2)
            source = parts[0] if parts else None
            target = parts[1] if len(parts) > 1 else None
        elif isinstance(mount, dict):
            source = mount.get("source")
            target = mount.get("target")
        else:
            raise EgressPolicyError(f"{field}[{index}] must be a string or object")

        paths = tuple(path for path in (source, target) if isinstance(path, str))
        if any(
            path in CONTAINER_CONTROL_SOCKETS
            or path.endswith("/docker.sock")
            or path.endswith("/containerd.sock")
            for path in paths
        ):
            mounts.append((source, target))
    return mounts


def _validate_warden_platform_network(
    networks: dict[str, Any],
    services: dict[str, Any],
    *,
    allow_warden_host_access: bool,
) -> None:
    network = networks.get(WARDEN_PLATFORM_NETWORK)
    if network is None:
        return
    if not allow_warden_host_access:
        raise EgressPolicyError(
            f"network {WARDEN_PLATFORM_NETWORK!r} requires the measured Warden profile"
        )

    app = services.get("app")
    if not isinstance(app, dict):
        raise EgressPolicyError("services.app must be an object")

    ipam = network.get("ipam")
    configs = ipam.get("config") if isinstance(ipam, dict) else None
    if not isinstance(configs, list) or not any(
        isinstance(config, dict)
        and config.get("subnet") == WARDEN_PLATFORM_SUBNET
        for config in configs
    ):
        raise EgressPolicyError(
            f"network {WARDEN_PLATFORM_NETWORK!r} must use subnet "
            f"{WARDEN_PLATFORM_SUBNET}"
        )

    app_networks = app.get("networks")
    app_network = (
        app_networks.get(WARDEN_PLATFORM_NETWORK)
        if isinstance(app_networks, dict)
        else None
    )
    if not isinstance(app_network, dict) or app_network.get("ipv4_address") != (
        WARDEN_PLATFORM_APP_IP
    ):
        raise EgressPolicyError(
            f"services.app must use {WARDEN_PLATFORM_APP_IP} on "
            f"{WARDEN_PLATFORM_NETWORK}"
        )

    for service_name, service in services.items():
        if service_name == "app":
            continue
        if not isinstance(service, dict):
            raise EgressPolicyError(f"services.{service_name} must be an object")
        if WARDEN_PLATFORM_NETWORK in _compose_network_names(
            service.get("networks"),
            f"services.{service_name}.networks",
        ):
            raise EgressPolicyError(
                f"only services.app may join {WARDEN_PLATFORM_NETWORK}"
            )


def validate_compose_config(
    compose: Any,
    *,
    allow_warden_host_access: bool = False,
) -> set[str]:
    if not isinstance(compose, dict):
        raise EgressPolicyError("Docker Compose configuration must be an object")
    services = compose.get("services")
    if not isinstance(services, dict) or "app" not in services:
        raise EgressPolicyError("Docker Compose configuration must define the app service")

    networks = compose.get("networks", {})
    if not isinstance(networks, dict):
        raise EgressPolicyError("Docker Compose networks must be an object")
    non_internal_networks = set()
    for network_name, network in networks.items():
        if network is None:
            network = {}
        if not isinstance(network_name, str) or not isinstance(network, dict):
            raise EgressPolicyError("invalid Docker Compose network definition")
        if network.get("driver", "bridge") != "bridge" or network.get("external") is True:
            raise EgressPolicyError(
                f"network {network_name!r} must be a non-external bridge network"
            )
        if network.get("internal") is not True:
            non_internal_networks.add(network_name)

    _validate_warden_platform_network(
        networks,
        services,
        allow_warden_host_access=allow_warden_host_access,
    )

    for service_name, service in services.items():
        field = f"services.{service_name}"
        if not isinstance(service_name, str) or not isinstance(service, dict):
            raise EgressPolicyError(f"{field} must be an object")
        if service.get("privileged") is True:
            raise EgressPolicyError(f"{field}.privileged cannot be enabled")
        if service.get("use_api_socket") is True:
            raise EgressPolicyError(f"{field}.use_api_socket cannot be enabled")
        if service.get("network_mode") not in (None, "none"):
            raise EgressPolicyError(
                f"{field}.network_mode must be omitted or set to 'none'"
            )
        for namespace_field in ("cgroup", "ipc", "pid", "userns_mode", "uts"):
            if service.get(namespace_field) == "host":
                raise EgressPolicyError(
                    f"{field}.{namespace_field} cannot share the host namespace"
                )

        capabilities = service.get("cap_add", [])
        if isinstance(capabilities, str):
            capabilities = [capabilities]
        if not isinstance(capabilities, list) or any(
            not isinstance(capability, str) for capability in capabilities
        ):
            raise EgressPolicyError(f"{field}.cap_add must be an array of names")
        blocked = {
            capability.upper().removeprefix("CAP_")
            for capability in capabilities
        } & BLOCKED_CAPABILITIES
        if blocked:
            raise EgressPolicyError(
                f"{field}.cap_add contains capability that can bypass isolation: "
                f"{', '.join(sorted(blocked))}"
            )

        control_socket_mounts = _compose_control_socket_mounts(
            service.get("volumes"),
            f"{field}.volumes",
        )
        docker_socket_is_allowed = (
            allow_warden_host_access
            and service_name == "app"
            and all(
                source == "/var/run/docker.sock"
                and target == "/var/run/docker.sock"
                for source, target in control_socket_mounts
            )
        )
        if control_socket_mounts and not docker_socket_is_allowed:
            raise EgressPolicyError(
                f"{field}.volumes cannot mount a container runtime socket"
            )
        if "/dev/net/tun" in _compose_mount_paths(
            service.get("devices"),
            f"{field}.devices",
        ):
            raise EgressPolicyError(f"{field}.devices cannot expose /dev/net/tun")

        service_networks = _compose_network_names(
            service.get("networks"),
            f"{field}.networks",
        )
        exposed_networks = service_networks & non_internal_networks
        if allow_warden_host_access and service_name == "app":
            exposed_networks -= {WARDEN_PLATFORM_NETWORK}
        if service_name != "caddy" and exposed_networks:
            exposed = ", ".join(sorted(exposed_networks))
            raise EgressPolicyError(
                f"{field} cannot join non-internal network(s): {exposed}"
            )

    app_networks = _compose_network_names(
        services["app"].get("networks"),
        "services.app.networks",
    )
    if "constrained-app" not in app_networks:
        raise EgressPolicyError("services.app must join constrained-app")

    return set(services)


def validate_compose_file(
    compose_path: Path,
    *,
    allow_warden_host_access: bool = False,
) -> set[str]:
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(compose_path.parent),
        "-f",
        str(compose_path),
        "config",
        "--format",
        "json",
        "--no-env-resolution",
        "--no-interpolate",
        "--no-path-resolution",
    ]
    try:
        rendered = subprocess.check_output(command, text=True, stderr=subprocess.PIPE)
        compose = json.loads(rendered)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise EgressPolicyError(
            f"could not parse Docker Compose configuration {compose_path}: {detail}"
        ) from exc
    return validate_compose_config(
        compose,
        allow_warden_host_access=allow_warden_host_access,
    )


def is_public_destination_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        return not any(address in network for network in NON_PUBLIC_IPV4_NETWORKS)
    if address.ipv4_mapped is not None:
        return is_public_destination_ip(address.ipv4_mapped)
    return address in ipaddress.ip_network("2000::/3") and not any(
        address in network for network in NON_PUBLIC_IPV6_NETWORKS
    )


def command_runner(command: list[str], check: bool = True) -> int:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.returncode


def inspect_docker_network(name: str) -> dict[str, Any] | None:
    result = subprocess.run(
        ["docker", "network", "inspect", name],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        if "not found" in detail.lower() or "no such network" in detail.lower():
            return None
        raise EgressPolicyError(
            f"could not inspect Docker network {name!r}: {detail}"
        )
    try:
        networks = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EgressPolicyError(
            f"Docker returned invalid JSON while inspecting network {name!r}"
        ) from exc
    if (
        not isinstance(networks, list)
        or len(networks) != 1
        or not isinstance(networks[0], dict)
    ):
        raise EgressPolicyError(
            f"Docker returned an invalid inspection result for network {name!r}"
        )
    return networks[0]


def ensure_builder_network(
    runner: Runner = command_runner,
    inspector: NetworkInspector = inspect_docker_network,
) -> None:
    network = inspector(BUILDER_NETWORK)
    if network is None:
        runner(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                BUILDER_NETWORK_SUBNET,
                "--gateway",
                BUILDER_NETWORK_GATEWAY,
                "--label",
                "io.temenos.role=builder",
                BUILDER_NETWORK,
            ],
            True,
        )
        network = inspector(BUILDER_NETWORK)

    if network is None:
        raise EgressPolicyError(
            f"Docker network {BUILDER_NETWORK!r} was not created"
        )
    ipam = network.get("IPAM")
    configs = ipam.get("Config") if isinstance(ipam, dict) else None
    if (
        network.get("Driver") != "bridge"
        or network.get("Internal") is True
        or not isinstance(configs, list)
        or not any(
            isinstance(config, dict)
            and config.get("Subnet") == BUILDER_NETWORK_SUBNET
            and config.get("Gateway") == BUILDER_NETWORK_GATEWAY
            for config in configs
        )
    ):
        raise EgressPolicyError(
            f"Docker network {BUILDER_NETWORK!r} must be a non-internal bridge "
            f"using {BUILDER_NETWORK_SUBNET} with gateway {BUILDER_NETWORK_GATEWAY}"
        )


def normalize_hostname(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EgressPolicyError(f"{field} must be a non-empty hostname")

    host = value.strip().lower().rstrip(".")
    if len(host) > 253 or "://" in host or "/" in host or "*" in host or ":" in host:
        raise EgressPolicyError(
            f"{field} must be a bare hostname without a scheme, path, port, or wildcard"
        )
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise EgressPolicyError(f"{field} is not a valid hostname")
    return host


def _normalize_entries(value: Any, field: str, *, app_scope: bool) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise EgressPolicyError(f"{field} must be an array")

    normalized = []
    seen = set()
    for index, entry in enumerate(value):
        entry_field = f"{field}[{index}]"
        if not isinstance(entry, dict):
            raise EgressPolicyError(f"{entry_field} must be an object")
        unexpected = set(entry) - {"host", "ip", "ports"}
        if unexpected:
            raise EgressPolicyError(
                f"{entry_field} contains unsupported field(s): {', '.join(sorted(unexpected))}"
            )
        if ("host" in entry) == ("ip" in entry) or "ports" not in entry:
            raise EgressPolicyError(
                f"{entry_field} must contain ports and exactly one of host or ip"
            )

        if "host" in entry:
            value_kind = "host"
            normalized_value = normalize_hostname(entry["host"], f"{entry_field}.host")
        else:
            value_kind = "ip"
            try:
                normalized_value = str(ipaddress.ip_address(entry["ip"]))
            except (TypeError, ValueError) as exc:
                raise EgressPolicyError(
                    f"{entry_field}.ip must be a literal IPv4 or IPv6 address"
                ) from exc

        ports = entry["ports"]
        if not isinstance(ports, list) or not ports:
            raise EgressPolicyError(f"{entry_field}.ports must be a non-empty array")
        if any(isinstance(port, bool) or not isinstance(port, int) for port in ports):
            raise EgressPolicyError(f"{entry_field}.ports must contain only integers")
        if any(port < 1 or port > 65535 for port in ports):
            raise EgressPolicyError(f"{entry_field}.ports must be in the range 1-65535")
        if len(set(ports)) != len(ports):
            raise EgressPolicyError(f"{entry_field}.ports must not contain duplicates")
        if app_scope and 53 in ports:
            raise EgressPolicyError(f"{entry_field} cannot grant DApp DNS egress")
        if value_kind == "ip":
            parsed_address = ipaddress.ip_address(normalized_value)
            if not is_public_destination_ip(parsed_address):
                raise EgressPolicyError(
                    f"{entry_field} must contain a globally routed destination IP, "
                    f"got {normalized_value}"
                )

        for port in sorted(ports):
            key = (value_kind, normalized_value, port)
            if key in seen:
                continue
            seen.add(key)
            normalized.append({value_kind: normalized_value, "port": port})

    return sorted(
        normalized,
        key=lambda item: (
            0 if "ip" in item else 1,
            (
                ipaddress.ip_address(item["ip"]).version,
                int(ipaddress.ip_address(item["ip"])),
            )
            if "ip" in item
            else (0, item["host"]),
            item["port"],
        ),
    )


def policy_from_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise EgressPolicyError("metadata must be a JSON object")
    if metadata.get("outbound_policy_version") != OUTBOUND_POLICY_VERSION:
        raise EgressPolicyError(
            f"outbound_policy_version must be {OUTBOUND_POLICY_VERSION}"
        )

    profile = metadata.get("egress_profile")
    if profile is not None and profile not in EGRESS_PROFILES:
        raise EgressPolicyError(
            "egress_profile must be 'unrestricted' or 'warden' when present"
        )
    if profile is not None and "outbound" in metadata:
        raise EgressPolicyError("egress_profile and outbound are mutually exclusive")

    return {
        "version": OUTBOUND_POLICY_VERSION,
        "profile": profile,
        "outbound": _normalize_entries(
            metadata.get("outbound", []),
            "outbound",
            app_scope=True,
        ),
        "platform_outbound": _normalize_entries(
            metadata.get("platform_outbound", []),
            "platform_outbound",
            app_scope=False,
        ),
    }


def _iptables_tool(version: int) -> str:
    return "iptables" if version == 4 else "ip6tables"


def _exists(runner: Runner, command: list[str]) -> bool:
    return runner(command, False) == 0


def _ensure_chain(tool: str, chain: str, runner: Runner) -> None:
    if not _exists(runner, [tool, "-w", "5", "-nL", chain]):
        runner([tool, "-w", "5", "-N", chain], True)


def _place_jump_first(tool: str, source: str, target: str, runner: Runner) -> None:
    check = [tool, "-w", "5", "-C", source, "-j", target]
    if _exists(runner, check):
        runner([tool, "-w", "5", "-D", source, "-j", target], True)
    runner([tool, "-w", "5", "-I", source, "1", "-j", target], True)


def _append_proxy_owner_accept(
    tool: str,
    chain: str,
    uid: int,
    port: int | None,
    runner: Runner,
) -> None:
    rule = ["-p", "tcp"]
    if port is not None:
        rule.extend(("--dport", str(port)))
    rule.extend(
        (
            "-m",
            "owner",
            "--uid-owner",
            str(uid),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        )
    )
    _ensure_rule(
        tool,
        chain,
        rule,
        runner,
        insert=True,
    )


def _append_proxy_dns_accept(
    tool: str,
    chain: str,
    uid: int,
    protocol: str,
    runner: Runner,
) -> None:
    _ensure_rule(
        tool,
        chain,
        [
            "-p",
            protocol,
            "-d",
            AZURE_DNS_IP,
            "--dport",
            "53",
            "-m",
            "owner",
            "--uid-owner",
            str(uid),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        runner,
        insert=True,
    )


def _append_warden_imds_accept(tool: str, chain: str, runner: Runner) -> None:
    _ensure_rule(
        tool,
        chain,
        [
            "-s",
            f"{WARDEN_PLATFORM_APP_IP}/32",
            "-d",
            f"{AZURE_IMDS_IP}/32",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        runner,
        insert=True,
    )


def _append_container_direct_accept(
    tool: str,
    chain: str,
    source: str,
    protocol: str,
    port: int,
    runner: Runner,
    *,
    destination: str | None = None,
) -> None:
    rule = [
        "-s",
        source,
    ]
    if destination is not None:
        rule.extend(("-d", f"{destination}/32"))
    rule.extend(
        (
            "-p",
            protocol,
            "--dport",
            str(port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        )
    )
    _ensure_rule(tool, chain, rule, runner, insert=True)


def _ensure_rule(
    tool: str,
    chain: str,
    rule: list[str],
    runner: Runner,
    *,
    insert: bool = False,
) -> None:
    if _exists(runner, [tool, "-w", "5", "-C", chain, *rule]):
        return
    action = "-I" if insert else "-A"
    runner([tool, "-w", "5", action, chain, *rule], True)


def _apply_family(
    policy: dict[str, Any],
    version: int,
    runner: Runner,
    proxy_uids: tuple[int, int],
) -> None:
    tool = _iptables_tool(version)
    app_proxy_ports = {entry["port"] for entry in policy["outbound"]}
    platform_proxy_ports = {
        entry["port"] for entry in policy["platform_outbound"]
    }
    if policy["profile"] == "warden":
        app_proxy_ports.add(443)

    _ensure_chain(tool, HOST_CHAIN, runner)
    for interface in ("br+", "docker+"):
        _ensure_rule(
            tool,
            HOST_CHAIN,
            ["-o", interface, "-j", "ACCEPT"],
            runner,
            insert=True,
        )
    if version == 4:
        for uid in proxy_uids:
            for protocol in ("udp", "tcp"):
                _append_proxy_dns_accept(tool, HOST_CHAIN, uid, protocol, runner)
    if policy["profile"] == "unrestricted":
        _append_proxy_owner_accept(tool, HOST_CHAIN, proxy_uids[0], None, runner)
    else:
        for port in sorted(app_proxy_ports):
            _append_proxy_owner_accept(
                tool,
                HOST_CHAIN,
                proxy_uids[0],
                port,
                runner,
            )
    for port in sorted(platform_proxy_ports):
        _append_proxy_owner_accept(
            tool,
            HOST_CHAIN,
            proxy_uids[1],
            port,
            runner,
        )
    _place_jump_first(tool, "OUTPUT", HOST_CHAIN, runner)

    _ensure_chain(tool, "DOCKER-USER", runner)
    _place_jump_first(tool, "FORWARD", "DOCKER-USER", runner)
    _ensure_chain(tool, CONTAINER_CHAIN, runner)
    # Keep the terminal DROP installed while grants are added. Flushing this
    # chain, even briefly, would let Docker's own FORWARD accepts fail open.
    _ensure_rule(tool, CONTAINER_CHAIN, ["-j", "DROP"], runner)
    _ensure_rule(
        tool,
        CONTAINER_CHAIN,
        ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        runner,
        insert=True,
    )
    if version == 4 and policy["profile"] == "warden":
        _append_warden_imds_accept(tool, CONTAINER_CHAIN, runner)
        for protocol in ("udp", "tcp"):
            _append_container_direct_accept(
                tool,
                CONTAINER_CHAIN,
                f"{WARDEN_PLATFORM_APP_IP}/32",
                protocol,
                53,
                runner,
                destination=AZURE_DNS_IP,
            )
            _append_container_direct_accept(
                tool,
                CONTAINER_CHAIN,
                BUILDER_NETWORK_SUBNET,
                protocol,
                53,
                runner,
                destination=AZURE_DNS_IP,
            )
        _append_container_direct_accept(
            tool,
            CONTAINER_CHAIN,
            f"{WARDEN_PLATFORM_APP_IP}/32",
            "tcp",
            443,
            runner,
        )
    for interface in ("br+", "docker+", "veth+"):
        _ensure_rule(
            tool,
            CONTAINER_CHAIN,
            ["-o", interface, "-j", "RETURN"],
            runner,
            insert=True,
        )
    _place_jump_first(tool, "DOCKER-USER", CONTAINER_CHAIN, runner)


def resolve_proxy_uids() -> tuple[int, int]:
    resolved = []
    for user in (APP_PROXY_USER, PLATFORM_PROXY_USER):
        try:
            resolved.append(pwd.getpwnam(user).pw_uid)
        except KeyError as exc:
            raise EgressPolicyError(
                f"required egress gateway user {user!r} does not exist"
            ) from exc
    return resolved[0], resolved[1]


def apply_policy(
    policy: dict[str, Any],
    runner: Runner = command_runner,
    *,
    proxy_uids: tuple[int, int] | None = None,
) -> None:
    if proxy_uids is None:
        proxy_uids = resolve_proxy_uids()
    for version in (4, 6):
        _apply_family(policy, version, runner, proxy_uids)


def write_policy_state(policy: dict[str, Any], path: Path = POLICY_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as temporary:
        temporary.write(payload)
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o644)
    temporary_path.replace(path)


def install_from_metadata(
    metadata_path: Path,
    *,
    state_path: Path = POLICY_STATE_PATH,
    runner: Runner = command_runner,
    proxy_uids: tuple[int, int] | None = None,
    builder_network_manager: Callable[[], None] = ensure_builder_network,
) -> dict[str, Any]:
    try:
        metadata = json.loads(metadata_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EgressPolicyError(f"could not read {metadata_path}: {exc}") from exc

    policy = policy_from_metadata(metadata)
    write_policy_state(policy, state_path)
    if policy["profile"] == "warden":
        builder_network_manager()
    apply_policy(policy, runner, proxy_uids=proxy_uids)
    return policy


def install_from_policy_file(
    policy_path: Path,
    *,
    if_present: bool = False,
    runner: Runner = command_runner,
    proxy_uids: tuple[int, int] | None = None,
) -> bool:
    if if_present and not policy_path.is_file():
        return False
    try:
        policy = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EgressPolicyError(f"could not read {policy_path}: {exc}") from exc
    if not isinstance(policy, dict) or set(policy) != {
        "version", "profile", "outbound", "platform_outbound"
    }:
        raise EgressPolicyError(f"invalid derived policy in {policy_path}")
    metadata = {
        "outbound_policy_version": policy["version"],
        "outbound": _expand_state_entries(policy["outbound"], "outbound"),
        "platform_outbound": _expand_state_entries(
            policy["platform_outbound"], "platform_outbound"
        ),
    }
    if policy["profile"] is not None:
        metadata.pop("outbound")
        metadata["egress_profile"] = policy["profile"]
    policy = policy_from_metadata(metadata)
    apply_policy(policy, runner, proxy_uids=proxy_uids)
    return True


def _expand_state_entries(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise EgressPolicyError(f"derived {field} must be an array")
    expanded = []
    for index, entry in enumerate(value):
        if (
            not isinstance(entry, dict)
            or "port" not in entry
            or ("host" in entry) == ("ip" in entry)
            or set(entry) - {"host", "ip", "port"}
        ):
            raise EgressPolicyError(
                f"derived {field}[{index}] must contain port and exactly one of host or ip"
            )
        value_kind = "host" if "host" in entry else "ip"
        expanded.append({value_kind: entry[value_kind], "ports": [entry["port"]]})
    return expanded


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--metadata", type=Path)
    source.add_argument("--policy-file", type=Path)
    parser.add_argument("--if-present", action="store_true")
    args = parser.parse_args()

    if args.metadata is not None:
        install_from_metadata(args.metadata)
    else:
        install_from_policy_file(args.policy_file, if_present=args.if_present)


if __name__ == "__main__":
    main()
