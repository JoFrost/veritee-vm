from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from veritee.proxy_policy import validate_proxy_allowed_paths

OUTBOUND_POLICY_VERSION = 2
MAA_HOST = "midnightl2.eus.attest.azure.net"
EGRESS_PROFILES = frozenset(("unrestricted", "warden"))
WARDEN_PLATFORM_NETWORK = "warden-platform"
WARDEN_PLATFORM_SUBNET = "172.30.254.0/28"
WARDEN_PLATFORM_APP_IP = "172.30.254.2"
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


class OutboundPolicyError(ValueError):
    pass


_BLOCKED_CAPABILITIES = frozenset(
    ("ALL", "BPF", "NET_ADMIN", "SYS_ADMIN", "SYS_MODULE")
)
_CONTAINER_CONTROL_SOCKETS = frozenset(
    (
        "/run/containerd/containerd.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/containerd/containerd.sock",
        "/var/run/docker.sock",
    )
)


def _compose_network_names(value: Any, field: str) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    if isinstance(value, dict) and all(isinstance(item, str) for item in value):
        return set(value)
    raise OutboundPolicyError(f"{field} must be a list or object of network names")


def _compose_mount_paths(value: Any, field: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list):
        raise OutboundPolicyError(f"{field} must be an array")

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
            raise OutboundPolicyError(f"{field}[{index}] must be a string or object")
    return paths


def _compose_control_socket_mounts(
    value: Any,
    field: str,
) -> list[tuple[str | None, str | None]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise OutboundPolicyError(f"{field} must be an array")

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
            raise OutboundPolicyError(f"{field}[{index}] must be a string or object")

        paths = tuple(path for path in (source, target) if isinstance(path, str))
        if any(
            path in _CONTAINER_CONTROL_SOCKETS
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
        raise OutboundPolicyError(
            f"network {WARDEN_PLATFORM_NETWORK!r} requires the measured Warden profile"
        )

    app = services.get("app")
    if not isinstance(app, dict):
        raise OutboundPolicyError("services.app must be an object")

    ipam = network.get("ipam")
    configs = ipam.get("config") if isinstance(ipam, dict) else None
    if not isinstance(configs, list) or not any(
        isinstance(config, dict)
        and config.get("subnet") == WARDEN_PLATFORM_SUBNET
        for config in configs
    ):
        raise OutboundPolicyError(
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
        raise OutboundPolicyError(
            f"services.app must use {WARDEN_PLATFORM_APP_IP} on "
            f"{WARDEN_PLATFORM_NETWORK}"
        )

    for service_name, service in services.items():
        if service_name == "app":
            continue
        if not isinstance(service, dict):
            raise OutboundPolicyError(f"services.{service_name} must be an object")
        if WARDEN_PLATFORM_NETWORK in _compose_network_names(
            service.get("networks"),
            f"services.{service_name}.networks",
        ):
            raise OutboundPolicyError(
                f"only services.app may join {WARDEN_PLATFORM_NETWORK}"
            )


def validate_compose_egress_boundary(
    compose_path: Path,
    *,
    allow_warden_host_access: bool = False,
) -> None:
    """Reject Compose settings that can bypass the measured egress boundary."""
    try:
        compose = yaml.safe_load(compose_path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise OutboundPolicyError(f"could not read {compose_path}: {exc}") from exc
    if not isinstance(compose, dict):
        raise OutboundPolicyError(f"{compose_path} must contain a Compose object")

    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        raise OutboundPolicyError(f"{compose_path} must define services")
    if "app" not in services:
        raise OutboundPolicyError(f"{compose_path} must define the app service")

    networks = compose.get("networks", {})
    if not isinstance(networks, dict):
        raise OutboundPolicyError(f"{compose_path}: networks must be an object")
    non_internal_networks = set()
    for network_name, network in networks.items():
        if network is None:
            network = {}
        if not isinstance(network_name, str) or not isinstance(network, dict):
            raise OutboundPolicyError(f"{compose_path}: invalid network definition")
        driver = network.get("driver", "bridge")
        if driver != "bridge" or network.get("external") is True:
            raise OutboundPolicyError(
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
            raise OutboundPolicyError(f"{field} must be an object")
        if service.get("privileged") is True:
            raise OutboundPolicyError(f"{field}.privileged cannot be enabled")
        if service.get("use_api_socket") is True:
            raise OutboundPolicyError(f"{field}.use_api_socket cannot be enabled")

        network_mode = service.get("network_mode")
        if network_mode not in (None, "none"):
            raise OutboundPolicyError(
                f"{field}.network_mode must be omitted or set to 'none'"
            )
        for namespace_field in ("cgroup", "ipc", "pid", "userns_mode", "uts"):
            if service.get(namespace_field) == "host":
                raise OutboundPolicyError(
                    f"{field}.{namespace_field} cannot share the host namespace"
                )

        capabilities = service.get("cap_add", [])
        if isinstance(capabilities, str):
            capabilities = [capabilities]
        if not isinstance(capabilities, list) or any(
            not isinstance(capability, str) for capability in capabilities
        ):
            raise OutboundPolicyError(f"{field}.cap_add must be an array of names")
        blocked = {
            capability.upper().removeprefix("CAP_")
            for capability in capabilities
        } & _BLOCKED_CAPABILITIES
        if blocked:
            raise OutboundPolicyError(
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
            raise OutboundPolicyError(
                f"{field}.volumes cannot mount a container runtime socket"
            )
        device_paths = _compose_mount_paths(service.get("devices"), f"{field}.devices")
        if "/dev/net/tun" in device_paths:
            raise OutboundPolicyError(f"{field}.devices cannot expose /dev/net/tun")

        service_networks = _compose_network_names(
            service.get("networks"),
            f"{field}.networks",
        )
        exposed_networks = service_networks & non_internal_networks
        if allow_warden_host_access and service_name == "app":
            exposed_networks -= {WARDEN_PLATFORM_NETWORK}
        if service_name != "caddy" and exposed_networks:
            exposed = ", ".join(sorted(exposed_networks))
            raise OutboundPolicyError(
                f"{field} cannot join non-internal network(s): {exposed}"
            )

    app_networks = _compose_network_names(
        services["app"].get("networks"),
        "services.app.networks",
    )
    if "constrained-app" not in app_networks:
        raise OutboundPolicyError("services.app must join constrained-app")


def _is_public_destination_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        return not any(address in network for network in NON_PUBLIC_IPV4_NETWORKS)
    if address.ipv4_mapped is not None:
        return _is_public_destination_ip(address.ipv4_mapped)
    return address in ipaddress.ip_network("2000::/3") and not any(
        address in network for network in NON_PUBLIC_IPV6_NETWORKS
    )


def _normalize_ip(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OutboundPolicyError(f"{field} must be a non-empty IP address")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise OutboundPolicyError(f"{field} must be a literal IP address: {value!r}") from exc


def _normalize_hostname(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OutboundPolicyError(f"{field} must be a non-empty hostname")

    host = value.strip().lower().rstrip(".")
    if len(host) > 253 or "://" in host or "/" in host or "*" in host or ":" in host:
        raise OutboundPolicyError(
            f"{field} must be a bare hostname without a scheme, path, port, or wildcard: {value!r}"
        )

    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise OutboundPolicyError(f"{field} is not a valid hostname: {value!r}")

    return host


def _normalize_ports(value: Any, field: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise OutboundPolicyError(f"{field} must be a non-empty array")
    if any(isinstance(port, bool) or not isinstance(port, int) for port in value):
        raise OutboundPolicyError(f"{field} must contain only integer TCP ports")
    if any(port < 1 or port > 65535 for port in value):
        raise OutboundPolicyError(f"{field} ports must be in the range 1-65535")
    if len(set(value)) != len(value):
        raise OutboundPolicyError(f"{field} must not contain duplicate ports")

    return sorted(value)


def _entry_sort_key(entry: dict[str, Any]) -> tuple[int, int, int | str, tuple[int, ...]]:
    if "ip" in entry:
        address = ipaddress.ip_address(entry["ip"])
        return (0, address.version, int(address), tuple(entry["ports"]))
    return (1, 0, entry["host"], tuple(entry["ports"]))


def _normalize_entries(
    value: Any,
    *,
    field: str,
    app_scope: bool,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise OutboundPolicyError(f"{field} must be an array")

    merged: dict[tuple[str, str], set[int]] = {}
    for index, raw_entry in enumerate(value):
        entry_field = f"{field}[{index}]"
        if not isinstance(raw_entry, dict):
            raise OutboundPolicyError(f"{entry_field} must be an object")

        unexpected = set(raw_entry) - {"host", "ip", "ports"}
        if unexpected:
            raise OutboundPolicyError(
                f"{entry_field} contains unsupported field(s): {', '.join(sorted(unexpected))}"
            )
        if ("host" in raw_entry) == ("ip" in raw_entry):
            raise OutboundPolicyError(f"{entry_field} must contain exactly one of host or ip")

        ports = _normalize_ports(raw_entry.get("ports"), f"{entry_field}.ports")
        if app_scope and 53 in ports:
            raise OutboundPolicyError(
                f"{entry_field} cannot allow port 53; DApp DNS is restricted to the platform resolver"
            )

        if "host" in raw_entry:
            host_value = raw_entry["host"]
            try:
                value_kind = "ip"
                normalized_value = _normalize_ip(host_value, f"{entry_field}.host")
            except OutboundPolicyError:
                value_kind = "host"
                normalized_value = _normalize_hostname(
                    host_value,
                    f"{entry_field}.host",
                )
        else:
            value_kind = "ip"
            normalized_value = _normalize_ip(raw_entry["ip"], f"{entry_field}.ip")

        if value_kind == "ip":
            parsed_address = ipaddress.ip_address(normalized_value)
            if not _is_public_destination_ip(parsed_address):
                raise OutboundPolicyError(
                    f"{entry_field} must contain a globally routed destination IP, "
                    f"got {normalized_value}"
                )
        merged.setdefault((value_kind, normalized_value), set()).update(ports)

    normalized = []
    for (value_kind, normalized_value), ports in merged.items():
        normalized.append({value_kind: normalized_value, "ports": sorted(ports)})

    return sorted(normalized, key=_entry_sort_key)


def prepare_shipped_metadata(
    metadata: dict[str, Any],
    *,
    tls_mode: str,
    tls_keyvault_name: str | None,
    allow_warden_profile: bool = False,
) -> dict[str, Any]:
    """Normalize authored outbound rules into the measured runtime policy."""
    if not isinstance(metadata, dict):
        raise OutboundPolicyError("metadata must be a JSON object")
    try:
        validate_proxy_allowed_paths(metadata)
    except ValueError as error:
        raise OutboundPolicyError(str(error)) from error
    if tls_mode not in ("internal", "azure_vault"):
        raise OutboundPolicyError(f"unsupported TLS mode: {tls_mode!r}")

    shipped = deepcopy(metadata)
    existing_version = shipped.get("outbound_policy_version")
    if existing_version not in (None, OUTBOUND_POLICY_VERSION):
        raise OutboundPolicyError(
            f"unsupported outbound_policy_version: {existing_version!r}"
        )

    profile = shipped.get("egress_profile")
    if profile is not None and profile not in EGRESS_PROFILES:
        raise OutboundPolicyError(
            "egress_profile must be 'unrestricted' or 'warden' when present"
        )
    if profile == "warden" and not allow_warden_profile:
        raise OutboundPolicyError(
            "egress_profile 'warden' requires the explicit packaging override"
        )
    if profile is not None and "outbound" in shipped:
        raise OutboundPolicyError("egress_profile and outbound are mutually exclusive")

    if profile is None:
        shipped["outbound"] = _normalize_entries(
            shipped.get("outbound", []),
            field="outbound",
            app_scope=True,
        )

    attestation_mode = shipped.get("attestation_mode")
    if attestation_mode not in (None, "maa", "raw-sev-snp"):
        raise OutboundPolicyError(
            "attestation_mode must be 'maa' or 'raw-sev-snp' when present"
        )
    base_os_image = shipped.get("base_os_image", "")
    uses_maa = attestation_mode == "maa" or (
        attestation_mode is None
        and "raw-sev-snp" not in str(base_os_image).lower()
    )

    existing_vault = shipped.get("tls_keyvault_name")
    if existing_vault is not None and not isinstance(existing_vault, str):
        raise OutboundPolicyError("tls_keyvault_name must be a string")
    effective_vault = tls_keyvault_name or existing_vault
    if tls_mode == "azure_vault":
        if not effective_vault:
            raise OutboundPolicyError(
                "azure_vault TLS requires a Key Vault name before packaging"
            )
        if tls_keyvault_name and existing_vault not in (None, tls_keyvault_name):
            raise OutboundPolicyError(
                "metadata tls_keyvault_name does not match the requested Key Vault"
            )
    elif existing_vault is not None:
        raise OutboundPolicyError(
            "tls_keyvault_name is only valid with azure_vault TLS"
        )

    required_platform_hosts = []
    if uses_maa:
        required_platform_hosts.append(MAA_HOST)
    if tls_mode == "azure_vault":
        required_platform_hosts.append(f"{effective_vault}.vault.azure.net")

    if "platform_outbound" in shipped:
        if existing_version != OUTBOUND_POLICY_VERSION:
            raise OutboundPolicyError(
                "platform_outbound is generated by packaging and cannot be authored directly"
            )
        platform_outbound = _normalize_entries(
            shipped["platform_outbound"],
            field="platform_outbound",
            app_scope=False,
        )
        actual_platform_hosts = {
            entry.get("host")
            for entry in platform_outbound
        }
        if actual_platform_hosts != set(required_platform_hosts) or any(
            entry["ports"] != [443] for entry in platform_outbound
        ):
            raise OutboundPolicyError(
                "platform_outbound does not match the required attestation/TLS destinations"
            )
    else:
        authored_platform = [
            {"host": host, "ports": [443]}
            for host in required_platform_hosts
        ]
        platform_outbound = _normalize_entries(
            authored_platform,
            field="platform_outbound",
            app_scope=False,
        )

    if tls_mode == "azure_vault":
        shipped["tls_keyvault_name"] = effective_vault

    shipped["outbound_policy_version"] = OUTBOUND_POLICY_VERSION
    shipped["platform_outbound"] = platform_outbound
    return shipped
