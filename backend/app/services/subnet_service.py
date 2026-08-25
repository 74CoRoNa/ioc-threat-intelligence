import ipaddress
from dataclasses import dataclass

from app.utils.validators import normalize_target, parse_interface


@dataclass(frozen=True, slots=True)
class SubnetResult:
    input: str
    ip_address: str
    version: int
    cidr: str
    prefix_length: int
    network: str
    subnet_mask: str
    wildcard_mask: str | None
    first_host: str
    last_host: str
    broadcast: str | None
    total_addresses: int
    usable_hosts: int
    assumed_prefix: bool


class SubnetService:
    """Calculate IPv4 and IPv6 networks with Python's standard library."""

    @staticmethod
    def calculate(ip_cidr: str) -> SubnetResult:
        normalized = normalize_target(ip_cidr)
        assumed_prefix = "/" not in normalized
        interface = parse_interface(normalized)
        network = interface.network

        if isinstance(network, ipaddress.IPv4Network):
            first_host, last_host, broadcast, usable_hosts = (
                SubnetService._ipv4_host_range(network)
            )
            wildcard_mask = str(network.hostmask)
        else:
            first_host = network.network_address
            last_host = network[-1]
            broadcast = None
            usable_hosts = network.num_addresses
            wildcard_mask = None

        return SubnetResult(
            input=normalized,
            ip_address=str(interface.ip),
            version=interface.version,
            cidr=network.with_prefixlen,
            prefix_length=network.prefixlen,
            network=str(network.network_address),
            subnet_mask=str(network.netmask),
            wildcard_mask=wildcard_mask,
            first_host=str(first_host),
            last_host=str(last_host),
            broadcast=str(broadcast) if broadcast is not None else None,
            total_addresses=network.num_addresses,
            usable_hosts=usable_hosts,
            assumed_prefix=assumed_prefix,
        )

    @staticmethod
    def _ipv4_host_range(
        network: ipaddress.IPv4Network,
    ) -> tuple[
        ipaddress.IPv4Address,
        ipaddress.IPv4Address,
        ipaddress.IPv4Address | None,
        int,
    ]:
        if network.prefixlen == 32:
            return network.network_address, network.network_address, None, 1
        if network.prefixlen == 31:
            return network.network_address, network[-1], None, 2
        return (
            network.network_address + 1,
            network.broadcast_address - 1,
            network.broadcast_address,
            network.num_addresses - 2,
        )

