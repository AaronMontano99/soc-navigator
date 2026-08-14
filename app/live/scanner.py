"""Real local-network scanning: device discovery + TCP port inventory.

This is the one place in the app that touches an actual network. It is
intentionally narrow and defensive:

  - `validate_subnet` is a hard boundary — only private (RFC1918) or
    link-local address space, capped at a /24, is ever allowed, no matter
    what's passed in from the API. This tool scans the network it's
    running on, not arbitrary targets.
  - Device discovery is a plain ICMP ping sweep (via the system `ping`
    binary, no raw sockets, no elevated privileges required).
  - Port scanning is a TCP connect scan against a small, fixed list of
    commonly-relevant ports — not a full 65535-port sweep.

Nothing here decides anything is malicious; it only reports what's
reachable. Interpretation happens downstream in the same Sigma-subset
rule engine and correlator the rest of the app uses.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

MAX_SUBNET_HOSTS = 256  # /24 cap — a home network, not a sweep of the internet

# A small, curated set of ports worth knowing about on a home network —
# not an exhaustive scan. Chosen for relevance (remote access, databases,
# file shares) rather than coverage.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS/SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    5000: "Dev/UPnP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
    32400: "Plex",
}


class UnsafeSubnetError(ValueError):
    """Raised when a scan target isn't a private, reasonably-sized subnet."""


def detect_local_subnet() -> str:
    """Best-effort local /24, derived from this machine's primary local IP.

    Opens a UDP socket "connected" to a public IP without sending any
    data — the standard trick for asking the OS which local interface/IP
    would be used, without actually requiring internet access.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def validate_subnet(subnet: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        raise UnsafeSubnetError(f"Not a valid subnet: {subnet}") from e
    if not isinstance(network, ipaddress.IPv4Network):
        raise UnsafeSubnetError("Only IPv4 subnets are supported.")
    if network.is_loopback or not (network.is_private or network.is_link_local):
        raise UnsafeSubnetError("Only private (RFC1918) or link-local subnets can be scanned.")
    if network.num_addresses > MAX_SUBNET_HOSTS:
        raise UnsafeSubnetError(f"Subnet too large ({network.num_addresses} addresses) — max is a /24.")
    return network


def _ping(ip: str, timeout_s: float = 0.8) -> bool:
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", count_flag, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _reverse_dns(ip: str, timeout_s: float = 0.3) -> str | None:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_s)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def discover_hosts(subnet: str, max_workers: int = 64) -> list[dict[str, Any]]:
    """Ping-sweep a validated subnet; return alive hosts with best-effort hostname."""
    network = validate_subnet(subnet)
    candidates = [str(ip) for ip in network.hosts()]

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in candidates}
        for future in as_completed(futures):
            if future.result():
                alive.append(futures[future])

    hostnames: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_reverse_dns, ip): ip for ip in alive}
        for future in as_completed(futures):
            hostnames[futures[future]] = future.result()

    return [
        {"ip": ip, "hostname": hostnames.get(ip)}
        for ip in sorted(alive, key=lambda addr: tuple(int(p) for p in addr.split(".")))
    ]


def _grab_banner(ip: str, port: int, timeout_s: float = 0.4) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            s.connect((ip, port))
            data = s.recv(128)
            return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def scan_ports(
    ip: str,
    ports: dict[int, str] | None = None,
    timeout_s: float = 0.35,
    max_workers: int = 32,
) -> list[dict[str, Any]]:
    ports = ports or COMMON_PORTS

    def check(port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_s)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            return None
        return None

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    findings = [{"port": p, "service": ports[p], "banner": _grab_banner(ip, p)} for p in sorted(open_ports)]
    return findings
