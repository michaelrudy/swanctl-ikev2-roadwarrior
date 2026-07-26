"""System detection for the VPN wizard.

Two halves, kept apart on purpose:

* **Parsers** take command output as a string and return values. No I/O, so
  they can be tested on any machine against captured output.
* **Probes** run the commands and feed the parsers. These are the only
  functions that touch the system or the network.

Everything degrades to ``None`` rather than raising. A detection failure means
the wizard asks the user instead of guessing.
"""

from __future__ import annotations

import re
import socket
import subprocess
import urllib.error
import urllib.request
from contextlib import contextmanager
from ipaddress import IPv4Interface, IPv4Network, ip_address, ip_network

CGNAT_RANGE = ip_network("100.64.0.0/10")

# Tried in order; the first two that agree win.
PUBLIC_IP_ENDPOINTS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)

POOL_CANDIDATES = (
    "10.10.10.0/24",
    "10.20.30.0/24",
    "10.99.99.0/24",
    "172.31.250.0/24",
    "192.168.240.0/24",
)

_IFACE_RE = re.compile(r"^\s*\d+:\s+([^\s:@]+)")
_INET_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
_DEV_RE = re.compile(r"\bdev\s+(\S+)")
_METRIC_RE = re.compile(r"\bmetric\s+(\d+)")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

SKIP_PREFIXES = ("lo", "virbr", "vnet", "docker", "veth", "tun", "tap", "wg")


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def parse_default_interface(ip_route_output: str) -> str | None:
    """Interface from `ip route show default`, lowest metric wins."""
    best: tuple[int, str] | None = None
    for line in ip_route_output.splitlines():
        if not line.strip().startswith("default"):
            continue
        dev = _DEV_RE.search(line)
        if not dev:
            continue
        metric_match = _METRIC_RE.search(line)
        metric = int(metric_match.group(1)) if metric_match else 0
        if best is None or metric < best[0]:
            best = (metric, dev.group(1))
    return best[1] if best else None


def parse_ipv4_addresses(ip_addr_output: str) -> dict[str, list[IPv4Interface]]:
    """Map interface name to its IPv4 addresses.

    Handles both `ip addr` and the single-line `ip -o -4 addr show` format.
    """
    found: dict[str, list[IPv4Interface]] = {}
    current: str | None = None
    for line in ip_addr_output.splitlines():
        iface = _IFACE_RE.match(line)
        if iface:
            current = iface.group(1)
        inet = _INET_RE.search(line)
        if inet and current:
            try:
                found.setdefault(current, []).append(IPv4Interface(inet.group(1)))
            except ValueError:
                continue
    return found


def networks_in_use(
    addresses: dict[str, list[IPv4Interface]], skip_virtual: bool = False
) -> list[IPv4Network]:
    """Networks already present on the host, for collision checks."""
    networks: list[IPv4Network] = []
    for iface, entries in addresses.items():
        if iface == "lo":
            continue
        if skip_virtual and iface.startswith(SKIP_PREFIXES):
            continue
        for entry in entries:
            if entry.network not in networks:
                networks.append(entry.network)
    return networks


def suggest_pool(in_use: list[IPv4Network], candidates: tuple[str, ...] = POOL_CANDIDATES) -> str | None:
    """First candidate pool that collides with nothing on the host."""
    for candidate in candidates:
        network = ip_network(candidate)
        if not any(network.overlaps(existing) for existing in in_use):
            return candidate
    return None


def classify_ipv4(value: str) -> str:
    """One of: public, private, cgnat, loopback, invalid."""
    try:
        address = ip_address(value.strip())
    except ValueError:
        return "invalid"
    if address.version != 4:
        return "invalid"
    if address.is_loopback:
        return "loopback"
    if address in CGNAT_RANGE:
        return "cgnat"
    if address.is_private:
        return "private"
    return "public"


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------


def _run(args: list[str], timeout: int = 5) -> str | None:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def detect_default_interface() -> str | None:
    output = _run(["ip", "route", "show", "default"])
    return parse_default_interface(output) if output else None


def detect_addresses() -> dict[str, list[IPv4Interface]]:
    output = _run(["ip", "-o", "-4", "addr", "show"])
    return parse_ipv4_addresses(output) if output else {}


def detect_lan_subnet(iface: str) -> str | None:
    """The network on the given interface, e.g. 192.168.1.0/24."""
    entries = detect_addresses().get(iface, [])
    return str(entries[0].network) if entries else None


def detect_public_ipv4(
    endpoints: tuple[str, ...] = PUBLIC_IP_ENDPOINTS, timeout: int = 5
) -> str | None:
    """Ask several services; return the first answer seen twice.

    Falls back to a single answer if only one endpoint responds. The result is
    untrusted input, so callers should confirm it with the user.
    """
    seen: list[str] = []
    with _ipv4_only():
        for url in endpoints:
            answer = _fetch(url, timeout)
            if answer is None:
                continue
            if answer in seen:
                return answer
            seen.append(answer)
    return seen[0] if seen else None


def _fetch(url: str, timeout: int) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": "vpnsetup"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(64).decode("ascii", "ignore").strip()
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return body if _IPV4_RE.match(body) else None


@contextmanager
def _ipv4_only():
    """Force outbound lookups to IPv4.

    Without this, a host with working IPv6 reaches the lookup service over v6
    and gets told its v6 address, which is not what the port forward is on.
    """
    original = socket.getaddrinfo

    def ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        return original(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = ipv4_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original


def resolve(name: str, family: int) -> list[str]:
    try:
        info = socket.getaddrinfo(name, None, family)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({item[4][0] for item in info})


def resolve_a(name: str) -> list[str]:
    return resolve(name, socket.AF_INET)


def resolve_aaaa(name: str) -> list[str]:
    """AAAA records. Any result here breaks Apple clients on cellular."""
    return resolve(name, socket.AF_INET6)
