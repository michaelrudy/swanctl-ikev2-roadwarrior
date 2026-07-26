"""Settings model for the VPN wizard.

Pure data, validation, and rendering. Nothing here touches the system or the
network, so it runs anywhere Python 3 does.

The output of this module is a ``vpn.conf`` file, which is the contract with
``scripts/install.sh``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, fields
from ipaddress import IPv4Network, ip_address, ip_network

FULL_TUNNEL = "0.0.0.0/0"
CGNAT_RANGE = ip_network("100.64.0.0/10")
PLACEHOLDER_PASSWORD = "CHANGE_ME_to_a_strong_password"
MIN_PASSWORD_LENGTH = 12

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# The password is written into vpn.conf (sourced by bash) and from there into
# swanctl.conf inside double quotes. Single quotes are escaped when rendering,
# so the only characters that can break out of either context are these.
_PASSWORD_FORBIDDEN = '"\\\n\r\t\x00'

ERROR = "error"
WARNING = "warning"


@dataclass(frozen=True)
class Problem:
    """A validation finding. Errors block; warnings are worth showing."""

    level: str
    field: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.field}: {self.message}"


@dataclass
class VpnSettings:
    vpn_dns_name: str = ""
    wan_iface: str = ""
    lan_subnet: str = ""
    vpn_pool: str = "10.10.10.0/24"
    dns_servers: str = "1.1.1.1, 8.8.8.8"
    local_ts: str = FULL_TUNNEL
    vpn_user: str = "vpnuser"
    vpn_password: str = ""
    fragment_size: int = 1280
    ssh_port: int = 22
    admin_ports: str = "22 3389 9090"

    def __repr__(self) -> str:
        shown = []
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "vpn_password":
                value = "<redacted>" if value else ""
            shown.append(f"{f.name}={value!r}")
        return f"{type(self).__name__}({', '.join(shown)})"

    @property
    def full_tunnel(self) -> bool:
        return self.local_ts.strip() == FULL_TUNNEL

    def errors(self) -> list[Problem]:
        return [p for p in self.validate() if p.level == ERROR]

    def is_valid(self) -> bool:
        return not self.errors()

    def validate(self) -> list[Problem]:
        problems: list[Problem] = []
        problems += self._check_hostname()
        problems += self._check_iface()
        lan, problems_lan = _parse_network("lan_subnet", self.lan_subnet, required=True)
        problems += problems_lan
        pool, problems_pool = _parse_network("vpn_pool", self.vpn_pool, required=True)
        problems += problems_pool
        problems += self._check_pool(pool, lan)
        problems += self._check_local_ts()
        problems += self._check_dns_servers()
        problems += self._check_user()
        problems += self._check_password()
        problems += self._check_fragment_size()
        problems += self._check_ports()
        return problems

    # -- individual checks ------------------------------------------------

    def _check_hostname(self) -> list[Problem]:
        name = self.vpn_dns_name.strip()
        if not name:
            return [Problem(ERROR, "vpn_dns_name", "required: the hostname clients connect to")]
        if not _HOSTNAME_RE.match(name):
            return [
                Problem(
                    ERROR,
                    "vpn_dns_name",
                    f"{name!r} is not a fully qualified domain name (needs at least one dot)",
                )
            ]
        return []

    def _check_iface(self) -> list[Problem]:
        iface = self.wan_iface.strip()
        if not iface:
            return [Problem(ERROR, "wan_iface", "required: the interface carrying the default route")]
        if not _IFACE_RE.match(iface):
            return [Problem(ERROR, "wan_iface", f"{iface!r} is not a valid interface name")]
        return []

    def _check_pool(self, pool: IPv4Network | None, lan: IPv4Network | None) -> list[Problem]:
        problems: list[Problem] = []
        if pool is None:
            return problems
        if not pool.is_private:
            problems.append(
                Problem(ERROR, "vpn_pool", f"{pool} is not a private range; clients would get routable addresses")
            )
        if pool.num_addresses < 4:
            problems.append(Problem(ERROR, "vpn_pool", f"{pool} is too small to hand out addresses"))
        if lan is not None and pool.overlaps(lan):
            problems.append(
                Problem(
                    ERROR,
                    "vpn_pool",
                    f"{pool} overlaps the LAN {lan}; clients could not reach the network they dialed in for",
                )
            )
        return problems

    def _check_local_ts(self) -> list[Problem]:
        value = self.local_ts.strip()
        if value == FULL_TUNNEL:
            return []
        _, problems = _parse_network("local_ts", value, required=True)
        return problems

    def _check_dns_servers(self) -> list[Problem]:
        entries = [e.strip() for e in self.dns_servers.split(",") if e.strip()]
        if not entries:
            return [Problem(ERROR, "dns_servers", "required: at least one DNS server to push to clients")]
        problems = []
        for entry in entries:
            try:
                ip_address(entry)
            except ValueError:
                problems.append(Problem(ERROR, "dns_servers", f"{entry!r} is not an IP address"))
        return problems

    def _check_user(self) -> list[Problem]:
        user = self.vpn_user.strip()
        if not user:
            return [Problem(ERROR, "vpn_user", "required: the username typed into the client")]
        if not _USER_RE.match(user):
            return [Problem(ERROR, "vpn_user", f"{user!r} contains characters that may confuse swanctl.conf")]
        return []

    def _check_password(self) -> list[Problem]:
        password = self.vpn_password
        if not password:
            return [Problem(ERROR, "vpn_password", "required")]
        if password == PLACEHOLDER_PASSWORD:
            return [Problem(ERROR, "vpn_password", "still set to the example placeholder")]
        problems = []
        bad = sorted({c for c in password if c in _PASSWORD_FORBIDDEN})
        if bad:
            problems.append(
                Problem(
                    ERROR,
                    "vpn_password",
                    "cannot contain double quotes, backslashes, or control characters",
                )
            )
        if password != password.strip():
            problems.append(Problem(ERROR, "vpn_password", "cannot start or end with whitespace"))
        if len(password) < MIN_PASSWORD_LENGTH:
            problems.append(
                Problem(
                    WARNING,
                    "vpn_password",
                    f"shorter than {MIN_PASSWORD_LENGTH} characters; this is exposed to the internet",
                )
            )
        return problems

    def _check_fragment_size(self) -> list[Problem]:
        try:
            size = int(self.fragment_size)
        except (TypeError, ValueError):
            return [Problem(ERROR, "fragment_size", f"{self.fragment_size!r} is not a number")]
        if not 256 <= size <= 1500:
            return [Problem(ERROR, "fragment_size", f"{size} is outside the usable range 256-1500")]
        if size > 1400:
            return [
                Problem(
                    WARNING,
                    "fragment_size",
                    f"{size} may be too high to fragment the IKE_AUTH response; iOS and Windows clients can fail",
                )
            ]
        return []

    def _check_ports(self) -> list[Problem]:
        problems = []
        try:
            ssh_port = int(self.ssh_port)
            if not 1 <= ssh_port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            problems.append(Problem(ERROR, "ssh_port", f"{self.ssh_port!r} is not a valid port"))
        for port in self.admin_ports.split():
            try:
                number = int(port)
                if not 1 <= number <= 65535:
                    raise ValueError
            except ValueError:
                problems.append(Problem(ERROR, "admin_ports", f"{port!r} is not a valid port"))
        return problems

    # -- serialisation ----------------------------------------------------

    def render(self) -> str:
        """Render a vpn.conf. Values are single-quoted for safe `source`."""
        tunnel = "full tunnel" if self.full_tunnel else "split tunnel"
        return f"""# vpn.conf - generated by the setup wizard.
# Holds the VPN password. Keep it at mode 600 and never commit it.

# Public DNS name clients connect to. The server cert is issued for this name.
VPN_DNS_NAME={_shquote(self.vpn_dns_name)}

# Interface carrying the default route.
WAN_IFACE={_shquote(self.wan_iface)}
LAN_SUBNET={_shquote(self.lan_subnet)}

# Addresses handed to clients. Must not overlap the LAN.
VPN_POOL={_shquote(self.vpn_pool)}
DNS_SERVERS={_shquote(self.dns_servers)}

# Traffic the client routes over the tunnel ({tunnel}).
LOCAL_TS={_shquote(self.local_ts)}

VPN_USER={_shquote(self.vpn_user)}
VPN_PASSWORD={_shquote(self.vpn_password)}

# Forces IKE-level fragmentation of the cert-bearing IKE_AUTH response.
# Without it, iOS and Windows clients behind NAT time out silently.
FRAGMENT_SIZE={_shquote(str(self.fragment_size))}

SSH_PORT={_shquote(str(self.ssh_port))}
ADMIN_PORTS={_shquote(self.admin_ports)}
"""

    @classmethod
    def parse(cls, text: str) -> VpnSettings:
        """Read an existing vpn.conf. Unknown keys are ignored."""
        known = {f.name.upper(): f for f in fields(cls)}
        values: dict[str, object] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, raw = line.partition("=")
            field = known.get(key.strip())
            if field is None:
                continue
            values[field.name] = _unquote(raw.strip())
        for name in ("fragment_size", "ssh_port"):
            if name in values:
                try:
                    values[name] = int(values[name])  # type: ignore[arg-type]
                except ValueError:
                    pass
        return cls(**values)  # type: ignore[arg-type]


def generate_password(length: int = 20) -> str:
    """A password safe for both bash and swanctl.conf quoting."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_cgnat(value: str) -> bool:
    try:
        return ip_address(value) in CGNAT_RANGE
    except ValueError:
        return False


def _parse_network(field: str, value: str, required: bool) -> tuple[IPv4Network | None, list[Problem]]:
    text = value.strip()
    if not text:
        if required:
            return None, [Problem(ERROR, field, "required")]
        return None, []
    try:
        network = ip_network(text, strict=False)
    except ValueError as exc:
        return None, [Problem(ERROR, field, f"{text!r} is not a valid network: {exc}")]
    if not isinstance(network, IPv4Network):
        return None, [Problem(ERROR, field, f"{text!r} is IPv6; this setup is IPv4 only")]
    if network.with_prefixlen != text:
        return network, [
            Problem(WARNING, field, f"{text} is a host address inside {network}; using {network}")
        ]
    return network, []


def _shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _unquote(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value
