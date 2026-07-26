"""Interactive setup for vpn.conf.

Run from the repo root:

    python3 -m vpnsetup            # ask questions, write vpn.conf
    python3 -m vpnsetup --dry-run  # print what it would write
    python3 -m vpnsetup --check    # validate the existing file

This only writes vpn.conf. Nothing here touches strongSwan or the firewall;
that is still ``sudo ./scripts/install.sh``.
"""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
from dataclasses import replace
from ipaddress import ip_address, ip_network
from pathlib import Path

from . import detect
from .model import ERROR, WARNING, Problem, VpnSettings, generate_password

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "vpn.conf"


# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------


def say(message: str = "") -> None:
    print(message)


def warn(message: str) -> None:
    print(f"  ! {message}")


def fail(message: str) -> None:
    print(f"  x {message}")


def heading(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def show(problems: list[Problem]) -> None:
    for problem in problems:
        (fail if problem.level == ERROR else warn)(f"{problem.field}: {problem.message}")


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------


def ask(label: str, default: str | None = None, note: str | None = None) -> str:
    if note:
        say(f"    {note}")
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"  {label}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            say()
            raise SystemExit("cancelled")
        if answer:
            return answer
        if default is not None:
            return default
        fail("required")


def ask_yes_no(label: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"  {label} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            say()
            raise SystemExit("cancelled")
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def ask_field(
    settings: VpnSettings,
    field: str,
    label: str,
    default: str | None = None,
    note: str | None = None,
) -> VpnSettings:
    """Ask for one field and re-ask until it validates in context."""
    if default is None:
        current = getattr(settings, field)
        default = str(current) if current else None
    while True:
        value: object = ask(label, default, note)
        note = None
        if isinstance(getattr(settings, field), int):
            try:
                value = int(str(value))
            except ValueError:
                fail("must be a number")
                continue
        trial = replace(settings, **{field: value})
        problems = [p for p in trial.validate() if p.field == field]
        show(problems)
        if any(p.level == ERROR for p in problems):
            continue
        return trial


def ask_password(settings: VpnSettings) -> VpnSettings:
    say("    Enter to generate one.")
    while True:
        try:
            first = getpass.getpass("  VPN password: ")
        except (EOFError, KeyboardInterrupt):
            say()
            raise SystemExit("cancelled")
        if not first:
            generated = generate_password()
            say(f"    generated: {generated}")
            return replace(settings, vpn_password=generated)
        if first != getpass.getpass("  Confirm: "):
            fail("passwords do not match")
            continue
        trial = replace(settings, vpn_password=first)
        problems = [p for p in trial.validate() if p.field == "vpn_password"]
        show(problems)
        if any(p.level == ERROR for p in problems):
            continue
        return trial


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------


def detected_defaults(settings: VpnSettings) -> VpnSettings:
    iface = detect.detect_default_interface()
    addresses = detect.detect_addresses()
    lan = detect.detect_lan_subnet(iface) if iface else None
    pool = detect.suggest_pool(detect.networks_in_use(addresses))
    return replace(
        settings,
        wan_iface=iface or settings.wan_iface,
        lan_subnet=lan or settings.lan_subnet,
        vpn_pool=pool or settings.vpn_pool,
    )


def network_checks(settings: VpnSettings) -> None:
    """Reachability sanity checks. Advisory only; none of these block."""
    heading("Checking how the outside world sees you")

    public = detect.detect_public_ipv4()
    if public is None:
        warn("could not determine the public IPv4 address")
    else:
        kind = detect.classify_ipv4(public)
        say(f"  public IPv4: {public} ({kind})")
        if kind == "cgnat":
            warn(
                "this is carrier-grade NAT. Your ISP shares it between customers, "
                "so inbound UDP 500/4500 cannot be forwarded to you. The VPN will "
                "not work until you get a real address."
            )

    a_records = detect.resolve_a(settings.vpn_dns_name)
    if not a_records:
        warn(f"{settings.vpn_dns_name} has no A record yet")
    else:
        say(f"  {settings.vpn_dns_name} A: {', '.join(a_records)}")
        if public and public not in a_records:
            warn(f"the A record does not point at {public}; check your dynamic DNS updater")

    aaaa = detect.resolve_aaaa(settings.vpn_dns_name)
    if aaaa:
        warn(
            f"{settings.vpn_dns_name} has an AAAA record ({aaaa[0]}). Apple devices "
            "prefer IPv6 and will try it first, then fail on cellular. Remove it."
        )
    else:
        say("  no AAAA record (good)")


def safety_checks(settings: VpnSettings) -> list[Problem]:
    """install.sh runs `ufw --force reset`. Do not get locked out."""
    problems: list[Problem] = []
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) < 4:
        return problems

    client_ip, server_port = connection[0], connection[3]
    allowed = set(settings.admin_ports.split()) | {str(settings.ssh_port)}
    if server_port not in allowed:
        problems.append(
            Problem(
                ERROR,
                "ssh_port",
                f"you are connected on port {server_port}, which is not in "
                f"SSH_PORT or ADMIN_PORTS. install.sh resets the firewall and "
                f"would cut you off",
            )
        )
    try:
        if ip_address(client_ip) in ip_network(settings.vpn_pool, strict=False):
            problems.append(
                Problem(
                    ERROR,
                    "vpn_pool",
                    f"you are connected from {client_ip}, inside the VPN pool. "
                    f"Rebuilding the tunnel would drop this session",
                )
            )
    except ValueError:
        pass
    return problems


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------


def write_conf(path: Path, text: str) -> None:
    """Write at mode 600, without ever existing as world-readable."""
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
        os.chmod(backup, 0o600)
        say(f"  previous file kept as {backup.name}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def summarise(settings: VpnSettings) -> None:
    heading("Summary")
    tunnel = "everything" if settings.full_tunnel else settings.local_ts
    say(f"  hostname     {settings.vpn_dns_name}")
    say(f"  interface    {settings.wan_iface}")
    say(f"  LAN          {settings.lan_subnet}")
    say(f"  client pool  {settings.vpn_pool}")
    say(f"  DNS          {settings.dns_servers}")
    say(f"  routes       {tunnel}")
    say(f"  username     {settings.vpn_user}")
    say(f"  password     {settings.vpn_password}")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def run_check(path: Path) -> int:
    if not path.exists():
        fail(f"{path} does not exist")
        return 1
    settings = VpnSettings.parse(path.read_text())
    heading(f"Checking {path.name}")

    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        warn(f"mode is {mode:o}; it holds a password, run: chmod 600 {path}")

    problems = settings.validate() + safety_checks(settings)
    if problems:
        show(problems)
    else:
        say("  settings look consistent")

    iface = detect.detect_default_interface()
    if iface is None:
        say("  (skipping live comparison, `ip` is not available here)")
    else:
        if iface != settings.wan_iface:
            warn(f"WAN_IFACE is {settings.wan_iface} but the default route is on {iface}")
        lan = detect.detect_lan_subnet(settings.wan_iface)
        if lan and lan != settings.lan_subnet:
            warn(f"LAN_SUBNET is {settings.lan_subnet} but {settings.wan_iface} is on {lan}")

    return 1 if any(p.level == ERROR for p in problems) else 0


def run_wizard(args: argparse.Namespace) -> int:
    path = Path(args.output)
    settings = VpnSettings()

    if path.exists():
        if args.non_interactive:
            settings = VpnSettings.parse(path.read_text())
            say(f"Starting from {path.name}")
        elif ask_yes_no(f"{path.name} exists. Start from it?"):
            settings = VpnSettings.parse(path.read_text())

    say("Looking at this machine...")
    settings = detected_defaults(settings)
    if not settings.wan_iface:
        warn("could not read the routing table; you will have to answer by hand")

    if args.hostname:
        settings = replace(settings, vpn_dns_name=args.hostname)

    if args.non_interactive:
        if args.password_file:
            settings = replace(
                settings, vpn_password=Path(args.password_file).read_text().splitlines()[0]
            )
        elif not settings.vpn_password:
            generated = generate_password()
            settings = replace(settings, vpn_password=generated)
            say(f"  generated password: {generated}")
    else:
        heading("Connection")
        settings = ask_field(
            settings,
            "vpn_dns_name",
            "Hostname clients will connect to",
            note="This must resolve to your public IP. The certificate is issued for it.",
        )
        settings = ask_field(
            settings,
            "wan_iface",
            "Interface with the default route",
            note="Traffic leaves through this one. On a bridged host it is the bridge, not the NIC.",
        )
        settings = ask_field(settings, "lan_subnet", "Local network")
        settings = ask_field(
            settings,
            "vpn_pool",
            "Addresses to hand out to clients",
            note="A spare private range. It must not overlap the LAN or anything clients use at home.",
        )

        heading("Clients")
        settings = ask_field(settings, "dns_servers", "DNS servers to push")
        full = ask_yes_no("Send all client traffic through the tunnel?", default=True)
        settings = replace(settings, local_ts="0.0.0.0/0" if full else settings.lan_subnet)
        settings = ask_field(settings, "vpn_user", "Username")
        settings = ask_password(settings)

        heading("Firewall")
        say("  install.sh resets ufw, so anything not listed here gets closed.")
        settings = ask_field(settings, "ssh_port", "SSH port")
        settings = ask_field(settings, "admin_ports", "Other ports to keep open")

    problems = settings.validate()
    blocking = safety_checks(settings)
    if problems or blocking:
        heading("Problems")
        show(problems + blocking)
    if any(p.level == ERROR for p in problems + blocking):
        say("\nNothing written.")
        return 1

    if not args.no_network:
        network_checks(settings)

    summarise(settings)

    if args.dry_run:
        heading(f"Would write {path}")
        say(settings.render())
        return 0

    if not args.non_interactive and not ask_yes_no(f"\nWrite {path}?", default=True):
        say("Nothing written.")
        return 1

    write_conf(path, settings.render())
    heading("Done")
    say(f"  wrote {path} (mode 600)")
    say("  next:  sudo ./scripts/install.sh")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m vpnsetup",
        description="Build a vpn.conf for scripts/install.sh.",
    )
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT), help="where to write vpn.conf")
    parser.add_argument("--check", action="store_true", help="validate an existing vpn.conf and exit")
    parser.add_argument("--dry-run", action="store_true", help="print the file instead of writing it")
    parser.add_argument(
        "--non-interactive", action="store_true", help="ask nothing; use detection and flags"
    )
    parser.add_argument("--hostname", help="the public DNS name clients connect to")
    parser.add_argument(
        "--password-file", help="read the VPN password from the first line of this file"
    )
    parser.add_argument("--no-network", action="store_true", help="skip DNS and public IP lookups")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check:
        return run_check(Path(args.output))
    if args.non_interactive and not (args.hostname or Path(args.output).exists()):
        fail("--non-interactive needs --hostname")
        return 2
    try:
        return run_wizard(args)
    except SystemExit as exc:
        say(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
