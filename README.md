# IKEv2 VPN on Ubuntu 24.04 (strongSwan + swanctl)

Scripts and notes for running an IKEv2 VPN on Ubuntu that macOS, iOS, and
Windows connect to using the VPN client already built into the OS. Nothing to
install on the phone or laptop.

I put this together after moving off OpenVPN and Tunnelblick. The Mac connected
on the first try. Getting my phone to connect over cellular took a lot longer,
and the guides I found didn't cover the things that were actually breaking. So
this repo has two jobs: get a VPN running without much fuss, and write down what
each piece is doing so it isn't a black box.

Everything here uses `swanctl` and `charon-systemd`, which is how strongSwan is
configured now. A lot of older guides use `ipsec.conf` and `strongswan-starter`.
That stack still works, but it's deprecated, so the commands in those guides
won't match what's on a current Ubuntu box.

## Quick start

```bash
git clone https://github.com/michaelrudy/swanctl-ikev2-roadwarrior
cd swanctl-ikev2-roadwarrior
python3 -m vpnsetup            # asks a few questions, writes vpn.conf
sudo ./scripts/install.sh
```

The wizard reads your routing table to fill in what it can, checks the answers
against each other, and flags the problems listed below before you hit them.
It only writes `vpn.conf`; `install.sh` still does the work. Python 3 is
already on Ubuntu Server, so there's nothing to install.

By hand instead:

```bash
cp vpn.conf.example vpn.conf
nano vpn.conf                 # DNS name, interface, subnet, password
sudo ./scripts/install.sh
```

Either way, the installer prints what's left to do. Then run the health check:

```bash
sudo ./scripts/diagnose.sh
```

## How it works

Worth reading once, even if you only want the thing running. It makes the
troubleshooting make sense.

A connection comes up in two exchanges:

1. `IKE_SA_INIT`. Client and server agree on which ciphers to use and do a
   Diffie-Hellman exchange, so everything after this point is encrypted. If the
   two sides can't agree on a cipher set, you get Windows' "policy match" error.
2. `IKE_AUTH`. Both sides prove who they are. The server sends its certificate,
   signed by a CA that `install.sh` generated. The client checks that signature,
   which is why every device has to import `ca-cert.pem` first. The client then
   sends a username and password over EAP-MSCHAPv2, inside the encrypted channel
   from step 1.

After that the server hands the client an address out of the pool
(`10.10.10.0/24` by default) and a DNS server to use. Traffic starts on UDP 500
and moves to UDP 4500 as soon as either side notices there's NAT in the path,
which there almost always is.

With `LOCAL_TS=0.0.0.0/0` the client sends all of its traffic to the server, and
the server NATs it out to the internet with a MASQUERADE rule. Same thing your
router does for devices on your LAN. Set `LOCAL_TS` to your LAN subnet instead
and the client only routes traffic for home; everything else goes out its local
connection.

The certificate authenticates the server. The password authenticates the user.
Both matter. Without the cert check, anything could claim to be your VPN.

## Three things that break

These cost me the most time.

**IKE fragmentation.** The server's `IKE_AUTH` response carries its certificate,
so it's a large packet. iOS and Windows behind NAT drop it rather than handle
it, and the connection times out with no error on either end. The fix is making
strongSwan split that packet at the IKE layer, with `fragment_size`.
`install.sh` sets it. Macs work either way, which is what made this hard to
track down.

**AAAA records.** If your hostname has an IPv6 record, Apple devices prefer it.
That works at home and fails on cellular, because the carrier can't route to
your home IPv6, and iOS won't fall back to IPv4. Publish an A record only.

**Windows crypto proposals.** Windows offers a narrow set of ciphers by default
and won't negotiate outside it. The server config here proposes a wide range. On
the client, `Set-VpnConnectionIPsecConfiguration` in an admin PowerShell with
`-DHGroup ECP256` is what gets it past the "policy match" error.

## What install.sh does

- Installs strongSwan, swanctl, charon-systemd, and the EAP plugins
- Generates a CA and a server certificate with the SAN set to your DNS name
- Writes `/etc/swanctl/swanctl.conf` with the connection, address pool, and EAP
  credentials
- Sets `fragment_size`
- Turns on IPv4 forwarding
- Sets up ufw as the only firewall in play. SSH and admin services (RDP,
  Cockpit) are reachable from the LAN and the VPN pool only. UDP 500 and 4500
  are the only ports open to the internet
- Adds the MASQUERADE rule to `before.rules` so it survives a reboot
- Enables the `strongswan` service, which loads the config on boot

It also runs `ufw --force reset`, which wipes existing rules. If the box has
firewall rules you care about, save them first.

## What you have to do yourself

The server can't do these for you.

1. Forward UDP 500 and UDP 4500 on your router to the server's LAN IP.
2. Point your hostname at your IPv4, with no AAAA record. `dig +short AAAA
   <host>` should print nothing.
3. Confirm you're not behind CGNAT. `curl -4 ifconfig.me` should match your
   router's WAN IP. If it doesn't, your ISP is NATing you and inbound
   connections won't reach you.
4. Get `generated/ca-cert.pem` onto each device and trust it. On macOS and iOS
   that means importing it and then turning on full trust, which are two
   separate steps. On Windows it goes into the Local Machine trusted root store.

The wizard checks 2 and 3 for you. It can't do anything about 1 or 4.

## Repo layout

```
vpn.conf.example              # copy to vpn.conf and edit; vpn.conf is gitignored
vpnsetup/                     # the setup wizard: python3 -m vpnsetup
scripts/
  install.sh                  # fresh install
  add-client.sh               # add a user
  diagnose.sh                 # health check, read-only
  migrate-from-ipsecconf.sh   # move an existing box off the old stack
  rollback-to-ipsecconf.sh    # put it back if the migration goes badly
```

Every script reads `vpn.conf`. Nothing else needs editing. The wizard writes
that file and nothing else, so the two halves stay independent.

## Day-to-day

Add a user with a generated password:

```bash
sudo ./scripts/add-client.sh alice
```

Or set one yourself: `sudo ./scripts/add-client.sh alice 'S0mePass!'`

Change a password by editing `secret` in `/etc/swanctl/swanctl.conf`, then run
`sudo swanctl --load-creds`. Update the device too, or it'll keep retrying with
the old one.

Watch a client connect:

```bash
sudo journalctl -u strongswan -f
```

After changing a bridge, a NIC, or your DNS, this re-reads `vpn.conf` and
compares it against what the machine actually looks like now:

```bash
python3 -m vpnsetup --check
```

Coming from `ipsec.conf`, run `scripts/migrate-from-ipsecconf.sh`. It reads the
same `vpn.conf` and leaves the old config in place, so
`scripts/rollback-to-ipsecconf.sh` can put things back.

## Keeping it locked down

Only UDP 500 and 4500 are open to the internet. Admin services stay on the LAN
and the VPN pool. `install.sh` sets `/etc/swanctl/swanctl.conf` and
`/etc/swanctl/private/` to mode 600, so leave them there.

The CA key is the sensitive one. Anyone holding it can issue certificates your
devices will trust, which is enough to impersonate the server. It stays on the
VPN box.

`vpn.conf` and `generated/` are gitignored because they hold the password and
the keys. Check `git status` before pushing.

## Assumptions

- Ubuntu 24.04 with root, a public IPv4, and a hostname pointing at it. A
  dynamic DNS name is fine.
- `WAN_IFACE` is whatever carries your default route. `ip route | grep default`
  will tell you. Usually `eth0`. Mine is `br0`, because the host is bridged.

## Still to do

Per-platform client setup notes, written out properly rather than left implicit.
Client config generation would remove most of the manual steps, particularly a
`.mobileconfig` for Apple devices that bundles the CA and the settings into one
file. A Let's Encrypt server certificate would drop the CA import entirely,
since devices already trust public CAs. Android and Linux aren't covered yet.

## License

MIT, see [LICENSE](LICENSE).
