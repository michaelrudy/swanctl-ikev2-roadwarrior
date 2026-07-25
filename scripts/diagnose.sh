#!/usr/bin/env bash
#
# diagnose.sh — read-only health check for the swanctl IKEv2 VPN.
# Surfaces the exact things that broke during the reference build.
#
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
[[ -f "${REPO_DIR}/vpn.conf" ]] && source "${REPO_DIR}/vpn.conf" || true

ok(){ echo "  [ OK ] $*"; }; warn(){ echo "  [WARN] $*"; }; bad(){ echo "  [FAIL] $*"; }

echo "=== swanctl IKEv2 diagnostics ==="

echo; echo "1. Service (must be 'strongswan', NOT 'strongswan-starter')"
systemctl is-active --quiet strongswan && ok "strongswan active" || bad "strongswan not active"
systemctl is-enabled --quiet strongswan 2>/dev/null && ok "enabled at boot" || warn "not enabled at boot"
systemctl is-active --quiet strongswan-starter 2>/dev/null && warn "OLD strongswan-starter is also active — conflict risk" || ok "old starter not running"

echo; echo "2. Connection + fragmentation fix"
swanctl --list-conns 2>/dev/null | grep -q ikev2 && ok "connection loaded" || bad "no connection loaded"
if grep -qs "^\s*fragment_size" /etc/strongswan.d/99-fragmentation-fix.conf; then
  ok "fragment_size set: $(grep -h '^\s*fragment_size' /etc/strongswan.d/99-fragmentation-fix.conf | tr -s ' ')"
else
  bad "fragment_size NOT set — iOS/Windows clients behind NAT will fail"
fi
# warn on duplicate fragment_size definitions
DUPES=$(grep -rl "^\s*fragment_size" /etc/strongswan.d/ /etc/strongswan.conf 2>/dev/null | wc -l)
[[ "$DUPES" -gt 1 ]] && warn "fragment_size defined in multiple files ($DUPES) — consolidate to avoid confusion"

echo; echo "3. Listening ports"
ss -tulpn 2>/dev/null | grep -q ':500 '  && ok "UDP 500 listening"  || bad "nothing on UDP 500"
ss -tulpn 2>/dev/null | grep -q ':4500 ' && ok "UDP 4500 listening" || bad "nothing on UDP 4500"

echo; echo "4. NAT + forwarding"
iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE && ok "MASQUERADE present" || warn "no MASQUERADE — full-tunnel clients get no internet"
[[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]] && ok "ip_forward on" || bad "ip_forward off"

echo; echo "5. DNS / IPv6 (the cellular gotcha)"
if [[ -n "${VPN_DNS_NAME:-}" ]]; then
  A=$(dig +short A "$VPN_DNS_NAME" 2>/dev/null | tail -1)
  AAAA=$(dig +short AAAA "$VPN_DNS_NAME" 2>/dev/null | tail -1)
  PUB=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null)
  [[ -n "$A" ]] && ok "A record: $A" || bad "no A record"
  [[ -z "$AAAA" ]] && ok "no AAAA record (good)" || warn "AAAA present ($AAAA) — Apple clients may fail on cellular; remove it"
  [[ -n "$PUB" && -n "$A" && "$PUB" == "$A" ]] && ok "public IPv4 matches A record" \
    || { [[ -n "$PUB" ]] && warn "public IPv4 ($PUB) != A ($A) — DDNS stale or CGNAT"; }
else
  warn "VPN_DNS_NAME not set — skipping DNS checks"
fi

echo; echo "6. Firewall"
ufw status 2>/dev/null | grep -q "Status: active" && ok "ufw active" || warn "ufw not active"
ufw status 2>/dev/null | grep -q "500,4500/udp" && ok "500,4500/udp allowed" || warn "500,4500/udp not in ufw"

echo; echo "7. Active tunnels"
echo "     $(swanctl --list-sas 2>/dev/null | grep -c ESTABLISHED) established SA(s)"

echo; echo "=== done ==="
echo "Router must forward UDP 500+4500 to this host — not checkable from here."
