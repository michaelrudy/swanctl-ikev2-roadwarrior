#!/usr/bin/env bash
#
# install.sh — Fresh install of a strongSwan IKEv2 (swanctl) VPN on Ubuntu 24.04
#              for native macOS / iOS / Windows clients.
#
# Uses the modern swanctl / charon-systemd stack (NOT the deprecated
# ipsec.conf / strongswan-starter stack). Includes the IKE-fragmentation fix
# that iOS and Windows clients require behind NAT.
#
# Run as root, from the LAN (not over the VPN you're configuring):
#   sudo ./install.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CONF="${REPO_DIR}/vpn.conf"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./install.sh)" >&2; exit 1; }
[[ -f "$CONF" ]] || { echo "ERROR: ${CONF} not found. cp vpn.conf.example vpn.conf and edit it." >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

: "${VPN_DNS_NAME:?set in vpn.conf}"
: "${WAN_IFACE:?set in vpn.conf}"
: "${LAN_SUBNET:?set in vpn.conf}"
: "${VPN_POOL:?set in vpn.conf}"
: "${DNS_SERVERS:?set in vpn.conf}"
: "${VPN_USER:?set in vpn.conf}"
: "${VPN_PASSWORD:?set in vpn.conf}"
LOCAL_TS="${LOCAL_TS:-0.0.0.0/0}"
FRAGMENT_SIZE="${FRAGMENT_SIZE:-1280}"
SSH_PORT="${SSH_PORT:-22}"
ADMIN_PORTS="${ADMIN_PORTS:-22 3389 9090}"

CERT_OUT="${REPO_DIR}/generated"
mkdir -p "$CERT_OUT"

echo "=== swanctl IKEv2 install for ${VPN_DNS_NAME} ==="
echo "    WAN=${WAN_IFACE}  pool=${VPN_POOL}  fragment_size=${FRAGMENT_SIZE}"
echo

# --- 1. Packages -------------------------------------------------------------
echo "[1/9] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  strongswan strongswan-pki strongswan-swanctl charon-systemd \
  libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins \
  iptables ufw

# --- 2. Certificates ---------------------------------------------------------
# 4096-bit CA + server cert. With IKE fragmentation on, the large cert is fine.
echo "[2/9] Certificates..."
mkdir -p /etc/swanctl/{x509ca,x509,private}
if [[ -f /etc/swanctl/x509ca/ca-cert.pem ]]; then
  echo "      CA already present — keeping it (delete /etc/swanctl/x509ca/ca-cert.pem to regenerate)."
else
  TMP="$(mktemp -d)"; pushd "$TMP" >/dev/null
  pki --gen --type rsa --size 4096 --outform pem > ca-key.pem
  pki --self --ca --lifetime 3650 --in ca-key.pem --type rsa \
      --dn "CN=${VPN_DNS_NAME} VPN CA" --outform pem > ca-cert.pem
  pki --gen --type rsa --size 4096 --outform pem > server-key.pem
  pki --pub --in server-key.pem --type rsa \
    | pki --issue --lifetime 1825 --cacert ca-cert.pem --cakey ca-key.pem \
        --dn "CN=${VPN_DNS_NAME}" --san "${VPN_DNS_NAME}" \
        --flag serverAuth --flag ikeIntermediate --outform pem > server-cert.pem
  install -m 600 ca-key.pem     /etc/swanctl/private/ca-key.pem
  install -m 644 ca-cert.pem    /etc/swanctl/x509ca/ca-cert.pem
  install -m 600 server-key.pem /etc/swanctl/private/server-key.pem
  install -m 644 server-cert.pem /etc/swanctl/x509/server-cert.pem
  popd >/dev/null; rm -rf "$TMP"
fi
cp /etc/swanctl/x509ca/ca-cert.pem "${CERT_OUT}/ca-cert.pem"
cp /etc/swanctl/x509ca/ca-cert.pem "${CERT_OUT}/ca-cert.crt"   # Windows-friendly extension
echo "      Client CA cert -> ${CERT_OUT}/ca-cert.pem (.crt copy for Windows)"

# --- 3. THE FRAGMENTATION FIX ------------------------------------------------
echo "[3/9] Writing fragmentation fix (fragment_size=${FRAGMENT_SIZE})..."
cat > /etc/strongswan.d/99-fragmentation-fix.conf <<EOF
# Forces IKE-level fragmentation of the cert-bearing IKE_AUTH response so that
# iOS and Windows clients behind NAT accept it. Without this, swanctl sends a
# single large UDP packet those clients drop.
charon {
    fragment_size = ${FRAGMENT_SIZE}
}
EOF

# --- 4. swanctl.conf ---------------------------------------------------------
echo "[4/9] Writing /etc/swanctl/swanctl.conf..."
cat > /etc/swanctl/swanctl.conf <<EOF
# Managed by swanctl-ikev2-roadwarrior install.sh
connections {
    ikev2-roadwarrior {
        version = 2
        pools = ikev2-pool
        fragmentation = yes
        dpd_delay = 300s
        send_cert = always
        send_certreq = no
        # Broad proposals so macOS, iOS, and Windows all negotiate.
        proposals = aes256-sha256-ecp256,aes256-sha256-modp2048,aes256-sha1-modp1024,default

        local {
            auth = pubkey
            certs = server-cert.pem
            id = ${VPN_DNS_NAME}
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            ikev2-roadwarrior {
                local_ts = ${LOCAL_TS}
                rekey_time = 0
                dpd_action = clear
                esp_proposals = aes256-sha256,aes256-sha1,aes128-sha256,default
            }
        }
    }
}

pools {
    ikev2-pool {
        addrs = ${VPN_POOL}
        dns = ${DNS_SERVERS}
    }
}

secrets {
    eap-${VPN_USER} {
        id = ${VPN_USER}
        secret = "${VPN_PASSWORD}"
    }
}
EOF
chmod 600 /etc/swanctl/swanctl.conf

# Extra users: EXTRA_USERS="alice:pass1 bob:pass2"
if [[ -n "${EXTRA_USERS:-}" ]]; then
  for pair in $EXTRA_USERS; do
    u="${pair%%:*}"; p="${pair#*:}"
    cat >> /etc/swanctl/swanctl.conf <<EOF

secrets {
    eap-${u} { id = ${u}  secret = "${p}" }
}
EOF
  done
fi

# --- 5. IP forwarding --------------------------------------------------------
echo "[5/9] Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/60-vpn-forwarding.conf
sysctl -p /etc/sysctl.d/60-vpn-forwarding.conf >/dev/null

# --- 6. Firewall + NAT -------------------------------------------------------
echo "[6/9] Firewall (ufw) + NAT..."
systemctl disable netfilter-persistent 2>/dev/null || true
apt-get purge -y -qq iptables-persistent 2>/dev/null || true

BR="/etc/ufw/before.rules"
MB="# BEGIN swanctl-ikev2-roadwarrior NAT"; ME="# END swanctl-ikev2-roadwarrior NAT"
grep -q "$MB" "$BR" && sed -i "/${MB}/,/${ME}/d" "$BR"
NAT_BLOCK="${MB}
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${VPN_POOL} -o ${WAN_IFACE} -j MASQUERADE
COMMIT
${ME}"
printf '%s\n%s\n' "$NAT_BLOCK" "$(cat "$BR")" > "$BR"
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

ufw --force reset >/dev/null
ufw allow from "${LAN_SUBNET}" to any port "${SSH_PORT}" proto tcp >/dev/null
ufw allow from "${VPN_POOL}"   to any port "${SSH_PORT}" proto tcp >/dev/null
ufw allow 500,4500/udp >/dev/null
for p in $ADMIN_PORTS; do
  [[ "$p" == "$SSH_PORT" ]] && continue
  ufw allow from "${LAN_SUBNET}" to any port "$p" proto tcp >/dev/null
  ufw allow from "${VPN_POOL}"   to any port "$p" proto tcp >/dev/null
done
ufw --force enable >/dev/null

# --- 7. Services -------------------------------------------------------------
echo "[7/9] Enabling swanctl stack (charon-systemd)..."
systemctl disable --now strongswan-starter 2>/dev/null || true
systemctl enable strongswan >/dev/null 2>&1 || true
systemctl restart strongswan
sleep 2
swanctl --load-all

# --- 8. Verify ---------------------------------------------------------------
echo "[8/9] Verifying..."
printf '      strongswan: %s / %s\n' \
  "$(systemctl is-active strongswan)" "$(systemctl is-enabled strongswan)"
grep -h fragment_size /etc/strongswan.d/99-fragmentation-fix.conf | sed 's/^/      /'
swanctl --list-conns 2>/dev/null | grep -q ikev2-roadwarrior \
  && echo "      connection loaded: OK" || echo "      WARNING: connection not loaded"

# --- 9. Reminders ------------------------------------------------------------
echo "[9/9] Done."
cat <<EOF

=== NEXT STEPS (cannot be scripted from the server) ===

  1. ROUTER: forward UDP 500 and UDP 4500 to this host
     ($(hostname -I | awk '{print $1}')).

  2. DNS: ${VPN_DNS_NAME} must resolve to your IPv4 and have NO AAAA record.
       dig +short A    ${VPN_DNS_NAME}
       dig +short AAAA ${VPN_DNS_NAME}    # must be EMPTY (Apple prefers IPv6)

  3. NOT behind CGNAT:  curl -4 ifconfig.me  must equal your router WAN IP.

  4. CLIENTS: import generated/ca-cert.pem and trust it on each device.
     Windows also needs the PowerShell proposal step (see the README).

  Health check anytime:  sudo ./scripts/diagnose.sh
EOF
