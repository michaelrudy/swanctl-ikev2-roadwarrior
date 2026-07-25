#!/usr/bin/env bash
#
# migrate-from-ipsecconf.sh
#
# Moves from the deprecated ipsec.conf/strongswan-starter stack to the modern
# swanctl/charon-systemd stack — WITH the fix for the iOS problem we diagnosed:
# forcing IKE-level fragmentation of the cert-bearing IKE_AUTH response.
#
# ROOT CAUSE (from comparing working vs failing logs):
#   The old stack fragmented the ~1952-byte AUTH response into IKE fragments
#   (EF(1/2), EF(2/2)) which iOS accepts. swanctl sent it as a single ~640-byte
#   UDP packet that iOS-over-NAT dropped. The fix is setting charon.fragment_size
#   low enough to FORCE IKE fragmentation of that packet.
#
# SAFETY: this does NOT delete the old ipsec.conf config or certs. If it fails,
# run rollback-to-ipsecconf.sh to return to the working old stack instantly.
#
# Run as root, from the LAN (not over the VPN):  sudo ./migrate-from-ipsecconf.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root (sudo ./migrate-from-ipsecconf.sh)" >&2
  exit 1
fi

# ---- Settings: read from vpn.conf (same file install.sh uses) --------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CONF="${REPO_DIR}/vpn.conf"
[[ -f "$CONF" ]] || { echo "ERROR: ${CONF} not found. cp vpn.conf.example vpn.conf and edit it." >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

: "${VPN_DNS_NAME:?set in vpn.conf}"
: "${VPN_POOL:?set in vpn.conf}"
: "${DNS_SERVERS:?set in vpn.conf}"
: "${VPN_USER:?set in vpn.conf}"
LOCAL_TS="${LOCAL_TS:-0.0.0.0/0}"
# THE FIX. Forces IKE fragmentation of the AUTH packet: the old stack fragmented
# ~1952B fine, this makes swanctl do the same.
FRAGMENT_SIZE="${FRAGMENT_SIZE:-1280}"
# ----------------------------------------------------------------------------

echo "=== Migrate to swanctl (with IKE-fragmentation fix) ==="
echo "    fragment_size = ${FRAGMENT_SIZE}  <- the setting that was missing"
echo

# We need the EAP password. Pull it from the existing ipsec.secrets so we don't
# have to retype it, but let the user confirm.
SECRET=""
if [[ -f /etc/ipsec.secrets ]]; then
  SECRET=$(grep -E "^${VPN_USER}[[:space:]]*:[[:space:]]*EAP" /etc/ipsec.secrets \
           | sed -E 's/.*EAP[[:space:]]+"?([^"]*)"?[[:space:]]*$/\1/' || true)
fi
if [[ -z "$SECRET" ]]; then
  echo "Could not auto-read the EAP password from /etc/ipsec.secrets."
  read -r -s -p "Enter the VPN (EAP) password for ${VPN_USER}: " SECRET
  echo
fi
if [[ -z "$SECRET" ]]; then
  echo "ERROR: no password provided. Aborting." >&2
  exit 1
fi

read -r -p "Proceed with migration to swanctl? (rollback script available if it fails) [y/N] " ans
[[ "${ans,,}" == "y" ]] || { echo "Aborted, no changes made."; exit 0; }
echo

# ---- 1. Ensure swanctl tooling is present ----------------------------------
echo "[1/7] Ensuring swanctl + charon-systemd are installed..."
export DEBIAN_FRONTEND=noninteractive
if ! command -v swanctl >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq charon-systemd strongswan-swanctl
fi

# ---- 2. Stage certs into swanctl locations ---------------------------------
echo "[2/7] Staging certs into /etc/swanctl/..."
mkdir -p /etc/swanctl/{x509ca,x509,private}
# Use the ORIGINAL 4096-bit certs from the old locations. With IKE fragmentation
# working, cert size no longer matters (old stack fragmented 1952B fine).
cp /etc/ipsec.d/cacerts/ca-cert.pem    /etc/swanctl/x509ca/ca-cert.pem
cp /etc/ipsec.d/certs/server-cert.pem  /etc/swanctl/x509/server-cert.pem
cp /etc/ipsec.d/private/server-key.pem /etc/swanctl/private/server-key.pem
chmod 600 /etc/swanctl/private/server-key.pem

# ---- 3. THE FIX: force IKE fragmentation in a loaded config -----------------
echo "[3/7] Setting charon.fragment_size = ${FRAGMENT_SIZE} (the iOS fix)..."
FRAG_CONF="/etc/strongswan.d/99-fragmentation-fix.conf"
cat > "$FRAG_CONF" <<EOF
# Added by migrate-from-ipsecconf.sh
# Forces IKE-level fragmentation of the cert-bearing IKE_AUTH response so that
# iOS clients behind NAT accept it. Without this, swanctl sends a single large
# UDP packet that iOS drops (diagnosed by comparing working ipsec.conf logs).
charon {
    fragment_size = ${FRAGMENT_SIZE}
}
EOF
echo "      wrote $FRAG_CONF"

# ---- 4. Write swanctl.conf --------------------------------------------------
echo "[4/7] Writing /etc/swanctl/swanctl.conf..."
cat > /etc/swanctl/swanctl.conf <<EOF
# Managed by migrate-from-ipsecconf.sh
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
        secret = "${SECRET}"
    }
}
EOF
chmod 600 /etc/swanctl/swanctl.conf

# ---- 5. Cutover: stop old, start new ---------------------------------------
echo "[5/7] Cutover: stopping strongswan-starter, starting strongswan..."
systemctl stop strongswan-starter
systemctl disable strongswan-starter
systemctl enable strongswan
systemctl restart strongswan
sleep 2

# ---- 6. Load config ---------------------------------------------------------
echo "[6/7] Loading swanctl config..."
swanctl --load-all

# ---- 7. Verify --------------------------------------------------------------
echo "[7/7] Verifying..."
echo
echo "  Service states:"
printf '    strongswan (swanctl): %s / %s\n' \
  "$(systemctl is-active strongswan 2>/dev/null)" \
  "$(systemctl is-enabled strongswan 2>/dev/null)"
printf '    strongswan-starter  : %s / %s\n' \
  "$(systemctl is-active strongswan-starter 2>/dev/null)" \
  "$(systemctl is-enabled strongswan-starter 2>/dev/null)"
echo
echo "  Fragment size loaded:"
grep -r "fragment_size" /etc/strongswan.d/*.conf 2>/dev/null | grep -v '^\s*#' | sed 's/^/    /'
echo
echo "  Connection:"
swanctl --list-conns 2>/dev/null | sed 's/^/    /' | head -15

echo
echo "=== Migration applied ==="
echo
echo "NOW TEST THE PHONE — this is the whole point:"
echo
echo "  1. Watch the log:   sudo journalctl -u strongswan -f"
echo "  2. On the phone: toggle Airplane mode (fresh state), then connect over"
echo "     CELLULAR (WiFi off)."
echo "  3. In the log, you MUST see:  'splitting IKE message ... into N fragments'"
echo "     followed by EF(1/2), EF(2/2). That's the fix working."
echo "     Then: EAP_MSCHAPV2 succeeded, IKE_SA established."
echo
echo "IF IT FAILS (phone won't connect):"
echo "     sudo ./rollback-to-ipsecconf.sh"
echo "  ...puts you back on the working old stack immediately."
echo
echo "Reminder: your Mac already trusts the CA and will keep working (same CA,"
echo "same certs). No client re-import needed."
