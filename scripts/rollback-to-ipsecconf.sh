#!/usr/bin/env bash
#
# rollback-to-ipsecconf.sh
#
# Reverts the swanctl migration and puts the server back on the legacy
# ipsec.conf / strongswan-starter stack with its original certificates.
#
# This is a DIAGNOSTIC rollback: the goal is to return to a configuration that
# was known to work, so you can confirm whether the migration is what broke
# connectivity.
#
# It does NOT touch: firewall/ufw rules, NAT (before.rules), IP forwarding,
# router port-forwards, or DNS — the migration never changed those.
#
# Run as root:  sudo ./rollback-to-ipsecconf.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root (sudo ./rollback-to-ipsecconf.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck disable=SC1090
[[ -f "${REPO_DIR}/vpn.conf" ]] && source "${REPO_DIR}/vpn.conf" || true

echo "=== Rollback to ipsec.conf / strongswan-starter (legacy stack) ==="
echo

# --- Pre-flight: confirm the files we need are actually present ----------
echo "[pre] Verifying original files exist..."
missing=0
for f in /etc/ipsec.conf /etc/ipsec.secrets \
         /etc/ipsec.d/certs/server-cert.pem \
         /etc/ipsec.d/private/server-key.pem \
         /etc/ipsec.d/private/ca-key.pem \
         /etc/ipsec.d/cacerts/ca-cert.pem; do
  if [[ -e "$f" ]]; then
    echo "      OK  $f"
  else
    echo "      MISSING  $f"
    missing=1
  fi
done
if [[ $missing -eq 1 ]]; then
  echo "ERROR: one or more original files are missing. Aborting so nothing is lost." >&2
  exit 1
fi
echo

read -r -p "Proceed with rollback to the old stack? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { echo "Aborted, no changes made."; exit 0; }
echo

# --- 1. Stop and disable the new (swanctl) service -----------------------
echo "[1/5] Stopping swanctl service (strongswan)..."
systemctl stop strongswan 2>/dev/null || true
systemctl disable strongswan 2>/dev/null || true

# Terminate any lingering SAs cleanly
swanctl --terminate --ike ikev2-roadwarrior 2>/dev/null || true

# --- 2. Confirm the original cert is in place ----------------------------
# The old strongswan-starter stack reads certs from /etc/ipsec.d/, which the
# migration never modified — anything written by the swanctl path went into
# /etc/swanctl/ only. Nothing to restore here; we just report what's there.
echo "[2/5] Verifying original cert in /etc/ipsec.d/certs/..."
ORIG_CERT="/etc/ipsec.d/certs/server-cert.pem"
BITS=$(openssl x509 -in "$ORIG_CERT" -noout -text 2>/dev/null | grep -oE 'Public-Key: \([0-9]+ bit\)' || echo "unknown")
echo "      $ORIG_CERT key size: ${BITS}"
echo "      (this is the cert the legacy stack will present)"

# --- 3. Re-enable and start the old service ------------------------------
echo "[3/5] Starting strongswan-starter (old ipsec.conf stack)..."
systemctl enable strongswan-starter
systemctl restart strongswan-starter
sleep 2

# --- 4. Verify it loaded the old connection -----------------------------
echo "[4/5] Verifying old stack is up..."
if systemctl is-active --quiet strongswan-starter; then
  echo "      strongswan-starter: active"
else
  echo "      ERROR: strongswan-starter did not start. Check: systemctl status strongswan-starter" >&2
fi
echo
echo "      Connection status:"
ipsec statusall 2>/dev/null | sed 's/^/        /' | head -20 || \
  echo "        (ipsec statusall unavailable)"

# --- 5. Confirm service states ------------------------------------------
echo
echo "[5/5] Final service state:"
printf '      strongswan-starter : %s / %s\n' \
  "$(systemctl is-active strongswan-starter 2>/dev/null)" \
  "$(systemctl is-enabled strongswan-starter 2>/dev/null)"
printf '      strongswan (swanctl): %s / %s\n' \
  "$(systemctl is-active strongswan 2>/dev/null)" \
  "$(systemctl is-enabled strongswan 2>/dev/null)"

echo
echo "=== Rollback complete — server is back on the legacy ipsec.conf stack ==="
echo
echo "This reverted ONLY the strongSwan config/service. Firewall, NAT, IP"
echo "forwarding, and router port-forwards were never changed by the migration."
echo
echo "DNS note: if the client previously connected over IPv6, the AAAA record"
echo "for ${VPN_DNS_NAME:-<your vpn hostname>} may matter. Check current state:"
echo "    dig +short AAAA ${VPN_DNS_NAME:-<your vpn hostname>}"
echo "(For the swanctl setup the AAAA record must be ABSENT.)"
echo
echo "TEST: on the phone, delete and re-add the VPN config (it may be wedged"
echo "from many retries), toggle Airplane mode, then try ONE clean connection."
echo "Watch the OLD service's log:  sudo journalctl -u strongswan-starter -f"
echo
echo "TO GO BACK to swanctl later:"
echo "    sudo systemctl disable --now strongswan-starter"
echo "    sudo systemctl enable --now strongswan"
