#!/usr/bin/env bash
#
# add-client.sh — add an EAP username/password so another person or device
# can connect. Clients all share the same CA cert (generated/ca-cert.pem);
# only their username/password differ.
#
#   sudo ./add-client.sh <username> [password]
#
# If password is omitted, a strong one is generated and printed.
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }

USER_NAME="${1:-}"
[[ -n "$USER_NAME" ]] || { echo "Usage: sudo ./add-client.sh <username> [password]" >&2; exit 1; }
PASS="${2:-$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)}"

CONF="/etc/swanctl/swanctl.conf"
[[ -f "$CONF" ]] || { echo "ERROR: $CONF not found — run install.sh first." >&2; exit 1; }

if grep -q "eap-${USER_NAME}\b" "$CONF"; then
  echo "ERROR: user '${USER_NAME}' already exists in $CONF." >&2
  exit 1
fi

# Append a new secret block.
cat >> "$CONF" <<EOF

secrets {
    eap-${USER_NAME} {
        id = ${USER_NAME}
        secret = "${PASS}"
    }
}
EOF

swanctl --load-creds >/dev/null
echo "Added VPN user."
echo "  Username: ${USER_NAME}"
echo "  Password: ${PASS}"
echo
echo "Give this person generated/ca-cert.pem along with the server hostname."
