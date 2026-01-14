#!/bin/bash

# ---- root check ----
if [[ "$EUID" -ne 0 ]]; then
    echo "[-] This script must be run as root."
    echo "[!] Run it like this:"
    echo "    sudo $0"
    exit 1
fi
# --------------------

NETWORK="192.168.152.0/24"
ALIAS="flarevm"
HOSTS_FILE="/etc/hosts"

echo "[*] Running netdiscover on $NETWORK ..."

OUTPUT=$(netdiscover -r "$NETWORK" -PN -c 2 2>/dev/null)

# Extract all IPv4 addresses
IPS=$(echo "$OUTPUT" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Remove known non-FLARE IPs and select remaining
FOUND_IP=$(echo "$IPS" | grep -Ev '\.(1|2|254)$' | tail -n 1)

if [[ -z "$FOUND_IP" ]]; then
    echo "[-] FLARE-VM not found"
    exit 1
fi

echo "[+] FLARE-VM detected at $FOUND_IP"

echo "[*] Updating /etc/hosts ..."

# Remove old alias entry
sed -i "/[[:space:]]$ALIAS$/d" "$HOSTS_FILE"

# Add new entry
echo "$FOUND_IP    $ALIAS" >> "$HOSTS_FILE"

echo "[✓] /etc/hosts updated:"
grep "$ALIAS" "$HOSTS_FILE"
