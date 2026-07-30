#!/bin/bash
# advisory-watch self-report — run from SmartConsole's Scripts Repository against
# a gateway object (or its management server). Executes ON the gateway using your
# already-authenticated SmartConsole session; no extra credentials involved.
#
# Collects the Gaia major version (fw ver) and the installed Jumbo Hotfix
# Accumulator Take (cpinfo), then POSTs them to the advisory-watch dashboard so
# the SmartConsole "Advisories" tab works for this gateway without the
# advisory-watch operator ever having credentials to this management server.
#
# Usage: gateway-report.sh [server-url] [object-name]
#   server-url   default: https://34.201.63.14:5443
#   object-name  default: this gateway's hostname. MUST match the gateway
#                object's name in SmartConsole (that's what the Advisories tab
#                sends when it looks this gateway up) — pass it explicitly if
#                your object names differ from Gaia hostnames.

SERVER="${1:-https://34.201.63.14:5443}"
NAME="${2:-$(hostname)}"

VER=$(fw ver 2>/dev/null | grep -oE 'R[0-9]+(\.[0-9]+)*' | head -1)
if [ -z "$VER" ]; then
    echo "ERROR: could not determine version from 'fw ver' — not a gateway?"
    exit 1
fi

# JHF line looks like: "HOTFIX_R82_20_T313_EA_JHF_MAIN Take: 20"
TAKE=$(timeout 60 cpinfo -y all 2>/dev/null | grep "HOTFIX" | grep "JHF" \
        | grep -oE 'Take: *[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)
if [ -z "$TAKE" ]; then
    TAKE_JSON="null"
    echo "No JHF Take found in cpinfo output — reporting take as unknown."
else
    TAKE_JSON="$TAKE"
fi

echo "Reporting: name=$NAME version=$VER take=$TAKE_JSON -> $SERVER"
RESP=$(curl_cli -k -s -X POST "$SERVER/api/report" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$NAME\",\"version\":\"$VER\",\"take\":$TAKE_JSON}")
echo "Server response: $RESP"
