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
CPINFO_OUT=$(timeout 60 cpinfo -y all 2>/dev/null)
TAKE=$(echo "$CPINFO_OUT" | grep "HOTFIX" | grep "JHF" \
        | grep -oE 'Take: *[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)

if [ -n "$TAKE" ]; then
    TAKE_JSON="$TAKE"
elif [ -n "$CPINFO_OUT" ]; then
    # cpinfo ran and returned output, but named no JHF Take: nothing is installed.
    # Report 0, not null -- "no Jumbo installed" is a confirmed answer, and an
    # unpatched gateway is exactly the case that must not be downgraded to
    # "installed Take unknown".
    TAKE_JSON="0"
    echo "No Jumbo Hotfix Accumulator installed — reporting Take 0."
else
    # cpinfo produced nothing (timed out, missing, or not permitted) -- genuinely
    # unknown, so say so rather than claiming an unpatched box.
    TAKE_JSON="null"
    echo "WARNING: cpinfo returned no output — reporting installed Take as unknown."
fi

echo "Reporting: name=$NAME version=$VER take=$TAKE_JSON -> $SERVER"
RESP=$(curl_cli -k -s -X POST "$SERVER/api/report" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$NAME\",\"version\":\"$VER\",\"take\":$TAKE_JSON}")
echo "Server response: $RESP"
