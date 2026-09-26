#!/bin/sh
# Print the ssh target for the build machine: the LAN address when it
# answers, the tunnel alias otherwise. BUILD_HOST overrides both.
if [ -n "$BUILD_HOST" ]; then
    echo "$BUILD_HOST"
    exit 0
fi
LAN=${BUILD_HOST_LAN:-sebastian@192.168.1.21}
TUNNEL=${BUILD_HOST_TUNNEL:-arch}
if ssh -o BatchMode=yes -o ConnectTimeout=4 -o StrictHostKeyChecking=accept-new "$LAN" true 2>/dev/null; then
    echo "$LAN"
else
    echo "$TUNNEL"
fi
