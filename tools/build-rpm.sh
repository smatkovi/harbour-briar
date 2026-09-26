#!/bin/sh
# Builds the Sailfish RPM in the SDK container on the Arch machine.
#
#   tools/build-rpm.sh [aarch64|armv7hl] ...     (default: aarch64)
#
# The daemon is not built by the RPM: it is the cross-built static binary
# from tools/build.sh, copied into the source tree as build/harbour-briar-briard
# so qmake can install it.
set -e
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCHES=${*:-aarch64}
HOST=$(sh "$ROOT/tools/buildhost.sh")
CONTAINER=${SDK_CONTAINER:-sfossdk52}
TARGET=${SDK_TARGET:-SailfishOS-5.2.0.15}
VERSION=$(sed -n 's/^Version: *//p' "$ROOT/rpm/harbour-briar.spec")

echo "harbour-briar $VERSION for: $ARCHES (build machine $HOST)"
mkdir -p "$HOME/ps/rpms/briar"
ssh "$HOST" "mkdir -p ~/briar-build/out"

for ARCH in $ARCHES; do
    case $ARCH in
        aarch64) DAEMON=build/briard-aarch64 ;;
        *)       DAEMON=build/briard-armv7 ;;
    esac
    [ -f "$ROOT/$DAEMON" ] || { echo "$DAEMON missing -- run tools/build.sh" >&2; exit 1; }
    cp "$ROOT/$DAEMON" "$ROOT/build/harbour-briar-briard"
    case $ARCH in
        aarch64) TORBIN=build/tor-aarch64 ;;
        *)       TORBIN=build/tor-armv7 ;;
    esac
    if [ -f "$ROOT/$TORBIN" ]; then
        cp "$ROOT/$TORBIN" "$ROOT/build/harbour-briar-tor"
    else
        echo "  (no $TORBIN -- the package goes out without Tor)"
        rm -f "$ROOT/build/harbour-briar-tor"
    fi
    rsync -a --delete --exclude .git --exclude target "$ROOT/" "$HOST:briar-build/src/"
    # Not inside the container's share mount: builds there fail in ways that
    # cost an hour to work out. Copy the tree in instead.
    ssh "$HOST" "cd ~/briar-build/src && tar czf /tmp/briar-src.tgz . && \
        docker cp /tmp/briar-src.tgz $CONTAINER:/tmp/briar-src.tgz"
    RPM=harbour-briar-$VERSION-1.$ARCH.rpm
    ssh "$HOST" "docker exec $CONTAINER bash -lc '\
        rm -rf ~/bbuild-$ARCH && mkdir -p ~/bbuild-$ARCH && cd ~/bbuild-$ARCH && \
        tar xzf /tmp/briar-src.tgz && mb2 -t $TARGET-$ARCH build' | \
        grep -E '^Wrote:|error:|Error|packages and'"
    ssh "$HOST" "docker cp $CONTAINER:/home/mersdk/bbuild-$ARCH/RPMS/$RPM ~/briar-build/out/"
    rsync -a "$HOST:briar-build/out/$RPM" "$HOME/ps/rpms/briar/"
    echo "  -> ~/ps/rpms/briar/$RPM"
done
