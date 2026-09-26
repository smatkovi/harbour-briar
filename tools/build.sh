#!/bin/sh
# Builds the daemon for both devices and the Harmattan interface.
#
#   tools/build.sh        # -> build/{briard-aarch64,briard-armv7,briar}
#
# Built on the Arch machine, not here: Rust, the musl toolchains and the
# Harmattan SDK live there.
set -e
cd "$(dirname "$0")/.."
HOST=$(sh tools/buildhost.sh)
REMOTE=/tmp/briar-src
echo "== build machine: $HOST"

rsync -a --delete --exclude build --exclude target --exclude .git ./ "$HOST:$REMOTE/"
ssh "$HOST" "SRC=$REMOTE sh $REMOTE/tools/remote-build.sh"

mkdir -p build
for f in briard-aarch64 briard-armv7 briar; do
    if ssh "$HOST" "test -f $REMOTE/build/$f"; then
        scp -q "$HOST:$REMOTE/build/$f" build/
    fi
done
ls -la build/
