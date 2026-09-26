#!/bin/sh
# Runs on the build machine: the daemon for both devices, and the Harmattan
# interface.
#
# Everything lives under /tmp there -- the root partition is full, /tmp is a
# 31 GB tmpfs. A reboot wipes it; tools/toolchain.sh puts it back.
set -e
SRC=${SRC:-/tmp/briar-src}
export RUSTUP_HOME=${RUSTUP_HOME:-/tmp/rust/rustup}
export CARGO_HOME=${CARGO_HOME:-/tmp/rust/cargo}
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/briar-target}

OUT=$SRC/build
mkdir -p "$OUT"

# --- the daemon, for both devices ----------------------------------------
# Static musl builds: Harmattan's glibc 2.10 and Sailfish's much newer one
# both stop mattering, and nothing has to be installed beside the binary.
cd "$SRC/kern"
for target in aarch64-unknown-linux-musl armv7-unknown-linux-musleabi; do
    rustup target list --installed | grep -qx "$target" || rustup target add "$target"
    # Only Sailfish gets the notification side: it needs D-Bus, and
    # Harmattan has no org.freedesktop.Notifications at all.
    case $target in
        aarch64-*) cargo build --release --target "$target" --features sfos ;;
        *)         cargo build --release --target "$target" ;;
    esac
done
cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/briard" "$OUT/briard-aarch64"
cp "$CARGO_TARGET_DIR/armv7-unknown-linux-musleabi/release/briard" "$OUT/briard-armv7"
echo "== briard: $(stat -c %s "$OUT/briard-aarch64") B (aarch64), $(stat -c %s "$OUT/briard-armv7") B (armv7)"

# --- the Harmattan interface ---------------------------------------------
# Qt 4.7 comes out of the Harmattan SDK's MADDE sysroot, compiled with the
# GCC cross from the Snapszer port. Two link settings are not cosmetic:
#
#   --dynamic-linker=/lib/ld-linux.so.3  -- otherwise the binary asks for
#     the armhf loader, which Harmattan does not have.
#   -static-libstdc++ -static-libgcc with --exclude-libs,ALL -- the modern
#     C++ runtime stays inside the binary instead of being exported to Qt,
#     which was built against the one from GCC 4.4.
XGCC=${XGCC:-/tmp/xgcc-harmattan}
SYSROOT=${SYSROOT:-$HOME/QtSDK/Madde/sysroots/harmattan_sysroot_10.2011.34-1_slim}
CXX=$XGCC/bin/arm-none-linux-gnueabi-g++
CC=$XGCC/bin/arm-none-linux-gnueabi-gcc
if [ ! -x "$CXX" ]; then
    echo "== cross C++ missing ($CXX) - only the daemon was built" >&2
    exit 0
fi
QTINC=$SYSROOT/usr/include/qt4
CXXFLAGS="--sysroot=$SYSROOT -std=gnu++17 -O2 -Wall -Wno-register \
 -Wno-deprecated-declarations -DQT_NO_DEBUG -I$QTINC"
for m in QtCore QtGui QtNetwork QtScript QtDeclarative; do
    CXXFLAGS="$CXXFLAGS -I$QTINC/$m"
done
LDFLAGS="--sysroot=$SYSROOT -static-libstdc++ -static-libgcc -Wl,-O1 \
 -Wl,--as-needed -Wl,--exclude-libs,ALL -Wl,--dynamic-linker=/lib/ld-linux.so.3"
LIBS="-lQtDeclarative -lQtScript -lQtNetwork -lQtGui -lQtCore -lpthread"

cd "$OUT"
# ImagePrep is a QObject, so it needs moc. The simulator Qt's moc produces
# Qt 4 meta code, which is what the sysroot's Qt expects.
MOC=${MOC:-$HOME/QtSDK/Simulator/Qt/gcc/bin/moc}
$MOC "$SRC/src/imageprep.h" -o moc_imageprep.cpp
$CXX $CXXFLAGS -c moc_imageprep.cpp -o moc_imageprep.o
$MOC "$SRC/meego/dienst.h" -o moc_dienst.cpp
$CXX $CXXFLAGS -c moc_dienst.cpp -o moc_dienst.o
# QR: our own encoder (qrencode.h) and quirc as the decoder -- neither
# device has a QR library, and quirc is four C files.
$MOC "$SRC/src/qrcode.h" -o moc_qrcode.cpp
$CXX $CXXFLAGS -I"$SRC/src" -c moc_qrcode.cpp -o moc_qrcode.o
QUIRCOBJS=""
for q in quirc decode identify version_db; do
    $CC --sysroot=$SYSROOT -O2 -std=gnu99 -I"$SRC/src/quirc" \
        -c "$SRC/src/quirc/$q.c" -o "quirc_$q.o"
    QUIRCOBJS="$QUIRCOBJS quirc_$q.o"
done
$CXX $CXXFLAGS -c "$SRC/meego/main.cpp" -o main.o
$CXX $LDFLAGS -o briar main.o moc_imageprep.o moc_dienst.o moc_qrcode.o $QUIRCOBJS $LIBS
echo "== briar (Harmattan interface): $(stat -c %s briar) B"
