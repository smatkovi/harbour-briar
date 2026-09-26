#!/bin/sh
# Builds a static Tor for the devices.
#
#   tools/build-tor.sh [aarch64|armv7|i486]   (default: die beiden Geraete)
#
# Neither device can install one: Sailfish has no Tor in its repositories and
# Harmattan's are long dead. So Tor is cross-compiled here, statically
# against musl, the same way the daemon is -- then it is one file that runs
# anywhere, and the daemon talks to it over its control and SOCKS ports.
#
# Runs on the build machine, under /tmp (the root partition there is full).
set -e
ARCHES=${*:-"aarch64 armv7"}
WORK=/tmp/tor-build
mkdir -p "$WORK"
cd "$WORK"

ZLIB=zlib-1.3.1
LIBEVENT=libevent-2.1.12-stable
OPENSSL=openssl-3.0.15
TOR=tor-0.4.8.14

fetch() {
    test -f "$2" || curl -sSL -o "$2" "$1"
    test -d "$3" || tar xf "$2"
}

# A per-architecture copy, unpacked rather than copied: cp -r gives every
# file the same fresh timestamp, and autotools then decides its generated
# files are out of date and tries to rerun aclocal, which is not installed.
unpack() {
    rm -rf "$1-$2"
    tar xf "$1.tar.gz"
    mv "$1" "$1-$2"
    tar xf "$1.tar.gz"
}

fetch "https://zlib.net/fossils/$ZLIB.tar.gz" "$ZLIB.tar.gz" "$ZLIB"
fetch "https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/$LIBEVENT.tar.gz" "$LIBEVENT.tar.gz" "$LIBEVENT"
fetch "https://www.openssl.org/source/$OPENSSL.tar.gz" "$OPENSSL.tar.gz" "$OPENSSL"
fetch "https://dist.torproject.org/$TOR.tar.gz" "$TOR.tar.gz" "$TOR"

for ARCH in $ARCHES; do
    case $ARCH in
        aarch64)
            TRIPLE=aarch64-linux-musl
            OSSL_TARGET=linux-aarch64
            EXTRA_LIBS=
            ;;
        armv7)
            TRIPLE=arm-linux-musleabi
            OSSL_TARGET=linux-armv4
            # OpenSSL 3 uses 64-bit atomics in its thread code. On 32-bit ARM
            # the compiler cannot inline those, so they come from libatomic,
            # and without it the link test says "no linkable openssl".
            EXTRA_LIBS=-latomic
            ;;
        i486)
            # Der Sailfish-Emulator. musl.cc nennt das Gespann i686, und
            # OpenSSL nennt das Ziel linux-x86; gebaut wird fuer i686, weil
            # kein 486 mehr Sailfish laeuft.
            TRIPLE=i686-linux-musl
            OSSL_TARGET=linux-x86
            # Wie auf 32-Bit-ARM: OpenSSL 3 will 64-Bit-Atomics, die der
            # Uebersetzer hier nicht einbaut.
            EXTRA_LIBS=-latomic
            ;;
        *) echo "unknown architecture: $ARCH" >&2; exit 1 ;;
    esac
    CROSS=/tmp/rust/$TRIPLE-cross
    if [ ! -d "$CROSS" ]; then
        echo "== toolchain $TRIPLE"
        curl -sSL -o "/tmp/$TRIPLE-cross.tgz" "https://musl.cc/$TRIPLE-cross.tgz"
        tar xf "/tmp/$TRIPLE-cross.tgz" -C /tmp/rust
    fi
    export PATH="$CROSS/bin:$PATH"
    export CC=$TRIPLE-gcc AR=$TRIPLE-ar RANLIB=$TRIPLE-ranlib
    PREFIX=$WORK/out-$ARCH
    mkdir -p "$PREFIX"

    # Each part is skipped when its library is already there: openssl alone
    # takes minutes, and a rerun after a stumble should not repeat it.
    if [ -f "$PREFIX/lib/libz.a" ]; then echo "== zlib ($ARCH) schon da"; else
    echo "== zlib ($ARCH)"
    unpack "$ZLIB" "$ARCH" && cd "$ZLIB-$ARCH"
    CHOST=$TRIPLE ./configure --prefix="$PREFIX" --static > /dev/null
    make -j8 > /dev/null && make install > /dev/null
    cd "$WORK"
    fi

    if [ -f "$PREFIX/lib/libcrypto.a" ]; then echo "== openssl ($ARCH) schon da"; else
    echo "== openssl ($ARCH)"
    unpack "$OPENSSL" "$ARCH" && cd "$OPENSSL-$ARCH"
    # Either CC or --cross-compile-prefix, not both: openssl glues the
    # prefix onto CC and then looks for aarch64-linux-musl-aarch64-linux-musl-gcc.
    ./Configure "$OSSL_TARGET" no-shared no-dso no-tests no-ui-console \
        --prefix="$PREFIX" --libdir=lib > /dev/null
    make -j8 > /dev/null 2>&1 && make install_sw > /dev/null 2>&1
    cd "$WORK"
    fi

    if [ -f "$PREFIX/lib/libevent.a" ]; then echo "== libevent ($ARCH) schon da"; else
    echo "== libevent ($ARCH)"
    unpack "$LIBEVENT" "$ARCH" && cd "$LIBEVENT-$ARCH"
    # --disable-openssl: libevent's own TLS support is not used by Tor, and
    # looking for it in a cross build only fails.
    ./configure --host="$TRIPLE" --prefix="$PREFIX" --disable-shared --enable-static \
        --disable-samples --disable-libevent-regress --disable-openssl \
        CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" > /dev/null
    make -j8 > /dev/null 2>&1 && make install > /dev/null
    cd "$WORK"
    fi

    echo "== tor ($ARCH)"
    unpack "$TOR" "$ARCH" && cd "$TOR-$ARCH"
    # Cross builds cannot run the target's binaries, so the two answers
    # configure would work out by running something are given here.
    ./configure --host="$TRIPLE" --prefix="$PREFIX" \
        --disable-asciidoc --disable-manpage --disable-html-manual \
        --disable-unittests --disable-tool-name-check --disable-module-relay \
        --disable-systemd --disable-seccomp --disable-lzma --disable-zstd \
        --enable-static-openssl --enable-static-libevent --enable-static-zlib \
        --with-openssl-dir="$PREFIX" --with-libevent-dir="$PREFIX" \
        --with-zlib-dir="$PREFIX" \
        CFLAGS="-O2 -I$PREFIX/include" LDFLAGS="-static -L$PREFIX/lib" \
        LIBS="$EXTRA_LIBS" \
        ac_cv_func_getentropy=no ac_cv_lib_cap_cap_init=no > /dev/null
    make -j8 > /dev/null 2>&1
    cp src/app/tor "$WORK/tor-$ARCH"
    "$TRIPLE-strip" "$WORK/tor-$ARCH"
    cd "$WORK"
    echo "== tor-$ARCH fertig: $(stat -c %s "$WORK/tor-$ARCH") B"
done
