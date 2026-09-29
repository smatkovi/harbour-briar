#!/bin/sh
# Builds a static Tor for the devices.
#
#   tools/build-tor.sh [aarch64|armv7|i486]   (default: die beiden Geraete)
#   tools/build-tor.sh --pruefen              (nur die Summen der vorhandenen
#                                              Archive pruefen, nichts bauen)
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
TOR=tor-0.4.9.12

# SHA-256 jedes Archivs, das hier hineingeht. Wer eine Fassung oben aendert,
# muss die Summe hier nachtragen -- ohne Eintrag bricht das Skript ab, statt
# ungeprueft zu bauen. Geprueft am 29.09.2026:
summe() {
    case $1 in
        # Tor: gleich der veroeffentlichten dist.torproject.org/
        # tor-0.4.9.12.tar.gz.sha256sum; deren Signatur .sha256sum.asc mit
        # gpg geprueft, gut von David Goulet (B744 17ED DF22 AC9F 9E90 F491
        # 42E8 6A2A 11F4 8D36) und Alexander Faeroy (1C1B C007 A9F6 07AA 8152
        # C040 BEA7 B180 B149 1921), Schluessel von keys.openpgp.org.
        tor-0.4.9.12.tar.gz)
            echo c0d307c9dcdaee4848a8ca53e9d6c4ec92823e4f30be12790b0fbddfc6515f5b ;;
        # OpenSSL: gleich openssl.org/source/openssl-3.0.15.tar.gz.sha256 und
        # der .sha256 auf der GitHub-Release-Seite; die .asc von dort mit gpg
        # geprueft, gut von OpenSSL <openssl@openssl.org> (BA54 73A2 B058
        # 7B07 FB27 CF2D 2160 94DF D0CB 81EF; der Schluessel ist inzwischen
        # abgelaufen, die Signatur stammt aus seiner Laufzeit, 03.09.2024).
        openssl-3.0.15.tar.gz)
            echo 23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533 ;;
        # zlib: zlib.net nennt nur noch die neueste Fassung; die .asc von der
        # GitHub-Release-Seite madler/zlib v1.3.1 mit gpg geprueft, gut von
        # Mark Adler (5ED4 6A67 21D3 6558 7791 E2AA 783F CD8E 58BC AFBA).
        zlib-1.3.1.tar.gz)
            echo 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 ;;
        # libevent: keine Summe veroeffentlicht; die .asc von der
        # GitHub-Release-Seite mit gpg geprueft, gut von Azat Khuzhin (9E3A
        # C83A 2797 4B84 D1B3 401D B860 8684 8EF8 686D).
        libevent-2.1.12-stable.tar.gz)
            echo 92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb ;;
        # Die Toolchains von musl.cc sind nicht signiert: Vertrauen beim
        # ersten Laden. Die Archive vom 26.09. und ein neuer Abruf am
        # 29.09.2026 ergaben dieselben Summen, und deren SHA-512 stimmen mit
        # musl.cc/SHA512SUMS ueberein -- das kommt aber vom selben Server und
        # beweist nichts gegen einen Angriff dort.
        aarch64-linux-musl-cross.tgz)
            echo c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38 ;;
        arm-linux-musleabi-cross.tgz)
            echo d70c607101fee5330083463feacf5992892a85b826d1626094500e0c37ec7d25 ;;
        i686-linux-musl-cross.tgz)
            echo 93bd5504d5d0349258c43d7a668b506acbd627d31c0843a96e4b4c47b27a0180 ;;
    esac
}

# Prueft ein Archiv gegen die Tabelle. Ein Download liegt bis zur Pruefung
# unter <name>.part; gesucht wird in der Tabelle unter dem Namen ohne .part.
# Weicht es ab, wird es geloescht -- sonst laege es beim naechsten Lauf da
# und `test -f` saehe es als geladen. Mit NUR_PRUEFEN=1 (--pruefen) wird
# nichts geloescht: das meldet nur.
NUR_PRUEFEN=0
pruefe() {
    name=$(basename "$1")
    name=${name%.part}
    soll=$(summe "$name")
    if [ -z "$soll" ]; then
        echo "keine SHA-256 fuer $name in tools/build-tor.sh -- abgebrochen" >&2
        exit 1
    fi
    ist=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$ist" != "$soll" ]; then
        if [ "$NUR_PRUEFEN" = 1 ]; then
            echo "SHA-256 von $1 stimmt nicht (nicht geloescht)" >&2
        else
            rm -f "$1"
            echo "SHA-256 von $1 stimmt nicht -- geloescht, abgebrochen" >&2
        fi
        echo "  erwartet $soll" >&2
        echo "  erhalten $ist" >&2
        exit 1
    fi
    echo "== $name: SHA-256 stimmt"
}

# Laedt nach <ziel>.part und legt erst nach bestandener Pruefung um: ein
# abgebrochener Download liegt so nie unter dem Endnamen.
laden() {
    rm -f "$2.part"
    curl -fsSL -o "$2.part" "$1"
    pruefe "$2.part"
    mv "$2.part" "$2"
}

if [ "$1" = --pruefen ]; then
    NUR_PRUEFEN=1
    fehlt=0
    for f in "$ZLIB.tar.gz" "$LIBEVENT.tar.gz" "$OPENSSL.tar.gz" "$TOR.tar.gz" \
        /tmp/aarch64-linux-musl-cross.tgz /tmp/arm-linux-musleabi-cross.tgz \
        /tmp/i686-linux-musl-cross.tgz; do
        if [ -f "$f" ]; then pruefe "$f"; else echo "== $f fehlt"; fehlt=1; fi
    done
    exit $fehlt
fi

# Geprueft wird vor dem Auspacken, auch wenn das Archiv schon da lag. Der
# Quellbaum wird jedes Mal frisch ausgepackt: ein alter koennte aus einem
# ungeprueften Archiv stammen, und Dateien, die es nicht mehr gibt,
# ueberlebten ein Auspacken darueber.
fetch() {
    if [ -f "$2" ]; then pruefe "$2"; else laden "$1" "$2"; fi
    rm -rf "$3"
    tar xf "$2"
}

# A per-architecture copy, unpacked rather than copied: cp -r gives every
# file the same fresh timestamp, and autotools then decides its generated
# files are out of date and tries to rerun aclocal, which is not installed.
unpack() {
    rm -rf "$1-$2" "$1"
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
    # Ohne Summe fuer diese Toolchain gar nicht erst anfangen -- auch wenn
    # sie schon ausgepackt daliegt, damit eine neue Architektur nicht an
    # der Tabelle vorbei hineinrutscht.
    if [ -z "$(summe "$TRIPLE-cross.tgz")" ]; then
        echo "keine SHA-256 fuer $TRIPLE-cross.tgz in tools/build-tor.sh -- abgebrochen" >&2
        exit 1
    fi
    CROSS=/tmp/rust/$TRIPLE-cross
    # Eine ausgepackte Toolchain gilt nur mit Stempel: .summe traegt die
    # Summe aus der Tabelle, und geschrieben wird er erst, wenn das
    # gepruefte Archiv ganz ausgepackt ist. Ohne ihn (halb ausgepackt, etwa
    # bei vollem Kontingent, oder von anderswo hingelegt) oder mit einer
    # anderen Summe: weg damit und neu aus dem geprueften Archiv.
    if [ "$(cat "$CROSS/.summe" 2>/dev/null)" != "$(summe "$TRIPLE-cross.tgz")" ]; then
        echo "== toolchain $TRIPLE"
        if [ -f "/tmp/$TRIPLE-cross.tgz" ]; then
            pruefe "/tmp/$TRIPLE-cross.tgz"
        else
            laden "https://musl.cc/$TRIPLE-cross.tgz" "/tmp/$TRIPLE-cross.tgz"
        fi
        rm -rf "$CROSS"
        tar xf "/tmp/$TRIPLE-cross.tgz" -C /tmp/rust
        summe "$TRIPLE-cross.tgz" > "$CROSS/.summe"
    fi
    export PATH="$CROSS/bin:$PATH"
    export CC=$TRIPLE-gcc AR=$TRIPLE-ar RANLIB=$TRIPLE-ranlib
    PREFIX=$WORK/out-$ARCH
    # Die Zwischenstaende ebenso: .quellen nennt die Summen der drei
    # Archive, aus denen alles darin gebaut wird. Fehlt er oder weicht er ab
    # (andere Fassung, oder gebaut, bevor es die Pruefung gab), faengt der
    # Ordner leer an und bekommt gleich den neuen Stempel -- was danach
    # hineinkommt, stammt aus den oben geprueften Archiven, und ein Lauf
    # nach einem Abbruch darf das schon Fertige weiterbenutzen.
    QUELLEN="$(summe "$ZLIB.tar.gz") $(summe "$OPENSSL.tar.gz") $(summe "$LIBEVENT.tar.gz")"
    if [ "$(cat "$PREFIX/.quellen" 2>/dev/null)" != "$QUELLEN" ]; then
        echo "== out-$ARCH ohne passenden Stempel -- wird neu gebaut"
        rm -rf "$PREFIX"
        mkdir -p "$PREFIX"
        echo "$QUELLEN" > "$PREFIX/.quellen"
    fi

    # Each part is skipped when its library is already there: openssl alone
    # takes minutes, and a rerun after a stumble should not repeat it. Der
    # Stempel oben sagt, dass sie aus den geprueften Archiven stammen.
    # (Eine Bibliothek entsteht erst mit make install, also nach einem
    # gelungenen Bau.)
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
    # Der eine Eingriff in Tors Quelltext, und der einzige Hebel, der am
    # Arbeitsspeicher wirklich etwas bewegt. Nach dem Bootstrap haelt Tor
    # alle Mikrodeskriptoren 30 Minuten lang im Heap, bevor es sie in die
    # Datei cached-microdescs schreibt und von da an nur noch einblendet
    # (mmap, vom Kernel verdraengbar). Das trifft nur den ERSTEN Lauf eines
    # frischen Verzeichnisses: beim naechsten Start liest Tor das Journal
    # und schreibt den Cache sofort beim Laden (microdesc.c:556). Am N9 mit
    # 1 GB heisst der erste Lauf trotzdem 28 Minuten zu 60 MB statt 22 MB
    # anonym -- und endet er vor der 30. Minute, hat der zweite Start eine
    # Spitze von 83 MB, weil er das ganze Journal einliest. Mit 120 s statt
    # 30 Minuten, gemessen am N9 (28.09.2026, Summe Private_Dirty aus
    # smaps): anonym 60,0 -> 22,6 MB, RSS 64,8 -> 44,3 MB, ab zwei Minuten
    # nach dem Bootstrap. Ueber die Leitung geht dadurch nichts anders: die
    # Deskriptoren liegen ohnehin ab Empfang im Journal
    # cached-microdescs.new, nur der Heap wird frueher frei. Die torrc kennt
    # dafuer keinen Schalter.
    #
    # Die Wache darunter: schlaegt sed ins Leere, weil eine neue Tor-Fassung
    # die Zeile anders schreibt, bricht der Bau ab, statt still ein
    # ungepatchtes Tor zu liefern.
    sed -i 's/CLEAN_CACHES_INTERVAL (30\*60)/CLEAN_CACHES_INTERVAL 120/' src/core/mainloop/mainloop.c
    grep -qx '#define CLEAN_CACHES_INTERVAL 120' src/core/mainloop/mainloop.c \
        || { echo "CLEAN_CACHES_INTERVAL nicht gefunden -- Tor-Quelltext geaendert?" >&2; exit 1; }
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
