#!/bin/sh
# Packs the Harmattan .deb: interface, daemon, QML and the icon.
#
#   tools/build-deb.sh [version]
#
# No versioned dependencies: "libqt4-gui (>= 4.7.4)" looks harmless and is
# not -- the installed Qt is 4.7.4~git20120327, and "~" sorts BELOW the empty
# string in Debian, so the condition could never be met.
set -e
cd "$(dirname "$0")/.."

VERSION=${1:-0.1}
STAGE=build/stage
rm -rf "$STAGE"

[ -x build/briar ]        || { echo "build/briar missing -- run tools/build.sh" >&2; exit 1; }
[ -f build/briard-armv7 ] || { echo "build/briard-armv7 missing -- run tools/build.sh" >&2; exit 1; }

mkdir -p "$STAGE/opt/briar/bin" "$STAGE/opt/briar/qml" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/icons/hicolor/80x80/apps" \
         "$STAGE/usr/share/themes/base/meegotouch/icons" \
         "$STAGE/DEBIAN"

cp build/briar "$STAGE/opt/briar/bin/briar"
cp build/briard-armv7 "$STAGE/opt/briar/bin/briard"
# Tor rides along when it has been built; Harmattan has no repository left
# to install one from.
[ -f build/tor-armv7 ] && cp build/tor-armv7 "$STAGE/opt/briar/bin/tor"
chmod 755 "$STAGE/opt/briar/bin/"*
cp meego/qml/*.qml "$STAGE/opt/briar/qml/"
# One shared file for both front ends; only the components differ.
cp qml/Briar.js qml/Strings.js "$STAGE/opt/briar/qml/"
cp meego/briar.desktop "$STAGE/usr/share/applications/"

# The icon carries the exact silhouette of the stock apps; a round one
# stands out immediately in the home screen's grid.
cp meego/icons/icon-80.png "$STAGE/usr/share/icons/hicolor/80x80/apps/briar.png"
cp meego/icons/icon-80.png "$STAGE/usr/share/themes/base/meegotouch/icons/briar-80.png"

VERSION="$VERSION" python3 - <<'PY'
import base64, io, os, textwrap
icon = base64.b64encode(open("meego/icons/icon-64.png", "rb").read()).decode("ascii")
text = io.open("meego/control.in", encoding="utf-8").read()
text = text.replace("@VERSION@", os.environ["VERSION"])
text = text.replace("@ICON@", "\n".join(" " + line for line in textwrap.wrap(icon, 76)))
io.open("build/stage/DEBIAN/control", "w", encoding="utf-8").write(text)
PY

# Nach dem Einspielen den alten Dienst beenden -- siehe die Begruendung im
# RPM-Rezept. busybox kennt kein pkill -x, also ueber pgrep.
cat > "$STAGE/DEBIAN/postinst" <<'SH'
#!/bin/sh
# Den alten Dienst beenden -- er ueberlebt sonst die Aktualisierung, und die
# App startet keinen zweiten. Am N9 lief so Paket 0.35.1 neben einem Dienst
# aus 0.34.0, und jede Reparatur schien wirkungslos.
#
# Ohne pgrep und ohne pkill: was in einem Wartungsskript unter aegis an
# Werkzeugen und PATH da ist, laesst sich nicht voraussetzen. /proc reicht.
getroffen=0
for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    case "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)" in
        */briard*)
            kill "${d#/proc/}" 2>/dev/null && getroffen=$((getroffen+1))
            ;;
    esac
done
# Eine Spur, damit sich nachsehen laesst, ob das Skript ueberhaupt lief.
echo "$(date) postinst: $getroffen Dienst(e) beendet" >> /home/user/briar-postinst.log 2>/dev/null
exit 0
SH
chmod 755 "$STAGE/DEBIAN/postinst"

DEB="briar_${VERSION}_armel.deb"
python3 meego/mkdeb.py "$STAGE" "$DEB"
echo "== $DEB"
