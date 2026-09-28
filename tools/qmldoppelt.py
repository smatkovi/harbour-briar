#!/usr/bin/env python3
"""Findet doppelte Eigenschaften und Signalempfaenger in QML.

Warum das ein eigenes Werkzeug verdient: QML laedt ein Bauteil, in dem
derselbe Signalempfaenger zweimal steht, gar nicht erst -- die Seite bleibt
weg, ohne dass am Geraet etwas Verstaendliches dazu steht. Auf Sailfish faellt
das beim Pruefen mit qmlscene auf; fuer die MeeGo-Seiten gibt es das nicht,
weil com.nokia.meego auf dem Baurechner fehlt.

Genau dieser Fehler hat die Treffen-Seite am N9 in 0.33.0 verschwinden lassen:
ein zweites `onStatusChanged` neben dem, das schon dastand.

    tools/qmldoppelt.py [Datei ...]     (ohne Angabe: alle QML im Baum)

Die Klammerzaehlung ist bewusst einfach gehalten -- sie zaehlt die Ebene, auf
der eine Angabe steht, und vergleicht nur innerhalb derselben Ebene desselben
Blocks. Das reicht fuer den Fehler, um den es geht, und meldet nichts, was
keiner ist.
"""
import re
import sys
from pathlib import Path

ANGABE = re.compile(r'^\s*(?:(?:readonly\s+)?property\s+\w+(?:<[\w.]+>)?\s+(\w+)|(on[A-Z]\w*))\s*:')
# Zeichenketten und Kommentare zaehlen beim Klammern nicht mit.
ZEICHENKETTE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def pruefe(pfad):
    fehler = []
    ebene = 0
    # Je Ebene die schon gesehenen Namen, samt Zeilennummer.
    gesehen = {}
    im_block_kommentar = False
    for nr, zeile in enumerate(Path(pfad).read_text(encoding="utf-8").splitlines(), 1):
        roh = zeile
        if im_block_kommentar:
            if "*/" in roh:
                roh = roh.split("*/", 1)[1]
                im_block_kommentar = False
            else:
                continue
        if "/*" in roh:
            vor, _, rest = roh.partition("/*")
            if "*/" in rest:
                roh = vor + rest.split("*/", 1)[1]
            else:
                roh = vor
                im_block_kommentar = True
        sauber = ZEICHENKETTE.sub('""', roh)
        sauber = sauber.split("//", 1)[0]

        treffer = ANGABE.match(sauber)
        if treffer:
            name = treffer.group(1) or treffer.group(2)
            vorher = gesehen.setdefault(ebene, {})
            if name in vorher:
                fehler.append(
                    "%s:%d: %r steht schon in Zeile %d (Ebene %d) -- "
                    "QML laedt das Bauteil damit nicht"
                    % (pfad, nr, name, vorher[name], ebene)
                )
            else:
                vorher[name] = nr

        auf = sauber.count("{")
        zu = sauber.count("}")
        if auf or zu:
            # Eine Zeile kann beides enthalten; die Reihenfolge ist fuer die
            # Ebene der naechsten Zeile ohne Belang.
            for _ in range(auf):
                ebene += 1
            for _ in range(zu):
                gesehen.pop(ebene, None)
                ebene = max(0, ebene - 1)
    return fehler


def main():
    ziele = [Path(a) for a in sys.argv[1:]]
    if not ziele:
        wurzel = Path(__file__).resolve().parent.parent
        ziele = sorted(wurzel.rglob("*.qml"))
        ziele = [z for z in ziele if "build" not in z.parts]
    alle = []
    for z in ziele:
        alle += pruefe(str(z))
    for f in alle:
        print(f)
    print("qmldoppelt: %d Dateien geprueft, %d Fund%s"
          % (len(ziele), len(alle), "" if len(alle) == 1 else "e"))
    return 1 if alle else 0


if __name__ == "__main__":
    sys.exit(main())
