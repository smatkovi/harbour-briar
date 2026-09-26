import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar

// Fotografiert den QR-Code des anderen Geraets ab.
//
// Kein Camera-Element aus QtMultimediaKit: dessen Unterbau (camerabin) kommt
// auf diesen Geraeten nicht ueber PAUSED hinaus und zeigt stumm Schwarz --
// QCamera meldet dabei faelschlich ActiveState, ein onError kommt nie.
// Die Aufnahme macht deshalb "kamera" (meego/kamera.h) ueber camsrcbin, den
// Weg, den auch die Kamera-App des Systems geht. Eine laufende Vorschau gibt
// Qt 4.7 hier ohnehin nicht her -- stattdessen liest die Kamera Rahmen, bis
// ein Code darin steht.
Page {
    id: seite

    property string meldung: fenster.tr("scanHint")
    property bool laeuft: false

    tools: ToolBarLayout {
        ToolIcon {
            // Absichtlich immer bedienbar: der Knopf muss gerade dann gehen,
            // wenn etwas klemmt. pageStack.pop() loest ueber Deactivating das
            // Aufraeumen aus, das ist der Notausgang.
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    // Beim Verlassen die Kamera freigeben: libomap3camd laesst sich nur
    // einmal oeffnen, und eine Seite, die sie behaelt, sperrt sie fuer jede
    // andere App -- und fuer den naechsten Besuch dieser Seite.
    onStatusChanged: {
        if (status === PageStatus.Deactivating)
            kamera.abbrechen()
    }

    Connections {
        target: kamera

        onScharf: seite.meldung = fenster.tr("scanning")

        onErkannt: {
            seite.laeuft = false
            var gefunden = Briar.qrParse(text)
            if (!gefunden || !gefunden.link) {
                seite.meldung = fenster.tr("scanNothing")
                return
            }
            pageStack.pop()
            pageStack.push(Qt.resolvedUrl("AddContactPage.qml"), {
                "vorgabeLink": gefunden.link,
                "vorgabeAdresse": gefunden.address,
                "vorgabeBluetooth": gefunden.bluetooth,
                "vorgabeOnion": gefunden.onion
            })
        }

        onFehlgeschlagen: {
            seite.laeuft = false
            // "Zeit" heisst: die Kamera lief, es war nur kein Code zu lesen.
            seite.meldung = grund === "Zeit" ? fenster.tr("scanNothing")
                                             : fenster.tr("scanFailed")
        }

        onAbgebrochen: seite.laeuft = false
    }

    Column {
        anchors { fill: parent; margins: 24 }
        spacing: 24

        Item { width: 1; height: 32 }

        Label {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: 22
            text: seite.meldung
        }

        BusyIndicator {
            anchors.horizontalCenter: parent.horizontalCenter
            running: seite.laeuft
            visible: seite.laeuft
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanTake")
            enabled: !seite.laeuft
            onClicked: {
                seite.laeuft = true
                seite.meldung = fenster.tr("scanning")
                kamera.aufnehmen()
            }
        }
    }
}
