import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import Briar 1.0

// Den QR-Code des anderen Geraets einlesen.
//
// Aufgenommen wird mit der Kamera-App des Systems, gelesen wird hier. Das
// ist kein Umweg, sondern der einzige Weg, der auf diesen Geraeten traegt:
// das QML-Kameraelement zeigt stumm Schwarz (sein Unterbau camerabin kommt
// nicht ueber PAUSED hinaus), und selbst aufnehmen ginge zwar, aber ohne
// Sucherbild -- und ohne Sucher trifft man einen Code auf einem Bildschirm
// nicht. Die Kamera-App hat Sucher und einen Autofokus, der auch einen
// dichten Code scharf bekommt.
Page {
    id: seite

    property string meldung: fenster.tr("scanCameraHint")

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    // Zurueck aus der Kamera-App oder aus MeeScan: erst die Zwischenablage
    // (MeeScan legt den Code dort ab), dann das frische Foto.
    onStatusChanged: {
        if (status !== PageStatus.Active) return
        if (seite.wartetAufFoto) {
            seite.wartetAufFoto = false
            seite.lesen()
        }
    }

    property bool wartetAufFoto: false

    // MeeScan laeuft als eigenes Programm im Vordergrund; wir lesen nur mit.
    Connections {
        target: kamera
        onMeeScanErkannt: {
            if (!seite.uebernehmen(text))
                seite.meldung = fenster.tr("scanNothing")
        }
        onMeeScanBeendet: seite.meldung = fenster.tr("scanNothing")
    }

    // Beim Verlassen der Seite MeeScan nicht weiterlaufen lassen.
    Component.onDestruction: { kamera.meeScanBeenden(); sucher.anhalten() }

    // Einen gelesenen Text als Kontakt uebernehmen. Gibt false zurueck, wenn
    // kein briar://-Link darin steht.
    function uebernehmen(text) {
        var gefunden = Briar.qrParse(text)
        if (!gefunden || !gefunden.link)
            return false
        pageStack.pop()
        pageStack.push(Qt.resolvedUrl("AddContactPage.qml"), {
            "vorgabeLink": gefunden.link,
            "vorgabeAdresse": gefunden.address,
            "vorgabeBluetooth": gefunden.bluetooth,
            "vorgabeOnion": gefunden.onion
        })
        return true
    }

    function lesen() {
        var alter = kamera.alterDesLetztenFotos()
        if (alter < 0) {
            seite.meldung = fenster.tr("scanNoPhoto")
            return
        }
        seite.meldung = fenster.tr("scanning")
        // Erst die rohen Bytes: ein Code zum persoenlichen Treffen (BQP)
        // enthaelt keine Schrift. Dafuer gibt es eine eigene Seite.
        var hex = kamera.letztenCodeAlsHex()
        if (Briar.istBqp(hex)) {
            seite.meldung = fenster.tr("scanIsMeetCode")
            pageStack.pop()
            pageStack.push(Qt.resolvedUrl("MeetPage.qml"), { "gescannt": hex })
            return
        }
        var text = Briar.hexZuText(hex)
        if (!text || !seite.uebernehmen(text))
            seite.meldung = fenster.tr("scanNothing")
    }

    // Ein Fund aus dem eigenen Sucher. Derselbe Weg wie beim Foto, nur ohne
    // Foto -- und wenn nichts Brauchbares drinstand, wird weitergesucht.
    function ausSucher(hex) {
        if (Briar.istBqp(hex)) {
            seite.meldung = fenster.tr("scanIsMeetCode")
            sucher.anhalten()
            pageStack.pop()
            pageStack.push(Qt.resolvedUrl("MeetPage.qml"), { "gescannt": hex })
            return
        }
        var text = Briar.hexZuText(hex)
        if (text && seite.uebernehmen(text)) {
            sucher.anhalten()
            return
        }
        seite.meldung = fenster.tr("scanNotBriar")
        sucher.weitersuchen()
    }

    onStatusChanged: {
        if (status === PageStatus.Active)
            sucher.starten()
        else
            sucher.anhalten()
    }

    Column {
        anchors { fill: parent; margins: 24 }
        spacing: 20

        Item { width: 1; height: 24 }

        Label {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: 20
            text: seite.meldung
        }

        // Der eigene Sucher. Er liest jedes Kamerabild selbst -- kein Foto,
        // kein zweiter Schritt. Siehe meego/sucher.h; die Kette ist am Geraet
        // nachgemessen.
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 400
            height: sucher.laeuft ? 300 : 0
            visible: height > 0
            color: "black"

            Sucher {
                id: sucher
                anchors.fill: parent
                onCodeGelesen: seite.ausSucher(hex)
            }
        }

        // MeeScan und die Kamera-App bleiben als Rueckfall, falls der eigene
        // Sucher nicht anlaeuft.
        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanWithMeeScan")
            visible: kamera.meeScanVorhanden() && !sucher.laeuft
            onClicked: {
                seite.meldung = fenster.tr("scanning")
                if (!kamera.meeScanStarten())
                    seite.meldung = fenster.tr("scanFailed")
            }
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanOpenCamera")
            visible: !sucher.laeuft
            onClicked: {
                seite.wartetAufFoto = true
                if (!kamera.oeffnen()) {
                    seite.wartetAufFoto = false
                    seite.meldung = fenster.tr("scanFailed")
                }
            }
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanReadPhoto")
            visible: !sucher.laeuft
            onClicked: seite.lesen()
        }
    }
}
