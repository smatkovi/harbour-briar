import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar

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
        if (seite.wartetAufMeeScan) {
            seite.wartetAufMeeScan = false
            var ausAblage = kamera.ablageLesen()
            if (ausAblage && seite.uebernehmen(ausAblage))
                return
            seite.meldung = fenster.tr("scanNothing")
        }
        if (seite.wartetAufFoto) {
            seite.wartetAufFoto = false
            seite.lesen()
        }
    }

    property bool wartetAufFoto: false
    property bool wartetAufMeeScan: false

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
        var text = kamera.letztenCodeLesen()
        if (!text || !seite.uebernehmen(text))
            seite.meldung = fenster.tr("scanNothing")
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

        // MeeScan zuerst, wenn es da ist: es hat als einziges einen Sucher,
        // mit dem man zielen kann.
        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanWithMeeScan")
            visible: kamera.meeScanVorhanden()
            onClicked: {
                seite.wartetAufMeeScan = true
                if (!kamera.meeScanOeffnen()) {
                    seite.wartetAufMeeScan = false
                    seite.meldung = fenster.tr("scanFailed")
                }
            }
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("scanOpenCamera")
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
            onClicked: seite.lesen()
        }
    }
}
