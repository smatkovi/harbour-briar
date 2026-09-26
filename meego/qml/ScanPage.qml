import QtQuick 1.1
import com.nokia.meego 1.0
import QtMultimediaKit 1.1
import "Briar.js" as Briar

// Fotografiert den QR-Code des anderen Geraets ab. Qt 4.7 gibt QML keine
// Kamerabilder, darum wird ausgeloest und dann die Datei gelesen.
Page {
    id: seite

    property string meldung: fenster.tr("scanHint")
    property bool laeuft: false

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    // Beim Verlassen anhalten: libomap3camd laesst sich nur einmal oeffnen,
    // und eine Seite, die die Kamera behaelt, sperrt sie fuer jede andere
    // App -- und fuer den naechsten Besuch dieser Seite. (Ein start() beim
    // Betreten braucht es nicht: das Element steht nach componentComplete
    // schon im ActiveState.)
    onStatusChanged: {
        if (status === PageStatus.Deactivating)
            kamera.stop()
    }

    Camera {
        id: kamera
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: parent.height - fuss.height - 16
        focus: true
        captureResolution: "1280x960"
        flashMode: Camera.FlashOff

        onImageSaved: {
            seite.laeuft = false
            var text = QrCode.decode(path)
            var gefunden = text ? Briar.qrParse(text) : null
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
        onError: {
            seite.laeuft = false
            // Den Grund mitschreiben: eine stumme schwarze Flaeche ist das,
            // was die Kamera hier vorher gezeigt hat.
            console.log("Kamera: " + errorString)
            seite.meldung = fenster.tr("scanFailed")
        }
    }

    Column {
        id: fuss
        anchors { bottom: parent.bottom; left: parent.left; right: parent.right
                  margins: 16 }
        spacing: 12

        Label {
            width: parent.width
            wrapMode: Text.Wrap
            color: "#a0a0a0"
            font.pixelSize: 20
            text: seite.meldung
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: seite.laeuft ? fenster.tr("scanning") : fenster.tr("scanTake")
            enabled: !seite.laeuft
            onClicked: {
                seite.laeuft = true
                seite.meldung = fenster.tr("scanning")
                kamera.captureImage()
            }
        }
    }
}
