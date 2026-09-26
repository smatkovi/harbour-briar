import QtQuick 2.0
import QtMultimedia 5.0
import Amber.QrFilter 1.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Photographs the other device's QR code and reads the link out of it.
// A picture, not a live scan: one tap is enough, and it works the same way
// on the N9, where QML gets no camera frames at all.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    property string message: app.tr("scanLiveHint")
    property bool busy: false

    Camera {
        id: camera
        captureMode: Camera.CaptureStillImage
        focus.focusMode: Camera.FocusContinuous
        imageCapture {
            onImageSaved: {
                page.busy = false
                var text = QrCode.decode(path)
                if (!text) {
                    page.message = app.tr("scanNothing")
                    return
                }
                var found = Briar.qrParse(text)
                if (!found.link) {
                    page.message = app.tr("scanNothing")
                    return
                }
                pageStack.replace(Qt.resolvedUrl("AddContactPage.qml"), {
                    "prefillLink": found.link,
                    "prefillAddress": found.address,
                    "prefillBluetooth": found.bluetooth,
                    "prefillOnion": found.onion
                })
            }
            onCaptureFailed: {
                page.busy = false
                page.message = app.tr("scanFailed")
            }
        }
    }

    VideoOutput {
        id: view
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: parent.height - footer.height
        source: camera
        fillMode: VideoOutput.PreserveAspectFit
        // Die Seite steht im Hochformat, der Sensor sitzt quer. camera.orientation
        // laesst sich auf diesem Geraet nicht auslesen (der Kamera-Stack
        // braucht ein echtes Fenster, headless stuerzt er ab), also steht hier
        // ein fester Wert. Das Erkennen beruehrt das ohnehin nicht -- der
        // Filter unten liest den Code in jeder Lage; die Drehung ist fuers Auge.
        orientation: 90

        // Liest den Code laufend aus dem Sucherbild. Das Modul gehoert zu
        // Sailfish (qr-filter-qml-plugin) und ist dasselbe, das die
        // Kamera-App benutzt -- kein Foto, kein Knopf, kein Umweg.
        filters: [ qrLeser ]
    }

    QrFilter {
        id: qrLeser
        active: !page.busy

        onDecodeFinished: {
            if (!result)
                return
            page.busy = true
            qrLeser.clearResult()
            var found = Briar.qrParse(result)
            if (!found || !found.link) {
                page.busy = false
                page.message = app.tr("scanNothing")
                return
            }
            pageStack.replace(Qt.resolvedUrl("AddContactPage.qml"), {
                "prefillLink": found.link,
                "prefillAddress": found.address,
                "prefillBluetooth": found.bluetooth,
                "prefillOnion": found.onion
            })
        }
    }

    Column {
        id: footer
        anchors { bottom: parent.bottom; left: parent.left; right: parent.right
                  bottomMargin: Theme.paddingLarge }
        spacing: Theme.paddingMedium

        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeSmall
            text: page.message
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: page.busy ? app.tr("scanning") : app.tr("scanTake")
            enabled: !page.busy
            onClicked: {
                page.busy = true
                page.message = app.tr("scanning")
                camera.imageCapture.capture()
            }
        }
    }
}
