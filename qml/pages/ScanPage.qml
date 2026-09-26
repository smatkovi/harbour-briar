import QtQuick 2.0
import QtMultimedia 5.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Photographs the other device's QR code and reads the link out of it.
// A picture, not a live scan: one tap is enough, and it works the same way
// on the N9, where QML gets no camera frames at all.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    property string message: app.tr("scanHint")
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
        // Aus der Einbaulage des Sensors, nicht fest verdrahtet: die Seite
        // steht im Hochformat, der Sensor sitzt quer, und um wie viel er
        // gedreht ist, weiss nur das Geraet. Mit einer festen -90 steht das
        // Sucherbild auf manchen Geraeten quer.
        // Das aufgenommene Bild beruehrt das nicht -- quirc findet den Code
        // in jeder Lage; die Drehung ist nur fuers Auge.
        orientation: -camera.orientation
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
