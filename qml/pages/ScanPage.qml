import QtQuick 2.0
import QtMultimedia 5.0
import Amber.QrFilter 1.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Liest den QR-Code der Gegenseite laufend aus dem Sucherbild -- kein Foto,
// kein Ausloesen. Der Filter gehoert zu Sailfish (qr-filter-qml-plugin) und
// ist derselbe, den die Kamera-App benutzt; deren Fund laesst sich nicht
// abgreifen, sie gibt ihn nicht heraus.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    property string message: app.tr("scanLiveHint")
    property bool busy: false

    // Wie das Sucherbild gedreht wird. Der Sensor sitzt quer im Geraet, und
    // wie weit, ist von Geraet zu Geraet verschieden; `camera.orientation`
    // meldet es nicht ueberall verlaesslich. Darum ein Vorgabewert, den der
    // Knopf unten weiterdreht -- einmal tippen, bis es aufrecht steht.
    // Das Erkennen beruehrt das ohnehin nicht: der Filter liest den Code in
    // jeder Lage, die Drehung ist fuers Auge.
    property int drehung: -90

    Camera {
        id: camera
        focus.focusMode: Camera.FocusContinuous
    }

    VideoOutput {
        id: view
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: parent.height - footer.height
        source: camera
        fillMode: VideoOutput.PreserveAspectFit
        orientation: page.drehung
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
                // Ein Code, aber keiner von Briar -- weiterschauen statt
                // stehenbleiben.
                page.message = app.tr("scanNotBriar")
                page.busy = false
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
            text: app.tr("turnPicture")
            onClicked: page.drehung = (page.drehung + 90) % 360
        }
    }
}
