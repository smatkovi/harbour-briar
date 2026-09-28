import QtQuick 2.0
import QtMultimedia 5.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Liest den QR-Code der Gegenseite von selbst aus dem Sucherbild -- kein
// Knopf, kein Ausloesen: alle anderthalb Sekunden ein Bild, gelesen wird es
// hier.
//
// Gelesen wird mit unserem eigenen Leser (quirc, src/quirc), nicht mit
// Sailfishs QrFilter auf dem Sucherstrom. Der Filter haengt am Videostrom und
// hat an der Jolla nachgesehen nichts erkannt -- die Bilder kommen dort als
// Textur aus dem Kamerastapel, und der Filter bekommt nichts Lesbares. Unser
// Leser liest ein gespeichertes Bild, und das ist derselbe Weg, der am N9
// zuverlaessig geht.
//
// Die Bilder wandern in den Zwischenspeicher und werden nach dem Lesen sofort
// weggeraeumt (QrCode.decodeAndRemove), sonst laeuft er voll.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    property string message: app.tr("scanLiveHint")
    // Laeuft gerade ein Bild durch den Leser? Dann kein zweites schiessen.
    property bool busy: false
    property int zaehler: 0

    Camera {
        id: camera
        cameraState: Camera.ActiveState
        captureMode: Camera.CaptureStillImage
        focus.focusMode: Camera.FocusContinuous

        imageCapture {
            onImageSaved: page.lesen(path)
            onCaptureFailed: {
                page.busy = false
                page.message = app.tr("scanLiveHint")
            }
        }
    }

    VideoOutput {
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: parent.height - footer.height
        source: camera
        fillMode: VideoOutput.PreserveAspectFit
    }

    // Der Taktgeber. Nur wenn die Seite vorn ist und der Leser frei ist --
    // sonst stapeln sich Aufnahmen, die niemand mehr braucht.
    Timer {
        interval: 1500
        repeat: true
        running: page.status === PageStatus.Active
        onTriggered: {
            if (page.busy || !camera.imageCapture.ready)
                return
            page.busy = true
            page.zaehler++
            camera.imageCapture.captureToLocation(
                StandardPaths.temporary + "/briar-qr-" + page.zaehler + ".jpg")
        }
    }

    // Ein frisches Bild ist da: lesen, wegraeumen, entscheiden.
    function lesen(pfad) {
        var hex = QrCode.decodeHexAndRemove(pfad)
        page.busy = false
        if (!hex)
            return
        // Ein Code zum persoenlichen Treffen (BQP) steckt voller Bytes, kein
        // Link. Dafuer gibt es eine eigene Seite -- also dorthin, samt dem
        // schon gelesenen Code, damit niemand zweimal zielen muss.
        if (Briar.istBqp(hex)) {
            page.message = app.tr("scanIsMeetCode")
            pageStack.replace(Qt.resolvedUrl("MeetPage.qml"), { "gescannt": hex })
            return
        }
        var text = Briar.hexZuText(hex)
        var found = Briar.qrParse(text)
        if (!found || !found.link) {
            // Ein Code, aber keiner von Briar -- weiterschauen statt
            // stehenbleiben.
            page.message = app.tr("scanNotBriar")
            return
        }
        pageStack.replace(Qt.resolvedUrl("AddContactPage.qml"), {
            "prefillLink": found.link,
            "prefillAddress": found.address,
            "prefillBluetooth": found.bluetooth,
            "prefillOnion": found.onion
        })
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
    }
}
