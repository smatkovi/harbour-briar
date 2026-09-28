import QtQuick 2.0
import QtMultimedia 5.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Zwei Geräte nebeneinander: BQP, Briars Verfahren für den Fall, dass man
// einander gegenübersteht. Jedes Gerät zeigt einen Code und liest den des
// anderen. Aus den beiden Codes kommt ein gemeinsames Geheimnis, das nie
// über die Leitung geht -- wer mithört, hat nichts, und wer sich
// dazwischenschiebt, fliegt auf, weil der Code die Verpflichtung auf genau
// einen Schlüssel enthält.
//
// Das ist derselbe Weg wie in Briar auf Android. Ein Code von dort wird hier
// gelesen und umgekehrt.
//
// Die Verbindung läuft über das lokale Netz. Ein Hotspot ohne Internet
// genügt -- es geht nichts nach draußen.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    // Der eigene Rumpf als Hex, so wie der Dienst ihn geliefert hat.
    property string eigenerCode: ""
    // Ein Code, der schon anderswo gelesen wurde (aus der Scanseite).
    property string gescannt: ""

    // 0 = zeigen und suchen, 1 = gelesen, warten, 2 = fertig, 3 = gescheitert
    property int lage: 0
    property string meldung: app.tr("meetScanning")
    property bool busy: false
    property int zaehler: 0
    property int kontakteVorher: 0

    function starten() {
        page.lage = 0
        page.meldung = app.tr("meetScanning")
        page.kontakteVorher = app.status.contacts ? app.status.contacts.length : 0
        Briar.bqpStart(function(antwort) {
            if (antwort.error || !antwort.payload) {
                page.lage = 3
                page.meldung = antwort.error ? antwort.error : app.tr("meetFailed")
                return
            }
            page.eigenerCode = antwort.payload
            qrBild.source = "file://" + QrCode.imageForHex(antwort.payload, 420)
            // Ein Code, den die Scanseite schon gelesen hat, geht sofort raus.
            if (page.gescannt.length > 0) {
                var code = page.gescannt
                page.gescannt = ""
                page.uebergeben(code)
            }
        })
    }

    function uebergeben(hex) {
        page.lage = 1
        page.meldung = app.tr("meetWaiting")
        geduld.restart()
        Briar.bqpScan(hex, function(antwort) {
            if (antwort.error) {
                page.lage = 3
                page.meldung = antwort.error
            }
        })
    }

    // Ein frisches Bild: lesen, wegräumen, entscheiden.
    function lesen(pfad) {
        var hex = QrCode.decodeHexAndRemove(pfad)
        page.busy = false
        if (!hex)
            return
        if (!Briar.istBqp(hex)) {
            page.meldung = app.tr("scanNotBriar")
            return
        }
        page.uebergeben(hex)
    }

    onStatusChanged: {
        if (status === PageStatus.Active && page.eigenerCode === "")
            page.starten()
    }

    // Beim Verlassen den Lauscher abräumen -- er hängt sonst am flüchtigen
    // Port, bis jemand anwählt.
    Component.onDestruction: Briar.bqpStop(function() {})

    // Der Dienst gibt nach einer Minute auf (Briars CONNECTION_TIMEOUT). Die
    // Seite muss das mitbekommen, sonst wartet sie ewig auf einen Kontakt,
    // der nicht mehr kommt.
    Timer {
        id: geduld
        interval: 75000
        repeat: false
        onTriggered: {
            if (page.lage === 1) {
                page.lage = 3
                page.meldung = app.tr("meetFailed")
            }
        }
    }

    Camera {
        id: camera
        cameraState: page.lage === 0 ? Camera.ActiveState : Camera.UnloadedState
        captureMode: Camera.CaptureStillImage
        focus.focusMode: Camera.FocusContinuous

        imageCapture {
            onImageSaved: page.lesen(path)
            onCaptureFailed: page.busy = false
        }
    }

    Timer {
        interval: 1500
        repeat: true
        running: page.status === PageStatus.Active && page.lage === 0
        onTriggered: {
            if (page.busy || !camera.imageCapture.ready)
                return
            page.busy = true
            page.zaehler++
            camera.imageCapture.captureToLocation(
                StandardPaths.temporary + "/briar-bqp-" + page.zaehler + ".jpg")
        }
    }

    // Nachschauen, ob der Kontakt schon steht. Der Dienst legt ihn an, sobald
    // beide Seiten fertig sind -- von welcher Seite die Verbindung kam, ist
    // dabei gleich.
    Timer {
        interval: 2000
        repeat: true
        running: page.status === PageStatus.Active && page.lage < 2
        onTriggered: app.refresh()
    }

    Connections {
        target: app
        onStatusChanged: {
            if (page.lage >= 2)
                return
            var jetzt = app.status.contacts ? app.status.contacts.length : 0
            if (jetzt > page.kontakteVorher) {
                page.lage = 2
                page.meldung = app.tr("meetDone")
                        + app.status.contacts[jetzt - 1].name
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: spalte.height

        PullDownMenu {
            visible: page.lage >= 2 || page.lage === 3
            MenuItem {
                text: app.tr("meetAgain")
                onClicked: {
                    page.eigenerCode = ""
                    qrBild.source = ""
                    page.starten()
                }
            }
        }

        Column {
            id: spalte
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: app.tr("meetTitle") }

            // Das Sucherbild nur, solange gesucht wird.
            Rectangle {
                width: parent.width
                height: page.lage === 0 ? Math.round(page.height * 0.36) : 0
                visible: height > 0
                color: "black"

                VideoOutput {
                    anchors.fill: parent
                    source: camera
                    fillMode: VideoOutput.PreserveAspectFit
                }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: page.lage === 3 ? Theme.errorColor : Theme.highlightColor
                text: page.meldung
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: app.tr("meetMyCode")
            }

            Image {
                id: qrBild
                anchors.horizontalCenter: parent.horizontalCenter
                width: Math.min(parent.width - 2 * Theme.horizontalPageMargin, 420)
                height: width
                fillMode: Image.PreserveAspectFit
                smooth: false
                cache: false
                source: ""
                visible: source != ""
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: app.tr("meetHint") + "\n\n" + app.tr("meetSameNetwork")
            }

            Item { width: 1; height: Theme.paddingLarge }
        }

        VerticalScrollDecorator {}
    }
}
