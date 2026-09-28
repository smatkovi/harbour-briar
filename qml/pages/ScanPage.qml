import QtQuick 2.0
import QtMultimedia 5.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Liest den QR-Code der Gegenseite von selbst aus dem Sucherbild -- kein
// Knopf, kein Ausloesen.
//
// Zwei Leser arbeiten hier nebeneinander, und das mit Absicht:
//
//  * Zuerst der Filter der Kamera-App (Amber.QrFilter, dahinter ZXing). Er
//    haengt im Videostrom und bekommt jedes Sucherbild, das ohnehin schon da
//    ist -- kein Foto, keine Datei, kein Skalieren. Deshalb ist die
//    Kamera-App so schnell. Genau so haengt sie ihn ein, nachgesehen in
//    /usr/share/jolla-camera/camera.qml: VideoOutput.source = camera und
//    filters: [ qrFilter ].
//
//  * Findet der nach ein paar Sekunden nichts, kommt zusaetzlich der alte Weg
//    dazu: ein Standbild und unser eigener Leser (quirc, src/quirc). Der ist
//    langsam, aber er geht nachweislich -- am N9 ist er der einzige.
//
// Das Netz ist nicht aus Vorsicht da, sondern aus Erfahrung: ein frueherer
// Versuch mit dem Filter hat an der Jolla nichts erkannt. Woran es lag, ist
// nicht mehr festzustellen; so oder so ist der Sucher nie schlechter als
// vorher, und im guten Fall sofort.
//
// Die Bilder des zweiten Weges wandern in den Zwischenspeicher und werden nach
// dem Lesen sofort weggeraeumt, sonst laeuft er voll.
Page {
    id: page
    allowedOrientations: Orientation.Portrait

    property string message: app.tr("scanLiveHint")
    // Laeuft gerade ein Bild durch den Leser? Dann kein zweites schiessen.
    property bool busy: false
    property int zaehler: 0

    /// Der Filter der Kamera-App, oder null, wenn das Paket
    /// qr-filter-qml-plugin auf diesem Geraet fehlt.
    property var leser: null
    /// Ist schon einmal etwas durchgegangen? Dann keine zweite Seite aufmachen.
    property bool fertig: false
    /// Notausgang, falls die Kamera die kleine Aufnahmegroesse nicht mag.
    property bool grosseAufnahme: false
    property int fehlschlaege: 0

    // Der Filter steht in einer eigenen Datei, weil sein Import nur dort
    // vorhanden ist, wo das Paket liegt. Stuende er hier oben, liesse sich die
    // ganze Seite ohne das Paket nicht mehr laden.
    Component.onCompleted: {
        var bauplan = Qt.createComponent(Qt.resolvedUrl("QrLive.qml"))
        if (bauplan.status !== Component.Ready)
            return
        page.leser = bauplan.createObject(page)
        if (page.leser)
            page.leser.decodeFinished.connect(page.ausFilter)
    }

    Binding {
        target: page.leser
        property: "active"
        value: page.status === PageStatus.Active && !page.fertig
        when: page.leser !== null
    }

    Camera {
        id: camera
        cameraState: Camera.ActiveState
        captureMode: Camera.CaptureStillImage
        focus.focusMode: Camera.FocusContinuous

        imageCapture {
            // Ohne diese Zeile schiesst die Jolla in voller Sensoraufloesung:
            // acht Millionen Bildpunkte, die als JPEG auf die Platte gehen,
            // wieder eingelesen, bis zu viermal weichgezeichnet skaliert und
            // durch quirc geschickt -- alles auf dem Oberflaechenfaden.
            // Solange das laeuft, steht der Sucher und der Autofokus kommt
            // nicht zur Ruhe. Zum Lesen eines QR-Codes reicht ein Bruchteil.
            resolution: page.grosseAufnahme ? Qt.size(-1, -1) : Qt.size(1280, 960)
            onImageSaved: page.lesen(path)
            onCaptureFailed: {
                page.busy = false
                page.message = app.tr("scanLiveHint")
                // Nimmt das Geraet die gewuenschte Groesse nicht an, ist der
                // Fotoweg sonst tot. Nach zwei Fehlschlaegen zurueck auf das,
                // was die Kamera von selbst waehlt.
                page.fehlschlaege++
                if (page.fehlschlaege >= 2)
                    page.grosseAufnahme = true
            }
        }
    }

    VideoOutput {
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: parent.height - footer.height
        source: camera
        fillMode: VideoOutput.PreserveAspectFit
        filters: page.leser ? [ page.leser ] : []
    }

    // Stellt die Meldung nach einem fremden Code wieder auf den Anfangstext.
    Timer {
        id: zuruecksetzen
        interval: 3000
        onTriggered: if (!page.fertig) page.message = app.tr("scanLiveHint")
    }

    // Gibt dem Filter einen Vorsprung. Erkennt er in dieser Zeit nichts, kommt
    // der Fotoweg dazu. Ohne Filter faengt der sofort an.
    Timer {
        id: vorsprung
        interval: 4000
        running: page.status === PageStatus.Active && page.leser !== null
    }

    // Der Taktgeber des Fotoweges. Nur wenn die Seite vorn ist und der Leser
    // frei ist -- sonst stapeln sich Aufnahmen, die niemand mehr braucht.
    Timer {
        interval: 1500
        repeat: true
        running: page.status === PageStatus.Active && !page.fertig
                 && (page.leser === null || !vorsprung.running)
        onTriggered: {
            if (page.busy || !camera.imageCapture.ready)
                return
            page.busy = true
            page.zaehler++
            camera.imageCapture.captureToLocation(
                StandardPaths.temporary + "/briar-qr-" + page.zaehler + ".jpg")
        }
    }

    // Der Filter hat etwas gelesen. ZXing gibt Text zurueck; ein BQP-Rumpf ist
    // aber binaer, und Briar bildet ihn auf Android ueber ISO-8859-1 ab. Genau
    // diesen Weg gehen wir zurueck. Steht darin ein Zeichen ueber 255, hat der
    // Leser die Bytes als etwas anderes gedeutet -- dann ist hier nichts zu
    // holen, und der Fotoweg macht es richtig.
    function ausFilter(text) {
        if (page.fertig || !text)
            return
        var hex = Briar.textZuHex(text)
        if (hex === null) {
            vorsprung.stop()
            return
        }
        if (!page.verarbeiten(hex)) {
            if (page.leser)
                page.leser.clearResult()
        }
    }

    // Ein frisches Bild ist da: lesen, wegraeumen, entscheiden.
    function lesen(pfad) {
        var hex = QrCode.decodeHexAndRemove(pfad)
        page.busy = false
        if (!hex)
            return
        page.verarbeiten(hex)
    }

    /// Entscheidet, was hinter den Bytes steckt. Gibt true zurueck, wenn die
    /// Seite gewechselt hat -- dann ist hier Schluss.
    function verarbeiten(hex) {
        if (page.fertig)
            return true
        // Ein Code zum persoenlichen Treffen (BQP) steckt voller Bytes, kein
        // Link. Dafuer gibt es eine eigene Seite -- also dorthin, samt dem
        // schon gelesenen Code, damit niemand zweimal zielen muss.
        if (Briar.istBqp(hex)) {
            page.fertig = true
            page.message = app.tr("scanIsMeetCode")
            pageStack.replace(Qt.resolvedUrl("MeetPage.qml"), { "gescannt": hex })
            return true
        }
        var text = Briar.hexZuText(hex)
        var found = Briar.qrParse(text)
        if (!found || !found.link) {
            // Ein Code, aber keiner von Briar -- weiterschauen statt
            // stehenbleiben. Die Meldung geht nach kurzer Zeit wieder weg,
            // sonst stuende sie unter dem Sucher, waehrend laengst richtig
            // gezielt wird.
            page.message = app.tr("scanNotBriar")
            zuruecksetzen.restart()
            return false
        }
        page.fertig = true
        pageStack.replace(Qt.resolvedUrl("AddContactPage.qml"), {
            "prefillLink": found.link,
            "prefillAddress": found.address,
            "prefillBluetooth": found.bluetooth,
            "prefillOnion": found.onion
        })
        return true
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
