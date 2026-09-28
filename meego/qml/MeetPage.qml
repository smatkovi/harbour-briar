import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings
import Briar 1.0

// Zwei Geräte nebeneinander: BQP, dasselbe Verfahren wie in Briar auf
// Android. Jedes Gerät zeigt einen Code und liest den des anderen; danach
// steht der Kontakt, ohne dass ein Link durch fremde Hände geht.
//
// Seit 0.33.0 steht hier ein Sucherbild, und es liest selbst mit: jedes
// Kamerabild geht durch quirc, kein Foto, kein zweiter Schritt. Das
// QML-Kameraelement bleibt auf diesen Geräten weiter schwarz -- sein Unterbau
// camerabin kommt nicht über PAUSED hinaus --, aber die Kamera selbst liefert
// sehr wohl: nachgemessen gibt subdevsrc2 Rahmen in UYVY, und dort ist die
// Helligkeit jedes zweite Byte, also genau das Feld, das quirc will. Siehe
// meego/sucher.h.
//
// Geht die Kette wider Erwarten nicht an, erscheinen die beiden alten Knöpfe:
// mit der Kamera-App fotografieren, hier lesen.
Page {
    id: seite

    property string eigenerCode: ""
    // Ein Code, den die Scanseite schon gelesen hat.
    property string gescannt: ""
    property string meldung: fenster.tr("meetScanning")
    // 0 = zeigen und suchen, 1 = gelesen, warten, 2 = fertig, 3 = gescheitert
    property int lage: 0
    property int kontakteVorher: 0
    property bool wartetAufFoto: false

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        ToolIcon {
            platformIconId: "toolbar-refresh"
            onClicked: seite.starten()
        }
    }

    Component.onCompleted: seite.starten()
    Component.onDestruction: {
        sucher.anhalten()
        Briar.bqpStop(function() {})
    }

    onStatusChanged: {
        if (status !== PageStatus.Active) {
            sucher.anhalten()
            return
        }
        if (seite.lage === 0)
            sucher.starten()
        if (seite.wartetAufFoto) {
            seite.wartetAufFoto = false
            seite.lesen()
        }
    }

    function starten() {
        seite.lage = 0
        seite.meldung = fenster.tr("meetScanning")
        seite.kontakteVorher = fenster.zustand.contacts
                ? fenster.zustand.contacts.length : 0
        Briar.bqpStart(function(antwort) {
            if (antwort.error || !antwort.payload) {
                seite.lage = 3
                seite.meldung = antwort.error ? antwort.error
                                              : fenster.tr("meetFailed")
                return
            }
            seite.eigenerCode = antwort.payload
            qrBild.source = "file://" + QrCode.imageForHex(antwort.payload, 360)
            // Was die Scanseite schon gelesen hat, geht sofort hinaus.
            if (seite.gescannt.length > 0) {
                var code = seite.gescannt
                seite.gescannt = ""
                seite.uebergeben(code)
            }
        })
    }

    function lesen() {
        if (kamera.alterDesLetztenFotos() < 0) {
            seite.meldung = fenster.tr("scanNoPhoto")
            return
        }
        var hex = kamera.letztenCodeAlsHex()
        if (!hex) {
            seite.meldung = fenster.tr("scanNothing")
            return
        }
        if (!Briar.istBqp(hex)) {
            seite.meldung = fenster.tr("scanNotBriar")
            return
        }
        seite.uebergeben(hex)
    }

    function uebergeben(hex) {
        seite.lage = 1
        seite.meldung = fenster.tr("meetWaiting")
        geduld.restart()
        Briar.bqpScan(hex, function(antwort) {
            if (antwort.error) {
                seite.lage = 3
                seite.meldung = antwort.error
            }
        })
    }

    // Der Dienst gibt nach einer Minute auf; die Seite darf nicht ewig warten.
    Timer {
        id: geduld
        interval: 75000
        repeat: false
        onTriggered: {
            if (seite.lage === 1) {
                seite.lage = 3
                seite.meldung = fenster.tr("meetFailed")
            }
        }
    }

    // Nachschauen, ob der Kontakt schon steht.
    Timer {
        interval: 2000
        repeat: true
        running: seite.status === PageStatus.Active && seite.lage < 2
        onTriggered: fenster.aktualisieren()
    }

    onLageChanged: if (seite.lage !== 0) sucher.anhalten()

    Connections {
        target: fenster
        onZustandChanged: {
            if (seite.lage >= 2) return
            var jetzt = fenster.zustand.contacts
                    ? fenster.zustand.contacts.length : 0
            if (jetzt > seite.kontakteVorher) {
                seite.lage = 2
                seite.meldung = fenster.tr("meetDone")
                        + fenster.zustand.contacts[jetzt - 1].name
            }
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: spalte.height + 32
        clip: true

        Column {
            id: spalte
            anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
            spacing: 16

            Label {
                text: fenster.tr("meetTitle")
                font.pixelSize: 32
                color: "white"
            }

            Label {
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 20
                color: seite.lage === 3 ? "#ff6666" : "#a0d0ff"
                text: seite.meldung
            }

            Image {
                id: qrBild
                anchors.horizontalCenter: parent.horizontalCenter
                width: 360
                height: 360
                fillMode: Image.PreserveAspectFit
                smooth: false
                cache: false
                source: ""
                visible: source != ""
            }

            // Der Sucher. Er liest selbst mit -- jedes Kamerabild geht durch
            // quirc, kein Foto, kein zweiter Schritt. Geht die Kette nicht
            // an (gemessen laeuft sie, aber verlassen wollen wir uns nicht
            // darauf), bleibt es bei den beiden Knoepfen darunter.
            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                // Hochkant, weil das Bild nach der Drehung hochkant ist.
                width: 360
                height: sucher.laeuft ? 420 : 0
                visible: height > 0
                color: "black"

                Sucher {
                    id: sucher
                    anchors.fill: parent
                    sucheNach: "bqp"
                    onCodeGelesen: {
                        if (seite.lage !== 0)
                            return
                        seite.uebergeben(hex)
                    }
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !sucher.laeuft
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
                visible: !sucher.laeuft
                text: fenster.tr("scanReadPhoto")
                onClicked: seite.lesen()
            }

            Label {
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 18
                color: "#b0b0b0"
                text: fenster.tr("meetHint") + "\n\n" + fenster.tr("meetSameNetwork")
            }
        }
    }
}
