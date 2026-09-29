import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar

// Steht vor allem anderen, solange der Dienst "locked" meldet.
Page {
    id: seite

    property bool laeuft: false
    property string meldung: fenster.tr("lockedHint")

    // Kein Zurueck-Knopf: dahinter ist nichts, solange gesperrt ist.
    tools: ToolBarLayout { }

    // Qt 4.7 kennt kein xhr.timeout, darum haelt hier ein Zeitgeber die Wacht.
    // Bleibt die Antwort aus, war der Knopf sonst fuer immer tot: "laeuft"
    // blieb auf true, und jedes weitere Tippen lief in die Sperre oben in
    // versuchen(). Genau so stand das N9 nach dem Neustart des Dienstes still.
    Timer {
        id: wache
        interval: 90000
        onTriggered: {
            if (!seite.laeuft)
                return
            seite.laeuft = false
            fenster.entsperrtGerade = false
            nachfrage.stop()
            seite.meldung = fenster.tr("unlockNoAnswer")
        }
    }

    // Neben dem POST eine eigene Nachfrage. Der Dienst war schon entsperrt
    // und lief -- nur die Antwort auf das POST kam nicht an, und die Seite
    // stand fuer immer auf "wird geprueft". Worauf es ankommt, ist nicht die
    // Antwort, sondern der Zustand: ist er aufgesperrt, geht es weiter,
    // gleichgueltig ob der Rueckruf je kommt.
    Timer {
        id: nachfrage
        interval: 1500
        repeat: true
        onTriggered: {
            if (!seite.laeuft) {
                nachfrage.stop()
                return
            }
            Briar.status(function(antwort) {
                if (!seite.laeuft || antwort.error || antwort.locked)
                    return
                nachfrage.stop()
                wache.stop()
                seite.laeuft = false
                fenster.entsperrtGerade = false
            fenster.entsperrt()
            })
        }
    }

    function versuchen() {
        if (seite.laeuft || feld.text.length === 0)
            return
        seite.laeuft = true
        fenster.entsperrtGerade = true
        seite.meldung = fenster.tr("unlockWorking")
        wache.restart()
        nachfrage.restart()
        Briar.unlock(feld.text, function(antwort) {
            wache.stop()
            nachfrage.stop()
            seite.laeuft = false
            fenster.entsperrtGerade = false
            if (antwort.error) {
                seite.meldung = antwort.error.indexOf("antwortet nicht") >= 0
                                ? fenster.tr("unlockNoAnswer")
                                : fenster.tr("unlockWrong")
                feld.text = ""
                return
            }
            fenster.entsperrt()
        })
    }

    Column {
        anchors { fill: parent; margins: 24 }
        spacing: 20

        Item { width: 1; height: 24 }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            font.pixelSize: 28
            font.bold: true
            text: fenster.tr("lockedTitle")
        }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            wrapMode: Text.Wrap
            font.pixelSize: 18
            color: "#a0a0a0"
            text: seite.meldung
        }

        TextField {
            id: feld
            width: parent.width
            placeholderText: fenster.tr("passwordField")
            echoMode: TextInput.Password
            enabled: !seite.laeuft
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            Keys.onReturnPressed: seite.versuchen()
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("unlockAction")
            enabled: !seite.laeuft && feld.text.length > 0
            onClicked: seite.versuchen()
        }

        // Der einzige Weg heraus, wenn das Passwort weg ist -- ohne es ist die
        // Datei nicht zu oeffnen, und ein Hintertuerchen waere genau das, was
        // hier niemand will.
        Label {
            textFormat: Text.PlainText
            width: parent.width
            wrapMode: Text.Wrap
            font.pixelSize: 18
            color: "#a0a0a0"
            text: fenster.tr("forgotPassword")
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: fenster.tr("deleteAccount")
            enabled: !seite.laeuft
            onClicked: kontoLoeschen.open()
        }
    }

    QueryDialog {
        id: kontoLoeschen
        titleText: fenster.tr("deleteAccount")
        message: fenster.tr("deleteAccountAsk")
        acceptButtonText: fenster.tr("deleteAccount")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.deleteAccount(function() {
            // Der Dienst beendet sich dabei; wir starten ihn neu und finden
            // dann ein leeres Geraet vor.
            fenster.gesperrt = false
            dienst.starten()
            fenster.aktualisieren()
            pageStack.replace(Qt.resolvedUrl("ContactsPage.qml"))
        })
    }
}
