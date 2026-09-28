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

    function versuchen() {
        if (seite.laeuft || feld.text.length === 0)
            return
        seite.laeuft = true
        seite.meldung = fenster.tr("unlockWorking")
        Briar.unlock(feld.text, function(antwort) {
            seite.laeuft = false
            if (antwort.error) {
                seite.meldung = fenster.tr("unlockWrong")
                feld.text = ""
                return
            }
            fenster.gesperrt = false
            fenster.aktualisieren()
            pageStack.pop()
        })
    }

    Column {
        anchors { fill: parent; margins: 24 }
        spacing: 20

        Item { width: 1; height: 24 }

        Label {
            width: parent.width
            font.pixelSize: 28
            font.bold: true
            text: fenster.tr("lockedTitle")
        }

        Label {
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
