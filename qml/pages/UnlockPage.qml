import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Steht vor allem anderen, solange der Dienst "locked" meldet. Ohne das
// Passwort gibt es nichts zu sehen -- Kontakte, Schluessel und Nachrichten
// liegen verschluesselt auf der Platte.
Page {
    id: page
    allowedOrientations: Orientation.All

    // Kein Zurueck: hinter dieser Seite ist nichts, solange gesperrt ist.
    backNavigation: false

    property bool busy: false
    property string message: app.tr("lockedHint")

    function versuchen() {
        if (page.busy || feld.text.length === 0)
            return
        page.busy = true
        page.message = app.tr("unlockWorking")
        Briar.unlock(feld.text, function(answer) {
            page.busy = false
            if (answer.error) {
                page.message = app.tr("unlockWrong")
                feld.text = ""
                feld.forceActiveFocus()
                return
            }
            // Der Dienst faehrt jetzt hoch; die Oberflaeche holt sich den
            // Zustand beim naechsten Durchlauf von selbst.
            app.locked = false
            app.refresh()
            pageStack.pop()
        })
    }

    Column {
        width: parent.width
        spacing: Theme.paddingLarge

        PageHeader { title: app.tr("lockedTitle") }

        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryHighlightColor
            font.pixelSize: Theme.fontSizeSmall
            text: page.message
        }

        PasswordField {
            id: feld
            width: parent.width
            label: app.tr("passwordField")
            enabled: !page.busy
            EnterKey.enabled: text.length > 0
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: page.versuchen()
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: app.tr("unlockAction")
            enabled: !page.busy && feld.text.length > 0
            onClicked: page.versuchen()
        }

        // Der einzige Weg heraus, wenn das Passwort weg ist. Es gibt keinen
        // anderen: ohne Passwort ist die Datei nicht zu oeffnen, und ein
        // Hintertuerchen waere genau das, was hier niemand will. Briar bietet
        // an derselben Stelle dasselbe an.
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: app.tr("forgotPassword")
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: app.tr("deleteAccount")
            enabled: !page.busy
            onClicked: loeschen.open()
        }
    }

    Dialog {
        id: loeschen
        canAccept: true
        Column {
            width: parent.width
            spacing: Theme.paddingLarge
            DialogHeader { acceptText: app.tr("deleteAccount") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: app.tr("deleteAccountAsk")
            }
        }
        onAccepted: Briar.deleteAccount(function() {
            // Der Dienst beendet sich dabei; die Oberflaeche startet ihn neu
            // und findet dann ein leeres Geraet vor.
            app.locked = false
            Daemon.ensureRunning()
            app.refresh()
            pageStack.replace(Qt.resolvedUrl("MainPage.qml"))
        })
    }

    Component.onCompleted: feld.forceActiveFocus()
}
