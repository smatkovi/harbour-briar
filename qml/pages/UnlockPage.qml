import QtQuick 2.0
import Sailfish.Silica 1.0
import org.nemomobile.devicelock 1.0
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
    /// Hat der Schluesselbund gerade versagt? Dann ist die Ablage vermutlich
    /// hinueber (Geraeteschloss entfernt oder neu eingerichtet), und das
    /// getippte Passwort fuellt sie wieder.
    property bool schluesselbundVersagt: false

    // Briar auf Android sperrt mit dem Bildschirmschloss des Telefons auf, nicht
    // mit dem Briar-Passwort (KeyguardManager, Fingerabdruck ueber
    // BiometricPrompt). Das geht hier auch: org.nemomobile.devicelock fragt
    // Fingerabdruck oder Gerätecode ab.
    //
    // Der Dienst weiss davon nichts, also bekommt die App beim Zusperren eine
    // einmalige Marke und gibt sie nach geglueckter Pruefung zurueck. Die Marke
    // liegt nur im Arbeitsspeicher; nach einem Neustart des Dienstes ist der
    // Speicher ohnehin versiegelt, und dann hilft nur das Passwort.
    // Zwei Wege mit dem Telefon:
    //  * die Marke -- nur wenn diese App gerade selbst zugesperrt hat,
    //  * der Schluesselbund -- auch nach einem Neustart, wenn das Passwort dort
    //    hinterlegt ist. Der zweite fragt beim Herausgeben selbst nach dem
    //    Fingerabdruck (DeviceLockVerifyLock), der erste braucht die Pruefung
    //    von uns.
    property bool mitTelefonMoeglich: (app.sperrMarke.length > 0
                                       && pruefer.availableMethods !== 0)
                                      || app.schluesselbundDa

    // Der Schluesselbund antwortet nebenher.
    Connections {
        target: Schluesselbund
        onGefunden: {
            Briar.unlock(passwort, function(answer) {
                page.busy = false
                if (answer.error) {
                    page.message = app.tr("unlockWrong")
                    return
                }
                app.locked = false
                app.refresh()
                pageStack.pop()
            })
        }
        onFehlgeschlagen: {
            page.busy = false
            // Kein Vorwurf und kein Raetsel: es bleibt das Passwort. Gemerkt
            // wird der Fehlschlag trotzdem -- glueckt gleich das Tippen, legen
            // wir das Passwort neu in den Schluesselbund.
            page.schluesselbundVersagt = true
            page.message = app.tr("unlockFallback")
        }
    }

    Authenticator {
        id: pruefer
        onAuthenticated: {
            page.busy = true
            Briar.unlock2(app.sperrMarke, function(answer) {
                page.busy = false
                if (answer.error) {
                    page.message = app.tr("unlockWrong")
                    return
                }
                app.sperrMarke = ""
                app.locked = false
                app.refresh()
                pageStack.pop()
            })
        }
        onAborted: page.message = app.tr("lockedHint")
    }

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
            // Hat der Schluesselbund vorher versagt, obwohl dort etwas liegen
            // sollte, ist die Ablage hinueber -- das passiert, wenn das
            // Geraeteschloss entfernt oder neu eingerichtet wurde. Das
            // getippte Passwort ist die Gelegenheit, sie wieder zu fuellen;
            // sonst bliebe der Knopf stehen und scheiterte jedes Mal.
            if (page.schluesselbundVersagt && Schluesselbund.verfuegbar) {
                page.schluesselbundVersagt = false
                Schluesselbund.merken(feld.text)
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

        // Mit dem Telefon statt mit dem Passwort -- nur wenn diese App gerade
        // selbst zugesperrt hat und das Telefon ein Schloss kennt.
        Column {
            visible: page.mitTelefonMoeglich
            width: parent.width
            spacing: Theme.paddingSmall

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.tr("unlockWithDevice")
                enabled: !page.busy
                onClicked: {
                    if (app.sperrMarke.length > 0 && pruefer.availableMethods !== 0) {
                        pruefer.authenticate("briar-unlock")
                        return
                    }
                    // Aus dem Schluesselbund: das Herausgeben fragt selbst nach
                    // Fingerabdruck oder Code. Die Antwort kommt als Signal --
                    // wer die Bestaetigung liegen laesst, haelt damit die App
                    // nicht an.
                    page.busy = true
                    page.message = app.tr("unlockWorking")
                    Schluesselbund.holen()
                }
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                horizontalAlignment: Text.AlignHCenter
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                text: app.tr("unlockDeviceHint")
            }
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
