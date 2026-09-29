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
    /// Was die Nachfrage zuletzt gesehen hat -- steht klein unter der
    /// Meldung, damit ein Haenger sich selbst erklaert.
    property string hinweis: ""

    // Zwei Wege ohne Passwort:
    //  * der Schluesselbund (Sailfish Secrets): liegt das Passwort dort, wird
    //    er gleich beim Aufbau der Seite gefragt -- so wie Storeman es haelt.
    //    Ob und wie er den Benutzer prueft, entscheidet der Geheimnisdienst
    //    selbst mit seinem eigenen Dialog; die App fragt nicht vorher noch
    //    einmal nach Sperrcode oder Fingerabdruck. Scheitert er oder wischt
    //    der Benutzer den Dialog weg, bleibt das Passwort. Ein Schalter setzt
    //    ihn fuer diese Sitzung aus (app.schluesselbundPause).
    //  * das Geraeteschloss mit der einmaligen Marke -- nur wenn diese App
    //    gerade selbst zugesperrt hat und kein Schluesselbund im Spiel ist:
    //    org.nemomobile.devicelock fragt Fingerabdruck oder Geraetecode ab,
    //    und die Marke geht an den Dienst zurueck. Nach einem Neustart des
    //    Dienstes ist der Speicher versiegelt, dann hilft nur das Passwort.
    property bool schluesselbundAktiv: app.schluesselbundDa && !app.schluesselbundPause
    property bool mitSchlossMoeglich: !app.schluesselbundDa
                                      && app.sperrMarke.length > 0
                                      && pruefer.availableMethods !== 0

    // Der Schluesselbund antwortet nebenher.
    Connections {
        target: Schluesselbund
        onGefunden: {
            // Auch hier die Nachfrage: der Schluesselbund und das
            // Geraeteschloss gehen nicht ueber versuchen(), und genau dort
            // blieb die Seite auf "wird geprueft" stehen.
            page.busy = true
            nachfrage.restart()
            Briar.unlock(passwort, function(answer) {
                nachfrage.stop()
                page.busy = false
                if (answer.error) {
                    page.message = app.tr("unlockWrong")
                    return
                }
                app.entsperrt()
            })
        }
        onFehlgeschlagen: {
            nachfrage.stop()
            page.busy = false
            // Kein Vorwurf und kein Raetsel: es bleibt das Passwort. Gemerkt
            // wird der Fehlschlag trotzdem -- glueckt gleich das Tippen, legen
            // wir das Passwort neu in den Schluesselbund.
            page.schluesselbundVersagt = true
            page.message = app.tr("unlockFallback")
            feld.forceActiveFocus()
        }
    }

    /// Den Schluesselbund fragen. Er prueft den Benutzer selbst, wenn er es
    /// fuer noetig haelt, und antwortet ueber die Connections oben.
    function schluesselbund() {
        if (page.busy)
            return
        page.busy = true
        page.message = app.tr("keychainWaiting")
        nachfrage.restart()
        Schluesselbund.holen()
    }

    /// Sobald die Seite steht und im Schluesselbund etwas liegt: ihn gleich
    /// fragen. Glueckt das, geht die App von selbst auf -- ein Schritt, kein
    /// Knopf, keine eigene Abfrage davor.
    Component.onCompleted: {
        // Das Tippen bleibt immer moeglich: der Fokus geht ins Feld, auch
        // wenn daneben der Geheimnisdienst fragt. Wer dessen Dialog wegwischt,
        // gibt einfach das Passwort ein.
        feld.forceActiveFocus()
        if (page.schluesselbundAktiv)
            vonSelbst.start()
    }

    Timer {
        id: vonSelbst
        interval: 250
        onTriggered: page.schluesselbund()
    }

    // Nur fuer die Marke: das Geraeteschloss prueft, der Dienst bekommt die
    // Marke zurueck. Dieselbe kurze Kennung wie frueher -- ein ganzer
    // uebersetzter Satz ist kein Pruefcode, damit kam die Abfrage gar nicht.
    Authenticator {
        id: pruefer
        onAuthenticated: {
            if (app.sperrMarke.length === 0) {
                // Schloss bestanden, aber keine Marke mehr: sagen, statt stumm
                // stehenzubleiben.
                page.message = app.tr("unlockFallback")
                feld.forceActiveFocus()
                return
            }
            page.busy = true
            nachfrage.restart()
            Briar.unlock2(app.sperrMarke, function(answer) {
                nachfrage.stop()
                page.busy = false
                if (answer.error) {
                    page.message = app.tr("unlockWrong")
                    return
                }
                app.sperrMarke = ""
                app.entsperrt()
            })
        }
        onAborted: page.message = app.tr("lockedHint")
    }

    // Neben dem POST eine eigene Nachfrage. Am N9 kam es vor, dass der Dienst
    // laengst entsperrt war und lief, waehrend die Antwort auf das POST nicht
    // ankam -- die Seite stand dann fuer immer auf "wird geprueft". Worauf es
    // ankommt, ist nicht die Antwort, sondern der Zustand.
    Timer {
        id: nachfrage
        interval: 1500
        repeat: true
        onTriggered: {
            if (!page.busy) {
                nachfrage.stop()
                return
            }
            Briar.status(function(antwort) {
                if (!page.busy)
                    return
                // Sagen, woran es liegt, statt stumm "wird geprueft" stehen
                // zu lassen: ein Mensch kann damit etwas anfangen, und ich
                // muss nicht raten.
                page.hinweis = antwort.error
                               ? "Dienst: " + antwort.error
                               : (antwort.locked
                                  ? "Dienst wartet noch auf das Passwort"
                                  : "")
                if (antwort.error || antwort.locked)
                    return
                nachfrage.stop()
                page.busy = false
                // Ohne das schiebt die naechste Auffrischung die Seite
                // gleich wieder davor -- der Dienst ist offen, die App
                // glaubt aber weiter, sie sei gesperrt.
                app.entsperrt()
            })
        }
    }

    function versuchen() {
        if (page.busy || feld.text.length === 0)
            return
        page.busy = true
        page.message = app.tr("unlockWorking")
        nachfrage.restart()
        Briar.unlock(feld.text, function(answer) {
            page.busy = false
            nachfrage.stop()
            if (answer.error) {
                // Ein ausbleibender Dienst ist kein falsches Passwort -- wer
                // das verwechselt, loescht am Ende sein Konto.
                page.message = answer.error.indexOf("antwortet nicht") >= 0
                               ? app.tr("unlockNoAnswer")
                               : app.tr("unlockWrong")
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
            app.entsperrt()
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

        // Was der Dienst gerade sagt, wenn es haengt -- damit ein Haenger
        // sich selbst erklaert.
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            visible: page.hinweis.length > 0
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.highlightColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: page.hinweis
        }

        // Der Schluesselbund: fuer diese Sitzung aussetzen, oder noch einmal
        // fragen, wenn sein Dialog weggewischt wurde.
        Column {
            visible: app.schluesselbundDa
            width: parent.width
            spacing: Theme.paddingSmall

            TextSwitch {
                text: app.tr("keychainSkip")
                description: app.tr("keychainSkipHint")
                checked: app.schluesselbundPause
                automaticCheck: false
                enabled: !page.busy
                onClicked: {
                    app.schluesselbundPause = !app.schluesselbundPause
                    if (app.schluesselbundPause) {
                        page.message = app.tr("lockedHint")
                        feld.forceActiveFocus()
                    } else {
                        page.schluesselbund()
                    }
                }
            }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !app.schluesselbundPause
                text: app.tr("keychainAsk")
                enabled: !page.busy
                onClicked: page.schluesselbund()
            }
        }

        // Mit dem Geraeteschloss statt mit dem Passwort -- nur wenn diese App
        // gerade selbst zugesperrt hat, das Telefon ein Schloss kennt und kein
        // Schluesselbund im Spiel ist.
        Column {
            visible: page.mitSchlossMoeglich
            width: parent.width
            spacing: Theme.paddingSmall

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.tr("unlockWithDevice")
                enabled: !page.busy
                onClicked: pruefer.authenticate("briar-unlock")
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

}
