import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Der zweite Schritt der Kontoanlage, wie bei Briar: dort ist die Reihenfolge
// AUTHOR_NAME, SET_PASSWORD, ... und das Konto entsteht erst am Ende, mit
// beidem. Ein Passwort ist nicht optional; ohne eines laege alles offen auf
// dem Geraet.
Page {
    id: page
    allowedOrientations: Orientation.All
    backNavigation: false

    property string wunschname: ""
    property bool busy: false
    property string message: ""

    property real staerke: Briar.passwordStrength(eins.text)

    function anlegen() {
        if (page.busy)
            return
        if (page.staerke < Briar.PASSWORD_MIN_STRENGTH) {
            page.message = app.tr("passwordWeak")
            return
        }
        if (eins.text !== zwei.text) {
            page.message = app.tr("passwordMismatch")
            return
        }
        page.busy = true
        // Erst das Konto, dann sofort das Passwort -- bei Briar entsteht das
        // Konto ebenfalls erst am Ende dieses Schrittes, und ohne Passwort
        // entsteht dort ueberhaupt keines.
        Briar.createIdentity(page.wunschname, function(answer) {
            if (answer.error) {
                page.busy = false
                page.message = answer.error
                return
            }
            Briar.setPassword("", eins.text, function(zweite) {
                page.busy = false
                if (zweite.error) {
                    page.message = Briar.klartext(zweite.error)
                    return
                }
                // Gleich ins Geraeteschloss, wenn gewuenscht: dann genuegt
                // kuenftig der Fingerabdruck.
                if (Schluesselbund.verfuegbar && imTelefon.checked) {
                    Schluesselbund.merken(eins.text)
                    app.schluesselbundDa = true
                }
                app.refresh()
                pageStack.pop()
            })
        })
    }

    Column {
        width: parent.width
        spacing: Theme.paddingLarge

        PageHeader { title: app.tr("setupPassword") }

        TextSwitch {
            id: imTelefon
            visible: Schluesselbund.verfuegbar
            text: app.tr("keepInDevice")
            description: app.tr("keepInDeviceHint")
            checked: true
        }

        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeSmall
            text: app.tr("setupPasswordWhy")
        }

        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.highlightColor
            font.pixelSize: Theme.fontSizeSmall
            text: app.tr("passwordWarn")
        }

        PasswordField {
            id: eins
            width: parent.width
            label: app.tr("passwordField")
            enabled: !page.busy
        }

        // Briars Staerkeanzeige, mit derselben Formel und denselben Schwellen.
        Item {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            height: balken.height + beschriftung.height + Theme.paddingSmall
            visible: eins.text.length > 0

            Rectangle {
                id: balken
                width: parent.width
                height: Theme.paddingSmall
                radius: height / 2
                color: Theme.secondaryHighlightColor
                Rectangle {
                    width: parent.width * page.staerke
                    height: parent.height
                    radius: parent.radius
                    color: page.staerke >= 0.75 ? "#4caf50"
                         : page.staerke >= Briar.PASSWORD_MIN_STRENGTH ? Theme.highlightColor
                         : Theme.errorColor
                }
            }
            Label {
                id: beschriftung
                anchors { top: balken.bottom; topMargin: Theme.paddingSmall }
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: page.staerke >= 0.75 ? app.tr("strengthStrong")
                    : page.staerke >= Briar.PASSWORD_MIN_STRENGTH ? app.tr("strengthMedium")
                    : app.tr("strengthWeak")
            }
        }

        PasswordField {
            id: zwei
            width: parent.width
            label: app.tr("passwordAgain")
            enabled: !page.busy
        }

        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.errorColor
            font.pixelSize: Theme.fontSizeSmall
            text: page.message
        }

        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: app.tr("createIdentity")
            enabled: !page.busy && eins.text.length > 0 && zwei.text.length > 0
            onClicked: page.anlegen()
        }
    }
}
