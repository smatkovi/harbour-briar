import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Passwort setzen, aendern oder aufheben.
//
// Die Warnung steht bewusst gross und vor dem Feld: ein vergessenes Passwort
// ist nicht wiederherzustellen. Das gilt bei Briar genauso, und es zu
// verschweigen waere schlechter als es zu sagen.
Page {
    id: page
    allowedOrientations: Orientation.All

    property bool busy: false
    property string message: app.status && app.status.encrypted
                             ? app.tr("passwordIsSet") : app.tr("passwordNotSet")

    function uebernehmen() {
        if (page.busy)
            return
        if (eins.text !== zwei.text) {
            page.message = app.tr("passwordMismatch")
            return
        }
        page.busy = true
        Briar.setPassword(eins.text, function(answer) {
            page.busy = false
            if (answer.error) {
                page.message = answer.error
                return
            }
            eins.text = ""
            zwei.text = ""
            app.refresh()
            page.message = answer.encrypted ? app.tr("passwordIsSet")
                                            : app.tr("passwordNotSet")
        })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: spalte.height + Theme.paddingLarge

        Column {
            id: spalte
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: app.tr("passwordSetTitle") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeSmall
                text: app.tr("passwordWhy")
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
                color: Theme.secondaryHighlightColor
                font.pixelSize: Theme.fontSizeExtraSmall
                text: page.message
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.tr("passwordSave")
                enabled: !page.busy && eins.text.length > 0
                onClicked: page.uebernehmen()
            }

            // Aufheben ist ausdruecklich moeglich: sonst waere ein
            // vergessenes Passwort bei noch laufendem Dienst eine Sackgasse.
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.tr("passwordRemove")
                visible: app.status && app.status.encrypted
                enabled: !page.busy
                onClicked: {
                    eins.text = ""
                    zwei.text = ""
                    page.uebernehmen()
                }
            }
        }
    }
}
