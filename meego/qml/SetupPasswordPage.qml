import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar

// Der zweite Schritt der Kontoanlage, wie bei Briar (AUTHOR_NAME,
// SET_PASSWORD, ...): das Konto entsteht erst am Ende, mit beidem.
Page {
    id: seite

    property string wunschname: ""
    property bool laeuft: false
    property string meldung: ""
    property real staerke: Briar.passwordStrength(eins.text)

    tools: ToolBarLayout { }

    function anlegen() {
        if (seite.laeuft)
            return
        if (seite.staerke < Briar.PASSWORD_MIN_STRENGTH) {
            seite.meldung = fenster.tr("passwordWeak")
            return
        }
        if (eins.text !== zwei.text) {
            seite.meldung = fenster.tr("passwordMismatch")
            return
        }
        seite.laeuft = true
        Briar.createIdentity(seite.wunschname, function(antwort) {
            if (antwort.error) {
                seite.laeuft = false
                seite.meldung = antwort.error
                return
            }
            Briar.setPassword("", eins.text, function(zweite) {
                seite.laeuft = false
                if (zweite.error) {
                    seite.meldung = Briar.klartext(zweite.error)
                    return
                }
                fenster.aktualisieren()
                pageStack.pop()
            })
        })
    }

    Flickable {
        anchors { fill: parent; margins: 20 }
        contentHeight: spalte.height

        Column {
            id: spalte
            width: parent.width
            spacing: 14

            Label {
                textFormat: Text.PlainText
                width: parent.width
                font.pixelSize: 26
                font.bold: true
                text: fenster.tr("setupPassword")
            }

            Label {
                textFormat: Text.PlainText
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 18
                color: "#a0a0a0"
                text: fenster.tr("setupPasswordWhy")
            }

            Label {
                textFormat: Text.PlainText
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 18
                color: "#ffb03b"
                text: fenster.tr("passwordWarn")
            }

            TextField {
                id: eins
                width: parent.width
                placeholderText: fenster.tr("passwordField")
                echoMode: TextInput.Password
                enabled: !seite.laeuft
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            // Briars Staerkeanzeige mit derselben Formel.
            Item {
                width: parent.width
                height: 28
                visible: eins.text.length > 0
                Rectangle {
                    id: balken
                    width: parent.width
                    height: 8
                    radius: 4
                    color: "#333333"
                    Rectangle {
                        width: parent.width * seite.staerke
                        height: parent.height
                        radius: parent.radius
                        color: seite.staerke >= 0.75 ? "#4caf50"
                             : seite.staerke >= Briar.PASSWORD_MIN_STRENGTH ? "#ffb03b"
                             : "#ff6b6b"
                    }
                }
                Label {
                    textFormat: Text.PlainText
                    anchors { top: balken.bottom; topMargin: 2 }
                    font.pixelSize: 14
                    color: "#a0a0a0"
                    text: seite.staerke >= 0.75 ? fenster.tr("strengthStrong")
                        : seite.staerke >= Briar.PASSWORD_MIN_STRENGTH ? fenster.tr("strengthMedium")
                        : fenster.tr("strengthWeak")
                }
            }

            TextField {
                id: zwei
                width: parent.width
                placeholderText: fenster.tr("passwordAgain")
                echoMode: TextInput.Password
                enabled: !seite.laeuft
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            Label {
                textFormat: Text.PlainText
                width: parent.width
                wrapMode: Text.Wrap
                horizontalAlignment: Text.AlignHCenter
                font.pixelSize: 18
                color: "#ff6b6b"
                text: seite.meldung
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: fenster.tr("createIdentity")
                enabled: !seite.laeuft && eins.text.length > 0 && zwei.text.length > 0
                onClicked: seite.anlegen()
            }
        }
    }
}
