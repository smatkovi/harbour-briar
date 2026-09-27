import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar

// Passwort setzen, aendern oder aufheben. Die Warnung steht vor dem Feld:
// ein vergessenes Passwort ist nicht wiederherzustellen.
Page {
    id: seite

    property bool laeuft: false
    property string meldung: fenster.zustand && fenster.zustand.encrypted
                             ? fenster.tr("passwordIsSet")
                             : fenster.tr("passwordNotSet")

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    function uebernehmen() {
        if (seite.laeuft)
            return
        if (eins.text !== zwei.text) {
            seite.meldung = fenster.tr("passwordMismatch")
            return
        }
        seite.laeuft = true
        Briar.setPassword(eins.text, function(antwort) {
            seite.laeuft = false
            if (antwort.error) {
                seite.meldung = antwort.error
                return
            }
            eins.text = ""
            zwei.text = ""
            fenster.aktualisieren()
            seite.meldung = antwort.encrypted ? fenster.tr("passwordIsSet")
                                              : fenster.tr("passwordNotSet")
        })
    }

    Flickable {
        anchors { fill: parent; margins: 20 }
        contentHeight: spalte.height

        Column {
            id: spalte
            width: parent.width
            spacing: 16

            Label {
                width: parent.width
                font.pixelSize: 26
                font.bold: true
                text: fenster.tr("passwordSetTitle")
            }

            Label {
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 18
                color: "#a0a0a0"
                text: fenster.tr("passwordWhy")
            }

            Label {
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

            TextField {
                id: zwei
                width: parent.width
                placeholderText: fenster.tr("passwordAgain")
                echoMode: TextInput.Password
                enabled: !seite.laeuft
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            Label {
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: 16
                color: "#a0a0a0"
                text: seite.meldung
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: fenster.tr("passwordSave")
                enabled: !seite.laeuft && eins.text.length > 0
                onClicked: seite.uebernehmen()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: fenster.tr("passwordRemove")
                visible: fenster.zustand && fenster.zustand.encrypted
                enabled: !seite.laeuft
                onClicked: { eins.text = ""; zwei.text = ""; seite.uebernehmen() }
            }
        }
    }
}
