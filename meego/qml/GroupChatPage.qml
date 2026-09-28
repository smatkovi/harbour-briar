import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    property string gruppe: ""
    property string name: ""
    property bool ersteller: false
    property bool aufgeloest: false
    property variant nachrichten: []
    property variant mitglieder: []
    /// Wem gegenueber sich die Beziehung in dieser Gruppe noch zeigen laesst.
    property variant zeigbar: []

    function neuLaden() {
        Briar.groupMessages(gruppe, function(antwort) {
            if (!antwort.error) {
                seite.nachrichten = antwort.messages
                seite.mitglieder = antwort.members
                seite.zeigbar = antwort.revealable ? antwort.revealable : []
                seite.aufgeloest = antwort.dissolved ? true : false
            }
        })
    }

    Component.onCompleted: {
        neuLaden()
        // Melden, dass die Gruppe offen war: das raeumt den Ungelesen-Zaehler
        // und den Hinweis auf die letzte Antwort der Gegenseite weg. Am N9
        // wurde das bisher nie gemeldet, also blieb beides stehen.
        Briar.markRead({ "group": seite.gruppe }, function() { fenster.aktualisieren() })
    }

    Timer {
        interval: 3000
        running: seite.status === PageStatus.Active
        repeat: true
        onTriggered: seite.neuLaden()
    }

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        Column {
            anchors.verticalCenter: parent.verticalCenter
            Label {
                text: seite.aufgeloest
                      ? seite.name + " (" + fenster.tr("dissolved") + ")"
                      : seite.name + " (" + seite.mitglieder.length + ")"
                color: "white"
                font.pixelSize: 24
            }
            // Die Namen, nicht bloss die Zahl -- die Hilfe verspricht sie, und
            // der Dienst liefert sie mit.
            Label {
                visible: !seite.aufgeloest && seite.mitglieder.length > 0
                text: seite.mitglieder.join(", ")
                color: "#a0a0a0"
                font.pixelSize: 16
                width: 300
                elide: Text.ElideRight
            }
        }
        // Nur wenn es wirklich jemanden gibt -- ein Knopf, der immer auf eine
        // leere Liste fuehrt, hilft niemandem.
        ToolIcon {
            platformIconId: "toolbar-share"
            visible: seite.zeigbar.length > 0
            onClicked: pageStack.push(Qt.resolvedUrl("RevealPage.qml"),
                                      { gruppe: seite.gruppe, name: seite.name,
                                        kandidaten: seite.zeigbar })
        }
        ToolIcon {
            platformIconId: "toolbar-add"
            visible: seite.ersteller
            onClicked: pageStack.push(Qt.resolvedUrl("InvitePage.qml"),
                                      { gruppe: seite.gruppe, name: seite.name })
        }
    }

    ListView {
        id: liste
        anchors { top: parent.top; left: parent.left; right: parent.right; bottom: eingabe.top }
        clip: true
        model: seite.nachrichten
        onCountChanged: positionViewAtEnd()

        // In a group, who wrote a post is half the message: the name stands
        // above every bubble, including one's own.
        delegate: Item {
            width: liste.width
            height: blase.height + absender.height + 16

            property bool eigen: fenster.zustand.identity
                                 && modelData.authorId === fenster.zustand.identity.authorId

            Text {
                id: absender
                anchors {
                    top: parent.top
                    right: eigen ? parent.right : undefined
                    left: eigen ? undefined : parent.left
                    margins: 12
                }
                text: modelData.author
                color: eigen ? "#7fbf7f" : "#95d220"
                font.pixelSize: 18
            }

            Rectangle {
                id: blase
                anchors {
                    top: absender.bottom
                    right: eigen ? parent.right : undefined
                    left: eigen ? undefined : parent.left
                    margins: 10
                }
                width: text.paintedWidth + 28
                height: text.paintedHeight + 22
                radius: 8
                color: eigen ? "#1d4d1d" : "#2a2a2a"

                Text {
                    id: text
                    x: 14
                    y: 11
                    width: liste.width - 48
                    text: modelData.text
                    wrapMode: Text.Wrap
                    color: "white"
                    font.pixelSize: 24
                }
            }

            Text {
                anchors {
                    top: blase.bottom
                    right: eigen ? blase.right : undefined
                    left: eigen ? undefined : blase.left
                }
                text: Strings.shortTime(modelData.timestamp)
                color: "#808080"
                font.pixelSize: 16
            }
        }
    }

    Row {
        id: eingabe
        // In eine aufgeloeste Gruppe geht nichts mehr hinaus.
        visible: !seite.aufgeloest
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        spacing: 8

        TextField {
            id: feld
            width: parent.width - senden.width - 8
            placeholderText: fenster.tr("message")
            Keys.onReturnPressed: senden.clicked()
        }

        Button {
            id: senden
            text: fenster.tr("send")
            width: 140
            enabled: feld.text.length > 0
            onClicked: {
                var text = feld.text
                if (text.length === 0)
                    return
                feld.text = ""
                Briar.sendToGroup(seite.gruppe, text, function(antwort) {
                    if (antwort.error)
                        fenster.fehler = antwort.error
                    seite.neuLaden()
                })
            }
        }
    }
}
