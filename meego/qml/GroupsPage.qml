import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    property variant gruppen: []

    function neuLaden() {
        Briar.groups(function(antwort) {
            if (!antwort.error)
                seite.gruppen = antwort.groups
        })
    }

    Component.onCompleted: neuLaden()

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
        ToolIcon {
            platformIconId: "toolbar-add"
            onClicked: neueGruppe.open()
        }
        ToolIcon {
            platformIconId: "toolbar-refresh"
            onClicked: seite.neuLaden()
        }
    }

    // Lange auf eine Gruppe tippen fragt hier nach. Bisher liess sich am N9
    // eine Gruppe gar nicht entfernen -- und eine aufgeloeste Gruppe waere so
    // fuer immer in der Liste geblieben.
    property string gewaehlt: ""
    property string gewaehltName: ""
    property bool gewaehltErsteller: false

    Menu {
        id: gruppenMenue
        MenuLayout {
            MenuItem {
                text: fenster.tr("invite")
                visible: seite.gewaehltErsteller
                onClicked: pageStack.push(Qt.resolvedUrl("InvitePage.qml"),
                                          { gruppe: seite.gewaehlt, name: seite.gewaehltName })
            }
            MenuItem {
                text: fenster.tr("remove")
                onClicked: gruppeEntfernen.open()
            }
        }
    }

    QueryDialog {
        id: gruppeEntfernen
        titleText: fenster.tr("remove")
        message: fenster.tr("removeGroupAsk")
        acceptButtonText: fenster.tr("remove")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.removeGroup(seite.gewaehlt, function() { seite.neuLaden() })
    }

    Sheet {
        id: neueGruppe
        acceptButtonText: fenster.tr("create")
        rejectButtonText: "✕"

        content: Column {
            anchors { fill: parent; margins: 16 }
            spacing: 12

            Label {
                textFormat: Text.PlainText
                text: fenster.tr("newGroup")
                font.pixelSize: 30
                color: "white"
            }

            TextField {
                id: gruppenName
                width: parent.width
                placeholderText: fenster.tr("groupName")
            }
        }

        onAccepted: {
            if (gruppenName.text.length === 0)
                return
            Briar.createGroup(gruppenName.text, function(antwort) {
                if (antwort.error)
                    fenster.fehler = antwort.error
                gruppenName.text = ""
                seite.neuLaden()
            })
        }
    }

    Label {
        id: kopf
        textFormat: Text.PlainText
        anchors { top: parent.top; left: parent.left; margins: 16 }
        text: fenster.tr("groups")
        font.pixelSize: 32
        color: "white"
    }

    ListView {
        id: liste
        anchors { top: kopf.bottom; topMargin: 16; left: parent.left
                  right: parent.right; bottom: parent.bottom }
        clip: true
        model: seite.gruppen

        delegate: Item {
            width: liste.width
            // Drei Zeilen brauchen mehr: QtQuick 1.1 gibt die Hoehe einer
            // Column nicht nach oben durch, die dritte fehlte sonst einfach.
            height: 120

            Column {
                anchors { left: parent.left; leftMargin: 16; verticalCenter: parent.verticalCenter }
                width: parent.width - 32

                Label {
                    textFormat: Text.PlainText
                    text: modelData.name
                    font.pixelSize: 26
                    color: "white"
                }
                Label {
                    textFormat: Text.PlainText
                    width: parent.width
                    elide: Text.ElideRight
                    font.pixelSize: 20
                    color: modelData.joined ? "#a0a0a0" : "#95d220"
                    text: modelData.dissolved
                          ? fenster.tr("dissolved")
                          : modelData.joined
                            ? (modelData.members + " " + fenster.tr("members")
                               + (modelData.lastText ? " · " + modelData.lastText : ""))
                            : fenster.tr("invitation") + " · " + fenster.tr("invitedBy")
                              + modelData.creator
                }
                // Die Antwort der Gegenseite. Eigene Zeile, weil der Platz in
                // der Zeile darueber schon vergeben ist.
                Label {
                    textFormat: Text.PlainText
                    width: parent.width
                    visible: modelData.event ? true : false
                    elide: Text.ElideRight
                    font.pixelSize: 18
                    color: "#95d220"
                    text: fenster.ereignis(modelData.event)
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    // Eine aufgeloeste Gruppe laesst sich lesen und entfernen,
                    // aber nicht mehr beitreten.
                    if (modelData.joined || modelData.dissolved) {
                        pageStack.push(Qt.resolvedUrl("GroupChatPage.qml"),
                                       { gruppe: modelData.id, name: modelData.name,
                                         ersteller: modelData.isCreator })
                    } else {
                        Briar.joinGroup(modelData.id, function(antwort) {
                            if (antwort.error)
                                fenster.fehler = antwort.error
                            seite.neuLaden()
                        })
                    }
                }
                onPressAndHold: {
                    seite.gewaehlt = modelData.id
                    seite.gewaehltName = modelData.name
                    seite.gewaehltErsteller = modelData.isCreator ? true : false
                    gruppenMenue.open()
                }
            }

            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 1
                color: "#303030"
            }
        }

        footer: Label {
            textFormat: Text.PlainText
            visible: seite.gruppen.length === 0
            x: 16
            width: liste.width - 32
            wrapMode: Text.Wrap
            color: "#a0a0a0"
            font.pixelSize: 20
            text: fenster.tr("noGroups")
        }
    }
}
