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

    Sheet {
        id: neueGruppe
        acceptButtonText: fenster.tr("create")
        rejectButtonText: "✕"

        content: Column {
            anchors { fill: parent; margins: 16 }
            spacing: 12

            Label {
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
            height: 96

            Column {
                anchors { left: parent.left; leftMargin: 16; verticalCenter: parent.verticalCenter }
                width: parent.width - 32

                Label {
                    text: modelData.name
                    font.pixelSize: 26
                    color: "white"
                }
                Label {
                    width: parent.width
                    elide: Text.ElideRight
                    font.pixelSize: 20
                    color: modelData.joined ? "#a0a0a0" : "#95d220"
                    text: modelData.joined
                          ? (modelData.members + " " + fenster.tr("members")
                             + (modelData.lastText ? " · " + modelData.lastText : ""))
                          : fenster.tr("invitation") + " · " + fenster.tr("invitedBy")
                            + modelData.creator
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    if (modelData.joined) {
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
                    if (modelData.isCreator)
                        pageStack.push(Qt.resolvedUrl("InvitePage.qml"),
                                       { gruppe: modelData.id, name: modelData.name })
                }
            }

            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 1
                color: "#303030"
            }
        }

        footer: Label {
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
