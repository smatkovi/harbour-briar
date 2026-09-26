import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    property string gruppe: ""
    property string name: ""

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    Column {
        id: kopf
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }

        Label {
            text: fenster.tr("inviteWho")
            font.pixelSize: 32
            color: "white"
        }
        Label {
            text: seite.name
            font.pixelSize: 22
            color: "#a0a0a0"
        }
    }

    ListView {
        id: liste
        anchors { top: kopf.bottom; topMargin: 16; left: parent.left
                  right: parent.right; bottom: parent.bottom }
        clip: true
        model: fenster.zustand.contacts

        delegate: Item {
            width: liste.width
            height: 72

            Label {
                anchors { left: parent.left; leftMargin: 16; verticalCenter: parent.verticalCenter }
                text: modelData.name
                font.pixelSize: 26
                color: "white"
            }

            MouseArea {
                anchors.fill: parent
                onClicked: Briar.inviteToGroup(seite.gruppe, modelData.id, function(antwort) {
                    if (antwort.error)
                        fenster.fehler = antwort.error
                    pageStack.pop()
                })
            }

            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 1
                color: "#303030"
            }
        }
    }
}
