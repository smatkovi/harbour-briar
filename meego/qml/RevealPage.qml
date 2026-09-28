import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

// "Kontakte zeigen" -- Briars revealRelationship.
//
// Es betrifft nur Kontakte, mit denen wir in derselben Gruppe sind, ohne dass
// einer den anderen eingeladen hat: bei Briar ist das die PEER-Rolle, und nur
// dort gibt es etwas zu zeigen. Welche das sind, entscheidet der Dienst
// (net::zeigbarkeit); hier steht nur, was er nennt.
Page {
    id: seite

    property string gruppe: ""
    property string name: ""
    property variant kandidaten: []

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    Column {
        id: kopf
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
        spacing: 8

        Label {
            text: fenster.tr("revealWho")
            font.pixelSize: 32
            color: "white"
        }
        Label {
            text: seite.name
            font.pixelSize: 22
            color: "#a0a0a0"
        }
        Label {
            width: parent.width
            wrapMode: Text.Wrap
            text: fenster.tr("revealHint")
            font.pixelSize: 18
            color: "#a0a0a0"
        }
    }

    Label {
        anchors { top: kopf.bottom; topMargin: 24; left: parent.left
                  right: parent.right; margins: 16 }
        visible: seite.kandidaten.length === 0
        wrapMode: Text.Wrap
        text: fenster.tr("revealNone")
        font.pixelSize: 20
        color: "#a0a0a0"
    }

    ListView {
        id: liste
        anchors { top: kopf.bottom; topMargin: 16; left: parent.left
                  right: parent.right; bottom: parent.bottom }
        clip: true
        model: seite.kandidaten

        delegate: Item {
            width: liste.width
            height: 72

            Label {
                anchors { left: parent.left; leftMargin: 16
                          verticalCenter: parent.verticalCenter }
                text: modelData.name
                font.pixelSize: 26
                color: "white"
            }

            MouseArea {
                anchors.fill: parent
                onClicked: Briar.reveal(seite.gruppe, modelData.id, function(antwort) {
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
