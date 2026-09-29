import QtQuick 1.1
import com.nokia.meego 1.0
import Qt.labs.folderlistmodel 1.0
import "Strings.js" as Strings

// The same plain browser as on Sailfish: Harmattan has no file picker to
// call, and MyDocs is where everything on this device lives anyway.
Page {
    id: seite

    property string ordner: "/home/user/MyDocs"
    signal gewaehlt(string pfad)

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        ToolIcon {
            platformIconId: "toolbar-up"
            onClicked: {
                var teile = seite.ordner.split("/")
                teile.pop()
                var oben = teile.join("/")
                seite.ordner = oben.length > 0 ? oben : "/"
            }
        }
    }

    Column {
        id: kopf
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }

        Label {
            text: fenster.tr("pickFile")
            font.pixelSize: 32
            color: "white"
        }
        Label {
            text: seite.ordner
            font.pixelSize: 18
            color: "#a0a0a0"
            width: parent.width
            elide: Text.ElideLeft
        }
        Label {
            width: parent.width
            wrapMode: Text.Wrap
            font.pixelSize: 18
            color: "#a0a0a0"
            text: fenster.tr("attachOthersHint")
        }
    }

    ListView {
        id: liste
        anchors { top: kopf.bottom; topMargin: 12; left: parent.left
                  right: parent.right; bottom: parent.bottom }
        clip: true

        model: FolderListModel {
            id: ordnerModell
            folder: "file://" + seite.ordner
            showDirs: true
            showDotAndDotDot: false
            nameFilters: ["*"]
        }

        delegate: Item {
            width: liste.width
            height: 64

            Label {
                anchors { left: parent.left; leftMargin: 16; right: parent.right
                          rightMargin: 16; verticalCenter: parent.verticalCenter }
                text: fileName
                elide: Text.ElideRight
                font.pixelSize: 24
                color: "white"
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    var pfad = seite.ordner + "/" + fileName
                    if (ordnerModell.isFolder(index))
                        seite.ordner = pfad
                    else
                        seite.gewaehlt(pfad)
                }
            }

            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 1
                color: "#303030"
            }
        }
    }
}
