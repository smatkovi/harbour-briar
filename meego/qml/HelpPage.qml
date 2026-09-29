import QtQuick 1.1
import com.nokia.meego 1.0
import "Strings.js" as Strings

Page {
    id: seite

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: spalte.height + 32
        clip: true

        Column {
            id: spalte
            anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
            spacing: 12

            Label {
                textFormat: Text.PlainText
                text: fenster.tr("help")
                font.pixelSize: 32
                color: "white"
            }

            Text {
                textFormat: Text.PlainText
                width: parent.width
                wrapMode: Text.Wrap
                color: "#d0d0d0"
                font.pixelSize: 21
                text: fenster.tr("helpText")
            }
        }
    }
}
