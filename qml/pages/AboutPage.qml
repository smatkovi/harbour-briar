import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Strings.js" as Strings

Page {
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: app.tr("about") + " " + app.tr("briar") }

            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                text: app.tr("aboutText")
            }
        }
    }
}
