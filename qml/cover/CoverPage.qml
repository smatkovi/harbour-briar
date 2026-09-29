import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

CoverBackground {
    Column {
        anchors.centerIn: parent
        spacing: Theme.paddingMedium
        width: parent.width - 2 * Theme.paddingLarge

        Label {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            text: app.tr("briar")
            font.pixelSize: Theme.fontSizeLarge
        }

        Label {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            horizontalAlignment: Text.AlignHCenter
            width: parent.width
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeSmall
            text: app.status.identity
                  ? app.status.contacts.length + " " + app.tr("contacts")
                    + (app.status.groups && app.status.groups.length > 0
                       ? "\n" + app.status.groups.length + " " + app.tr("groups")
                       : "")
                  : app.tr("noIdentity")
        }
    }

    CoverActionList {
        CoverAction {
            iconSource: "image://theme/icon-cover-refresh"
            onTriggered: Briar.poll(function() { app.refresh() })
        }
    }
}
