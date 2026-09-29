import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    id: page
    allowedOrientations: Orientation.All

    property string groupId: ""
    property string groupName: ""

    SilicaListView {
        anchors.fill: parent
        model: app.status.contacts
        header: PageHeader {
            title: app.tr("inviteWho")
            description: page.groupName
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeSmall
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.name
            }
            onClicked: Briar.inviteToGroup(page.groupId, modelData.id, function(answer) {
                if (answer.error)
                    app.lastError = answer.error
                pageStack.pop()
            })
        }

        ViewPlaceholder {
            enabled: app.status.contacts.length === 0
            text: app.tr("noContacts")
        }
    }
}
