import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    id: page
    allowedOrientations: Orientation.All

    property var groups: []

    function reload() {
        Briar.groups(function(answer) {
            if (!answer.error)
                page.groups = answer.groups
        })
    }

    Component.onCompleted: reload()

    Timer {
        interval: 3000
        running: page.status === PageStatus.Active
        repeat: true
        onTriggered: page.reload()
    }

    SilicaListView {
        anchors.fill: parent
        model: page.groups
        header: PageHeader { title: app.tr("groups") }

        PullDownMenu {
            MenuItem {
                text: app.tr("newGroup")
                onClicked: pageStack.push(newGroupDialog)
            }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeMedium

            Column {
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - 2 * Theme.horizontalPageMargin

                Label {
                    text: modelData.name
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    color: Theme.secondaryColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                    text: modelData.joined
                          ? (modelData.members + " " + app.tr("members")
                             + (modelData.lastText ? " · " + modelData.lastText : ""))
                          : app.tr("invitation") + " · "
                            + app.tr("invitedBy") + modelData.creator
                }
            }

            onClicked: {
                if (modelData.joined) {
                    pageStack.push(Qt.resolvedUrl("GroupChatPage.qml"),
                                   { groupId: modelData.id, groupName: modelData.name,
                                     isCreator: modelData.isCreator })
                } else {
                    Briar.joinGroup(modelData.id, function(answer) {
                        if (answer.error)
                            app.lastError = answer.error
                        page.reload()
                    })
                }
            }

            menu: ContextMenu {
                MenuItem {
                    visible: !modelData.joined
                    text: app.tr("join")
                    onClicked: Briar.joinGroup(modelData.id, function() { page.reload() })
                }
                MenuItem {
                    visible: modelData.isCreator
                    text: app.tr("invite")
                    onClicked: pageStack.push(Qt.resolvedUrl("InvitePage.qml"),
                                              { groupId: modelData.id,
                                                groupName: modelData.name })
                }
                MenuItem {
                    text: app.tr("remove")
                    onClicked: Briar.removeGroup(modelData.id, function() { page.reload() })
                }
            }
        }

        ViewPlaceholder {
            enabled: page.groups.length === 0
            text: app.tr("noGroups")
            hintText: app.tr("newGroup")
        }

        VerticalScrollDecorator { }
    }

    Component {
        id: newGroupDialog

        Dialog {
            id: dialog
            canAccept: groupNameField.text.trim().length > 0

            DialogHeader { id: header; acceptText: app.tr("create") }

            TextField {
                id: groupNameField
                anchors.top: header.bottom
                width: parent.width
                label: app.tr("groupName")
                placeholderText: app.tr("groupName")
                EnterKey.onClicked: dialog.accept()
            }

            onAccepted: Briar.createGroup(groupNameField.text.trim(), function(answer) {
                if (answer.error)
                    app.lastError = answer.error
                page.reload()
            })
        }
    }
}
