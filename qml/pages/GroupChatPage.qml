import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    id: page
    allowedOrientations: Orientation.All

    property string groupId: ""
    property string groupName: ""
    property bool isCreator: false
    property var messages: []
    property var members: []

    function reload() {
        Briar.groupMessages(groupId, function(answer) {
            if (!answer.error) {
                page.messages = answer.messages
                page.members = answer.members
            }
        })
    }

    Component.onCompleted: {
        reload()
        Briar.markRead({"group": page.groupId}, function() { app.refresh() })
    }

    Timer {
        interval: 3000
        running: page.status === PageStatus.Active
        repeat: true
        onTriggered: page.reload()
    }

    SilicaListView {
        id: view
        anchors { left: parent.left; right: parent.right; top: parent.top; bottom: input.top }
        model: page.messages
        clip: true
        onCountChanged: positionViewAtEnd()

        header: PageHeader {
            title: page.groupName
            description: page.members.length + " " + app.tr("members")
        }

        PullDownMenu {
            MenuItem {
                visible: page.isCreator
                text: app.tr("invite")
                onClicked: pageStack.push(Qt.resolvedUrl("InvitePage.qml"),
                                          { groupId: page.groupId, groupName: page.groupName })
            }
        }

        // Who wrote a post matters more in a group than in a chat, so the
        // author's name stands above every message, not only on incoming ones.
        delegate: Item {
            width: view.width
            height: column.height + Theme.paddingMedium

            property bool mine: app.status.identity
                                && modelData.authorId === app.status.identity.authorId

            Column {
                id: column
                anchors {
                    left: mine ? undefined : parent.left
                    right: mine ? parent.right : undefined
                    margins: Theme.horizontalPageMargin
                }
                width: Math.min(view.width * 0.82, Theme.itemSizeHuge * 4)

                Label {
                    width: parent.width
                    horizontalAlignment: mine ? Text.AlignRight : Text.AlignLeft
                    text: modelData.author
                    color: mine ? Theme.secondaryHighlightColor : Theme.highlightColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                    truncationMode: TruncationMode.Fade
                }

                Rectangle {
                    width: Math.min(text.implicitWidth + 2 * Theme.paddingMedium, parent.width)
                    height: text.implicitHeight + 2 * Theme.paddingMedium
                    radius: Theme.paddingSmall
                    anchors.right: mine ? parent.right : undefined
                    color: mine ? Theme.rgba(Theme.highlightBackgroundColor, 0.3)
                                : Theme.rgba(Theme.secondaryHighlightColor, 0.2)

                    Label {
                        id: text
                        anchors.centerIn: parent
                        width: parent.width - 2 * Theme.paddingMedium
                        text: modelData.text
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.fontSizeSmall
                    }
                }

                Label {
                    width: parent.width
                    horizontalAlignment: mine ? Text.AlignRight : Text.AlignLeft
                    text: Strings.shortTime(modelData.timestamp)
                    color: Theme.secondaryColor
                    font.pixelSize: Theme.fontSizeTiny
                }
            }
        }

        VerticalScrollDecorator { }
    }

    Row {
        id: input
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: field.height

        TextField {
            id: field
            width: parent.width - sendButton.width
            placeholderText: app.tr("message")
            label: app.tr("message")
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: sendButton.clicked(null)
        }

        IconButton {
            id: sendButton
            width: Theme.itemSizeMedium
            anchors.verticalCenter: field.verticalCenter
            icon.source: "image://theme/icon-m-message"
            enabled: field.text.trim().length > 0
            onClicked: {
                var text = field.text.trim()
                if (text.length === 0)
                    return
                field.text = ""
                Briar.sendToGroup(page.groupId, text, function(answer) {
                    if (answer.error)
                        app.lastError = answer.error
                    page.reload()
                })
            }
        }
    }
}
