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
                    textFormat: Text.PlainText
                    text: modelData.name
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                }
                Label {
                    textFormat: Text.PlainText
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    color: Theme.secondaryColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                    // "aufgelöst" steht vor allem anderen: es sagt, dass hier
                    // nichts mehr hinausgeht.
                    text: modelData.dissolved
                          ? app.tr("dissolved")
                          : modelData.joined
                            ? (modelData.members + " " + app.tr("members")
                               + (modelData.lastText ? " · " + modelData.lastText : ""))
                            : app.tr("invitation") + " · "
                              + app.tr("invitedBy") + modelData.creator
                }
                // Die Antwort der Gegenseite gehört hierher: Briar zeigt sie
                // als Zeile im Gespräch, wir haben dort keine Zeile. Sie
                // verschwindet, sobald die Gruppe einmal offen war (/read).
                Label {
                    textFormat: Text.PlainText
                    width: parent.width
                    visible: !!modelData.event
                    truncationMode: TruncationMode.Fade
                    color: Theme.highlightColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                    text: app.ereignis(modelData.event)
                }
            }

            onClicked: {
                // Eine aufgelöste Gruppe soll sich öffnen lassen -- Verlauf
                // lesen und entfernen --, nur nicht mehr per Tipp beitreten.
                if (modelData.joined || modelData.dissolved) {
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
                    visible: !modelData.joined && !modelData.dissolved
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
                    // Mit Bedenkzeit: das schickt den anderen Mitgliedern ein
                    // LEAVE, und bei einer Einladung ist es die Ablehnung.
                    onClicked: remorseAction(app.tr("remove"), function() {
                        Briar.removeGroup(modelData.id, function() { page.reload() })
                    })
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

            // acceptText zeigt Silica immer als RichText (DialogHeader.qml:266-267,
            // QTBUG-40161): hier nie fremden Text, nur eigene aus Strings.js.
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
