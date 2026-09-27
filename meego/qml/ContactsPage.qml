import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-refresh"
            onClicked: Briar.poll(function() { fenster.aktualisieren() })
        }
        ToolIcon {
            platformIconId: "toolbar-add"
            visible: !!fenster.zustand.identity
            onClicked: pageStack.push(Qt.resolvedUrl("AddContactPage.qml"))
        }
        ToolIcon {
            platformIconId: "toolbar-list"
            visible: !!fenster.zustand.identity
            onClicked: pageStack.push(Qt.resolvedUrl("GroupsPage.qml"))
        }
        ToolIcon {
            platformIconId: "toolbar-view-menu"
            onClicked: menue.open()
        }
    }

    Menu {
        id: menue
        MenuLayout {
            MenuItem {
                text: fenster.tr("scanQr")
                enabled: !!fenster.zustand.identity
                onClicked: pageStack.push(Qt.resolvedUrl("ScanPage.qml"))
            }
            MenuItem {
                text: fenster.tr("myLink")
                enabled: !!fenster.zustand.identity
                onClicked: pageStack.push(Qt.resolvedUrl("LinkPage.qml"))
            }
            MenuItem {
                text: fenster.tr("passwordMenu")
                onClicked: pageStack.push(Qt.resolvedUrl("PasswordPage.qml"))
            }
            MenuItem {
                text: fenster.tr("groups")
                enabled: !!fenster.zustand.identity
                onClicked: pageStack.push(Qt.resolvedUrl("GroupsPage.qml"))
            }
            MenuItem {
                text: Strings.language() === "de" ? fenster.tr("switchToEnglish")
                                                  : fenster.tr("switchToGerman")
                onClicked: fenster.spracheUmschalten()
            }
            MenuItem {
                text: fenster.tr("help")
                onClicked: pageStack.push(Qt.resolvedUrl("HelpPage.qml"))
            }
            MenuItem {
                text: fenster.tr("about")
                onClicked: ueber.open()
            }
        }
    }

    QueryDialog {
        id: ueber
        titleText: fenster.tr("briar")
        message: fenster.tr("aboutText")
        acceptButtonText: "OK"
    }

    Column {
        id: kopf
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
        spacing: 12

        Label {
            text: fenster.zustand.identity
                  ? fenster.tr("briar") + " – " + fenster.zustand.identity.name
                  : fenster.tr("briar")
            font.pixelSize: 32
            color: "white"
        }

        Label {
            visible: fenster.fehler.length > 0
            text: fenster.fehler
            width: parent.width
            wrapMode: Text.Wrap
            color: "#ff6666"
            font.pixelSize: 20
        }

        // No identity yet: everything starts with the author key pair
        Row {
            visible: !fenster.zustand.identity
            spacing: 8
            width: parent.width

            TextField {
                id: nameFeld
                width: parent.width - anlegen.width - 8
                placeholderText: fenster.tr("name")
            }

            Button {
                id: anlegen
                text: fenster.tr("create")
                width: 160
                enabled: nameFeld.text.length > 0
                onClicked: {
                    // Wie bei Briar: der Name ist der erste Schritt, das
                    // Konto entsteht erst nach dem Passwort.
                    pageStack.push(Qt.resolvedUrl("SetupPasswordPage.qml"),
                                   { "wunschname": nameFeld.text })
                }
            }
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
            height: 88

            Column {
                anchors { left: parent.left; leftMargin: 16; verticalCenter: parent.verticalCenter }
                width: parent.width - 32

                Label {
                    text: modelData.name
                    font.pixelSize: 26
                    color: "white"
                }
                Label {
                    text: modelData.lastText
                          ? modelData.lastText
                          : (modelData.address ? modelData.address
                             : (modelData.bluetooth ? "BT " + modelData.bluetooth
                                                    : fenster.tr("noAddress")))
                    font.pixelSize: 20
                    color: "#a0a0a0"
                    width: parent.width
                    elide: Text.ElideRight
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: pageStack.push(Qt.resolvedUrl("ChatPage.qml"),
                                          { kontakt: modelData.id, name: modelData.name })
            }

            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 1
                color: "#303030"
            }
        }

        footer: Column {
            width: liste.width

            Repeater {
                model: fenster.zustand.pending
                delegate: Label {
                    width: liste.width - 32
                    x: 16
                    height: 56
                    verticalAlignment: Text.AlignVCenter
                    color: "#a0a0a0"
                    font.pixelSize: 20
                    elide: Text.ElideRight
                    text: (modelData.alias.length > 0 ? modelData.alias : "?")
                          + " – " + fenster.tr("waiting")
                          + (modelData.address ? " (" + modelData.address + ")" : "")
                          + (modelData.bluetooth ? " (BT)" : "")
                }
            }

            Label {
                visible: fenster.zustand.contacts.length === 0
                         && fenster.zustand.pending.length === 0
                         && !!fenster.zustand.identity
                x: 16
                width: liste.width - 32
                wrapMode: Text.Wrap
                color: "#a0a0a0"
                font.pixelSize: 20
                text: fenster.tr("noContacts") + ". " + fenster.tr("addContactHint")
            }
        }
    }
}
