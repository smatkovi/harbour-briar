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
                // Zusperren wie Briars Bildschirmsperre: der Dienst laeuft
                // weiter, die Oberflaeche zeigt nichts mehr.
                text: fenster.tr("lockNow")
                onClicked: Briar.lock(function(antwort) {
                    if (antwort.error)
                        fenster.fehler = fenster.tr("lockNeedsPassword")
                    else
                        fenster.aktualisieren()
                })
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

    // Lange auf einen Wartenden tippen fragt hier nach. Ohne das Streichen
    // veroeffentlicht er zwei Tage lang jede Minute einen Treffpunkt, auch
    // wenn niemand mehr kommt.
    property string streichSchluessel: ""

    // Einen Kontakt entfernen -- am N9 gab es das bisher gar nicht, obwohl der
    // Dienst die Route laengst hat. Mit Rueckfrage, wie beim Wartenden.
    property int entferneId: 0
    property string entferneName: ""

    QueryDialog {
        id: kontaktEntfernen
        titleText: fenster.tr("remove")
        message: fenster.tr("removeContactAsk")
        acceptButtonText: fenster.tr("remove")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.removeContact(seite.entferneId, function(antwort) {
            if (!antwort.error)
                fenster.zustand = antwort
        })
    }

    QueryDialog {
        id: streichen
        titleText: fenster.tr("removeWaiting")
        message: fenster.tr("removeWaitingAsk")
        acceptButtonText: fenster.tr("removeWaiting")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.removePending(seite.streichSchluessel, function(antwort) {
            if (!antwort.error)
                fenster.zustand = antwort
        })
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
                    // Ungelesenes gehoert an den Namen: der Dienst rechnet es
                    // je Kontakt, angezeigt hat es bisher keine der beiden
                    // Oberflaechen.
                    text: modelData.unread > 0
                          ? modelData.name + "  (" + modelData.unread + ")"
                          : modelData.name
                    font.pixelSize: 26
                    color: modelData.unread > 0 ? "#95d220" : "white"
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
                onPressAndHold: {
                    seite.entferneId = modelData.id
                    seite.entferneName = modelData.name
                    kontaktEntfernen.open()
                }
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
                delegate: Item {
                    width: liste.width
                    height: 56
                    Label {
                        width: liste.width - 32
                        x: 16
                        anchors.verticalCenter: parent.verticalCenter
                        color: "#a0a0a0"
                        font.pixelSize: 20
                        elide: Text.ElideRight
                        text: (modelData.alias.length > 0 ? modelData.alias : "?")
                              + " – " + fenster.tr("waiting")
                              + (modelData.address ? " (" + modelData.address + ")" : "")
                              + (modelData.bluetooth ? " (BT)" : "")
                    }
                    MouseArea {
                        anchors.fill: parent
                        onPressAndHold: {
                            seite.streichSchluessel = modelData.publicKey
                            streichen.open()
                        }
                    }
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
