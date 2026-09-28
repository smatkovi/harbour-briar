import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    id: page
    allowedOrientations: Orientation.All

    SilicaListView {
        id: list
        anchors.fill: parent
        model: app.status.contacts

        header: Column {
            width: page.width

            PageHeader {
                title: app.tr("briar")
                description: app.status.identity
                             ? app.status.identity.name
                             : app.tr("noIdentity")
            }

            // Before anything else can happen there has to be an identity:
            // Briar's author, the key pair everything else hangs on.
            Column {
                visible: !app.status.identity
                width: parent.width
                spacing: Theme.paddingMedium

                TextField {
                    id: nameField
                    width: parent.width
                    label: app.tr("name")
                    placeholderText: app.tr("yourName")
                    EnterKey.onClicked: createButton.clicked(null)
                }

                Button {
                    id: createButton
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: app.tr("createIdentity")
                    enabled: nameField.text.trim().length > 0
                    onClicked: {
                        // Wie bei Briar: der Name ist nur der erste Schritt,
                        // das Konto entsteht erst nach dem Passwort.
                        pageStack.push(Qt.resolvedUrl("SetupPasswordPage.qml"),
                                       { "wunschname": nameField.text.trim() })
                    }
                }
            }

            Label {
                visible: app.lastError.length > 0
                width: parent.width - 2 * Theme.horizontalPageMargin
                x: Theme.horizontalPageMargin
                text: app.lastError
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeExtraSmall
            }

            // Contacts whose handshake has not run yet
            Repeater {
                model: app.status.pending
                delegate: ListItem {
                    contentHeight: Theme.itemSizeSmall
                    Label {
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        truncationMode: TruncationMode.Fade
                        color: Theme.secondaryColor
                        font.pixelSize: Theme.fontSizeSmall
                        text: (modelData.alias.length > 0 ? modelData.alias : "?")
                              + " – " + app.tr("waiting")
                              + (modelData.address ? " (" + modelData.address + ")" : "")
                              + (modelData.bluetooth ? " (BT " + modelData.bluetooth + ")" : "")
                    }
                    onClicked: Briar.poll(function() { app.refresh() })

                    // Ein Wartender laesst sich auch wieder streichen --
                    // sonst veroeffentlicht er zwei Tage lang jede Minute
                    // einen Treffpunkt, auch wenn niemand mehr kommt.
                    menu: ContextMenu {
                        MenuItem {
                            text: app.tr("removeWaiting")
                            onClicked: remorseAction(app.tr("removeWaiting"), function() {
                                Briar.removePending(modelData.publicKey,
                                                    function(answer) {
                                    if (!answer.error)
                                        app.status = answer
                                })
                            })
                        }
                    }
                }
            }
        }

        PullDownMenu {
            MenuItem {
                text: Strings.tr(Strings.language() === "de" ? "switchToEnglish"
                                                            : "switchToGerman",
                                 app.languageRevision)
                onClicked: app.toggleLanguage()
            }
            MenuItem {
                text: app.tr("passwordMenu")
                onClicked: pageStack.push(Qt.resolvedUrl("PasswordPage.qml"))
            }
            MenuItem {
                // Zusperren wie Briars Bildschirmsperre: der Dienst laeuft
                // weiter und nimmt Nachrichten an, die App zeigt nichts mehr.
                text: app.tr("lockNow")
                onClicked: Briar.lock(function(answer) {
                    if (answer.error)
                        app.lastError = app.tr("lockNeedsPassword")
                    else
                        app.refresh()
                })
            }
            MenuItem {
                text: app.tr("about")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                // Wie bei Briar in den Einstellungen: alles weg und von vorn.
                // Mit Bedenkzeit, denn danach muessen dich alle neu hinzufuegen.
                text: app.tr("deleteAccount")
                onClicked: remorseAction(app.tr("deleteAccount"), function() {
                    Briar.deleteAccount(function() {
                        Daemon.ensureRunning()
                        app.refresh()
                    })
                })
            }
            MenuItem {
                text: app.tr("help")
                onClicked: pageStack.push(Qt.resolvedUrl("HelpPage.qml"))
            }
            MenuItem {
                text: app.tr("connectNow")
                onClicked: Briar.poll(function() { app.refresh() })
            }
            MenuItem {
                text: app.tr("groups")
                enabled: !!app.status.identity
                onClicked: pageStack.push(Qt.resolvedUrl("GroupsPage.qml"))
            }
            MenuItem {
                text: app.tr("scanQr")
                enabled: !!app.status.identity
                onClicked: pageStack.push(Qt.resolvedUrl("ScanPage.qml"))
            }
            MenuItem {
                text: app.tr("addContact")
                enabled: !!app.status.identity
                onClicked: pageStack.push(Qt.resolvedUrl("AddContactPage.qml"))
            }
            MenuItem {
                text: app.tr("myLink")
                enabled: !!app.status.identity
                onClicked: pageStack.push(Qt.resolvedUrl("LinkPage.qml"))
            }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeMedium

            Column {
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - 2 * Theme.horizontalPageMargin

                Label {
                    // Ungelesenes gehoert an den Namen. Der Dienst rechnet es
                    // je Kontakt (api.rs), angezeigt hat es bisher niemand.
                    text: modelData.unread > 0
                          ? modelData.name + "  (" + modelData.unread + ")"
                          : modelData.name
                    color: modelData.unread > 0 ? Theme.highlightColor
                                                : Theme.primaryColor
                    truncationMode: TruncationMode.Fade
                    width: parent.width
                }
                Label {
                    text: modelData.lastText
                          ? modelData.lastText
                          : (modelData.address ? modelData.address
                                               : (modelData.bluetooth
                                                  ? "BT " + modelData.bluetooth
                                                  : app.tr("noAddress")))
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    color: Theme.secondaryColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                }
            }

            Label {
                visible: modelData.unsent > 0
                anchors.right: parent.right
                anchors.rightMargin: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.unsent + " ↑"
                color: Theme.highlightColor
                font.pixelSize: Theme.fontSizeExtraSmall
            }

            onClicked: pageStack.push(Qt.resolvedUrl("ChatPage.qml"),
                                      { contactId: modelData.id,
                                        contactName: modelData.name })

            menu: ContextMenu {
                MenuItem {
                    text: app.tr("connect")
                    onClicked: Briar.connectContact(modelData.id, "", "",
                                                    function() { app.refresh() })
                }
                MenuItem {
                    text: app.tr("remove")
                    // Mit Bedenkzeit: Verlauf und Schluessel gehen mit, und
                    // danach muessten sich beide neu hinzufuegen. Am N9 fragt
                    // ein Dialog nach, hier tut es die Remorse-Leiste.
                    onClicked: remorseAction(app.tr("remove"), function() {
                        Briar.removeContact(modelData.id, function(answer) {
                            if (!answer.error)
                                app.status = answer
                        })
                    })
                }
            }
        }

        ViewPlaceholder {
            enabled: !!app.status.identity && app.status.contacts.length === 0
                     && app.status.pending.length === 0
            text: app.tr("noContacts")
            hintText: app.tr("addContactHint")
        }

        VerticalScrollDecorator { }
    }
}
