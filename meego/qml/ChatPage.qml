import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    property int kontakt: 0
    property string name: ""
    property variant nachrichten: []

    function neuLaden() {
        Briar.messages(kontakt, function(antwort) {
            if (!antwort.error)
                seite.nachrichten = antwort.messages
        })
    }

    Component.onCompleted: {
        neuLaden()
        // Dasselbe wie an der Jolla: offen heisst gelesen, sonst bleibt der
        // Zaehler am Kontakt fuer immer stehen.
        Briar.markRead({ "contact": seite.kontakt }, function() { fenster.aktualisieren() })
    }

    // Briar puts an attachment in one message, so a photo from this camera
    // has to be scaled down first. ImagePrep hands back a copy that fits.
    function dateiSenden(pfad) {
        var typ = ImagePrep.contentType(pfad)
        var fertig = ImagePrep.prepare(pfad, 32200)
        if (fertig.length === 0) {
            fenster.fehler = fenster.tr("tooBig")
            return
        }
        if (fertig !== pfad)
            typ = "image/jpeg"
        Briar.sendFile(seite.kontakt, feld.text, fertig, typ, function(antwort) {
            if (antwort.error)
                fenster.fehler = antwort.error
            feld.text = ""
            seite.neuLaden()
        })
    }

    Timer {
        interval: 3000
        running: seite.status === PageStatus.Active
        repeat: true
        onTriggered: seite.neuLaden()
    }

    property string loeschKennung: ""

    QueryDialog {
        id: einzelneLoeschen
        titleText: fenster.tr("deleteMessage")
        message: fenster.tr("deleteMessagesAsk")
        acceptButtonText: fenster.tr("deleteMessage")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.deleteMessage(seite.kontakt, seite.loeschKennung,
                                        function() { seite.neuLaden() })
    }

    QueryDialog {
        id: alleLoeschen
        titleText: fenster.tr("deleteAllMessages")
        message: fenster.tr("deleteMessagesAsk")
        acceptButtonText: fenster.tr("deleteAllMessages")
        rejectButtonText: fenster.tr("cancel")
        onAccepted: Briar.deleteAllMessages(seite.kontakt,
                                            function() { seite.neuLaden() })
    }

    Menu {
        id: gespraechsMenue
        MenuLayout {
            MenuItem {
                text: fenster.tr("deleteAllMessages")
                onClicked: alleLoeschen.open()
            }
        }
    }

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        Label {
            text: seite.name
            color: "white"
            font.pixelSize: 24
            anchors.verticalCenter: parent.verticalCenter
        }
        ToolIcon {
            platformIconId: "toolbar-refresh"
            onClicked: Briar.connectContact(seite.kontakt, "", "", function() { seite.neuLaden() })
        }
        ToolIcon {
            platformIconId: "toolbar-view-menu"
            onClicked: gespraechsMenue.open()
        }
    }

    ListView {
        id: liste
        anchors { top: parent.top; left: parent.left; right: parent.right; bottom: eingabe.top }
        clip: true
        model: seite.nachrichten
        onCountChanged: positionViewAtEnd()

        // The text is given its own width first; the bubble then takes the
        // width the text actually painted. Binding the text's width to the
        // bubble instead makes the two chase each other, and the bubble ends
        // up a couple of characters wide.
        delegate: Item {
            width: liste.width
            height: blase.height + 14

            Rectangle {
                id: blase
                width: Math.max(text.paintedWidth, bild.width, anhang.paintedWidth) + 28
                height: inhalt.height + 22
                radius: 8
                color: modelData.outgoing ? "#1d4d1d" : "#2a2a2a"
                anchors {
                    right: modelData.outgoing ? parent.right : undefined
                    left: modelData.outgoing ? undefined : parent.left
                    margins: 10
                }

                Column {
                    id: inhalt
                    x: 14
                    y: 11
                    width: liste.width - 48
                    spacing: 6

                    // Antippen zeigt den Anhang in der App -- eigene ebenso
                    // wie empfangene. Die Datei bleibt dabei im Datenordner.
                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            if (modelData.attachmentPath !== undefined
                                    && modelData.attachmentPath !== null)
                                pageStack.push(Qt.resolvedUrl("AttachmentPage.qml"), {
                                    "pfad": modelData.attachmentPath,
                                    "typ": "" + modelData.attachmentType,
                                    "groesse": modelData.attachmentSize
                                               ? modelData.attachmentSize : 0
                                })
                        }
                        // Halten loescht sie -- nur hier, die Gegenseite
                        // behaelt ihre Kopie.
                        onPressAndHold: {
                            seite.loeschKennung = modelData.id
                            einzelneLoeschen.open()
                        }
                    }

                    Image {
                        id: bild
                        visible: modelData.attachmentPath !== undefined
                                 && modelData.attachmentPath !== null
                                 && ("" + modelData.attachmentType).indexOf("image/") === 0
                        source: visible ? "file://" + modelData.attachmentPath : ""
                        width: visible ? Math.min(sourceSize.width, liste.width * 0.62) : 0
                        height: visible ? width * (sourceSize.height / Math.max(1, sourceSize.width)) : 0
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                    }

                    Text {
                        id: anhang
                        visible: modelData.attachmentPath !== undefined
                                 && modelData.attachmentPath !== null && !bild.visible
                        width: parent.width
                        wrapMode: Text.Wrap
                        color: "#95d220"
                        font.pixelSize: 20
                        text: fenster.tr("attach") + ": " + ("" + modelData.attachmentType)
                    }

                    Text {
                        id: text
                        width: parent.width
                        visible: modelData.text.length > 0
                        height: visible ? paintedHeight : 0
                        text: modelData.text
                        wrapMode: Text.Wrap
                        color: "white"
                        font.pixelSize: 24
                    }
                }
            }

            Text {
                anchors {
                    top: blase.bottom
                    right: modelData.outgoing ? blase.right : undefined
                    left: modelData.outgoing ? undefined : blase.left
                }
                text: Strings.shortTime(modelData.timestamp)
                      + (modelData.outgoing ? (modelData.acked ? " ✓" : " …") : "")
                color: "#808080"
                font.pixelSize: 16
            }
        }
    }

    Row {
        id: eingabe
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        spacing: 8

        Button {
            id: anhaengen
            text: "+"
            width: 70
            onClicked: {
                var seiteDatei = pageStack.push(Qt.resolvedUrl("FilePage.qml"))
                seiteDatei.gewaehlt.connect(function(pfad) {
                    pageStack.pop()
                    seite.dateiSenden(pfad)
                })
            }
        }

        TextField {
            id: feld
            width: parent.width - senden.width - anhaengen.width - 16
            placeholderText: fenster.tr("message")
            Keys.onReturnPressed: senden.clicked()
        }

        Button {
            id: senden
            text: fenster.tr("send")
            width: 140
            enabled: feld.text.length > 0
            onClicked: {
                var text = feld.text
                if (text.length === 0)
                    return
                feld.text = ""
                Briar.send(seite.kontakt, text, function(antwort) {
                    if (antwort.error)
                        fenster.fehler = antwort.error
                    seite.neuLaden()
                })
            }
        }
    }
}
