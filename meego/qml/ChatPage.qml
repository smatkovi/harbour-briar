import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    property int kontakt: 0
    property string name: ""
    property variant nachrichten: []
    // Verschwindende Nachrichten: die Dauer in Millisekunden, -1 heisst aus.
    property int zuenddauer: -1
    property bool zuendbereit: false
    // Ein Hinweis ueber dem Eingabefeld -- kein Fehler, nur etwas, das man
    // wissen sollte (etwa: dieser Anhang kommt bei Android nicht an).
    property string hinweis: ""

    function neuLaden() {
        Briar.messages(kontakt, function(antwort) {
            if (!antwort.error) {
                seite.nachrichten = antwort.messages
                seite.zuenddauer = antwort.autoDelete !== undefined
                        ? antwort.autoDelete : -1
                seite.zuendbereit = !!antwort.autoDeleteReady
            }
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
        // Nicht verboten, aber gesagt: Briar auf Android zeigt fuer alles
        // ausser Bildern nur einen Fehler; zwischen MeeGo und Sailfish geht es.
        seite.hinweis = typ.indexOf("image/") === 0 ? "" : fenster.tr("attachOthersHint")
        Briar.sendFile(seite.kontakt, feld.text, fertig, typ, function(antwort) {
            // Die verkleinerte Kopie hat der Dienst gelesen (oder nie mehr):
            // weg damit. ImagePrep loescht nur im eigenen versand-Ordner.
            if (fertig !== pfad)
                ImagePrep.aufraeumen(fertig)
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
                text: fenster.tr("autoDelete") + ": "
                      + Briar.autoDeleteName(seite.zuenddauer, fenster.tr)
                onClicked: zuendauswahl.open()
            }
            MenuItem {
                text: fenster.tr("deleteAllMessages")
                onClicked: alleLoeschen.open()
            }
        }
    }

    // Wie lange eine neue Nachricht in diesem Gespraech stehen bleibt. Die
    // Einstellung gilt fuer beide Seiten -- sie faehrt in der naechsten
    // Nachricht mit.
    SelectionDialog {
        id: zuendauswahl
        titleText: fenster.tr("autoDelete")
        model: ListModel {
            ListElement { name: "Aus"; dauer: -1 }
            ListElement { name: "1"; dauer: 60000 }
            ListElement { name: "2"; dauer: 3600000 }
            ListElement { name: "3"; dauer: 86400000 }
            ListElement { name: "4"; dauer: 604800000 }
        }
        Component.onCompleted: {
            // Die Namen erst hier, damit sie aus den Sprachtexten kommen.
            model.setProperty(0, "name", fenster.tr("autoDeleteOff"))
            model.setProperty(1, "name", fenster.tr("autoDelete1Min"))
            model.setProperty(2, "name", fenster.tr("autoDelete1Hour"))
            model.setProperty(3, "name", fenster.tr("autoDelete1Day"))
            model.setProperty(4, "name", fenster.tr("autoDelete1Week"))
        }
        onAccepted: {
            var dauer = model.get(selectedIndex).dauer
            Briar.setAutoDelete(seite.kontakt, dauer, function(antwort) {
                if (!antwort.error)
                    seite.zuenddauer = dauer
            })
        }
    }

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        Label {
            textFormat: Text.PlainText
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
        anchors { top: parent.top; left: parent.left; right: parent.right; bottom: hinweisZeile.top }
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
                            var liste = Briar.attachmentsOf(modelData)
                            if (liste.length > 0 && liste[0].path)
                                pageStack.push(Qt.resolvedUrl("AttachmentPage.qml"), {
                                    "pfad": liste[0].path,
                                    "typ": "" + liste[0].type,
                                    "groesse": liste[0].size ? liste[0].size : 0
                                })
                        }
                        // Halten loescht sie -- nur hier, die Gegenseite
                        // behaelt ihre Kopie.
                        onPressAndHold: {
                            seite.loeschKennung = modelData.id
                            einzelneLoeschen.open()
                        }
                    }

                    // Alle Anhaenge, nicht nur der erste: Briar haengt bis zu
                    // zehn Bilder an eine Nachricht.
                    Repeater {
                        model: Briar.attachmentsOf(modelData)

                        Item {
                            width: parent.width
                            height: einzelbild.visible ? einzelbild.height : einzeltext.height

                            Image {
                                id: einzelbild
                                visible: Briar.isImage(modelData) && !!modelData.path
                                source: visible ? "file://" + modelData.path : ""
                                // Grenze fuer die entpackten Pixel (ein 32-KiB-PNG
                                // kann Gigabyte ergeben). Gesetzt liest sich
                                // sourceSize als diese Grenze zurueck, die wahre
                                // Groesse steht in implicitWidth/implicitHeight.
                                sourceSize.width: 1024
                                sourceSize.height: 1024
                                width: visible ? Math.min(implicitWidth, liste.width * 0.62) : 0
                                height: visible ? width * (implicitHeight / Math.max(1, implicitWidth)) : 0
                                fillMode: Image.PreserveAspectFit
                                asynchronous: true
                            }

                            Text {
                                id: einzeltext
                                textFormat: Text.PlainText
                                visible: !einzelbild.visible
                                width: parent.width
                                wrapMode: Text.Wrap
                                color: "#95d220"
                                font.pixelSize: 20
                                text: fenster.tr("attach") + ": " + ("" + modelData.type)
                            }

                            MouseArea {
                                anchors.fill: parent
                                enabled: !!modelData.path
                                onClicked: pageStack.push(
                                    Qt.resolvedUrl("AttachmentPage.qml"), {
                                        "pfad": modelData.path,
                                        "typ": "" + modelData.type,
                                        "groesse": modelData.size ? modelData.size : 0
                                    })
                            }
                        }
                    }

                    Text {
                        id: text
                        textFormat: Text.PlainText
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
                textFormat: Text.PlainText
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

    Label {
        id: hinweisZeile
        textFormat: Text.PlainText
        anchors { left: parent.left; right: parent.right; bottom: eingabe.top; margins: 8 }
        visible: seite.hinweis.length > 0
        height: visible ? paintedHeight + 8 : 0
        wrapMode: Text.Wrap
        color: "#a0a0a0"
        font.pixelSize: 18
        text: seite.hinweis
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
                seite.hinweis = ""
                Briar.send(seite.kontakt, text, function(antwort) {
                    if (antwort.error)
                        fenster.fehler = antwort.error
                    seite.neuLaden()
                })
            }
        }
    }
}
