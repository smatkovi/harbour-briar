import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    id: page
    allowedOrientations: Orientation.All

    property int contactId: 0
    property string contactName: ""
    property var messages: []
    // Verschwindende Nachrichten: die Dauer in Millisekunden, -1 heisst aus.
    property int autoDelete: -1
    property bool autoDeleteReady: false
    // Wieviele fremde Nachrichten schon als gelesen gemeldet sind.
    property int fremdeGesehen: 0
    // Ein Hinweis ueber dem Eingabefeld -- kein Fehler, nur etwas, das man
    // wissen sollte (etwa: dieser Anhang kommt bei Android nicht an).
    property string hinweis: ""

    function reload() {
        Briar.messages(contactId, function(answer) {
            if (!answer.error) {
                // Ist etwas Neues gekommen, waehrend das Gespraech offen war,
                // gilt es als gelesen -- sonst liefe die Uhr einer
                // verschwindenden Nachricht erst beim naechsten Oeffnen an.
                var fremde = 0
                for (var i = 0; i < answer.messages.length; i++)
                    if (!answer.messages[i].outgoing)
                        fremde++
                if (fremde > page.fremdeGesehen) {
                    page.fremdeGesehen = fremde
                    if (page.messages.length > 0)
                        Briar.markRead({"contact": page.contactId},
                                       function() { app.refresh() })
                }
                page.messages = answer.messages
                page.autoDelete = answer.autoDelete !== undefined
                        ? answer.autoDelete : -1
                page.autoDeleteReady = !!answer.autoDeleteReady
            }
        })
    }

    Component.onCompleted: {
        reload()
        // Takes the notification away as well.
        Briar.markRead({"contact": page.contactId}, function() { app.refresh() })
    }

    // Briar puts an attachment in one message, so a photo has to be scaled
    // down first -- ImagePrep does that and hands back a copy that fits.
    function sendFile(path) {
        var type = ImagePrep.contentType(path)
        var prepared = ImagePrep.prepare(path, 32200)
        if (prepared.length === 0) {
            app.lastError = app.tr("tooBig")
            return
        }
        if (prepared !== path)
            type = "image/jpeg"
        // Nicht verboten, aber gesagt: Briar auf Android zeigt fuer alles
        // ausser Bildern nur einen Fehler; zwischen MeeGo und Sailfish geht es.
        page.hinweis = type.indexOf("image/") === 0 ? "" : app.tr("attachOthersHint")
        Briar.sendFile(page.contactId, field.text.trim(), prepared, type,
                       function(answer) {
            // Die verkleinerte Kopie hat der Dienst gelesen (oder nie mehr):
            // weg damit. ImagePrep loescht nur im eigenen versand-Ordner.
            if (prepared !== path)
                ImagePrep.aufraeumen(prepared)
            if (answer.error)
                app.lastError = answer.error
            field.text = ""
            page.reload()
        })
    }

    // Wie lange eine neue Nachricht in diesem Gespraech stehen bleibt. Die
    // Einstellung gilt fuer beide Seiten: sie faehrt in der naechsten
    // Nachricht mit, und die Gegenseite uebernimmt sie.
    Component {
        id: zuenddauer
        Page {
            allowedOrientations: Orientation.All
            Column {
                width: parent.width
                spacing: Theme.paddingMedium

                PageHeader { title: app.tr("autoDelete") }

                Label {
                    textFormat: Text.PlainText
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: page.autoDeleteReady ? app.tr("autoDeleteHint")
                                               : app.tr("autoDeleteNotYet")
                }

                Repeater {
                    model: [ { "t": -1,      "k": "autoDeleteOff" },
                             { "t": 60000,   "k": "autoDelete1Min" },
                             { "t": 3600000, "k": "autoDelete1Hour" },
                             { "t": 86400000, "k": "autoDelete1Day" },
                             { "t": 604800000, "k": "autoDelete1Week" } ]
                    ListItem {
                        width: parent.width
                        Label {
                            textFormat: Text.PlainText
                            x: Theme.horizontalPageMargin
                            anchors.verticalCenter: parent.verticalCenter
                            text: app.tr(modelData.k)
                            color: modelData.t === page.autoDelete
                                   ? Theme.highlightColor : Theme.primaryColor
                        }
                        onClicked: {
                            Briar.setAutoDelete(page.contactId, modelData.t,
                                                function(antwort) {
                                if (antwort.error)
                                    app.lastError = antwort.error
                                else
                                    page.autoDelete = modelData.t
                                pageStack.pop()
                            })
                        }
                    }
                }
            }
        }
    }

    // Bild oder Datei -- zwei Wege, weil die Galerie anders aussieht als
    // ein Dateibaum und man meistens ein Bild schicken will.
    Component {
        id: auswahl
        Page {
            allowedOrientations: Orientation.All
            Column {
                width: parent.width
                PageHeader { title: app.tr("attachAction") }
                ListItem {
                    Label {
                        textFormat: Text.PlainText
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        text: app.tr("fromGallery")
                    }
                    onClicked: pageStack.replace(bildAuswahl)
                }
                ListItem {
                    Label {
                        textFormat: Text.PlainText
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        text: app.tr("fromFiles")
                    }
                    onClicked: pageStack.replace(dateiAuswahl)
                }
                Label {
                    textFormat: Text.PlainText
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: app.tr("attachOthersHint")
                }
            }
        }
    }

    Component {
        id: bildAuswahl
        ImagePickerPage {
            onSelectedContentPropertiesChanged: {
                page.sendFile(selectedContentProperties.filePath)
                pageStack.pop(page)
            }
        }
    }

    Component {
        id: dateiAuswahl
        ContentPickerPage {
            onSelectedContentPropertiesChanged: {
                page.sendFile(selectedContentProperties.filePath)
                pageStack.pop(page)
            }
        }
    }

    Timer {
        interval: 3000
        running: page.status === PageStatus.Active
        repeat: true
        onTriggered: page.reload()
    }

    // Eine Bedenkzeit fuer beides -- Loeschen ist hier endgueltig.
    RemorsePopup { id: entfernen }

    // Briars Auswahlmodus: mehrere antippen, dann zusammen loeschen. Die
    // Auswahl haengt an den Kennungen, nicht an den Reihen -- die Liste laedt
    // alle drei Sekunden neu.
    property bool auswahl: false
    property var gewaehlt: ({})
    property int gewaehltAnzahl: 0

    function auswahlUmschalten(id) {
        var neu = page.gewaehlt
        if (neu[id]) {
            delete neu[id]
            page.gewaehltAnzahl--
        } else {
            neu[id] = true
            page.gewaehltAnzahl++
        }
        page.gewaehlt = neu
    }

    function auswahlBeenden() {
        page.auswahl = false
        page.gewaehlt = ({})
        page.gewaehltAnzahl = 0
    }

    // Eine einzelne Nachricht loeschen, mit Bedenkzeit. Zwei Bereiche in der
    // Blase rufen das -- die Blase selbst und jeder Anhang darauf.
    function nachrichtLoeschen(id) {
        entfernen.execute(app.tr("deleteMessage"), function() {
            Briar.deleteMessage(page.contactId, id, function() { page.reload() })
        })
    }

    SilicaListView {
        id: view
        anchors { left: parent.left; right: parent.right; top: parent.top; bottom: hinweisZeile.top }
        model: page.messages
        clip: true
        header: Column {
            width: parent.width
            PageHeader { title: page.contactName }
            // Steht die Zuenddauer, soll man das sehen, ohne ins Menue zu
            // gehen -- sonst schreibt man ahnungslos etwas, das wieder geht.
            Label {
                textFormat: Text.PlainText
                visible: page.autoDelete > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignRight
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: app.tr("autoDeleteOn")
                      + Briar.autoDeleteName(page.autoDelete, app.tr)
            }
        }
        onCountChanged: positionViewAtEnd()

        PullDownMenu {
            MenuItem {
                visible: page.auswahl && page.gewaehltAnzahl > 0
                text: app.tr("deleteSelected") + " (" + page.gewaehltAnzahl + ")"
                onClicked: {
                    var ids = Object.keys(page.gewaehlt)
                    entfernen.execute(app.tr("deleteSelected"), function() {
                        Briar.deleteMessages(page.contactId, ids, function() {
                            page.auswahlBeenden()
                            page.reload()
                        })
                    })
                }
            }
            MenuItem {
                text: page.auswahl ? app.tr("selectionDone") : app.tr("selectMessages")
                onClicked: {
                    if (page.auswahl)
                        page.auswahlBeenden()
                    else
                        page.auswahl = true
                }
            }
            MenuItem {
                text: app.tr("autoDelete") + ": "
                      + Briar.autoDeleteName(page.autoDelete, app.tr)
                onClicked: pageStack.push(zuenddauer)
            }
            MenuItem {
                text: app.tr("deleteAllMessages")
                onClicked: entfernen.execute(app.tr("deleteAllMessages"), function() {
                    Briar.deleteAllMessages(page.contactId, function() { page.reload() })
                })
            }
        }

        // Der Inhalt bekommt zuerst seine eigene Breite, die Blase nimmt
        // danach die, die wirklich gemalt wurde. Umgekehrt -- der Text so
        // breit wie die Blase, die Blase so breit wie der Text -- jagen die
        // beiden einander, und am Ende ist die Blase ein paar Zeichen breit.
        delegate: Item {
            id: zeile
            width: view.width
            // Die Uhrzeit steht unter der Blase und gehoert zur Hoehe: ohne
            // sie schiebt sich die naechste Nachricht darueber.
            height: bubble.height + zeit.height + Theme.paddingMedium

            // Die Nachricht selbst. Im Anhang-Repeater ist `modelData` der
            // Anhang, dort ist sie sonst nicht mehr zu erreichen.
            property var nachricht: modelData
            // Die breiteste Anhangsvorschau. Die Kinder des Repeaters melden
            // sie herauf -- ihre Kennungen gelten nur in ihrem eigenen
            // Bauteil und sind von hier aus nicht sichtbar.
            property real anhangBreite: 0

            Rectangle {
                id: bubble
                width: Math.min(Math.max(body.visible ? body.paintedWidth : 0,
                                         zeile.anhangBreite)
                                + 2 * Theme.paddingMedium,
                                view.width * 0.8)
                height: content.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: page.auswahl && page.gewaehlt[modelData.id]
                       ? Theme.rgba(Theme.highlightColor, 0.4)
                       : modelData.outgoing
                         ? Theme.rgba(Theme.highlightBackgroundColor, 0.3)
                         : Theme.rgba(Theme.secondaryHighlightColor, 0.2)
                anchors {
                    right: modelData.outgoing ? parent.right : undefined
                    left: modelData.outgoing ? undefined : parent.left
                    margins: Theme.horizontalPageMargin
                }

                // Die ganze Blase ist antippbar. Sie liegt vor der Spalte,
                // damit ein Anhang den Tipp zuerst bekommt. In einer Column
                // waere sie fehl am Platz: Positionierer verbieten
                // anchors.fill, der Bereich bliebe ohne Groesse.
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (page.auswahl) {
                            page.auswahlUmschalten(zeile.nachricht.id)
                            return
                        }
                        var liste = Briar.attachmentsOf(zeile.nachricht)
                        if (liste.length > 0 && liste[0].path)
                            pageStack.push(Qt.resolvedUrl("AttachmentPage.qml"), {
                                "pfad": liste[0].path,
                                "typ": "" + liste[0].type,
                                "groesse": liste[0].size || 0
                            })
                    }
                    // Halten loescht sie -- nur hier, die Gegenseite
                    // behaelt ihre Kopie. Mit Bedenkzeit, denn zurueck
                    // geht es nicht.
                    onPressAndHold: page.nachrichtLoeschen(zeile.nachricht.id)
                }

                Column {
                    id: content
                    x: Theme.paddingMedium
                    y: Theme.paddingMedium
                    // Fest, nicht aus der Blase: so bleibt der Umbruch
                    // unabhaengig davon, wie breit die Blase wird.
                    width: view.width * 0.8 - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall

                    // Alle Anhaenge, nicht nur der erste: Briar haengt bis
                    // zu zehn Bilder an eine Nachricht. Jeder laesst sich
                    // einzeln antippen.
                    Repeater {
                        model: Briar.attachmentsOf(modelData)

                        Item {
                            width: parent.width
                            height: bild.visible ? bild.height : sonstiges.height

                            // Was die Blase von diesem Anhang wissen muss.
                            // Von aussen ist hier nichts zu sehen, also wird
                            // es hinaufgemeldet; die breiteste gewinnt.
                            property real eigenBreite: bild.visible
                                    ? bild.width : sonstiges.paintedWidth
                            onEigenBreiteChanged: if (eigenBreite > zeile.anhangBreite)
                                                      zeile.anhangBreite = eigenBreite
                            Component.onCompleted: if (eigenBreite > zeile.anhangBreite)
                                                       zeile.anhangBreite = eigenBreite

                            // Die Quelle nur fuer Bilder: ein Image laedt auch
                            // unsichtbar, und Qt waehlt den Leser am Inhalt,
                            // nicht an der Endung -- sonst ginge jeder Anhang
                            // ohne Antippen an jedes Bild-Plugin (Gegenpruefung
                            // 7b, C1). sourceSize begrenzt die entpackten Pixel:
                            // ein 32-KiB-PNG kann Gigabyte ergeben. Fest statt
                            // an view.width gebunden, sonst wuerde bei jeder
                            // Drehung neu entpackt. Gesetzt liest sich
                            // sourceSize als diese Grenze zurueck; die wahre
                            // Groesse steht in implicitWidth/implicitHeight.
                            Image {
                                id: bild
                                visible: Briar.isImage(modelData) && !!modelData.path
                                source: visible ? "file://" + modelData.path : ""
                                sourceSize.width: 1024
                                sourceSize.height: 1024
                                width: Math.min(implicitWidth, view.width * 0.6)
                                height: implicitWidth > 0
                                        ? width * implicitHeight / implicitWidth : 0
                                fillMode: Image.PreserveAspectFit
                                asynchronous: true
                            }

                            Label {
                                id: sonstiges
                                textFormat: Text.PlainText
                                visible: !bild.visible
                                width: parent.width
                                wrapMode: Text.Wrap
                                color: Theme.highlightColor
                                font.pixelSize: Theme.fontSizeExtraSmall
                                text: app.tr("attach") + ": "
                                      + ("" + modelData.type)
                                      + " (" + Math.round((modelData.size || 0) / 1024)
                                      + " KB)"
                            }

                            MouseArea {
                                anchors.fill: parent
                                enabled: !page.auswahl && !!modelData.path
                                onClicked: pageStack.push(
                                    Qt.resolvedUrl("AttachmentPage.qml"), {
                                        "pfad": modelData.path,
                                        "typ": "" + modelData.type,
                                        "groesse": modelData.size || 0
                                    })
                                // Auch auf dem Bild haelt man die Nachricht
                                // zum Loeschen fest: dieser Bereich liegt
                                // ueber dem der Blase und bekaeme es sonst
                                // allein, ohne etwas damit zu tun.
                                onPressAndHold: page.nachrichtLoeschen(zeile.nachricht.id)
                            }
                        }
                    }

                    Label {
                        id: body
                        textFormat: Text.PlainText
                        width: parent.width
                        visible: modelData.text.length > 0
                        height: visible ? implicitHeight : 0
                        text: modelData.text
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.fontSizeSmall
                    }
                }
            }

            Label {
                id: zeit
                textFormat: Text.PlainText
                anchors {
                    top: bubble.bottom
                    right: modelData.outgoing ? bubble.right : undefined
                    left: modelData.outgoing ? undefined : bubble.left
                }
                text: Strings.shortTime(modelData.timestamp)
                      + (modelData.outgoing ? (modelData.acked ? " ✓" : " …") : "")
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeTiny
            }
        }

        VerticalScrollDecorator { }
    }

    Label {
        id: hinweisZeile
        textFormat: Text.PlainText
        anchors {
            left: parent.left; right: parent.right; bottom: input.top
            leftMargin: Theme.horizontalPageMargin; rightMargin: Theme.horizontalPageMargin
        }
        visible: page.hinweis.length > 0
        height: visible ? implicitHeight + Theme.paddingSmall : 0
        wrapMode: Text.Wrap
        font.pixelSize: Theme.fontSizeExtraSmall
        color: Theme.secondaryHighlightColor
        text: page.hinweis
    }

    Row {
        id: input
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: field.height

        IconButton {
            id: attachButton
            width: Theme.itemSizeMedium
            anchors.verticalCenter: field.verticalCenter
            icon.source: "image://theme/icon-m-attach"
            // Die Auswahl des Systems statt eines eigenen Dateibrowsers:
            // Galerie, Dokumente, Downloads -- das, was man auf diesem Gerät
            // von jeder anderen App kennt.
            onClicked: pageStack.push(auswahl)
        }

        TextField {
            id: field
            width: parent.width - sendButton.width - attachButton.width
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
                page.hinweis = ""
                Briar.send(page.contactId, text, function(answer) {
                    if (answer.error)
                        app.lastError = answer.error
                    page.reload()
                })
            }
        }
    }
}
