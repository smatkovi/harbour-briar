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

    function reload() {
        Briar.messages(contactId, function(answer) {
            if (!answer.error)
                page.messages = answer.messages
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
        Briar.sendFile(page.contactId, field.text.trim(), prepared, type,
                       function(answer) {
            if (answer.error)
                app.lastError = answer.error
            field.text = ""
            page.reload()
        })
    }

    // Bild oder Datei -- zwei Wege, weil die Galerie anders aussieht als
    // ein Dateibaum und man meistens ein Bild schicken will.
    Component {
        id: auswahl
        Page {
            allowedOrientations: Orientation.All
            Column {
                width: parent.width
                PageHeader { title: app.tr("attach") }
                ListItem {
                    Label {
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        text: app.tr("fromGallery")
                    }
                    onClicked: pageStack.replace(bildAuswahl)
                }
                ListItem {
                    Label {
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        text: app.tr("fromFiles")
                    }
                    onClicked: pageStack.replace(dateiAuswahl)
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

    SilicaListView {
        id: view
        anchors { left: parent.left; right: parent.right; top: parent.top; bottom: input.top }
        model: page.messages
        clip: true
        header: PageHeader { title: page.contactName }
        onCountChanged: positionViewAtEnd()

        delegate: Item {
            width: view.width
            height: bubble.height + Theme.paddingMedium

            Rectangle {
                id: bubble
                width: Math.min(content.widest + 2 * Theme.paddingMedium,
                                view.width * 0.8)
                height: content.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: modelData.outgoing
                       ? Theme.rgba(Theme.highlightBackgroundColor, 0.3)
                       : Theme.rgba(Theme.secondaryHighlightColor, 0.2)
                anchors {
                    right: modelData.outgoing ? parent.right : undefined
                    left: modelData.outgoing ? undefined : parent.left
                    margins: Theme.horizontalPageMargin
                }

                Column {
                    id: content
                    anchors.centerIn: parent
                    width: parent.width - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall

                    // What the bubble is sized from. Declaring implicitWidth
                    // on a Column would shadow Item's own property.
                    property real widest: Math.max(
                            body.visible ? body.implicitWidth : 0,
                            picture.visible ? picture.width : 0,
                            other.visible ? other.implicitWidth : 0)

                    // Ein Anhang laesst sich antippen und dann in der App
                    // ansehen -- eigene ebenso wie empfangene. Aus der Hand
                    // gegeben wird er dabei nicht: die Datei bleibt im
                    // Datenordner, der auf 0700 steht.
                    MouseArea {
                        anchors.fill: parent
                        enabled: !!modelData.attachmentPath
                        onClicked: pageStack.push(Qt.resolvedUrl("AttachmentPage.qml"), {
                            "pfad": modelData.attachmentPath,
                            "typ": "" + modelData.attachmentType,
                            "groesse": modelData.attachmentSize || 0
                        })
                    }

                    Image {
                        id: picture
                        visible: modelData.attachmentPath
                                 && ("" + modelData.attachmentType).indexOf("image/") === 0
                        source: modelData.attachmentPath
                                ? "file://" + modelData.attachmentPath : ""
                        width: Math.min(sourceSize.width, view.width * 0.6)
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                    }

                    Label {
                        id: other
                        visible: modelData.attachmentPath && !picture.visible
                        width: parent.width
                        wrapMode: Text.Wrap
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeExtraSmall
                        text: app.tr("attach") + ": "
                              + ("" + modelData.attachmentType)
                              + " (" + Math.round((modelData.attachmentSize || 0) / 1024)
                              + " KB)"
                    }

                    Label {
                        id: body
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
                Briar.send(page.contactId, text, function(answer) {
                    if (answer.error)
                        app.lastError = answer.error
                    page.reload()
                })
            }
        }
    }
}
