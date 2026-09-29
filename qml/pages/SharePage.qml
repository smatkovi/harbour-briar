import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// Where a file from the share menu lands: pick who gets it. The file goes
// the same way as one picked inside a chat -- one message, at most 32 KB,
// images scaled down first.
Page {
    allowedOrientations: Orientation.All

    SilicaListView {
        anchors.fill: parent
        header: Column {
            width: parent.width
            PageHeader { title: app.tr("shareTitle") }
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                text: app.pendingShareFiles.length > 0
                      ? app.pendingShareFiles[0]
                      : app.pendingShareText
            }
        }

        model: app.status.contacts

        delegate: ListItem {
            width: parent.width
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.name
            }
            onClicked: {
                var file = app.pendingShareFiles.length > 0
                           ? app.pendingShareFiles[0] : ""
                if (file) {
                    // The same route as a file picked inside a chat: images
                    // are scaled until they fit, everything else has to be
                    // small enough by itself.
                    var type = ImagePrep.contentType(file)
                    var prepared = ImagePrep.prepare(file, 32200)
                    if (prepared.length === 0) {
                        app.lastError = app.tr("tooBig")
                        return
                    }
                    if (prepared !== file)
                        type = "image/jpeg"
                    Briar.sendFile(modelData.id, app.pendingShareText,
                                   prepared, type,
                                   function(answer) {
                        // Die verkleinerte Kopie wegraeumen, wie im Chat.
                        if (prepared !== file)
                            ImagePrep.aufraeumen(prepared)
                        app.lastError = answer.error ? answer.error : ""
                        app.pendingShareFiles = []
                        app.pendingShareText = ""
                        pageStack.pop()
                    })
                } else if (app.pendingShareText) {
                    Briar.send(modelData.id, app.pendingShareText, function(answer) {
                        app.lastError = answer.error ? answer.error : ""
                        app.pendingShareText = ""
                        pageStack.pop()
                    })
                }
            }
        }

        ViewPlaceholder {
            enabled: app.status.contacts.length === 0
            text: app.tr("noContacts")
        }
    }
}
