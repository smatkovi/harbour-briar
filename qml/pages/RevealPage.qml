import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar

// "Kontakte zeigen" -- Briars revealRelationship.
//
// Es betrifft nur die Kontakte, mit denen wir in derselben Gruppe sind, ohne
// dass einer den anderen eingeladen hat: bei Briar ist das die PEER-Rolle,
// und nur dort gibt es etwas zu zeigen. Wer eingeladen hat oder eingeladen
// wurde, hat sein JOIN laengst geschickt -- ein zweites gabelte die Kette.
// Welche Kontakte in Frage kommen, entscheidet der Dienst (net::zeigbarkeit);
// hier steht nur, was er nennt.
Page {
    id: page
    allowedOrientations: Orientation.All

    property string groupId: ""
    property string groupName: ""
    /// Vom Aufrufer gereicht: was /group/messages unter "revealable" nannte.
    property var kandidaten: []

    SilicaListView {
        anchors.fill: parent
        model: page.kandidaten

        header: Column {
            width: page.width
            PageHeader {
                title: app.tr("revealWho")
                description: page.groupName
            }
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeSmall
                text: app.tr("revealHint")
            }
            Item { width: 1; height: Theme.paddingLarge }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeSmall
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.name
            }
            onClicked: Briar.reveal(page.groupId, modelData.id, function(antwort) {
                if (antwort.error)
                    app.lastError = antwort.error
                pageStack.pop()
            })
        }

        ViewPlaceholder {
            enabled: page.kandidaten.length === 0
            text: app.tr("revealNone")
        }
    }
}
