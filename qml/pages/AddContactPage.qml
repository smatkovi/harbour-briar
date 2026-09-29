import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Dialog {
    id: dialog
    allowedOrientations: Orientation.All

    // Filled in when the values come from a photographed QR code.
    property string prefillLink: ""
    property string prefillAddress: ""
    property string prefillBluetooth: ""
    property string prefillOnion: ""
    canAccept: linkField.text.indexOf("briar://") >= 0 || linkField.text.trim().length >= 53

    // acceptText zeigt Silica immer als RichText (DialogHeader.qml:266-267,
    // QTBUG-40161): hier nie fremden Text, nur eigene aus Strings.js.
    DialogHeader { id: header; acceptText: app.tr("add") }

    Column {
        anchors { top: header.bottom; left: parent.left; right: parent.right }
        spacing: Theme.paddingMedium

        TextArea {
            id: linkField
            width: parent.width
            label: app.tr("linkOfContact")
            placeholderText: "briar://..."
            text: dialog.prefillLink
        }

        TextField {
            id: aliasField
            width: parent.width
            label: app.tr("nameFree")
            placeholderText: app.tr("name")
        }

        // Die drei Adressfelder gehoeren zu den eigenen Fassungen: ein Briar
        // auf Android hat keine und findet den Weg ueber Tor selbst.
        Label {
            textFormat: Text.PlainText
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryHighlightColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: app.tr("addressOwnHint")
        }

        TextField {
            id: addressField
            width: parent.width
            label: app.tr("lanAddress")
            placeholderText: "IP:Port"
            text: dialog.prefillAddress
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
        }

        TextField {
            id: bluetoothField
            width: parent.width
            label: app.tr("btAddress")
            placeholderText: "00:11:22:33:44:55"
            text: dialog.prefillBluetooth
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
        }

        TextField {
            id: onionField
            width: parent.width
            label: app.tr("onionAddress")
            placeholderText: "abcd...xyz"
            text: dialog.prefillOnion
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
        }

        Label {
            textFormat: Text.PlainText
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: app.tr("addHint")
        }

        // Der Fall, der sich spaeter nicht mehr heilen laesst: ohne Tor wird
        // keine .onion ausgetauscht, und getrennte Wege kennen weder WLAN noch
        // Bluetooth. Die Meldung spaeter nachzureichen braucht einen Kanal,
        // den es dann nicht mehr gibt.
        Label {
            textFormat: Text.PlainText
            visible: !app.status.tor
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.errorColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: app.tr("torOffWhenAdding")
        }
    }

    onAccepted: {
        Briar.addPending(linkField.text.trim(), aliasField.text.trim(),
                         addressField.text.trim(), bluetoothField.text.trim(),
                         onionField.text.trim(), function(answer) {
            if (answer.error)
                app.lastError = answer.error
            else
                app.status = answer
        })
    }
}
