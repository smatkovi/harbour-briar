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
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeExtraSmall
            text: app.tr("addHint")
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
