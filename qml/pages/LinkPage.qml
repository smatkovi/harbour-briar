import QtQuick 2.0
import Sailfish.Silica 1.0
import "../Briar.js" as Briar
import "../Strings.js" as Strings

Page {
    allowedOrientations: Orientation.All

    property bool backgroundOn: false

    function refreshQr() {
        var payload = Briar.qrPayload(app.status)
        qrImage.source = payload ? "file://" + QrCode.imageFor(payload) : ""
    }

    onStatusChanged: if (status === PageStatus.Active) {
        refreshQr()
        backgroundOn = Daemon.backgroundEnabled()
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: app.tr("myLink") }

            TextArea {
                width: parent.width
                readOnly: true
                label: app.tr("myLink")
                text: app.status.link ? app.status.link : ""
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.tr("copyLink")
                onClicked: Clipboard.text = app.status.link
            }

            // The same link as a QR code, with the addresses behind it: the
            // other device photographs this and has everything it needs.
            Image {
                id: qrImage
                anchors.horizontalCenter: parent.horizontalCenter
                width: Math.min(parent.width - 2 * Theme.horizontalPageMargin, 480)
                height: width
                fillMode: Image.PreserveAspectFit
                cache: false
                source: ""
                visible: source != ""
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                text: app.tr("qrHint")
                visible: qrImage.visible
            }

            // The transports, where the addresses are shown. Tor starts and
            // stops with this switch; the daemon notices within a few seconds.
            TextSwitch {
                text: app.tr("torSwitch")
                // Vor dem ersten Lauf dazu, was der kostet: Tor holt sich
                // das ganze Verzeichnis, und auf 2G dauert das.
                description: app.tr("torSwitchHint")
                             + (app.status.torFirstRun === true ? "\n" + app.tr("torFirstRun") : "")
                checked: app.status.tor === true
                automaticCheck: false
                onClicked: Briar.setTor(!checked, app.refresh)
            }

            TextSwitch {
                text: app.tr("background")
                description: app.tr("backgroundHint")
                checked: page.backgroundOn
                automaticCheck: false
                onClicked: {
                    Daemon.setBackground(!checked)
                    page.backgroundOn = !checked
                }
            }

            TextSwitch {
                text: app.tr("btSwitch")
                checked: app.status.bluetooth === true
                automaticCheck: false
                onClicked: Briar.setBluetooth(!checked, app.refresh)
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                text: app.tr("linkHint") + app.status.port
                      + (app.status.bluetoothAddress
                         ? "\n" + app.tr("btHere") + app.status.bluetoothAddress
                         : "")
                      + "\n" + (app.status.onion
                                ? app.tr("torHere") + app.status.onion + ".onion"
                                : app.tr("torOff"))
            }
        }
    }
}
