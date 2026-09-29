import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    Component.onCompleted: {
        var nutzlast = Briar.qrPayload(fenster.zustand)
        if (nutzlast)
            qrBild.source = "file://" + QrCode.imageFor(nutzlast, 360)
    }

    Column {
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
        spacing: 16

        Label {
            textFormat: Text.PlainText
            text: fenster.tr("myLink")
            font.pixelSize: 32
            color: "white"
        }

        // Selectable, so the link can be copied out and sent by any other
        // means -- there is no QR scanner on this device anyway.
        TextArea {
            width: parent.width
            height: 160
            readOnly: true
            // Klartext wie jedes Textfeld hier, siehe AddContactPage.
            textFormat: TextEdit.PlainText
            text: fenster.zustand.link ? fenster.zustand.link : ""
        }

        Image {
            id: qrBild
            anchors.horizontalCenter: parent.horizontalCenter
            width: 360
            height: 360
            fillMode: Image.PreserveAspectFit
            cache: false
            source: ""
            visible: source != ""
        }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: "#a0a0a0"
            font.pixelSize: 18
            text: fenster.tr("qrHint")
            visible: qrBild.visible
        }

        // Tor kostet Arbeitsspeicher, darum ist es hier anfangs aus; der
        // Dienst startet und beendet es mit diesem Schalter.
        Row {
            spacing: 16
            Switch {
                id: torSchalter
                checked: fenster.zustand.tor === true
                onCheckedChanged: {
                    if (checked !== (fenster.zustand.tor === true))
                        Briar.setTor(checked, fenster.aktualisieren)
                }
            }
            Column {
                Label {
                    textFormat: Text.PlainText
                    text: fenster.tr("torSwitch")
                    color: "white"
                    font.pixelSize: 24
                }
                Label {
                    textFormat: Text.PlainText
                    text: fenster.tr("torSwitchHint")
                    color: "#a0a0a0"
                    font.pixelSize: 18
                    width: seite.width - torSchalter.width - 48
                    wrapMode: Text.Wrap
                }
                // Vor dem ersten Lauf dazu, was der kostet: Tor holt sich
                // das ganze Verzeichnis, und auf 2G dauert das.
                Label {
                    textFormat: Text.PlainText
                    visible: fenster.zustand.torFirstRun === true
                    text: fenster.tr("torFirstRun")
                    color: "#a0a0a0"
                    font.pixelSize: 18
                    width: seite.width - torSchalter.width - 48
                    wrapMode: Text.Wrap
                }
            }
        }

        Row {
            spacing: 16
            Switch {
                checked: fenster.zustand.bluetooth === true
                onCheckedChanged: {
                    if (checked !== (fenster.zustand.bluetooth === true))
                        Briar.setBluetooth(checked, fenster.aktualisieren)
                }
            }
            Label {
                textFormat: Text.PlainText
                text: fenster.tr("btSwitch")
                color: "white"
                font.pixelSize: 24
            }
        }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            wrapMode: Text.Wrap
            color: "#a0a0a0"
            font.pixelSize: 20
            text: fenster.tr("linkHint") + fenster.zustand.port
                  + (fenster.zustand.bluetoothAddress
                     ? "\n" + fenster.tr("btHere") + fenster.zustand.bluetoothAddress
                     : "")
                  + "\n" + (fenster.zustand.onion
                            ? fenster.tr("torHere") + fenster.zustand.onion + ".onion"
                            : fenster.tr("torOff"))
        }
    }
}
