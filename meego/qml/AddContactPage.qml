import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

Page {
    id: seite

    // Gefuellt, wenn die Werte aus einem abfotografierten QR-Code kommen.
    property string vorgabeLink: ""
    property string vorgabeAdresse: ""
    property string vorgabeBluetooth: ""
    property string vorgabeOnion: ""

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: spalte.height + 32

        Column {
            id: spalte
            anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
            spacing: 12

            Label {
                text: fenster.tr("addContact")
                font.pixelSize: 32
                color: "white"
            }

            TextArea {
                id: linkFeld
                width: parent.width
                placeholderText: "briar://..."
                height: 120
                text: seite.vorgabeLink
            }

            TextField {
                id: nameFeld
                width: parent.width
                placeholderText: fenster.tr("nameFree")
            }

            // Die drei Adressfelder gehoeren zu den eigenen Fassungen: ein
            // Briar auf Android hat keine und findet den Weg ueber Tor selbst.
            Label {
                width: parent.width
                wrapMode: Text.Wrap
                color: "#a0a0a0"
                font.pixelSize: 20
                text: fenster.tr("addressOwnHint")
            }

            TextField {
                id: adressFeld
                width: parent.width
                text: seite.vorgabeAdresse
                placeholderText: fenster.tr("lanAddress")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            TextField {
                id: btFeld
                width: parent.width
                text: seite.vorgabeBluetooth
                placeholderText: fenster.tr("btAddress")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            TextField {
                id: onionFeld
                width: parent.width
                text: seite.vorgabeOnion
                placeholderText: fenster.tr("onionAddress")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }
            Label {
                width: parent.width
                wrapMode: Text.Wrap
                color: "#a0a0a0"
                font.pixelSize: 20
                text: fenster.tr("addHint")
            }


            // Ohne Tor wird keine .onion ausgetauscht -- und getrennte Wege kennen

            // weder WLAN noch Bluetooth.

            Label {

                visible: !fenster.zustand.tor

                width: parent.width

                wrapMode: Text.Wrap

                color: "#ff6666"

                font.pixelSize: 18

                text: fenster.tr("torOffWhenAdding")

            }

            Button {
                text: fenster.tr("add")
                width: parent.width
                enabled: linkFeld.text.length > 20
                onClicked: {
                    Briar.addPending(linkFeld.text, nameFeld.text, adressFeld.text,
                                     btFeld.text, onionFeld.text, function(antwort) {
                        if (antwort.error) {
                            fenster.fehler = antwort.error
                        } else {
                            fenster.zustand = antwort
                            pageStack.pop()
                        }
                    })
                }
            }
        }
    }
}
