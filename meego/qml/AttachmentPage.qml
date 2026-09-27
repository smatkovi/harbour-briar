import QtQuick 1.1
import com.nokia.meego 1.0

// Einen Anhang ansehen, ohne ihn aus der Hand zu geben.
//
// Wie an der Jolla: die Anhaenge liegen im Datenordner der App, kein anderes
// Programm kommt hinein, und genau so bleibt es. Gezeigt wird darum hier --
// Bilder mit Zoom, Text als Text. Ton und Video zeigt diese Seite nicht: ein
// Anhang passt in eine Briar-Nachricht, ist also hoechstens 32 KiB gross, und
// die Abspieler von Harmattan hier hereinzuholen waere ein Bauteil mehr, das
// beim Laden scheitern kann.
Page {
    id: seite

    property string pfad: ""
    property string typ: ""
    property int groesse: 0

    property bool istBild: ("" + typ).indexOf("image/") === 0
    property bool istText: ("" + typ).indexOf("text/") === 0
    property string quelle: pfad ? "file://" + pfad : ""

    tools: ToolBarLayout {
        ToolIcon {
            platformIconId: "toolbar-back"
            onClicked: pageStack.pop()
        }
        ToolIcon {
            platformIconId: "toolbar-refresh"
            visible: seite.istBild
            onClicked: bild.faktor = 1
        }
    }

    // Bild: ziehen und zoomen, Doppeltipp setzt zurueck.
    Flickable {
        id: rahmen
        anchors.fill: parent
        visible: seite.istBild
        contentWidth: Math.max(bild.width, width)
        contentHeight: Math.max(bild.height, height)
        clip: true

        Image {
            id: bild
            source: seite.istBild ? seite.quelle : ""
            asynchronous: true
            fillMode: Image.PreserveAspectFit
            width: grundbreite * faktor
            height: grundhoehe * faktor

            property real faktor: 1
            property real grundbreite: sourceSize.width > 0
                    ? Math.min(sourceSize.width, rahmen.width) : rahmen.width
            property real grundhoehe: sourceSize.width > 0
                    ? grundbreite * sourceSize.height / sourceSize.width : rahmen.height

            PinchArea {
                anchors.fill: parent
                onPinchUpdated: {
                    var neu = bild.faktor * (1 + (pinch.scale - pinch.previousScale))
                    bild.faktor = Math.max(1, Math.min(6, neu))
                }
            }

            MouseArea {
                anchors.fill: parent
                onDoubleClicked: bild.faktor = bild.faktor > 1 ? 1 : 3
            }
        }
    }

    // Text: einfach lesen.
    Flickable {
        anchors { fill: parent; margins: 16 }
        visible: seite.istText
        contentHeight: textblock.paintedHeight + 32

        Text {
            id: textblock
            width: parent.width
            wrapMode: Text.Wrap
            color: "white"
            font.pixelSize: 22
            text: seite.istText ? ImagePrep.textOf(seite.pfad) : ""
        }
    }

    // Alles andere: sagen, was es ist.
    Column {
        anchors { centerIn: parent }
        width: parent.width - 48
        spacing: 12
        visible: !seite.istBild && !seite.istText

        Text {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: "white"
            font.pixelSize: 24
            text: ("" + seite.typ) + "  ·  " + Math.round((seite.groesse || 0) / 1024) + " KB"
        }
        Text {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: "#a0a0a0"
            font.pixelSize: 20
            text: fenster.tr("attachmentNoViewer")
        }
    }
}
