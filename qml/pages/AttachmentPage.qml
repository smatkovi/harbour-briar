import QtQuick 2.0
import QtMultimedia 5.0
import Sailfish.Silica 1.0

// Einen Anhang ansehen, ohne ihn aus der Hand zu geben.
//
// Die Anhaenge liegen im Datenordner der App, und der steht auf 0700: kein
// anderes Programm kommt hinein. Das ist Absicht -- eine Kopie in die Galerie
// waere eine Kopie ausserhalb von Briar, und wer ein Bild in einem Gespraech
// bekommt, hat es nicht dorthin gelegt. Darum zeigt die App es selbst:
// Bilder mit Zoom, Text als Text, Ton und Video mit einem Abspieler.
//
// Briar auf Android macht es genauso (ImageActivity im eigenen Prozess).
Page {
    id: page
    allowedOrientations: Orientation.All

    property string pfad: ""
    property string typ: ""
    property int groesse: 0

    property bool istBild: ("" + typ).indexOf("image/") === 0
    property bool istTon: ("" + typ).indexOf("audio/") === 0
    property bool istVideo: ("" + typ).indexOf("video/") === 0
    property bool istText: ("" + typ).indexOf("text/") === 0
    property string quelle: pfad ? "file://" + pfad : ""

    // Bild: ziehen und zoomen. Ein Doppeltipp setzt zurueck.
    SilicaFlickable {
        id: rahmen
        anchors.fill: parent
        visible: page.istBild
        contentWidth: Math.max(bild.width, width)
        contentHeight: Math.max(bild.height, height)
        clip: true

        PullDownMenu {
            MenuItem {
                text: app.tr("attachmentReset")
                onClicked: bild.zuruecksetzen()
            }
        }

        Image {
            id: bild
            source: page.istBild ? page.quelle : ""
            asynchronous: true
            fillMode: Image.PreserveAspectFit
            width: grundbreite * faktor
            height: grundhoehe * faktor

            property real faktor: 1
            property real grundbreite: sourceSize.width > 0
                    ? Math.min(sourceSize.width, rahmen.width) : rahmen.width
            property real grundhoehe: sourceSize.width > 0
                    ? grundbreite * sourceSize.height / sourceSize.width : rahmen.height

            function zuruecksetzen() { faktor = 1 }

            PinchArea {
                anchors.fill: parent
                pinch.target: null
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

    // Ton und Video: derselbe Abspieler, beim Video mit Bild.
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.horizontalPageMargin
        spacing: Theme.paddingLarge
        visible: page.istTon || page.istVideo

        VideoOutput {
            width: parent.width
            height: page.istVideo ? width * 0.6 : 0
            visible: page.istVideo
            source: spieler
            fillMode: VideoOutput.PreserveAspectFit
        }

        Slider {
            id: schieber
            width: parent.width
            minimumValue: 0
            maximumValue: Math.max(1, spieler.duration)
            value: spieler.position
            onReleased: spieler.seek(value)
        }

        Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Theme.paddingLarge

            Button {
                text: spieler.playbackState === MediaPlayer.PlayingState
                      ? app.tr("attachmentPause") : app.tr("attachmentPlay")
                onClicked: spieler.playbackState === MediaPlayer.PlayingState
                           ? spieler.pause() : spieler.play()
            }
            Button {
                text: app.tr("attachmentReset")
                onClicked: { spieler.stop(); spieler.seek(0) }
            }
        }
    }

    MediaPlayer {
        id: spieler
        source: (page.istTon || page.istVideo) ? page.quelle : ""
        autoLoad: true
    }

    // Text: einfach lesen.
    SilicaFlickable {
        anchors.fill: parent
        visible: page.istText
        contentHeight: textblock.height + 2 * Theme.paddingLarge

        Label {
            id: textblock
            x: Theme.horizontalPageMargin
            y: Theme.paddingLarge
            width: page.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            font.pixelSize: Theme.fontSizeSmall
            text: page.istText ? ImagePrep.textOf(page.pfad) : ""
        }
    }

    // Alles andere: sagen, was es ist, und dass es hier nicht zu zeigen ist.
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.horizontalPageMargin
        spacing: Theme.paddingMedium
        visible: !page.istBild && !page.istTon && !page.istVideo && !page.istText

        Label {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            text: ("" + page.typ) + "  ·  "
                  + Math.round((page.groesse || 0) / 1024) + " KB"
        }
        Label {
            width: parent.width
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeSmall
            text: app.tr("attachmentNoViewer")
        }
    }

    Component.onDestruction: spieler.stop()
}
