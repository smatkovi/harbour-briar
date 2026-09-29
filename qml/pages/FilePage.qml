import QtQuick 2.0
import Sailfish.Silica 1.0
import Qt.labs.folderlistmodel 2.1
import "../Strings.js" as Strings

// A plain browser rather than the system picker: the same design works on
// Harmattan, where there is no picker to call.
Page {
    id: page
    allowedOrientations: Orientation.All

    // A URL, because FolderListModel and parentFolder speak URLs
    property string folder: "file://" + StandardPaths.home
    signal picked(string path)

    SilicaListView {
        anchors.fill: parent
        model: FolderListModel {
            id: folderModel
            folder: page.folder
            showDirsFirst: true
            showDotAndDotDot: false
            nameFilters: ["*"]
        }

        header: Column {
            width: page.width
            PageHeader { title: app.tr("pickFile") }
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: page.folder.toString().replace("file://", "")
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                truncationMode: TruncationMode.Fade
            }
        }

        PullDownMenu {
            MenuItem {
                text: app.tr("up")
                onClicked: page.folder = folderModel.parentFolder
            }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeSmall
            Label {
                textFormat: Text.PlainText
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - 2 * Theme.horizontalPageMargin
                truncationMode: TruncationMode.Fade
                text: fileIsDir ? fileName + "/" : fileName
                color: fileIsDir ? Theme.highlightColor : Theme.primaryColor
            }
            onClicked: {
                if (fileIsDir)
                    page.folder = "file://" + filePath
                else
                    page.picked("" + filePath)
            }
        }

        VerticalScrollDecorator { }
    }
}
