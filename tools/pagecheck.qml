// Instantiates every page once, so the QML engine reports type and binding
// errors before the package is built. Runs without a screen:
//
//   QT_QPA_PLATFORM=minimal qmlscene --quit tools/pagecheck.qml
//
// The pages expect an ApplicationWindow called `app` with the three
// properties the real one has; that is all this stands in for.
import QtQuick 2.0
import Sailfish.Silica 1.0

ApplicationWindow {
    id: app
    property var status: ({
        "running": true, "identity": {"name": "Pruefer", "link": "briar://x"},
        "contacts": [{"id": 1, "name": "Kontakt", "online": true, "unread": 1}],
        "pending": [], "groups": [{"id": "abcd", "name": "Gruppe", "unread": 0}],
        "bluetooth": true, "tor": true, "onion": "abc"
    })
    property string lastError: ""
    property var pendingShareFiles: []
    property string pendingShareText: ""
    property int languageRevision: 0
    function tr(key) { return languageRevision, "x" }
    function refresh() {}

    Component.onCompleted: {
        var seiten = ["MainPage", "ChatPage", "AddContactPage", "LinkPage",
                      "AboutPage", "HelpPage", "GroupsPage", "GroupChatPage",
                      "InvitePage", "FilePage", "ScanPage", "SharePage"]
        for (var i = 0; i < seiten.length; i++) {
            var c = Qt.createComponent(Qt.resolvedUrl("../qml/pages/" + seiten[i] + ".qml"))
            if (c.status === Component.Error) {
                console.log("FEHLER " + seiten[i] + ": " + c.errorString())
                continue
            }
            var o = c.createObject(app)
            if (!o) console.log("FEHLER " + seiten[i] + ": createObject")
            else console.log("ok " + seiten[i])
        }
        console.log("pagecheck fertig")
    }
}
