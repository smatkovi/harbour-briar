import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Share 1.0
import Nemo.DBus 2.0
import "Briar.js" as Briar
import "Strings.js" as Strings
import "pages"
import "cover"

ApplicationWindow {
    id: app

    // The daemon's last answer to /status, shared by every page.
    property var status: ({ contacts: [], pending: [], identity: null })
    property string lastError: ""
    // Bumped when the language changes, so every binding that calls
    // Strings.t() is re-evaluated.
    property int languageRevision: 0

    // Every label goes through this, so one comma expression ties all of
    // them to languageRevision -- otherwise the texts would only change on
    // the next page.
    function tr(key) {
        return languageRevision, Strings.t(key)
    }

    function toggleLanguage() {
        Briar.setLanguage(Strings.language() === "de" ? "en" : "de", function() {
            app.refresh()
        })
    }

    function refresh() {
        Briar.status(function(answer) {
            if (answer.error) {
                app.lastError = answer.error
                // The daemon is gone -- start it again rather than leaving
                // the user with a dead window.
                Daemon.ensureRunning()
            } else {
                app.lastError = ""
                app.status = answer
                // The daemon keeps the choice, so a restart or the other
                // front end finds the same language.
                if (answer.language && answer.language !== Strings.language()) {
                    Strings.setLanguage(answer.language)
                    app.languageRevision++
                }
            }
        })
    }

    Timer {
        // The daemon changes things by itself -- messages arrive, a pending
        // contact becomes a contact -- so the interface asks regularly.
        interval: 3000
        running: Qt.application.active
        repeat: true
        onTriggered: app.refresh()
    }

    Component.onCompleted: {
        // English until the daemon says otherwise -- see toggleLanguage.
        app.refresh()
    }

    // What the share menu hands over, until a contact has been picked.
    property var pendingShareFiles: []
    property string pendingShareText: ""

    // Tapping a notification lands here; so does the share dialog. Both are
    // ordinary D-Bus calls, and sailjaild starts the app for them when it is
    // not running (see dbus/harbour.harbour-briar.service).
    DBusAdaptor {
        service: "harbour.harbour-briar"
        path: "/"
        iface: "harbour.briar.Gui"

        function openChat(contactId) {
            var id = parseInt(contactId)
            var name = ""
            for (var i = 0; i < app.status.contacts.length; i++) {
                if (app.status.contacts[i].id === id)
                    name = app.status.contacts[i].name
            }
            app.activate()
            pageStack.push(Qt.resolvedUrl("pages/ChatPage.qml"),
                           {"contactId": id, "contactName": name})
        }

        function openGroup(groupId) {
            var name = ""
            for (var i = 0; i < app.status.groups.length; i++) {
                if (app.status.groups[i].id === groupId)
                    name = app.status.groups[i].name
            }
            app.activate()
            pageStack.push(Qt.resolvedUrl("pages/GroupChatPage.qml"),
                           {"groupId": groupId, "groupName": name})
        }
    }

    ShareAction { id: shareParser }

    // The share dialog calls its own object: /share/<method>, interface
    // org.sailfishos.share. Without it the dialog says "could not share".
    DBusAdaptor {
        service: "harbour.harbour-briar"
        path: "/share/briar_share"
        iface: "org.sailfishos.share"

        function share(shareConfiguration) {
            shareParser.loadConfiguration(shareConfiguration)
            var files = []
            var resources = shareParser.resources
            if (resources) {
                for (var i = 0; i < resources.length; i++) {
                    var item = resources[i]
                    var url = (typeof item === "string") ? item
                                                         : (item.url || item.filePath)
                    if (url)
                        files.push(String(url).replace(/^file:\/\//, ""))
                }
            }
            app.pendingShareFiles = files
            app.pendingShareText = shareParser.text || ""
            app.activate()
            pageStack.push(Qt.resolvedUrl("pages/SharePage.qml"))
        }
    }

    initialPage: Component { MainPage { } }
    cover: Component { CoverPage { } }
    allowedOrientations: defaultAllowedOrientations
}
