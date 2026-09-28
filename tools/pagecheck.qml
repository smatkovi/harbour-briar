// Loads every page once, so the QML engine reports type and syntax errors
// before the package is built. Runs without a screen:
//
//   QT_LOGGING_TO_CONSOLE=1 QT_QPA_PLATFORM=minimal qmlscene --quit tools/pagecheck.qml
//
// Two things about that line. QT_LOGGING_TO_CONSOLE is not decoration: on
// Sailfish the messages otherwise go to the journal, and the check looks as
// if it had said nothing. And the pages are only *loaded*, not instantiated:
// Silica's ApplicationWindow wants the compositor and takes qmlscene down
// with it on a headless device, so whatever needs a window has to wait for
// the real run on the phone. Loading still catches what goes wrong most
// often -- a typo in a type name, a missing import, a broken expression.
import QtQuick 2.0

QtObject {
    Component.onCompleted: {
        var seiten = ["MainPage", "ChatPage", "AddContactPage", "LinkPage",
                      "AboutPage", "HelpPage", "GroupsPage", "GroupChatPage",
                      "InvitePage", "FilePage", "ScanPage", "SharePage",
                      "MeetPage", "AttachmentPage", "UnlockPage",
                      "PasswordPage", "SetupPasswordPage"]
        var fehler = 0
        for (var i = 0; i < seiten.length; i++) {
            var c = Qt.createComponent(
                        Qt.resolvedUrl("../qml/pages/" + seiten[i] + ".qml"))
            if (c.status === Component.Error) {
                console.warn("FEHLER " + seiten[i] + ": " + c.errorString())
                fehler++
            } else {
                console.warn("ok " + seiten[i])
            }
        }
        console.warn("pagecheck fertig, Fehler: " + fehler)
        Qt.quit()
    }
}
