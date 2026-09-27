import QtQuick 1.1
import com.nokia.meego 1.0
import "Briar.js" as Briar
import "Strings.js" as Strings

PageStackWindow {
    id: fenster
    showStatusBar: true
    showToolBar: true

    // The N9's AMOLED shows black as black; in the dark that is the
    // difference between readable and blinding.
    platformStyle: PageStackWindowStyle { background: "" }

    property variant zustand: { "contacts": [], "pending": [], "groups": [], "identity": null }
    property string fehler: ""
    property int sprachStand: 0

    // Alle Beschriftungen gehen hier durch, damit ein Sprachwechsel sofort
    // ueberall ankommt.
    function tr(schluessel) {
        return sprachStand, Strings.t(schluessel)
    }

    // Dasselbe fuer das letzte Ereignis einer Gruppe: der Dienst schickt nur
    // die Art und den Namen, den Satz macht die Oberflaeche -- und er muss
    // beim Sprachwechsel mitkommen, darum ueber sprachStand.
    function ereignis(e) {
        return sprachStand, Strings.ereignis(e)
    }

    function spracheUmschalten() {
        Briar.setLanguage(Strings.language() === "de" ? "en" : "de",
                          function() { fenster.aktualisieren() })
    }

    // Meldet der Dienst "locked", steht die Entsperrseite vor allem anderen.
    property bool gesperrt: false

    function entsperrseiteZeigen() {
        if (pageStack.currentPage
                && pageStack.currentPage.objectName === "entsperren")
            return
        pageStack.replace(Qt.resolvedUrl("UnlockPage.qml"),
                          { "objectName": "entsperren" })
    }

    // Ein Konto ohne Passwort: das kennt Briar auf Android nicht. Hier kann es
    // eines geben -- angelegt mit einer Fassung, die noch keines verlangte.
    // Dann fragt die App beim Start danach und laesst nichts anderes zu.
    function passwortseiteZeigen() {
        if (pageStack.currentPage
                && pageStack.currentPage.objectName === "passwortSetzen")
            return
        pageStack.replace(Qt.resolvedUrl("SetupPasswordPage.qml"),
                          { "objectName": "passwortSetzen", "nurPasswort": true })
    }

    function aktualisieren() {
        Briar.status(function(antwort) {
            if (antwort.locked) {
                fenster.gesperrt = true
                fenster.fehler = ""
                fenster.entsperrseiteZeigen()
                return
            }
            fenster.gesperrt = false
            if (antwort.error) {
                fenster.fehler = antwort.error
                dienst.starten()
            } else {
                fenster.fehler = ""
                fenster.zustand = antwort
                if (antwort.identity && antwort.encrypted === false) {
                    fenster.passwortseiteZeigen()
                    return
                }
                if (antwort.language && antwort.language !== Strings.language()) {
                    Strings.setLanguage(antwort.language)
                    fenster.sprachStand++
                }
            }
        })
    }

    Component.onCompleted: {
        theme.inverted = true
        // Englisch, bis der Dienst etwas anderes sagt.
        aktualisieren()
    }

    Timer {
        interval: 3000
        running: Qt.application.active
        repeat: true
        onTriggered: fenster.aktualisieren()
    }

    initialPage: kontakteSeite
    ContactsPage { id: kontakteSeite }
}
