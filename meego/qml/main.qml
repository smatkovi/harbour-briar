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

    function spracheUmschalten() {
        Briar.setLanguage(Strings.language() === "de" ? "en" : "de",
                          function() { fenster.aktualisieren() })
    }

    function aktualisieren() {
        Briar.status(function(antwort) {
            if (antwort.error) {
                fenster.fehler = antwort.error
                dienst.starten()
            } else {
                fenster.fehler = ""
                fenster.zustand = antwort
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
