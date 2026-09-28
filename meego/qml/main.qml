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
    /// Die Marke vom Zusperren: mit ihr geht Briar wieder auf, sobald das
    /// Telefon aufgesperrt wird -- ohne dass das Passwort irgendwo liegt.
    property string sperrMarke: ""

    // Das Geraeteschloss fuehrt Briars Sperre. Sperrt das Telefon zu, sperrt
    // Briar mit; sperrt es auf, geht auch Briar wieder auf. Ist gar kein
    // Sperrcode eingestellt -- Harmattan erlaubt das --, meldet der Dienst nie
    // eine Sperre, und es bleibt beim Briar-Passwort nach dem Neustart.
    Connections {
        target: geraeteschloss
        onGesperrtChanged: {
            if (geraeteschloss.gesperrt) {
                Briar.lock(function(antwort) {
                    if (!antwort.error)
                        fenster.sperrMarke = antwort.token ? antwort.token : ""
                })
            } else if (fenster.sperrMarke.length > 0) {
                Briar.unlock2(fenster.sperrMarke, function(antwort) {
                    if (!antwort.error) {
                        fenster.sperrMarke = ""
                        fenster.gesperrt = false
                        fenster.aktualisieren()
                    }
                })
            }
        }
    }

    // Der eine Weg von der Entsperrseite herunter -- siehe harbour-briar.qml:
    // sie kommt per replace() herein, pop() tut bei Tiefe 1 nichts.
    function entsperrt() {
        fenster.gesperrt = false
        fenster.fehler = ""
        pageStack.replace(kontakteSeite)
        fenster.aktualisieren()
    }

    function entsperrseiteZeigen() {
        if (pageStack.currentPage
                && pageStack.currentPage.objectName === "entsperren")
            return
        pageStack.replace(Qt.resolvedUrl("UnlockPage.qml"),
                          { "objectName": "entsperren" })
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

    // Der Takt, in dem die Oberflaeche den Dienst fragt.
    //
    // Frueher hing das allein an Qt.application.active. Am N9 stand die Liste
    // damit still: es liefen zwei Oberflaechen-Prozesse, in sechs Sekunden
    // ging keine einzige Anfrage an den Dienst -- und ein Kontakt, den der
    // Dienst laengst hatte, tauchte nie auf. Wovon Harmattan die Kennzeichnung
    // genau abhaengig macht, ist nicht festzustellen; also haengt der Takt
    // nicht mehr allein daran. Im Vordergrund alle drei Sekunden, sonst alle
    // fuenfzehn -- das kostet fast nichts und die Liste kann nicht mehr
    // einfrieren.
    /// Laeuft gerade ein Entsperrversuch? Dann ruht die Abfrage: sie brachte
    /// in dieser Zeit nichts, kam dem Entsperren aber in die Quere.
    property bool entsperrtGerade: false

    Timer {
        interval: Qt.application.active ? 3000 : 15000
        running: !fenster.entsperrtGerade
        repeat: true
        onTriggered: fenster.aktualisieren()
    }

    initialPage: kontakteSeite
    ContactsPage { id: kontakteSeite }
}
