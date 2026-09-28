// Briar for MeeGo Harmattan (Nokia N9 / N950).
//
// The protocol runs in briard, the same static Rust binary the Sailfish port
// uses; this program starts it and shows the Qt 4.7 interface. Briar itself
// is Java and needs Java 8 -- nothing that will ever run on this device --
// so the port is a reimplementation of Bramble's wire protocols, not a port
// of Briar's code.

#include <QApplication>
#include <QDeclarativeContext>
#include <QDeclarativeEngine>
#include <QDeclarativeView>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QInputContext>
#include <QInputContextFactory>
#include <QLocale>
#include <QProcess>
#include <QTcpSocket>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>

#include "../src/imageprep.h"

static const quint16 ApiPort = 8105;

// Harmattan writes the session bus address here. A process started over ssh
// or from a service does not inherit it, and without it nothing on the bus
// works -- the same trap the other ports on this device ran into.
static void sitzungsBusSetzen()
{
    if (!qgetenv("DBUS_SESSION_BUS_ADDRESS").isEmpty())
        return;
    QFile f(QLatin1String("/tmp/session_bus_address.user"));
    if (!f.open(QIODevice::ReadOnly))
        return;
    const QStringList zeilen = QString::fromLatin1(f.readAll()).split(QLatin1Char('\n'));
    for (int i = 0; i < zeilen.size(); ++i) {
        const QString z = zeilen.at(i);
        const int p = z.indexOf(QLatin1String("DBUS_SESSION_BUS_ADDRESS="));
        if (p < 0)
            continue;
        QString wert = z.mid(p + 25).trimmed();
        if (wert.endsWith(QLatin1Char(';')))
            wert.chop(1);
        if (wert.length() > 1 && (wert.at(0) == QLatin1Char('"') || wert.at(0) == QLatin1Char('\''))
                && wert.at(wert.length() - 1) == wert.at(0)) {
            wert = wert.mid(1, wert.length() - 2);
        }
        if (!wert.isEmpty())
            qputenv("DBUS_SESSION_BUS_ADDRESS", wert.toLatin1());
        return;
    }
}

static bool dienstAntwortet()
{
    QTcpSocket socket;
    socket.connectToHost(QLatin1String("127.0.0.1"), ApiPort);
    return socket.waitForConnected(300);
}

#if __has_include("briarversion.h")
#include "briarversion.h"
#endif
#ifndef BRIAR_VERSION
#define BRIAR_VERSION "unbekannt"
#endif

/// Welche Fassung der laufende Dienst ist -- leer, wenn er nicht antwortet
/// oder es nicht sagt (dann ist er aelter als 0.35.2).
static QString dienstFassung()
{
    QTcpSocket socket;
    socket.connectToHost(QLatin1String("127.0.0.1"), ApiPort);
    if (!socket.waitForConnected(300))
        return QString();
    socket.write("GET /status HTTP/1.0\r\n\r\n");
    if (!socket.waitForBytesWritten(300))
        return QString();
    QByteArray antwort;
    while (socket.waitForReadyRead(700))
        antwort += socket.readAll();
    const int i = antwort.indexOf("\"version\":\"");
    if (i < 0)
        return QString();
    const int a = i + 11;
    const int e = antwort.indexOf('"', a);
    if (e < 0)
        return QString();
    return QString::fromLatin1(antwort.mid(a, e - a));
}

/// Den laufenden Dienst beenden.
///
/// Ueber /proc, weil sich in dieser Umgebung weder pkill noch pgrep
/// voraussetzen laesst -- und weil der Weg ueber das Paket am N9 gar nicht
/// geht: aegis-dpkg fuehrt Wartungsskripte nicht aus (nachgemessen, die
/// Spur des postinst blieb aus). Der Dienst gehoert demselben Benutzer,
/// also darf die App ihn beenden.
static void dienstBeenden()
{
    QDir proc(QLatin1String("/proc"));
    const QStringList eintraege =
        proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (int i = 0; i < eintraege.size(); ++i) {
        bool zahl = false;
        const int pid = eintraege.at(i).toInt(&zahl);
        if (!zahl || pid <= 1)
            continue;
        QFile f(QLatin1String("/proc/") + eintraege.at(i)
                + QLatin1String("/cmdline"));
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QByteArray zeile = f.readAll();
        f.close();
        // Nur das erste Wort der Befehlszeile, siehe die Sailfish-Seite.
        if (zeile.split('\0').value(0) == "/opt/briar/bin/briard")
            ::kill(pid, SIGTERM);
    }
}

#include "dienst.h"
#include "../src/qrcode.h"
#include "kamera.h"
#include "geraeteschloss.h"
#include "sucher.h"

static void dienstStarten();

void Dienst::starten()
{
    dienstStarten();
}

static void dienstStarten()
{
    if (dienstAntwortet()) {
        // Laeuft schon einer -- aber ist es der zur App gehoerende? Der
        // Dienst ueberlebt eine Aktualisierung des Pakets, und die App
        // startet sonst keinen zweiten. Am N9 lief so Paket 0.35.3 neben
        // einem Dienst aus 0.34.0, und jede Reparatur schien wirkungslos.
        const QString laeuft = dienstFassung();
        if (laeuft == QLatin1String(BRIAR_VERSION))
            return;
        // Keine Fassung lesbar: nicht beenden -- siehe die Sailfish-Seite.
        if (laeuft.isEmpty()) {
            qWarning("Dienst nennt keine Fassung -- bleibt stehen");
            return;
        }
        qWarning("Dienst ist Fassung '%s', die App ist %s -- neu starten",
                 qPrintable(laeuft.isEmpty() ? QLatin1String("aelter als 0.35.2")
                                             : laeuft),
                 BRIAR_VERSION);
        dienstBeenden();
        // Kurz warten, bis der Port wieder frei ist.
        // QThread::msleep ist in Qt 4.7 geschuetzt -- also unmittelbar.
        for (int i = 0; i < 20 && dienstAntwortet(); ++i)
            ::usleep(100 * 1000);
    }
    const QString daten = QDir::homePath() + QLatin1String("/.local/share/harbour-briar");
    QDir().mkpath(daten);
    QStringList argumente;
    argumente << QLatin1String("--state") << daten + QLatin1String("/state.json")
              << QLatin1String("--api-port") << QString::number(ApiPort);
    // Detached, so messages keep arriving after the interface is closed.
    QProcess::startDetached(QLatin1String("/opt/briar/bin/briard"), argumente);
}

int main(int argc, char *argv[])
{
    sitzungsBusSetzen();
    // GStreamer fuer den Sucher (sucher.h). Scheitert es, faellt nur der
    // Sucher aus -- die Seite geht dann den alten Weg ueber die Kamera-App.
    gst_init(&argc, &argv);

    QApplication app(argc, argv);

    // Without this the virtual keyboard never appears once the hardware one
    // is closed: a bare QApplication picks no input context at all.
    if (QInputContext *ic = QInputContextFactory::create(
            QLatin1String("MInputContext"), &app)) {
        app.setInputContext(ic);
    }

    dienstStarten();
    Dienst dienst;
    QrCode qrCode;
    // Vor der QDeclarativeView angelegt: Stapelobjekte sterben in umgekehrter
    // Reihenfolge, und die Engine haelt beim Abbau noch eine
    // Kontext-Eigenschaft darauf.
    Kamera kamera;
    Geraeteschloss geraeteschloss;

    // Der Sucher ist ein zeichnendes Element, keine Eigenschaft: er muss
    // als Typ angemeldet werden, damit QML ihn hinstellen kann.
    qmlRegisterType<Sucher>("Briar", 1, 0, "Sucher");

    QDeclarativeView view;
    // Qt 4.7's QML has no Qt.locale(), so the interface gets the system's
    // language from here and picks German or English from it.
    view.rootContext()->setContextProperty(QLatin1String("systemSprache"),
                                           QLocale::system().name());
    ImagePrep imagePrep;
    view.rootContext()->setContextProperty(QLatin1String("ImagePrep"), &imagePrep);
    view.rootContext()->setContextProperty(QLatin1String("dienst"), &dienst);
    view.rootContext()->setContextProperty(QLatin1String("QrCode"), &qrCode);
    // Klein geschrieben wie "dienst": ein unbekannter Name faellt in QML 1.1
    // nicht auf, er faellt aus -- Connections greift dann still auf das
    // Elternobjekt zurueck.
    view.rootContext()->setContextProperty(QLatin1String("kamera"), &kamera);
    // Das Geraeteschloss: sperrt das Telefon zu, sperrt Briar mit.
    view.rootContext()->setContextProperty(QLatin1String("geraeteschloss"),
                                           &geraeteschloss);
    view.setResizeMode(QDeclarativeView::SizeRootObjectToView);
    view.setSource(QUrl::fromLocalFile(QLatin1String("/opt/briar/qml/main.qml")));
    view.showFullScreen();
    return app.exec();
}
