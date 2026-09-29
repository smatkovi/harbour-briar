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
#include <QLocalSocket>
#include <QProcess>
#include <QTcpSocket>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>

#include "../src/imageprep.h"
#include "sha256.h"

// Nur noch, um einen alten Dienst (bis 0.41.0) zu erkennen, der dort
// lauscht statt auf dem Sockel -- siehe dienstStarten.
static const quint16 AlterApiPort = 8105;
// So lange wartet eine Anfrage auf ihre Antwort, wie ZEITGRENZE in Briar.js.
static const int AnfrageZeitgrenze = 90000;
// Mehr nimmt eine Anfrage nicht an: ein Fremder am Sockel soll den Speicher
// nicht fuellen (frueher 64 MiB). Nicht die 4 MiB aus der Gegenpruefung 7b
// (H): /messages und /group/messages geben den ganzen Verlauf zurueck, ohne
// Grenze (kern/src/api.rs, "/messages"), rund 300 Byte je Nachricht -- ab
// etwa 14000 Nachrichten waere ein Chat mit 4 MiB fuer immer Status 0.
static const int MaxAntwort = 16 * 1024 * 1024;

static QString datenOrdner();

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

/// Der Sockel der Schnittstelle, neben der state.json.
static QString sockelPfad()
{
    return datenOrdner() + QLatin1String("/api.sock");
}

static bool dienstAntwortet()
{
    QLocalSocket socket;
    socket.connectToServer(sockelPfad());
    return socket.waitForConnected(300);
}

/// Lauscht auf dem alten Port noch ein Dienst bis 0.41.0? Der kennt den
/// Sockel nicht, haelt aber die Instanzsperre -- ein neu gestarteter kaeme
/// nie an die Reihe.
static bool alterDienstAufPort()
{
    QTcpSocket socket;
    socket.connectToHost(QLatin1String("127.0.0.1"), AlterApiPort);
    return socket.waitForConnected(300);
}

#if __has_include("briarversion.h")
#include "briarversion.h"
#endif
#ifndef BRIAR_VERSION
#define BRIAR_VERSION "unbekannt"
#endif

/// Wo der Dienst seinen Zustand hat -- und daneben sein api-token.
static QString datenOrdner()
{
    return QDir::homePath() + QLatin1String("/.local/share/harbour-briar");
}

/// Das Geheimnis der Schnittstelle, roh aus der Datei; leer, wenn keine da ist.
static QByteArray tokenDatei()
{
    QFile f(datenOrdner() + QLatin1String("/api-token"));
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    return f.readAll().trimmed();
}

/// GET /status, roh -- mit Geheimnis, wenn eines uebergeben wird.
static QByteArray statusRoh(const QByteArray &geheimnis)
{
    QLocalSocket socket;
    socket.connectToServer(sockelPfad());
    if (!socket.waitForConnected(300))
        return QByteArray();
    QByteArray anfrage("GET /status HTTP/1.0\r\n");
    if (!geheimnis.isEmpty())
        anfrage += "Authorization: Bearer " + geheimnis + "\r\n";
    anfrage += "\r\n";
    socket.write(anfrage);
    if (!socket.waitForBytesWritten(300))
        return QByteArray();
    QByteArray antwort;
    while (socket.waitForReadyRead(700))
        antwort += socket.readAll();
    return antwort;
}

/// Den Wert eines Zeichenkettenfelds aus der rohen Antwort schneiden.
static QByteArray feld(const QByteArray &antwort, const char *name)
{
    const QByteArray schluessel = QByteArray("\"") + name + "\":\"";
    const int i = antwort.indexOf(schluessel);
    if (i < 0)
        return QByteArray();
    const int a = i + schluessel.size();
    const int e = antwort.indexOf('"', a);
    return e < 0 ? QByteArray() : antwort.mid(a, e - a);
}

/// Welche Fassung der laufende Dienst ist -- leer, wenn er nicht antwortet
/// oder es nicht sagt (dann ist er aelter als 0.35.2, oder neuer und kennt
/// unser Geheimnis nicht: seit 0.41.0 nennt er die Fassung nur mit
/// Geheimnis, ein aelterer ignoriert den Kopf).
static QString dienstFassung()
{
    return QString::fromLatin1(feld(statusRoh(tokenDatei()), "version"));
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

/// Die rohe Antwort in Status und Rumpf zerlegen. Falsch, wenn sie nicht
/// vollstaendig ist -- der Dienst nennt immer Content-Length, und ein
/// abgeschnittener Rumpf soll nicht als halbes JSON bei Briar.js ankommen.
static bool antwortZerlegen(const QByteArray &roh, int *status, QByteArray *rumpf)
{
    const int kopfEnde = roh.indexOf("\r\n\r\n");
    if (!roh.startsWith("HTTP/") || kopfEnde < 0)
        return false;
    const QList<QByteArray> zeilen = roh.left(kopfEnde).split('\n');
    const QList<QByteArray> erste = zeilen.at(0).trimmed().split(' ');
    bool zahl = false;
    const int code = erste.size() > 1 ? erste.at(1).toInt(&zahl) : 0;
    if (!zahl || code <= 0)
        return false;
    int laenge = -1;
    for (int i = 1; i < zeilen.size(); ++i) {
        const QByteArray z = zeilen.at(i).trimmed();
        const int p = z.indexOf(':');
        if (p > 0 && z.left(p).trimmed().toLower() == "content-length")
            laenge = z.mid(p + 1).trimmed().toInt();
    }
    QByteArray r = roh.mid(kopfEnde + 4);
    if (laenge >= 0) {
        if (r.size() < laenge)
            return false;
        r.truncate(laenge);
    }
    *status = code;
    *rumpf = r;
    return true;
}

DienstAnfrage::DienstAnfrage(int id, const QString &sockel, const QByteArray &anfrage,
                             int zeitgrenze, QObject *parent)
    : QObject(parent), m_id(id), m_sockel(sockel), m_anfrage(anfrage),
      m_socket(new QLocalSocket(this)), m_zeit(new QTimer(this)), m_erledigt(false)
{
    m_zeit->setSingleShot(true);
    m_zeit->setInterval(zeitgrenze);
    connect(m_zeit, SIGNAL(timeout()), this, SLOT(zeitUm()));
    connect(m_socket, SIGNAL(connected()), this, SLOT(verbunden()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(lesen()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(getrennt()));
    connect(m_socket, SIGNAL(error(QLocalSocket::LocalSocketError)),
            this, SLOT(fehler(QLocalSocket::LocalSocketError)));
}

void DienstAnfrage::starten()
{
    if (m_anfrage.isEmpty()) {
        abschliessen(false);
        return;
    }
    m_zeit->start();
    m_socket->connectToServer(m_sockel);
}

void DienstAnfrage::verbunden()
{
    m_socket->write(m_anfrage);
}

void DienstAnfrage::lesen()
{
    m_antwort += m_socket->readAll();
    // Siehe MaxAntwort.
    if (m_antwort.size() > MaxAntwort)
        abschliessen(false);
}

void DienstAnfrage::getrennt()
{
    abschliessen(false);
}

void DienstAnfrage::fehler(QLocalSocket::LocalSocketError)
{
    // Auch das Schliessen durch den Dienst kommt als "Fehler"
    // (PeerClosedError); abschliessen schaut, ob die Antwort ganz ist.
    abschliessen(false);
}

void DienstAnfrage::zeitUm()
{
    abschliessen(true);
}

void DienstAnfrage::abschliessen(bool zeitUm)
{
    if (m_erledigt)
        return;
    m_erledigt = true;
    m_zeit->stop();
    if (!zeitUm && m_socket->bytesAvailable() > 0)
        m_antwort += m_socket->readAll();
    int status = 0;
    QByteArray rumpf;
    if (zeitUm || !antwortZerlegen(m_antwort, &status, &rumpf))
        status = 0;
    m_socket->abort();
    emit fertig(m_id, status, status == 0 ? QString() : QString::fromUtf8(rumpf));
    deleteLater();
}

void Dienst::anfrage(int nummer, const QString &method, const QString &path,
                     const QString &body, const QString &geheimnis)
{
    const QByteArray verb = method.toLatin1();
    const QByteArray weg = path.toUtf8();
    const QByteArray g = geheimnis.toLatin1();
    const QByteArray rumpf = body.toUtf8();
    QByteArray a;
    // Kein Zeilenumbruch in Anfragezeile oder Kopf, kein Leerzeichen in Verb
    // oder Pfad:
    // sonst liesse sich ein Kopf unterschieben. Leer heisst "gleich Status 0".
    const QByteArray alles = verb + weg + g;
    if (!verb.isEmpty() && !weg.isEmpty() && alles.indexOf('\r') < 0
            && alles.indexOf('\n') < 0 && weg.indexOf(' ') < 0
            && verb.indexOf(' ') < 0) {
        a = verb + ' ' + weg + " HTTP/1.0\r\n";
        a += "Content-Type: application/json\r\n";
        a += "Content-Length: " + QByteArray::number(rumpf.size()) + "\r\n";
        if (!g.isEmpty()) {
            a += "Authorization: Bearer " + g + "\r\n";
            a += "X-Briar-Geheimnis: " + g + "\r\n";
        }
        a += "\r\n";
        a += rumpf;
    }
    DienstAnfrage *laeufer =
        new DienstAnfrage(nummer, sockelPfad(), a, AnfrageZeitgrenze, this);
    connect(laeufer, SIGNAL(fertig(int,int,QString)),
            this, SIGNAL(antwort(int,int,QString)));
    // Erst aus der Ereignisschleife: die Antwort kommt so immer spaeter als
    // der Aufruf zurueckkehrt, wie bei XMLHttpRequest -- auch wenn der
    // Sockel fehlt und QLocalSocket den Fehler sofort meldet.
    QTimer::singleShot(0, laeufer, SLOT(starten()));
}

/// Siehe die Sailfish-Seite: nur an einen Dienst, der mit SHA-256 ueber das
/// Geheimnis nachweist, dass er die Datei selbst kennt.
QString Dienst::token()
{
    const QByteArray geheimnis = tokenDatei();
    if (geheimnis.isEmpty())
        return QString();
    const std::string erwartet = sha256::hex(std::string(geheimnis.constData(), geheimnis.size()));
    const QByteArray nachweis = feld(statusRoh(QByteArray()), "nachweis");
    if (std::string(nachweis.constData(), nachweis.size()) != erwartet)
        return QString();
    return QString::fromLatin1(geheimnis);
}

static void dienstStarten()
{
    if (!dienstAntwortet() && alterDienstAufPort()) {
        // Nach der Aktualisierung auf 0.42.0 laeuft womoeglich noch der alte
        // Dienst: er lauscht auf 8105, nicht auf dem Sockel. Eine Fassung
        // laesst sich von ihm nicht mehr lesen, aber er ist es sicher --
        // dienstBeenden trifft nur /opt/briar/bin/briard.
        qWarning("alter Dienst auf Port %d -- neu starten", int(AlterApiPort));
        dienstBeenden();
        for (int i = 0; i < 20 && alterDienstAufPort(); ++i)
            ::usleep(100 * 1000);
    }
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
    const QString daten = datenOrdner();
    QDir().mkpath(daten);
    QStringList argumente;
    // Ohne --api-port: die Schnittstelle liegt nur auf dem Sockel.
    argumente << QLatin1String("--state") << daten + QLatin1String("/state.json");
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
    // Verkleinerte Bilder vor dem Senden: im Datenordner, der nur uns
    // gehoert -- Harmattan hat keinen XDG_RUNTIME_DIR, und /tmp teilen sich
    // alle Konten.
    imagePrep.setVersandOrdner(datenOrdner() + QLatin1String("/versand"));
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
