// Briar for Sailfish OS.
//
// The protocol lives in briard, a static Rust binary that speaks Briar's
// Bramble protocols and offers a small HTTP interface on a Unix socket beside
// its state (api.sock; before 0.42.0 on 127.0.0.1:8105). This
// program is only its front end: it makes sure the daemon runs and shows the
// Silica interface.

#include <QCoreApplication>
#include <QGuiApplication>
#include <QLocalSocket>
#include <QProcess>
#include <QQmlContext>
#include <QQuickView>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <csignal>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>

#include <sailfishapp.h>

#include "imageprep.h"
#include "qrcode.h"
#include "tresorsecrets.h"

namespace {

// Nur noch, um einen alten Dienst (bis 0.41.0) zu erkennen, der dort
// lauscht statt auf dem Sockel -- siehe startDaemon.
const quint16 AlterApiPort = 8105;
// So lange wartet eine Anfrage auf ihre Antwort, wie ZEITGRENZE in Briar.js.
const int AnfrageZeitgrenze = 90000;
// Mehr nimmt eine Anfrage nicht an: ein Fremder am Sockel soll den Speicher
// nicht fuellen (frueher 64 MiB). Nicht die 4 MiB aus der Gegenpruefung 7b
// (H): /messages und /group/messages geben den ganzen Verlauf zurueck, ohne
// Grenze (kern/src/api.rs, "/messages"), rund 300 Byte je Nachricht -- ab
// etwa 14000 Nachrichten waere ein Chat mit 4 MiB fuer immer Status 0.
const int MaxAntwort = 16 * 1024 * 1024;

static QString dataDir();

/// Der Sockel der Schnittstelle, neben der state.json.
static QString sockelPfad()
{
    return dataDir() + QStringLiteral("/api.sock");
}

/// Das Geheimnis der Schnittstelle, wie es der Dienst neben die state.json
/// legt -- roh aus der Datei, leer, wenn es keine gibt.
static QByteArray tokenDatei()
{
    QFile f(dataDir() + QStringLiteral("/api-token"));
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    return f.readAll().trimmed();
}

/// GET /status, roh -- mit Geheimnis, wenn eines uebergeben wird. Leer,
/// wenn niemand antwortet.
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
    QByteArray answer;
    while (socket.waitForReadyRead(700))
        answer += socket.readAll();
    return answer;
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

bool daemonAnswers()
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
    socket.connectToHost(QStringLiteral("127.0.0.1"), AlterApiPort);
    return socket.waitForConnected(300);
}

#if __has_include("briarversion.h")
#include "briarversion.h"
#endif
#ifndef BRIAR_VERSION
#define BRIAR_VERSION "unbekannt"
#endif

/// Welche Fassung der laufende Dienst ist. Leer heisst: er antwortet nicht
/// oder sagt es nicht -- dann ist er aelter als 0.35.2, oder er ist neuer
/// und kennt unser Geheimnis nicht (seit 0.41.0 nennt er die Fassung nur
/// noch mit Geheimnis; ein aelterer Dienst ignoriert den Kopf einfach).
static QString daemonVersion()
{
    return QString::fromLatin1(feld(statusRoh(tokenDatei()), "version"));
}

/// Den laufenden Dienst beenden -- ueber /proc.
///
/// Nicht ueber pkill: Linux kuerzt den Prozessnamen auf 15 Zeichen, und
/// "harbour-briar-briard" hat 20. `pkill -x` mit dem vollen Namen findet
/// deshalb nie etwas, /proc/<pid>/comm sagt nur "harbour-briar-b". Genau
/// daran lief hier stundenlang ein veralteter Dienst weiter.
static void stopDaemon()
{
    QDir proc(QStringLiteral("/proc"));
    const QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &name : entries) {
        bool number = false;
        const int pid = name.toInt(&number);
        if (!number || pid <= 1)
            continue;
        QFile f(QStringLiteral("/proc/") + name + QStringLiteral("/cmdline"));
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QByteArray line = f.readAll();
        f.close();
        // Nur das erste Wort der Befehlszeile: ein `contains` traf auch eine
        // Shell, in deren Zeile der Pfad bloss vorkam.
        if (line.split('\0').value(0) == "/usr/bin/harbour-briar-briard")
            ::kill(pid, SIGTERM);
    }
}

/// Wo der Dienst seinen Zustand hat -- und daneben sein api-token.
static QString dataDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
            + QStringLiteral("/harbour-briar");
}

void startDaemon()
{
    if (!daemonAnswers() && alterDienstAufPort()) {
        // Nach der Aktualisierung auf 0.42.0 laeuft womoeglich noch der alte
        // Dienst: er lauscht auf 8105, nicht auf dem Sockel. Eine Fassung
        // laesst sich von ihm nicht mehr lesen, aber er ist es sicher --
        // stopDaemon trifft nur /usr/bin/harbour-briar-briard.
        qWarning("alter Dienst auf Port %d -- neu starten", int(AlterApiPort));
        stopDaemon();
        for (int i = 0; i < 20 && alterDienstAufPort(); ++i)
            QThread::msleep(100);
    }
    if (daemonAnswers()) {
        // Laeuft schon einer -- aber der zur App gehoerende? Der Dienst
        // ueberlebt eine Aktualisierung, und ohne diese Pruefung startet die
        // App keinen zweiten. Dann liegt die neue Binaerdatei da, waehrend
        // der alte Dienst weiterlaeuft und jede Reparatur wirkungslos scheint.
        const QString running = daemonVersion();
        if (running == QLatin1String(BRIAR_VERSION))
            return;
        // Keine Fassung lesbar: NICHT beenden. Das war ein wartender Dienst
        // vor dem Entsperren, oder ein sehr alter -- und den ersten mitten im
        // Passwort zu toeten kostet mehr als den zweiten stehenzulassen.
        if (running.isEmpty()) {
            qWarning("Dienst nennt keine Fassung -- bleibt stehen");
            return;
        }
        qWarning("Dienst ist Fassung '%s', die App ist %s -- neu starten",
                 qPrintable(running.isEmpty()
                            ? QStringLiteral("aelter als 0.35.2") : running),
                 BRIAR_VERSION);
        stopDaemon();
        for (int i = 0; i < 20 && daemonAnswers(); ++i)
            QThread::msleep(100);
    }
    const QString data = dataDir();
    QDir().mkpath(data);
    QStringList arguments;
    // Ohne --api-port: die Schnittstelle liegt nur auf dem Sockel.
    arguments << QStringLiteral("--state") << data + QStringLiteral("/state.json");
    // Detached on purpose: messages should keep arriving while the interface
    // is closed. Starting it again is harmless, the socket check above sees it.
    QProcess::startDetached(QStringLiteral("/usr/bin/harbour-briar-briard"), arguments);
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

/// Eine Anfrage an den Dienst ueber seinen Unix-Sockel. XMLHttpRequest in
/// QML kann keinen Sockel, also geht Briar.js seit 0.42.0 hier durch. Je
/// Anfrage ein Objekt mit eigenem QLocalSocket, damit mehrere gleichzeitig
/// laufen; es raeumt sich nach der Antwort selbst weg. Gleich gebaut wie
/// DienstAnfrage in meego/dienst.h (Qt 4.7, darum SIGNAL/SLOT).
class DienstAnfrage : public QObject
{
    Q_OBJECT
public:
    DienstAnfrage(int id, const QString &sockel, const QByteArray &anfrage,
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
signals:
    /// status 0: keine Verbindung, keine vollstaendige Antwort, Zeit um.
    void fertig(int nummer, int code, const QString &rumpf);
public slots:
    void starten()
    {
        if (m_anfrage.isEmpty()) {
            abschliessen(false);
            return;
        }
        m_zeit->start();
        m_socket->connectToServer(m_sockel);
    }
private slots:
    void verbunden() { m_socket->write(m_anfrage); }
    void lesen()
    {
        m_antwort += m_socket->readAll();
        // Siehe MaxAntwort.
        if (m_antwort.size() > MaxAntwort)
            abschliessen(false);
    }
    void getrennt() { abschliessen(false); }
    // Auch das Schliessen durch den Dienst kommt als "Fehler"
    // (PeerClosedError); abschliessen schaut, ob die Antwort ganz ist.
    void fehler(QLocalSocket::LocalSocketError) { abschliessen(false); }
    void zeitUm() { abschliessen(true); }
private:
    void abschliessen(bool zeitUm)
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

    int m_id;
    QString m_sockel;
    QByteArray m_anfrage;
    QByteArray m_antwort;
    QLocalSocket *m_socket;
    QTimer *m_zeit;
    bool m_erledigt;
};

// Reachable from QML, so the interface can put the daemon back on its feet
// instead of only reporting that it does not answer -- it can be killed by
// the system while the window is open. It also switches the background
// service, which is what keeps messages arriving while the app is closed.
class Daemon : public QObject
{
    Q_OBJECT
public:
    Q_INVOKABLE void ensureRunning() { startDaemon(); }

    /// Das Geheimnis der Schnittstelle, das der Dienst beim Start neben die
    /// state.json legt (api-token). Jedes Mal frisch gelesen: der Dienst
    /// wuerfelt bei jedem Start ein neues, und Briar.js fragt nur nach einem
    /// 401 noch einmal.
    ///
    /// Herausgegeben wird es nur, wenn der Dienst auf dem Sockel nachweist,
    /// dass er es selbst kennt: sein /status ohne Geheimnis traegt SHA-256
    /// darueber. Wer den Sockel haelt, ohne die Datei lesen zu koennen -- ein
    /// anderes Konto etwa --, bekommt so weder Geheimnis noch das Passwort,
    /// das die Entsperrseite danach schickt.
    Q_INVOKABLE QString token()
    {
        const QByteArray geheimnis = tokenDatei();
        if (geheimnis.isEmpty())
            return QString();
        const QByteArray erwartet =
                QCryptographicHash::hash(geheimnis, QCryptographicHash::Sha256).toHex();
        if (feld(statusRoh(QByteArray()), "nachweis") != erwartet)
            return QString();
        return QString::fromLatin1(geheimnis);
    }

    /// Eine Anfrage an die Schnittstelle, asynchron; die Antwort kommt als
    /// Signal antwort mit derselben Nummer. Siehe Briar.js, anfrage().
    Q_INVOKABLE void anfrage(int nummer, const QString &method, const QString &path,
                             const QString &body, const QString &geheimnis)
    {
        const QByteArray verb = method.toLatin1();
        const QByteArray weg = path.toUtf8();
        const QByteArray g = geheimnis.toLatin1();
        const QByteArray rumpf = body.toUtf8();
        QByteArray a;
        // Kein Zeilenumbruch in Anfragezeile oder Kopf, kein Leerzeichen in Verb
        // oder Pfad:
        // sonst liesse sich ein Kopf unterschieben. Leer heisst "gleich
        // Status 0".
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
        // Erst aus der Ereignisschleife: die Antwort kommt so immer spaeter
        // als der Aufruf zurueckkehrt, wie bei XMLHttpRequest -- auch wenn
        // der Sockel fehlt und QLocalSocket den Fehler sofort meldet.
        QTimer::singleShot(0, laeufer, SLOT(starten()));
    }

    /// Whether the user unit is enabled -- systemctl answers "enabled" or
    /// "disabled" and exits non-zero for the latter, so the text is read.
    Q_INVOKABLE bool backgroundEnabled()
    {
        QProcess process;
        process.start(QStringLiteral("systemctl"),
                      QStringList() << QStringLiteral("--user")
                                    << QStringLiteral("is-enabled")
                                    << QStringLiteral("harbour-briar-briard.service"));
        process.waitForFinished(4000);
        return QString::fromUtf8(process.readAllStandardOutput())
                .trimmed() == QLatin1String("enabled");
    }

    /// Enables and starts the unit, or stops and disables it. Nothing here
    /// needs root: it is the user's own systemd instance.
    Q_INVOKABLE void setBackground(bool on)
    {
        QStringList arguments;
        arguments << QStringLiteral("--user")
                  << (on ? QStringLiteral("enable") : QStringLiteral("disable"))
                  << QStringLiteral("--now")
                  << QStringLiteral("harbour-briar-briard.service");
        QProcess::startDetached(QStringLiteral("systemctl"), arguments);
    }

signals:
    // Nicht id und status: in QtQuick 1.1 legen sich Signalparameter vor
    // den Gueltigkeitsbereich, und die Wurzel hat eine Eigenschaft status
    // (Gegenpruefung 7b, B1). Gleich benannt wie auf MeeGo.
    void antwort(int nummer, int code, const QString &rumpf);
};

}

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));
    app->setOrganizationName(QStringLiteral("harbour-briar"));
    app->setApplicationName(QStringLiteral("harbour-briar"));
    startDaemon();

    QScopedPointer<QQuickView> view(SailfishApp::createView());
    ImagePrep imagePrep;
    // Verkleinerte Bilder vor dem Senden: im Laufzeitordner (tmpfs, mit der
    // Sitzung weg), neben dem anhaenge-Ordner des Dienstes. Ohne ihn im
    // Datenordner, der ohnehin nur uns gehoert.
    const QString laufzeit =
            QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    imagePrep.setVersandOrdner((laufzeit.isEmpty()
                                ? dataDir()
                                : laufzeit + QStringLiteral("/harbour-briar"))
                               + QStringLiteral("/versand"));
    Daemon daemon;
    QrCode qrCode;
    TresorSecrets schluesselbund;
    view->rootContext()->setContextProperty(QStringLiteral("ImagePrep"), &imagePrep);
    view->rootContext()->setContextProperty(QStringLiteral("Daemon"), &daemon);
    view->rootContext()->setContextProperty(QStringLiteral("QrCode"), &qrCode);
    // Das Geraeteschloss als Schluesselbund: damit sperrt der Fingerabdruck
    // auch einen versiegelten Dienst auf, so wie Briar es auf Android haelt.
    view->rootContext()->setContextProperty(QStringLiteral("Schluesselbund"),
                                            &schluesselbund);
    view->setSource(SailfishApp::pathTo(QStringLiteral("qml/harbour-briar.qml")));
    view->show();
    return app->exec();
}

#include "harbour-briar.moc"
