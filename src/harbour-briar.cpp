// Briar for Sailfish OS.
//
// The protocol lives in briard, a static Rust binary that speaks Briar's
// Bramble protocols and offers a small HTTP interface on 127.0.0.1. This
// program is only its front end: it makes sure the daemon runs and shows the
// Silica interface.

#include <QCoreApplication>
#include <QGuiApplication>
#include <QProcess>
#include <QQmlContext>
#include <QQuickView>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QThread>
#include <csignal>
#include <QDir>

#include <sailfishapp.h>

#include "imageprep.h"
#include "qrcode.h"
#include "tresorsecrets.h"

namespace {

const quint16 ApiPort = 8105;

bool daemonAnswers()
{
    QTcpSocket socket;
    socket.connectToHost(QStringLiteral("127.0.0.1"), ApiPort);
    return socket.waitForConnected(300);
}

#if __has_include("briarversion.h")
#include "briarversion.h"
#endif
#ifndef BRIAR_VERSION
#define BRIAR_VERSION "unbekannt"
#endif

/// Welche Fassung der laufende Dienst ist. Leer heisst: er antwortet nicht
/// oder sagt es nicht -- dann ist er aelter als 0.35.2.
static QString daemonVersion()
{
    QTcpSocket socket;
    socket.connectToHost(QStringLiteral("127.0.0.1"), ApiPort);
    if (!socket.waitForConnected(300))
        return QString();
    socket.write("GET /status HTTP/1.0\r\n\r\n");
    if (!socket.waitForBytesWritten(300))
        return QString();
    QByteArray answer;
    while (socket.waitForReadyRead(700))
        answer += socket.readAll();
    const int i = answer.indexOf("\"version\":\"");
    if (i < 0)
        return QString();
    const int a = i + 11;
    const int e = answer.indexOf('"', a);
    return e < 0 ? QString() : QString::fromLatin1(answer.mid(a, e - a));
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

void startDaemon()
{
    if (daemonAnswers()) {
        // Laeuft schon einer -- aber der zur App gehoerende? Der Dienst
        // ueberlebt eine Aktualisierung, und ohne diese Pruefung startet die
        // App keinen zweiten. Dann liegt die neue Binaerdatei da, waehrend
        // der alte Dienst weiterlaeuft und jede Reparatur wirkungslos scheint.
        const QString running = daemonVersion();
        if (running == QLatin1String(BRIAR_VERSION))
            return;
        qWarning("Dienst ist Fassung '%s', die App ist %s -- neu starten",
                 qPrintable(running.isEmpty()
                            ? QStringLiteral("aelter als 0.35.2") : running),
                 BRIAR_VERSION);
        stopDaemon();
        for (int i = 0; i < 20 && daemonAnswers(); ++i)
            QThread::msleep(100);
    }
    const QString data = QStandardPaths::writableLocation(
                QStandardPaths::GenericDataLocation) + QStringLiteral("/harbour-briar");
    QDir().mkpath(data);
    QStringList arguments;
    arguments << QStringLiteral("--state") << data + QStringLiteral("/state.json")
              << QStringLiteral("--api-port") << QString::number(ApiPort);
    // Detached on purpose: messages should keep arriving while the interface
    // is closed. Starting it again is harmless, the port check above sees it.
    QProcess::startDetached(QStringLiteral("/usr/bin/harbour-briar-briard"), arguments);
}

// Reachable from QML, so the interface can put the daemon back on its feet
// instead of only reporting that it does not answer -- it can be killed by
// the system while the window is open. It also switches the background
// service, which is what keeps messages arriving while the app is closed.
class Daemon : public QObject
{
    Q_OBJECT
public:
    Q_INVOKABLE void ensureRunning() { startDaemon(); }

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
