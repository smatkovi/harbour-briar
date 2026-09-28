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

void startDaemon()
{
    if (daemonAnswers())
        return;
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
