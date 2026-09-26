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

#include "dienst.h"
#include "../src/qrcode.h"

static void dienstStarten();

void Dienst::starten()
{
    dienstStarten();
}

static void dienstStarten()
{
    if (dienstAntwortet())
        return;
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

    QDeclarativeView view;
    // Qt 4.7's QML has no Qt.locale(), so the interface gets the system's
    // language from here and picks German or English from it.
    view.rootContext()->setContextProperty(QLatin1String("systemSprache"),
                                           QLocale::system().name());
    ImagePrep imagePrep;
    view.rootContext()->setContextProperty(QLatin1String("ImagePrep"), &imagePrep);
    view.rootContext()->setContextProperty(QLatin1String("dienst"), &dienst);
    view.rootContext()->setContextProperty(QLatin1String("QrCode"), &qrCode);
    view.setResizeMode(QDeclarativeView::SizeRootObjectToView);
    view.setSource(QUrl::fromLocalFile(QLatin1String("/opt/briar/qml/main.qml")));
    view.showFullScreen();
    return app.exec();
}
