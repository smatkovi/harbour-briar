#ifndef KAMERA_H
#define KAMERA_H

// Den QR-Code eines anderen Geraets einlesen, auf N9 und N950.
//
// Der Umweg ueber die Kamera-App des Systems ist hier nicht Bequemlichkeit,
// sondern der einzige Weg, der traegt:
//
// * Das QML-Element aus QtMultimediaKit faellt aus. Sein Unterbau (Qt
//   Mobility 1.2, libqgstengine.so) baut auf dem GStreamer-Element
//   "camerabin" auf, und das kommt auf diesen Geraeten nicht ueber PAUSED
//   hinaus -- gemessen: "Pipeline doesn't want to pause", auch mit
//   ausdruecklich gesetzter Quelle. QCamera meldet dabei faelschlich
//   ActiveState und schickt nie ein onError: die Seite bleibt stumm schwarz.
// * Selbst aufnehmen geht zwar (ueber camsrcbin oder subdevsrc2 mit
//   appsink), aber dann gibt es kein Sucherbild -- Qt 4.7 reicht QML keine
//   laufenden Kamerabilder durch --, und ohne Sucher trifft man einen
//   Code auf einem Bildschirm nicht.
// * Die Kamera-App des Systems hat beides: einen Sucher zum Zielen und
//   einen Autofokus, der einen dichten Code auf einem Bildschirm wirklich
//   scharf bekommt.
//
// Also: aufnehmen laesst die Kamera-App, gelesen wird hier. Denselben Weg
// geht die CES-Chor-App auf demselben Geraet, nachdem ihr eigener Scanner
// am dichten Code regelmaessig gescheitert war.

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QSocketNotifier>
#include <QStringList>

#include <errno.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/qrcode.h"

class Kamera : public QObject
{
    Q_OBJECT

public:
    explicit Kamera(QObject *parent = 0)
        : QObject(parent), m_master(-1), m_kind(-1), m_wachen(0),
          m_gefunden(false), m_marke(false), m_zeilenNachMarke(0) {}

    ~Kamera() { meeScanBeenden(); }

    // Startet die Kamera-App. Sie legt sich vor die eigene Oberflaeche; ist
    // das Foto gemacht, kommt der Anwender ueber den Aufgabenumschalter
    // zurueck und drueckt hier auf Lesen.
    Q_INVOKABLE bool oeffnen()
    {
        QStringList argumente;
        argumente << QLatin1String("--type=m") << QLatin1String("/usr/bin/camera-ui");
        if (QProcess::startDetached(QLatin1String("/usr/bin/invoker"), argumente))
            return true;
        // Ohne invoker startet sie langsamer, aber sie startet.
        return QProcess::startDetached(QLatin1String("/usr/bin/camera-ui"));
    }

    // MeeScan ist der bequemere Weg, wenn es da ist: ein richtiger Sucher
    // zum Zielen. Es ist ein Fremdprogramm von 2011 (libdmtx + ZBar) und
    // liegt nicht auf jedem Geraet -- deshalb fragt die Oberflaeche erst.
    Q_INVOKABLE bool meeScanVorhanden() const
    {
        return QFile::exists(QLatin1String("/opt/MeeScan/bin/MeeScan"));
    }

    // Startet MeeScan und liest mit, was es findet.
    //
    // Das Mitlesen geht ueber ein Pty, nicht ueber eine Roehre: MeeScan
    // puffert seine Ausgabe, wenn sie nicht an einem Endgeraet haengt, und
    // dann kommt bis zum Programmende nichts an. Auf die Zwischenablage ist
    // auch kein Verlass -- nachgemessen: MeeScan legt den Code dort nicht ab.
    // Denselben Umweg nimmt die CES-Chor-App auf demselben Geraet.
    //
    // Das Ausgabemuster ist:  barcode found:  /  <Typ>  /  <Inhalt>
    Q_INVOKABLE bool meeScanStarten()
    {
        meeScanBeenden();
        m_puffer.clear();
        m_gefunden = false;
        m_marke = false;
        m_zeilenNachMarke = 0;

        int master = -1;
        const pid_t kind = forkpty(&master, 0, 0, 0);
        if (kind < 0) return false;
        if (kind == 0) {
            // Im Kind: MeeScan braucht einen Bildschirm.
            if (!getenv("DISPLAY")) setenv("DISPLAY", ":0", 1);
            execl("/opt/MeeScan/bin/MeeScan", "MeeScan", (char *)0);
            _exit(127);
        }
        m_master = master;
        m_kind = kind;
        m_wachen = new QSocketNotifier(master, QSocketNotifier::Read, this);
        connect(m_wachen, SIGNAL(activated(int)), this, SLOT(lesbar()));
        return true;
    }

    // Beenden und aufraeumen. Darf beliebig oft kommen.
    Q_INVOKABLE void meeScanBeenden()
    {
        if (m_wachen) {
            m_wachen->setEnabled(false);
            m_wachen->deleteLater();
            m_wachen = 0;
        }
        if (m_master >= 0) { ::close(m_master); m_master = -1; }
        if (m_kind > 0) {
            ::kill(m_kind, SIGTERM);
            int zustand = 0;
            ::waitpid(m_kind, &zustand, WNOHANG);
            m_kind = -1;
        }
    }

    // Gibt es ueberhaupt ein Foto, und wie alt ist es? Damit kann die
    // Oberflaeche sagen "vor 5 s aufgenommen" statt nur "nichts gefunden".
    Q_INVOKABLE int alterDesLetztenFotos() const
    {
        const QFileInfo foto = letztesFoto();
        if (!foto.exists()) return -1;
        return int(foto.lastModified().secsTo(QDateTime::currentDateTime()));
    }

    // Liest den QR-Code aus dem zuletzt aufgenommenen Foto. Leerer String
    // heisst: kein Foto da oder keiner drin -- die Oberflaeche unterscheidet
    // das ueber alterDesLetztenFotos().
    Q_INVOKABLE QString letztenCodeLesen() const
    {
        const QFileInfo foto = letztesFoto();
        if (!foto.exists()) return QString();
        return QrCode::decodeStatic(foto.absoluteFilePath());
    }

    // Dasselbe, aber als Hex der rohen Bytes: ein BQP-Code -- Briars
    // Verfahren fuer zwei Geraete nebeneinander -- enthaelt keine Schrift.
    Q_INVOKABLE QString letztenCodeAlsHex() const
    {
        const QFileInfo foto = letztesFoto();
        if (!foto.exists()) return QString();
        return QrCode::decodeHexStatic(foto.absoluteFilePath());
    }

signals:
    // MeeScan hat etwas gelesen.
    void meeScanErkannt(const QString &text);
    // MeeScan ist beendet worden, ohne etwas zu finden.
    void meeScanBeendet();

private slots:
    void lesbar()
    {
        char block[4096];
        const ssize_t gelesen = ::read(m_master, block, sizeof(block));
        if (gelesen <= 0) {
            // EIO heisst hier: das Kind ist weg. Alles andere auch.
            meeScanBeenden();
            if (!m_gefunden) emit meeScanBeendet();
            return;
        }
        m_puffer.append(block, int(gelesen));
        int bruch;
        while ((bruch = m_puffer.indexOf('\n')) >= 0) {
            QString zeile = QString::fromUtf8(m_puffer.left(bruch)).trimmed();
            m_puffer.remove(0, bruch + 1);
            zeileVerarbeiten(zeile);
        }
    }

private:
    // barcode found:  ->  naechste Zeile ist der Typ  ->  dann der Inhalt.
    void zeileVerarbeiten(QString zeile)
    {
        if (zeile.isEmpty()) return;
        if (zeile.contains(QLatin1String("barcode found:"))) {
            m_marke = true;
            m_zeilenNachMarke = 0;
            return;
        }
        if (!m_marke) return;
        ++m_zeilenNachMarke;
        if (m_zeilenNachMarke == 1) return;      // der Typ, uninteressant
        // Die zweite Zeile nach der Marke ist der Inhalt, oft in
        // Anfuehrungszeichen.
        if (zeile.startsWith(QLatin1Char('"')) && zeile.endsWith(QLatin1Char('"')))
            zeile = zeile.mid(1, zeile.length() - 2);
        m_marke = false;
        if (zeile.isEmpty() || m_gefunden) return;
        m_gefunden = true;
        const QString text = zeile;
        meeScanBeenden();
        emit meeScanErkannt(text);
    }

    int m_master;
    pid_t m_kind;
    QSocketNotifier *m_wachen;
    QByteArray m_puffer;
    bool m_gefunden;
    bool m_marke;
    int m_zeilenNachMarke;

    // Das neueste Bild aus dem Kameraordner. Harmattan legt alles flach
    // dorthin (26020011.jpg), Unterordner gibt es nicht.
    static QFileInfo letztesFoto()
    {
        QDir ordner(QLatin1String("/home/user/MyDocs/DCIM"));
        QStringList muster;
        muster << QLatin1String("*.jpg") << QLatin1String("*.jpeg")
               << QLatin1String("*.JPG");
        const QFileInfoList bilder =
                ordner.entryInfoList(muster, QDir::Files, QDir::Time);
        return bilder.isEmpty() ? QFileInfo() : bilder.first();
    }
};

#endif
