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
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

#include "../src/qrcode.h"

class Kamera : public QObject
{
    Q_OBJECT

public:
    explicit Kamera(QObject *parent = 0) : QObject(parent) {}

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

    // Startet MeeScan. Es legt den gelesenen Code in die Zwischenablage; beim
    // Zurueckkommen wird sie ausgelesen. (Die CES-Chor-App faengt stattdessen
    // seine Debug-Ausgabe ueber ein Pty ab -- das braucht es nur, wenn die
    // Zwischenablage nichts hergibt.)
    Q_INVOKABLE bool meeScanOeffnen()
    {
        merkeAblage();
        return QProcess::startDetached(QLatin1String("/opt/MeeScan/bin/MeeScan"));
    }

    // Was in der Zwischenablage steht -- aber nur, wenn es sich seit dem
    // Start von MeeScan geaendert hat. Sonst laese man beim blossen Oeffnen
    // der Seite einen alten Inhalt wieder ein.
    Q_INVOKABLE QString ablageLesen()
    {
        const QClipboard *ablage = QApplication::clipboard();
        if (!ablage) return QString();
        const QString jetzt = ablage->text();
        if (jetzt.isEmpty() || jetzt == m_ablageVorher) return QString();
        return jetzt;
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

private:
    void merkeAblage()
    {
        const QClipboard *ablage = QApplication::clipboard();
        m_ablageVorher = ablage ? ablage->text() : QString();
    }

    QString m_ablageVorher;

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
