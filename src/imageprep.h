// Scaling an image down until it fits in one Briar message.
//
// Briar puts an attachment into a single sync message, and a message body
// cannot exceed 32 KiB -- which is why Briar compresses images before it
// sends them. A photo off either of these cameras is a hundred times that,
// so the picture is scaled and re-encoded here until it fits, and the copy
// is what gets sent.
//
// One header for both front ends: QImage's API is the same in Qt 4.7 and
// Qt 5, and this is the only C++ either interface needs beyond starting the
// daemon.

#ifndef IMAGEPREP_H
#define IMAGEPREP_H

#include <QBuffer>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImage>
#include <QObject>
#include <QString>
#include <QTemporaryFile>
#include <unistd.h>

class ImagePrep : public QObject
{
    Q_OBJECT

public:
    explicit ImagePrep(QObject *parent = 0) : QObject(parent) {}

    /**
     * Wohin die verkleinerten Kopien kommen: ein eigener Ordner, den beide
     * main.cpp setzen (QStandardPaths gibt es unter Qt 4.7 nicht, darum
     * nicht hier). Frueher lag jede Kopie als /tmp/briar-anhang.jpg da --
     * fester Name, fuer alle lesbar, nie geloescht; ein anderes Konto konnte
     * die Datei vorbelegen, mitlesen und den Inhalt vor dem Senden tauschen
     * (Gegenpruefung 7b, C5). Beim Setzen wird geleert, was ein Absturz
     * liegen liess.
     */
    void setVersandOrdner(const QString &ordner)
    {
        m_versand = ordner;
        // Ohne abschliessenden Schraegstrich: mit "/" am Ende folgt lstat
        // einem Link, isSymLink() sagt dann nein, und ein Link auf den
        // Bilderordner galt als echter Ordner -- der wuerde gleich unten
        // geleert (Nachpruefung 8, N6).
        while (m_versand.length() > 1 && m_versand.endsWith(QLatin1Char('/')))
            m_versand.chop(1);
        if (!versandBereit())
            return;
        const QFileInfoList reste = QDir(m_versand).entryInfoList(
                QDir::Files | QDir::Hidden | QDir::System | QDir::NoSymLinks);
        for (int i = 0; i < reste.size(); ++i)
            QFile::remove(reste.at(i).absoluteFilePath());
    }

    /**
     * Loescht eine Kopie aus prepare(), sobald /send sie gelesen hat. Nur
     * Dateien direkt im eigenen versand-Ordner: QML ruft das auch mit dem
     * Pfad des Originals auf, wenn das schon klein genug war -- das darf
     * hier nie verschwinden.
     */
    Q_INVOKABLE void aufraeumen(const QString &pfad)
    {
        QString p = pfad;
        if (p.startsWith(QLatin1String("file://")))
            p = p.mid(7);
        if (p.isEmpty() || m_versand.isEmpty())
            return;
        // Ist der versand-Ordner selbst ein Link, zeigte canonicalFilePath
        // unten dorthin, wohin er zeigt -- etwa auf den Bilderordner, und das
        // Original fiele (Nachpruefung 8, N6). Dann nichts loeschen.
        if (QFileInfo(m_versand).isSymLink())
            return;
        const QString ordner = QFileInfo(m_versand).canonicalFilePath();
        const QFileInfo datei(p);
        if (ordner.isEmpty() || datei.isSymLink() || !datei.isFile()
                || datei.canonicalPath() != ordner)
            return;
        QFile::remove(datei.canonicalFilePath());
    }

    /**
     * Der Text eines Anhangs, fuer den Betrachter in der App. QML kann keine
     * Datei lesen, und hinausgeben wollen wir sie nicht: die Anhaenge liegen im
     * Datenordner der App, der auf 0700 steht.
     *
     * Ein Anhang passt in eine Briar-Nachricht, ist also hoechstens 32 KiB
     * gross; die Grenze hier ist bloss ein Riegel gegen eine verbogene Datei.
     */
    Q_INVOKABLE QString textOf(const QString &pfad, int maxBytes = 200000)
    {
        QString p = pfad;
        if (p.startsWith(QLatin1String("file://")))
            p = p.mid(7);
        QFile datei(p);
        if (!datei.open(QIODevice::ReadOnly))
            return QString();
        const QByteArray rohdaten = datei.read(maxBytes);
        return QString::fromUtf8(rohdaten.constData(), rohdaten.size());
    }

    /**
     * Returns a path that fits in maxBytes: the file itself when it is
     * already small enough, a scaled JPEG copy when it is an image, and an
     * empty string when neither is possible. Die Kopie liegt im
     * versand-Ordner; wer sie gesendet hat, gibt sie an aufraeumen().
     */
    Q_INVOKABLE QString prepare(const QString &pfad, int maxBytes)
    {
        QString datei = pfad;
        if (datei.startsWith(QLatin1String("file://")))
            datei = datei.mid(7);
        QFileInfo info(datei);
        if (!info.exists())
            return QString();
        if (info.size() <= maxBytes)
            return datei;

        QImage bild(datei);
        if (bild.isNull())
            return QString();   // too big and not an image: nothing to do

        // Halve the long edge until the encoded size fits. Quality drops
        // first, size second: a readable small picture beats a sharp
        // unsendable one.
        int kante = bild.width() > bild.height() ? bild.width() : bild.height();
        if (kante > 1024)
            kante = 1024;
        for (int versuch = 0; versuch < 12; ++versuch) {
            const QImage klein = bild.scaled(kante, kante, Qt::KeepAspectRatio,
                                             Qt::SmoothTransformation);
            for (int guete = 80; guete >= 20; guete -= 20) {
                QByteArray daten;
                QBuffer puffer(&daten);
                puffer.open(QIODevice::WriteOnly);
                if (!klein.save(&puffer, "JPEG", guete))
                    return QString();
                puffer.close();
                if (daten.size() <= maxBytes)
                    return ablegen(daten);
            }
            kante = kante / 2;
            if (kante < 64)
                break;
        }
        return QString();
    }

    /** The content type, guessed from the file's ending. */
    Q_INVOKABLE QString contentType(const QString &pfad)
    {
        const QString lower = pfad.toLower();
        if (lower.endsWith(QLatin1String(".png")))
            return QLatin1String("image/png");
        if (lower.endsWith(QLatin1String(".gif")))
            return QLatin1String("image/gif");
        if (lower.endsWith(QLatin1String(".jpg")) || lower.endsWith(QLatin1String(".jpeg")))
            return QLatin1String("image/jpeg");
        if (lower.endsWith(QLatin1String(".txt")))
            return QLatin1String("text/plain");
        return QLatin1String("application/octet-stream");
    }

private:
    /// Der versand-Ordner steht, ist ein echter Ordner (kein Link), gehoert
    /// uns und steht auf 0700. Sonst nichts ablegen.
    bool versandBereit() const
    {
        if (m_versand.isEmpty() || !QDir().mkpath(m_versand))
            return false;
        const QFileInfo vorher(m_versand);
        if (vorher.isSymLink() || !vorher.isDir()
                || vorher.ownerId() != uint(::getuid()))
            return false;
        const QFile::Permissions nurIch =
                QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
        if (!QFile::setPermissions(m_versand, nurIch))
            return false;
        // Neu gelesen: QFileInfo haelt die alten Rechte zwischengespeichert.
        const QFileInfo nachher(m_versand);
        return (nachher.permissions() & (QFile::ReadGroup | QFile::WriteGroup
                | QFile::ExeGroup | QFile::ReadOther | QFile::WriteOther
                | QFile::ExeOther)) == 0;
    }

    /// Die Bytes in eine frische Datei mit zufaelligem Namen: QTemporaryFile
    /// legt sie mit O_EXCL und 0600 an. Das XXXXXX steht am Ende, weil Qt
    /// 4.7 es nur dort ersetzt; den Typ bekommt /send ohnehin gesagt.
    QString ablegen(const QByteArray &daten) const
    {
        if (!versandBereit())
            return QString();
        QTemporaryFile aus(m_versand + QLatin1String("/anhang-XXXXXX"));
        aus.setAutoRemove(false);
        if (!aus.open())
            return QString();
        const QString name = aus.fileName();
        aus.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
        if (aus.write(daten) != daten.size() || !aus.flush()) {
            aus.close();
            QFile::remove(name);
            return QString();
        }
        aus.close();
        return name;
    }

    QString m_versand;
};

#endif
