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
#include <QFileInfo>
#include <QImage>
#include <QObject>
#include <QString>

class ImagePrep : public QObject
{
    Q_OBJECT

public:
    explicit ImagePrep(QObject *parent = 0) : QObject(parent) {}

    /**
     * Returns a path that fits in maxBytes: the file itself when it is
     * already small enough, a scaled JPEG copy when it is an image, and an
     * empty string when neither is possible.
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
                if (daten.size() <= maxBytes) {
                    const QString ziel = QDir::tempPath()
                            + QLatin1String("/briar-anhang.jpg");
                    QFile aus(ziel);
                    if (!aus.open(QIODevice::WriteOnly))
                        return QString();
                    aus.write(daten);
                    aus.close();
                    return ziel;
                }
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
};

#endif
