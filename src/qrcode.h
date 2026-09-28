#ifndef QRCODE_H
#define QRCODE_H

// The QR side of adding a contact, for both front ends.
//
//   QrCode.imageFor(text)  -- writes a PNG and returns its path, to show
//   QrCode.decode(path)    -- reads a photo and returns what it holds
//
// Encoding is ours (qrencode.h); decoding is quirc, a small decoder that
// compiles anywhere, because neither device has a QR library. A photograph
// is taken and then decoded -- there is no live scanning: on Harmattan the
// camera gives no frames to QML, and one tap is little enough to ask.

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QImage>
#include <QObject>
#include <QPainter>
#include <QString>

#include "qrencode.h"

extern "C" {
#include "quirc/quirc.h"
}

class QrCode : public QObject
{
    Q_OBJECT

public:
    explicit QrCode(QObject *parent = 0) : QObject(parent) {}

    /// Ein Code aus rohen Bytes, als Hex uebergeben.
    ///
    /// BQP -- Briars Verfahren fuer zwei Geraete nebeneinander -- steckt keine
    /// Schrift in den Code, sondern Bytes. Android baut daraus einen String
    /// nach ISO-8859-1 und laesst ZXing ihn im Byte-Modus schreiben; gelesen
    /// wird mit demselben Zeichensatz zurueck. Unser Schreiber nimmt ohnehin
    /// Bytes, also geht der Umweg ueber den Zeichensatz hier gar nicht erst
    /// los: Hex herein, Bytes in den Code.
    Q_INVOKABLE QString imageForHex(const QString &hex, int pixels = 480)
    {
        const QByteArray roh = QByteArray::fromHex(hex.toLatin1());
        if (roh.isEmpty())
            return QString();
        return imageForBytes(roh, pixels);
    }

    /// Wie decodeAndRemove(), liefert aber die rohen Bytes als Hex.
    ///
    /// Ein BQP-Rumpf ist kein Text: `QString::fromUtf8` wuerde ihn zerstoeren.
    /// Wer Schrift erwartet, macht aus dem Hex wieder Zeichen -- das steht in
    /// der Oberflaeche, weil nur sie weiss, was sie gerade sucht.
    Q_INVOKABLE QString decodeHexAndRemove(const QString &file)
    {
        QString path = file;
        if (path.startsWith(QLatin1String("file://")))
            path = path.mid(7);
        const QByteArray roh = decodeBytes(path);
        QFile::remove(path);
        return QString::fromLatin1(roh.toHex());
    }

    Q_INVOKABLE QString imageFor(const QString &text, int pixels = 480)
    {
        return imageForBytes(text.toUtf8(), pixels);
    }

    QString imageForBytes(const QByteArray &utf8, int pixels)
    {
        qr::Matrix matrix = qr::encode(std::string(utf8.constData(), utf8.size()));
        if (matrix.size == 0)
            return QString();

        const int quiet = 4;
        const int modules = matrix.size + 2 * quiet;
        const int scale = qMax(1, pixels / modules);
        const int side = modules * scale;

        QImage image(side, side, QImage::Format_RGB32);
        image.fill(qRgb(255, 255, 255));
        QPainter painter(&image);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(0, 0, 0));
        for (int y = 0; y < matrix.size; ++y) {
            for (int x = 0; x < matrix.size; ++x) {
                if (matrix.dark(x, y)) {
                    painter.drawRect((x + quiet) * scale, (y + quiet) * scale,
                                     scale, scale);
                }
            }
        }
        painter.end();

        // One file per text, so showing the same link twice costs nothing.
        const QString name = QString::fromLatin1(
                    QCryptographicHash::hash(utf8, QCryptographicHash::Md5).toHex());
        const QString path = cacheDir() + QLatin1String("/qr-") + name
                             + QLatin1String(".png");
        if (!image.save(path, "PNG"))
            return QString();
        // Nur der Eigentuemer. Die Dateien standen auf 0666, also auch
        // schreibbar fuer jeden -- ein ausgetauschtes Bild waere ein
        // ausgetauschter Kontakt.
        QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner);
        return path;
    }

    /// Reads a photograph and returns the text of the first QR code in it,
    /// or an empty string. Tries a few sizes: a full camera picture is far
    /// bigger than the decoder needs, and shrinking it helps as often as it
    /// hurts.
    Q_INVOKABLE QString decode(const QString &file)
    {
        return QString::fromUtf8(decodeBytes(pfadVon(file)));
    }

    /// Wie decode(), raeumt die Datei danach aber weg. Der Sucher schiesst
    /// alle anderthalb Sekunden ein Bild; ohne das Wegraeumen liefe der
    /// Zwischenspeicher voll, und QML kann keine Datei loeschen.
    Q_INVOKABLE QString decodeAndRemove(const QString &file)
    {
        const QString pfad = pfadVon(file);
        const QString text = QString::fromUtf8(decodeBytes(pfad));
        QFile::remove(pfad);
        return text;
    }

    // Dasselbe wie decode(), aber ohne Objekt -- die Kamera-Klasse liest so
    // das zuletzt aufgenommene Foto.
    static QString decodeStatic(const QString &file)
    {
        return QString::fromUtf8(decodeBytes(pfadVon(file)));
    }

    // Dasselbe in Rohbytes, als Hex -- fuer BQP, das keine Schrift im Code
    // hat, sondern Bytes.
    static QString decodeHexStatic(const QString &file)
    {
        return QString::fromLatin1(decodeBytes(pfadVon(file)).toHex());
    }

private:
    static QString pfadVon(const QString &file)
    {
        QString path = file;
        if (path.startsWith(QLatin1String("file://")))
            path = path.mid(7);
        return path;
    }

    /// Liest die rohen Bytes des ersten Codes im Bild.
    ///
    /// Mehrere Groessen: ein formatfuellender Code will die erste Stufe, ein
    /// kleiner im Bild die zweite, und bei einem unscharfen Foto helfen
    /// weniger Bildpunkte mehr als mehr.
    static QByteArray decodeBytes(const QString &pfad)
    {
        QImage image(pfad);
        if (image.isNull())
            return QByteArray();
        // Dieselbe Breite nie zweimal. Bisher liefen bei einem Bild, das
        // ohnehin schmaler ist als die erste Stufe, drei gleiche Durchgaenge
        // -- und der vierte auf dem Original noch einmal derselbe. Vier
        // identische quirc-Laeufe ueber dasselbe Bild kosten das Vierfache und
        // finden nichts, was der erste nicht gefunden haette. Die Stufen
        // selbst bleiben, es faellt nur das Doppelte weg.
        const int stufen[3] = { 1280, 1600, 800 };
        int schon[4] = { 0, 0, 0, 0 };
        int anzahl = 0;
        for (int i = 0; i < 4; ++i) {
            // Der letzte Durchgang ist das unverkleinerte Bild.
            const int breite = (i < 3) ? qMin(stufen[i], image.width())
                                       : image.width();
            bool doppelt = false;
            for (int j = 0; j < anzahl; ++j) {
                if (schon[j] == breite)
                    doppelt = true;
            }
            if (doppelt)
                continue;
            schon[anzahl++] = breite;
            QImage scaled = image;
            if (breite < image.width())
                scaled = image.scaledToWidth(breite, Qt::SmoothTransformation);
            const QByteArray roh = decodeImage(scaled);
            if (!roh.isEmpty())
                return roh;
        }
        return QByteArray();
    }

    static QString cacheDir()
    {
        // Both systems have a home directory; this port keeps its data in
        // the same place on each.
        const QString dir = QDir::homePath()
                + QLatin1String("/.local/share/harbour-briar/qr");
        QDir().mkpath(dir);
        QFile::setPermissions(dir, QFile::ReadOwner | QFile::WriteOwner
                                   | QFile::ExeOwner);
        return dir;
    }

public:
    /// Ein Bild, das schon Graustufen ist, unmittelbar an quirc.
    ///
    /// Der Sucher am N9 (meego/sucher.h) liefert genau das: das
    /// Helligkeitsfeld, das er aus UYVY herausgreift. Der Weg ueber
    /// decodeImage() wuerde es erst nach RGB32 kopieren und dann Bildpunkt
    /// fuer Bildpunkt wieder auf Grau zurueckrechnen -- zweimal umsonst, und
    /// auf einem 1-GHz-A8 ist das nicht wenig.
    static QString decodeHexAusBild(const QImage &grau)
    {
        if (grau.format() != QImage::Format_Indexed8)
            return QString::fromLatin1(decodeImage(grau).toHex());

        struct quirc *q = quirc_new();
        if (!q)
            return QString();
        QByteArray ergebnis;
        if (quirc_resize(q, grau.width(), grau.height()) >= 0) {
            uint8_t *puffer = quirc_begin(q, 0, 0);
            for (int y = 0; y < grau.height(); ++y) {
                memcpy(puffer + (size_t)y * (size_t)grau.width(),
                       grau.scanLine(y), (size_t)grau.width());
            }
            quirc_end(q);
            const int anzahl = quirc_count(q);
            for (int i = 0; i < anzahl && ergebnis.isEmpty(); ++i) {
                struct quirc_code code;
                struct quirc_data data;
                quirc_extract(q, i, &code);
                if (quirc_decode(&code, &data) == QUIRC_SUCCESS)
                    ergebnis = QByteArray((const char *)data.payload, data.payload_len);
            }
        }
        quirc_destroy(q);
        return QString::fromLatin1(ergebnis.toHex());
    }

private:
    static QByteArray decodeImage(const QImage &source)
    {
        QImage grey = source.convertToFormat(QImage::Format_RGB32);
        struct quirc *q = quirc_new();
        if (!q)
            return QByteArray();
        QByteArray result;
        if (quirc_resize(q, grey.width(), grey.height()) >= 0) {
            uint8_t *buffer = quirc_begin(q, 0, 0);
            for (int y = 0; y < grey.height(); ++y) {
                const QRgb *line = reinterpret_cast<const QRgb *>(grey.scanLine(y));
                uint8_t *out = buffer + y * grey.width();
                for (int x = 0; x < grey.width(); ++x) {
                    const QRgb p = line[x];
                    out[x] = (uint8_t)((qRed(p) * 77 + qGreen(p) * 151 + qBlue(p) * 28) >> 8);
                }
            }
            quirc_end(q);
            const int count = quirc_count(q);
            for (int i = 0; i < count && result.isEmpty(); ++i) {
                struct quirc_code code;
                struct quirc_data data;
                quirc_extract(q, i, &code);
                if (quirc_decode(&code, &data) == QUIRC_SUCCESS)
                    result = QByteArray((const char *)data.payload, data.payload_len);
            }
        }
        quirc_destroy(q);
        return result;
    }
};

#endif
