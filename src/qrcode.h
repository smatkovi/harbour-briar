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

    Q_INVOKABLE QString imageFor(const QString &text, int pixels = 480)
    {
        const QByteArray utf8 = text.toUtf8();
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
        return path;
    }

    /// Reads a photograph and returns the text of the first QR code in it,
    /// or an empty string. Tries a few sizes: a full camera picture is far
    /// bigger than the decoder needs, and shrinking it helps as often as it
    /// hurts.
    Q_INVOKABLE QString decode(const QString &file)
    {
        QString path = file;
        if (path.startsWith(QLatin1String("file://")))
            path = path.mid(7);
        QImage image(path);
        if (image.isNull())
            return QString();
        const int widths[3] = { 1280, 800, 0 };
        for (int i = 0; i < 3; ++i) {
            QImage scaled = image;
            if (widths[i] > 0 && image.width() > widths[i])
                scaled = image.scaledToWidth(widths[i], Qt::SmoothTransformation);
            const QString text = decodeImage(scaled);
            if (!text.isEmpty())
                return text;
        }
        return QString();
    }

private:
    static QString cacheDir()
    {
        // Both systems have a home directory; this port keeps its data in
        // the same place on each.
        const QString dir = QDir::homePath()
                + QLatin1String("/.local/share/harbour-briar/qr");
        QDir().mkpath(dir);
        return dir;
    }

    static QString decodeImage(const QImage &source)
    {
        QImage grey = source.convertToFormat(QImage::Format_RGB32);
        struct quirc *q = quirc_new();
        if (!q)
            return QString();
        QString result;
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
                    result = QString::fromUtf8((const char *)data.payload, data.payload_len);
            }
        }
        quirc_destroy(q);
        return result;
    }
};

#endif
