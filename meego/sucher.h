#ifndef SUCHER_H
#define SUCHER_H

// Ein Sucherbild am N9 und N950 -- und darin gelesen wird gleich mit.
//
// Warum das ueberhaupt geht, obwohl der Kommentar in kamera.h das Gegenteil
// nahelegt: dort faellt das QML-Element aus QtMultimediaKit aus, weil sein
// Unterbau auf "camerabin" steht, und camerabin kommt auf diesen Geraeten
// nicht ueber PAUSED hinaus. Die Kamera selbst liefert aber sehr wohl.
// Nachgemessen am N9 (28.09.2026):
//
//   subdevsrc2 -> fakesink                     10 von 10 Puffern
//   subdevsrc2, UYVY 640x480 angefragt          6 von 6 Puffern, kein Fehler
//   subdevsrc2, UYVY 320x240 angefragt          6 von 6 Puffern, kein Fehler
//   camsrcbin  -> fakesink                      0 Puffer, bleibt bei PAUSED
//   v4l2src /dev/video0                         0 Puffer, "not a capture device"
//
// Also: subdevsrc2 unmittelbar, ohne camerabin und ohne QtMultimediaKit.
//
// Das Format ist der eigentliche Glueckfall. UYVY ist gepacktes 4:2:2:
//
//   U Y0 V Y1   U Y0 V Y1   ...
//
// Die Helligkeit steht auf jeder ungeraden Stelle. quirc will genau ein
// Graustufenfeld -- es ist also nur jedes zweite Byte herauszugreifen, ohne
// Farbumrechnung, ohne Skalieren, ohne eine einzige QImage-Kopie. Dasselbe
// Feld ist zugleich das Sucherbild; grau reicht zum Zielen auf einen Code.
//
// Gelesen wird im Faden von GStreamer, nicht im Oberflaechenfaden: quirc
// braucht auf einem 1-GHz-A8 seine Zeit, und der Sucher soll dabei nicht
// stehenbleiben. Der appsink laesst alte Rahmen fallen (max-buffers=1,
// drop=true), das bremst sich damit von selbst ein.

#include <QDeclarativeItem>
#include <QImage>
#include <QMutex>
#include <QMutexLocker>
#include <QPainter>
#include <QVector>
#include <QString>

#include <gst/gst.h>
#include <gst/app/gstappsink.h>

#include "../src/qrcode.h"

class Sucher : public QDeclarativeItem
{
    Q_OBJECT
    Q_PROPERTY(bool laeuft READ laeuft NOTIFY laeuftChanged)
    /// Wonach gesucht wird: "" heisst jeder Code, "bqp" nur ein
    /// Treffen-Code. Die Seite entscheidet das, nicht diese Klasse.
    Q_PROPERTY(QString sucheNach READ sucheNach WRITE setSucheNach NOTIFY sucheNachChanged)

public:
    explicit Sucher(QDeclarativeItem *parent = 0)
        : QDeclarativeItem(parent), m_pipeline(0), m_sink(0), m_gefunden(false)
    {
        setFlag(QGraphicsItem::ItemHasNoContents, false);
    }

    ~Sucher() { anhalten(); }

    bool laeuft() const { return m_pipeline != 0; }
    QString sucheNach() const { return m_sucheNach; }
    void setSucheNach(const QString &s)
    {
        if (m_sucheNach == s) return;
        m_sucheNach = s;
        emit sucheNachChanged();
    }

    /// Die Kamera anwerfen. Gibt false zurueck, wenn die Kette nicht steht --
    /// dann bleibt es beim alten Weg ueber die Kamera-App, und die Seite sagt
    /// das auch.
    Q_INVOKABLE bool starten()
    {
        if (m_pipeline) return true;
        m_gefunden = false;

        GError *fehler = 0;
        // 640x480 ist ausgehandelt worden, nicht geraten. Kleiner waere
        // billiger, aber ein Code auf einem Bildschirm braucht die Punkte.
        m_pipeline = gst_parse_launch(
            "subdevsrc2 ! video/x-raw-yuv,format=(fourcc)UYVY,width=640,height=480"
            " ! appsink name=aus",
            &fehler);
        if (!m_pipeline) {
            if (fehler) {
                qWarning("Sucher: Kette nicht zu bauen: %s", fehler->message);
                g_error_free(fehler);
            }
            return false;
        }
        if (fehler) g_error_free(fehler);

        m_sink = gst_bin_get_by_name(GST_BIN(m_pipeline), "aus");
        if (!m_sink) {
            anhalten();
            return false;
        }
        // Alte Rahmen fallen lassen: lieber ein frisches Bild als eine
        // Warteschlange, die hinterherhinkt.
        g_object_set(G_OBJECT(m_sink), "emit-signals", TRUE, "sync", FALSE,
                     "max-buffers", 1, "drop", TRUE, NULL);
        g_signal_connect(m_sink, "new-buffer", G_CALLBACK(rahmenAngekommen), this);

        if (gst_element_set_state(m_pipeline, GST_STATE_PLAYING)
                == GST_STATE_CHANGE_FAILURE) {
            qWarning("Sucher: die Kette laeuft nicht an");
            anhalten();
            return false;
        }
        emit laeuftChanged();
        return true;
    }

    /// Weitersuchen, nachdem ein Fund nichts taugte -- ein fremder QR-Code
    /// zum Beispiel. Ohne das bliebe der Sucher nach dem ersten Code stumm.
    Q_INVOKABLE void weitersuchen() { m_gefunden = false; }

    Q_INVOKABLE void anhalten()
    {
        if (m_sink) {
            g_signal_handlers_disconnect_by_func(
                m_sink, (gpointer)G_CALLBACK(rahmenAngekommen), this);
            gst_object_unref(m_sink);
            m_sink = 0;
        }
        if (m_pipeline) {
            gst_element_set_state(m_pipeline, GST_STATE_NULL);
            gst_object_unref(m_pipeline);
            m_pipeline = 0;
            emit laeuftChanged();
        }
        QMutexLocker sperre(&m_sperre);
        m_bild = QImage();
    }

    void paint(QPainter *maler, const QStyleOptionGraphicsItem *, QWidget *)
    {
        QImage bild;
        {
            QMutexLocker sperre(&m_sperre);
            bild = m_bild;
        }
        if (bild.isNull()) {
            maler->fillRect(boundingRect(), Qt::black);
            return;
        }
        // Seitenverhaeltnis wahren, Rest schwarz -- ein verzerrter Code ist
        // schwerer zu treffen.
        const QRectF ziel = boundingRect();
        QSizeF passend = QSizeF(bild.size());
        passend.scale(ziel.size(), Qt::KeepAspectRatio);
        const QRectF hin(ziel.x() + (ziel.width() - passend.width()) / 2,
                         ziel.y() + (ziel.height() - passend.height()) / 2,
                         passend.width(), passend.height());
        maler->fillRect(ziel, Qt::black);
        maler->drawImage(hin, bild);
    }

signals:
    /// Ein Code ist gelesen worden, als Hex der rohen Bytes -- ein
    /// Treffen-Code ist binaer und vertraegt keine Schrift.
    void codeGelesen(const QString &hex);
    void laeuftChanged();
    void sucheNachChanged();

private slots:
    /// Im Oberflaechenfaden: nur neu zeichnen.
    void neuZeichnen() { update(); }

    /// Im Oberflaechenfaden: den Fund melden. Ueber eine Warteschlange, weil
    /// er im Faden von GStreamer entsteht.
    void fundMelden(const QString &hex)
    {
        if (m_gefunden) return;
        m_gefunden = true;
        emit codeGelesen(hex);
    }

private:
    /// Im Faden von GStreamer. Hier wird das Helligkeitsfeld herausgegriffen
    /// und gleich gelesen; der Oberflaechenfaden bekommt nur Bescheid.
    static void rahmenAngekommen(GstAppSink *sink, gpointer daten)
    {
        Sucher *selbst = static_cast<Sucher *>(daten);
        GstBuffer *puffer = gst_app_sink_pull_buffer(sink);
        if (!puffer) return;

        int breite = 0, hoehe = 0;
        GstCaps *caps = gst_buffer_get_caps(puffer);
        if (caps) {
            GstStructure *bau = gst_caps_get_structure(caps, 0);
            if (bau) {
                gst_structure_get_int(bau, "width", &breite);
                gst_structure_get_int(bau, "height", &hoehe);
            }
            gst_caps_unref(caps);
        }
        const guint8 *roh = GST_BUFFER_DATA(puffer);
        const guint groesse = GST_BUFFER_SIZE(puffer);
        if (breite <= 0 || hoehe <= 0
                || groesse < (guint)(breite * hoehe * 2)) {
            gst_buffer_unref(puffer);
            return;
        }

        // UYVY: U Y0 V Y1 -- die Helligkeit auf jeder ungeraden Stelle.
        QImage grau(breite, hoehe, QImage::Format_Indexed8);
        grau.setColorTable(graustufen());
        for (int y = 0; y < hoehe; ++y) {
            const guint8 *zeile = roh + (guint)y * (guint)breite * 2;
            uchar *hin = grau.scanLine(y);
            for (int x = 0; x < breite; ++x)
                hin[x] = zeile[x * 2 + 1];
        }
        gst_buffer_unref(puffer);

        {
            QMutexLocker sperre(&selbst->m_sperre);
            selbst->m_bild = grau;
        }
        QMetaObject::invokeMethod(selbst, "neuZeichnen", Qt::QueuedConnection);

        if (selbst->m_gefunden) return;
        // Lesen kostet auf einem 1-GHz-A8 seine Zeit -- deshalb hier und
        // nicht im Oberflaechenfaden. Der appsink laesst derweil fallen, was
        // sich stapelt.
        const QString hex = QrCode::decodeHexAusBild(grau);
        if (hex.isEmpty()) return;
        if (selbst->m_sucheNach == QLatin1String("bqp")
                && !hex.startsWith(QLatin1String("04")))
            return;
        QMetaObject::invokeMethod(selbst, "fundMelden", Qt::QueuedConnection,
                                  Q_ARG(QString, hex));
    }

    /// Einmal bauen, nicht je Rahmen: 256 Eintraege, 30-mal in der Sekunde.
    static const QVector<QRgb> &graustufen()
    {
        static QVector<QRgb> tafel;
        if (tafel.isEmpty()) {
            tafel.resize(256);
            for (int i = 0; i < 256; ++i) tafel[i] = qRgb(i, i, i);
        }
        return tafel;
    }

    GstElement *m_pipeline;
    GstElement *m_sink;
    QImage m_bild;
    QMutex m_sperre;
    QString m_sucheNach;
    volatile bool m_gefunden;
};

#endif
