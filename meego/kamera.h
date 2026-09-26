#ifndef KAMERA_H
#define KAMERA_H

// Die Kamera am N9/N950, fuer das Abfotografieren eines QR-Codes.
//
// Warum nicht das QML-Element aus QtMultimediaKit: dessen Unterbau
// (libqgstengine.so, Qt Mobility 1.2) baut auf dem GStreamer-Element
// "camerabin" auf, und das kommt auf diesen Geraeten nicht ueber PAUSED
// hinaus -- gemessen: "ERROR: Pipeline doesn't want to pause", auch mit
// ausdruecklich gesetzter Quelle. Die QML-Seite zeigt daraufhin stumm
// Schwarz: QCamera meldet faelschlich ActiveState, ein onError kommt nie.
// Die Kamera-App des Systems geht einen anderen Weg -- "camsrcbin" --, und
// der funktioniert. Die rohe Quelle "subdevsrc2" allein genuegt nicht: sie
// liefert Puffer, aber Nullbilder (jedes Bildpunkt gleich).
//
// Eine laufende Vorschau gibt Qt 4.7 hier ohnehin nicht her. Gebraucht wird
// nur ein lesbares Bild, also laeuft die Pipeline, jeder ankommende Rahmen
// wird gelesen, und beim ersten erkannten Code ist Schluss.

#include <QByteArray>
#include <QImage>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QtGlobal>

#define GST_USE_UNSTABLE_API 1
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/interfaces/photography.h>

#include "../src/qrcode.h"

class Kamera : public QObject
{
    Q_OBJECT

public:
    explicit Kamera(QObject *parent = 0)
        : QObject(parent), m_pipeline(0), m_quelle(0), m_senke(0), m_laeuft(false),
          m_rahmen(0), m_echte(0)
    {
        m_frist.setSingleShot(true);
        connect(&m_frist, SIGNAL(timeout()), this, SLOT(fristAbgelaufen()));
    }

    ~Kamera() { aufraeumen(); }

    // Laeuft gerade eine Aufnahme? Die Oberflaeche fragt danach, statt sich
    // den Zustand selbst zu merken.
    Q_INVOKABLE bool laeuft() const { return m_laeuft; }

    // Beginnt die Aufnahme und kehrt sofort zurueck. Das Ergebnis kommt als
    // erkannt() oder fehlgeschlagen(). Der eigentliche Aufbau haengt am
    // Oeffnen der Kamera und braucht spuerbar Zeit, deshalb erst im naechsten
    // Durchlauf der Ereignisschleife -- sonst wird die Fortschrittszeile in
    // der Oberflaeche nie gezeichnet.
    Q_INVOKABLE void aufnehmen()
    {
        if (m_laeuft) return;
        m_laeuft = true;
        QTimer::singleShot(0, this, SLOT(aufbauen()));
    }

    // Abbrechen ist immer erlaubt und darf beliebig oft kommen: aufraeumen()
    // nullt die Zeiger, ein zweiter Aufruf ist folgenlos.
    Q_INVOKABLE void abbrechen()
    {
        if (!m_laeuft) return;
        aufraeumen();
        emit abgebrochen();
    }

signals:
    void scharf();                          // Pipeline laeuft, Bilder kommen
    void erkannt(const QString &text);      // ein QR-Code wurde gelesen
    void fehlgeschlagen(const QString &grund);
    void abgebrochen();

private slots:
    void aufbauen()
    {
        if (!m_laeuft) return;              // zwischenzeitlich abgebrochen

        // gst_parse_launch statt Elemente von Hand zu verbinden: camsrcbin
        // hat drei Quell-Pads (vfsrc, imgsrc, vidsrc), teils als Request-Pads,
        // und gst_parse_launch loest genau das so auf, wie es in der von Hand
        // geprueften gst-launch-Zeile funktioniert hat.
        GError *fehler = 0;
        m_pipeline = gst_parse_launch(
            "camsrcbin name=q q.vfsrc ! ffmpegcolorspace ! jpegenc quality=85"
            " ! appsink name=ziel sync=false drop=true max-buffers=1",
            &fehler);
        if (!m_pipeline) {
            const QString grund = fehler ? QString::fromUtf8(fehler->message)
                                         : QLatin1String("Pipeline");
            if (fehler) g_error_free(fehler);
            scheitern(grund);
            return;
        }
        if (fehler) g_error_free(fehler);

        m_senke = gst_bin_get_by_name(GST_BIN(m_pipeline), "ziel");
        if (!m_senke) { scheitern(QLatin1String("appsink")); return; }

        // READY reicht, damit camsrcbin seine innere Quelle angelegt hat --
        // im Zustand NULL gibt es sie noch nicht, und ein g_object_set darauf
        // waere nur eine stille GLib-Meldung.
        if (!zustandSetzen(GST_STATE_READY)) {
            scheitern(QLatin1String("belegt"));
            return;
        }
        fokusVorbereiten();

        if (!zustandSetzen(GST_STATE_PLAYING)) {
            scheitern(QLatin1String("belegt"));
            return;
        }

        // Erst jetzt: "autofocus" ist ein Ausloeser, kein Zustand. Vor
        // PLAYING ist der Sensor nicht offen und die Fokussuche kann nicht
        // laufen.
        if (m_quelle)
            g_object_set(G_OBJECT(m_quelle), "autofocus", TRUE, (void *)0);

        // Ab hier laufen Puffer ein. Der Rueckruf kommt im Streaming-Faden,
        // deshalb nur kopieren und in den Hauptfaden zurueckreichen.
        g_object_set(G_OBJECT(m_senke), "emit-signals", TRUE, (void *)0);
        g_signal_connect(m_senke, "new-buffer", G_CALLBACK(pufferKam), this);

        m_frist.start(9000);
        emit scharf();
    }

    // Laeuft im Hauptfaden (queued), nicht im Streaming-Faden.
    void pufferVerarbeiten()
    {
        if (!m_laeuft) return;

        QByteArray daten;
        {
            QMutexLocker sperre(&m_sperre);
            daten = m_letzter;
            m_letzter.clear();
        }
        if (daten.isEmpty()) return;

        QImage bild;
        ++m_rahmen;
        if (!bild.loadFromData(daten, "JPEG")) return;
        if (istLeer(bild)) return;          // Nullbild, siehe Kopf
        ++m_echte;

        const QString text = QrCode::decodeFrame(bild);
        if (text.isEmpty()) return;         // noch unscharf, naechster Rahmen

        aufraeumen();                       // Kamera zuerst freigeben
        emit erkannt(text);
    }

    void fristAbgelaufen() { scheitern(QLatin1String("Zeit")); }

private:
    // Ein Rahmen, in dem jeder Bildpunkt denselben Wert hat, ist kein dunkles
    // Motiv, sondern gar keine Aufnahme -- das liefert die rohe Quelle
    // subdevsrc2 (gemessen: durchgehend 17). Eine Stichprobe genuegt.
    static bool istLeer(const QImage &bild)
    {
        if (bild.isNull()) return true;
        int min = 256, max = -1;
        const int schrittX = qMax(1, bild.width() / 20);
        const int schrittY = qMax(1, bild.height() / 20);
        for (int y = 0; y < bild.height(); y += schrittY) {
            for (int x = 0; x < bild.width(); x += schrittX) {
                const int g = qGray(bild.pixel(x, y));
                if (g < min) min = g;
                if (g > max) max = g;
                if (max - min > 3) return false;
            }
        }
        return true;
    }

    // Im Streaming-Faden. Hier wird nichts abgebaut und nichts dekodiert --
    // ein gst_element_set_state(NULL) von hier aus verklemmt sich mit dem
    // eigenen Faden, und genau dann bliebe libomap3camd gehalten.
    static void pufferKam(GstElement *senke, gpointer nutzer)
    {
        Kamera *self = static_cast<Kamera *>(nutzer);
        GstBuffer *puffer = gst_app_sink_pull_buffer(GST_APP_SINK(senke));
        if (!puffer) return;
        {
            QMutexLocker sperre(&self->m_sperre);
            self->m_letzter = QByteArray(
                reinterpret_cast<const char *>(GST_BUFFER_DATA(puffer)),
                int(GST_BUFFER_SIZE(puffer)));
        }
        gst_buffer_unref(puffer);
        QMetaObject::invokeMethod(self, "pufferVerarbeiten", Qt::QueuedConnection);
    }

    void fokusVorbereiten()
    {
        GstElement *bin = gst_bin_get_by_name(GST_BIN(m_pipeline), "q");
        if (!bin) return;
        // g_object_get gibt eine NEUE Referenz -- sie muss wieder weg, sonst
        // ueberlebt die innere Quelle samt /dev/video-Griff das Abbauen der
        // Pipeline und die Kamera bleibt bis zum Programmende belegt.
        g_object_get(G_OBJECT(bin), "video-source", &m_quelle, (void *)0);
        gst_object_unref(bin);
        if (!m_quelle) return;
        // Makro: der Code wird aus 10 bis 20 cm fotografiert.
        g_object_set(G_OBJECT(m_quelle), "focus-mode",
                     GST_PHOTOGRAPHY_FOCUS_MODE_MACRO, (void *)0);
    }

    // Zustandswechsel mit Frist. "Kein Fehler bisher" ist kein Erfolg --
    // genau daran ist camerabin lautlos gescheitert.
    bool zustandSetzen(GstState ziel)
    {
        const GstStateChangeReturn ergebnis =
                gst_element_set_state(m_pipeline, ziel);
        if (ergebnis == GST_STATE_CHANGE_FAILURE) return false;
        GstState ist = GST_STATE_NULL, wartet = GST_STATE_NULL;
        return gst_element_get_state(m_pipeline, &ist, &wartet, 4 * GST_SECOND)
                != GST_STATE_CHANGE_FAILURE && ist == ziel;
    }

    void scheitern(const QString &grund)
    {
        aufraeumen();
        emit fehlgeschlagen(grund);
    }

    // Der einzige Abbauweg. Alles kommt hier durch: Erfolg, Fehler, Frist,
    // Abbruch, Destruktor. Danach sind die Zeiger 0, ein zweiter Aufruf ist
    // folgenlos.
    void aufraeumen()
    {
        // Steht im Protokoll, wenn jemand dem Scan nachgeht: ob ueberhaupt
        // Rahmen kamen, und wie viele davon ein Bild trugen. Ein Lauf mit
        // vielen Rahmen und null echten ist der Nullbild-Fall.
        if (m_rahmen || m_echte)
            qDebug("Kamera: %d Rahmen, davon %d mit Bild", m_rahmen, m_echte);
        m_rahmen = 0;
        m_echte = 0;
        m_frist.stop();
        m_laeuft = false;
        if (m_senke) {
            g_signal_handlers_disconnect_by_func(
                m_senke, (void *)G_CALLBACK(pufferKam), this);
            gst_object_unref(m_senke);
            m_senke = 0;
        }
        if (m_pipeline) {
            gst_element_set_state(m_pipeline, GST_STATE_NULL);
            // Abwarten, bis der Wechsel wirklich durch ist -- sonst ist die
            // Kamera beim naechsten Versuch noch belegt.
            GstState ist = GST_STATE_NULL, wartet = GST_STATE_NULL;
            gst_element_get_state(m_pipeline, &ist, &wartet, 4 * GST_SECOND);
        }
        if (m_quelle) { gst_object_unref(m_quelle); m_quelle = 0; }
        if (m_pipeline) { gst_object_unref(m_pipeline); m_pipeline = 0; }
        QMutexLocker sperre(&m_sperre);
        m_letzter.clear();
    }

    GstElement *m_pipeline;
    GstElement *m_quelle;       // die innere Quelle von camsrcbin
    GstElement *m_senke;        // appsink
    bool m_laeuft;
    QTimer m_frist;
    QMutex m_sperre;
    QByteArray m_letzter;
    int m_rahmen;               // angekommene Rahmen
    int m_echte;                // davon mit Bildinhalt
};

#endif
