#ifndef QRLESER_H
#define QRLESER_H

// Liest ein Standbild in einem Arbeitsfaden und meldet das Ergebnis per
// Signal.
//
// Warum das noetig ist: der Sucher an der Jolla schiesst im Takt, und
// QrCode.decodeHexAndRemove() lief bisher synchron aus QML heraus -- also auf
// dem Oberflaechenfaden. Solange quirc lief, stand das Sucherbild still und
// der Dauerautofokus fand keine Ruhe. Beides zusammen macht genau den
// Eindruck, ueber den sich das Scannen an der Jolla beschwert hat: es stockt,
// und es erwischt selten ein scharfes Bild.
//
// Nur die Jolla benutzt das. Am N9 loest ein Mensch einmal aus und wartet
// ohnehin auf das Ergebnis -- dort gibt es nichts zu entkoppeln, und
// meego/briar.pro sieht diese Datei nicht.
//
// src/qrcode.h bleibt unberuehrt: decodeHexStatic() ist dort schon oeffentlich
// und statisch, genau fuer solche Aufrufe.
//
// Qt am Ziel ist 5.6.3 (am Bauwirt nachgesehen), deshalb QtConcurrent::run
// mit einem Zeiger auf eine statische Funktion -- QThread::create gibt es erst
// ab 5.10.

#include <QFile>
#include <QFutureWatcher>
#include <QObject>
#include <QString>
#include <QtConcurrent/QtConcurrentRun>

#include "qrcode.h"

class QrLeser : public QObject
{
    Q_OBJECT

public:
    explicit QrLeser(QObject *parent = 0) : QObject(parent)
    {
        connect(&m_wache, SIGNAL(finished()), this, SLOT(fertigGeworden()));
    }

    /// Ein Bild zum Lesen geben. Gibt false zurueck, wenn schon eines im
    /// Leser liegt -- dann ist die Datei bereits weggeraeumt, sonst liefe der
    /// Zwischenspeicher voll.
    Q_INVOKABLE bool lesen(const QString &datei)
    {
        QString pfad = datei;
        if (pfad.startsWith(QLatin1String("file://")))
            pfad = pfad.mid(7);
        if (m_wache.isRunning()) {
            QFile::remove(pfad);
            return false;
        }
        m_wache.setFuture(QtConcurrent::run(&QrLeser::arbeiten, pfad));
        return true;
    }

signals:
    /// Leerer String heisst: in dem Bild stand kein Code.
    void fertig(const QString &hex);

private slots:
    void fertigGeworden() { emit fertig(m_wache.result()); }

private:
    // Laeuft im Arbeitsfaden. Raeumt die Datei selbst weg, damit der
    // Zwischenspeicher nicht vollaeuft -- QML kann keine Datei loeschen.
    static QString arbeiten(const QString &pfad)
    {
        const QString hex = QrCode::decodeHexStatic(pfad);
        QFile::remove(pfad);
        return hex;
    }

    QFutureWatcher<QString> m_wache;
};

#endif
