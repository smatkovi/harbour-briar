// Der Sperrzustand des Telefons, für Briars eigene Sperre.
//
// Harmattan hat keinen Fingerabdruck und keinen Schlüsselbund, aber es hat ein
// Geräteschloss: com.nokia.devicelock auf dem Systembus, mit getState und dem
// Signal stateChanged. Damit lässt sich dasselbe bauen, was Briar auf Android
// tut -- die App sperrt zu, wenn das Telefon zusperrt, und geht wieder auf,
// wenn der Benutzer es aufsperrt.
//
// Ist gar kein Sperrcode eingestellt -- Harmattan erlaubt das --, meldet der
// Dienst nie eine Sperre. Dann bleibt es beim Briar-Passwort, das nach einem
// Neustart ohnehin verlangt wird: der Speicher ist dann versiegelt.
//
// Was hier NICHT geschieht: das Passwort irgendwo ablegen. Die Oberfläche holt
// sich beim Zusperren eine einmalige Marke vom Dienst und gibt sie beim
// Aufsperren zurück -- dieselbe Mechanik wie der Fingerabdruck an der Jolla.

#ifndef GERAETESCHLOSS_H
#define GERAETESCHLOSS_H

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QObject>

class Geraeteschloss : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool gesperrt READ gesperrt NOTIFY gesperrtChanged)
    Q_PROPERTY(bool vorhanden READ vorhanden CONSTANT)

public:
    explicit Geraeteschloss(QObject *parent = 0)
        : QObject(parent)
        , m_gesperrt(false)
        , m_vorhanden(false)
    {
        QDBusConnection bus = QDBusConnection::systemBus();
        // Das Signal zuerst: kommt der Dienst später, hören wir trotzdem mit.
        m_vorhanden = bus.connect(QLatin1String("com.nokia.devicelock"),
                                  QLatin1String("/request"),
                                  QLatin1String("com.nokia.devicelock"),
                                  QLatin1String("stateChanged"),
                                  this, SLOT(zustandKam(int, int)));
        QDBusInterface schloss(QLatin1String("com.nokia.devicelock"),
                               QLatin1String("/request"),
                               QLatin1String("com.nokia.devicelock"), bus);
        if (schloss.isValid()) {
            // Argument 1: das Gerät selbst (nicht die SIM).
            QDBusReply<int> antwort = schloss.call(QLatin1String("getState"), 1);
            if (antwort.isValid())
                m_gesperrt = antwort.value() != 0;
        }
    }

    bool gesperrt() const { return m_gesperrt; }
    bool vorhanden() const { return m_vorhanden; }

signals:
    void gesperrtChanged();

private slots:
    void zustandKam(int geraet, int zustand)
    {
        // 1 ist das Gerät, alles andere (SIM) geht uns nichts an.
        if (geraet != 1)
            return;
        const bool neu = zustand != 0;
        if (neu == m_gesperrt)
            return;
        m_gesperrt = neu;
        emit gesperrtChanged();
    }

private:
    bool m_gesperrt;
    bool m_vorhanden;
};

#endif
