#ifndef DIENST_H
#define DIENST_H

#include <QObject>
#include <QString>

// Reachable from QML: if the daemon does not answer, the interface can start
// it again instead of only showing "the daemon does not answer". The system
// may stop it while the window is open, and a dead window helps nobody.
class Dienst : public QObject
{
    Q_OBJECT
public:
    explicit Dienst(QObject *parent = 0) : QObject(parent) {}
    Q_INVOKABLE void starten();
    /// Das Geheimnis der Schnittstelle (api-token neben der state.json),
    /// jedes Mal frisch gelesen -- siehe die Sailfish-Seite.
    Q_INVOKABLE QString token();
};

#endif
