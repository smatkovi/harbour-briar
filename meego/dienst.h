#ifndef DIENST_H
#define DIENST_H

#include <QObject>

// Reachable from QML: if the daemon does not answer, the interface can start
// it again instead of only showing "the daemon does not answer". The system
// may stop it while the window is open, and a dead window helps nobody.
class Dienst : public QObject
{
    Q_OBJECT
public:
    explicit Dienst(QObject *parent = 0) : QObject(parent) {}
    Q_INVOKABLE void starten();
};

#endif
