#ifndef DIENST_H
#define DIENST_H

#include <QByteArray>
#include <QLocalSocket>
#include <QObject>
#include <QString>
#include <QTimer>

/// Eine Anfrage an den Dienst ueber seinen Unix-Sockel (api.sock neben der
/// state.json). XMLHttpRequest in QML kann keinen Sockel, also geht Briar.js
/// seit 0.42.0 hier durch. Je Anfrage ein Objekt mit eigenem QLocalSocket,
/// damit mehrere gleichzeitig laufen; es raeumt sich nach der Antwort selbst
/// weg. Steht hier und nicht in main.cpp, weil tools/remote-build.sh moc nur
/// ueber dienst.h laufen laesst.
class DienstAnfrage : public QObject
{
    Q_OBJECT
public:
    DienstAnfrage(int id, const QString &sockel, const QByteArray &anfrage,
                  int zeitgrenze, QObject *parent);
signals:
    /// status 0: keine Verbindung, keine vollstaendige Antwort, Zeit um.
    void fertig(int nummer, int code, const QString &rumpf);
public slots:
    void starten();
private slots:
    void verbunden();
    void lesen();
    void getrennt();
    void fehler(QLocalSocket::LocalSocketError);
    void zeitUm();
private:
    void abschliessen(bool zeitUm);

    int m_id;
    QString m_sockel;
    QByteArray m_anfrage;
    QByteArray m_antwort;
    QLocalSocket *m_socket;
    QTimer *m_zeit;
    bool m_erledigt;
};

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
    /// Eine Anfrage an die Schnittstelle, asynchron; die Antwort kommt als
    /// Signal antwort mit derselben Nummer. Siehe Briar.js, anfrage().
    Q_INVOKABLE void anfrage(int nummer, const QString &method, const QString &path,
                             const QString &body, const QString &geheimnis);
signals:
    // Die Namen der Parameter braucht QtQuick 1.1: onAntwort sieht sie nur
    // so. Nicht id und status -- id ist in QML besonders, status heisst auch
    // eine Eigenschaft der Sailfish-Wurzel (Gegenpruefung 7b, B1).
    void antwort(int nummer, int code, const QString &rumpf);
};

#endif
