// Das Briar-Passwort im Geräteschloss von Sailfish hinterlegen.
//
// Briar auf Android sperrt mit dem Bildschirmschloss des Telefons auf, nicht
// mit dem Briar-Passwort (KeyguardManager, Fingerabdruck über BiometricPrompt).
// An der Jolla gibt es dafür zwei Stücke: org.nemomobile.devicelock fragt
// Fingerabdruck oder Gerätecode ab, und Sailfish Secrets verwahrt ein Geheimnis
// so, dass es nur nach genau dieser Prüfung wieder herauskommt
// (DeviceLockVerifyLock).
//
// Damit lässt sich auch der Fall lösen, den die einmalige Marke nicht deckt:
// nach einem Neustart ist der Speicher versiegelt, und sonst hilft nur Tippen.
// Liegt das Passwort hier, genügt der Finger.
//
// Was das nicht ist: ein zweiter Ort, an dem das Passwort im Klartext liegt.
// Sailfish Secrets verschlüsselt es mit einem Schlüssel, den der Dienst hält,
// und gibt es nur an diese Anwendung heraus (OwnerOnlyMode), nachdem das Gerät
// den Benutzer erkannt hat.
//
// **Alles hier ist unblockierend.** Die Prüfung ist ein Dialog des Systems, und
// wer ihn liegen lässt -- weil das Telefon in die Tasche wandert --, darf die
// App nicht anhalten. Ein blockierendes waitForFinished() hätte genau das
// getan: die Oberfläche steht, bis der Dienst von selbst aufgibt. Darum
// Signale, und dazu eine eigene Frist, nach der wir nicht mehr warten.
//
// Fehlt der Dienst oder lehnt er ab, bleibt es beim Passwort; die App merkt es
// nur daran, dass `verfuegbar` falsch ist oder `fehlgeschlagen` kommt.

#ifndef TRESORSECRETS_H
#define TRESORSECRETS_H

#include <QObject>
#include <QString>
#include <QTimer>

#include <Sailfish/Secrets/createcollectionrequest.h>
#include <Sailfish/Secrets/deletesecretrequest.h>
#include <Sailfish/Secrets/request.h>
#include <Sailfish/Secrets/secret.h>
#include <Sailfish/Secrets/secretmanager.h>
#include <Sailfish/Secrets/storedsecretrequest.h>
#include <Sailfish/Secrets/storesecretrequest.h>

class TresorSecrets : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool verfuegbar READ verfuegbar CONSTANT)
    Q_PROPERTY(bool laeuft READ laeuft NOTIFY laeuftChanged)

public:
    explicit TresorSecrets(QObject *parent = 0)
        : QObject(parent)
        , m_holen(0)
        , m_laeuft(false)
    {
        // Wer die Bestätigung liegen lässt, soll die App nicht festhalten.
        // Nach der Frist geben wir auf und sagen es; der Dialog des Systems
        // darf ruhig noch stehen, seine Antwort läuft dann ins Leere.
        m_frist.setSingleShot(true);
        m_frist.setInterval(90000);
        connect(&m_frist, SIGNAL(timeout()), this, SLOT(fristAbgelaufen()));
    }

    /// Gibt es den Geheimnisdienst überhaupt? Ohne ihn bleibt alles beim
    /// Passwort -- das ist kein Fehler, nur ein Gerät ohne diese Ablage.
    bool verfuegbar() const { return verwalter.isInitialized(); }

    /// Läuft gerade eine Anfrage? Die Oberfläche zeigt derweil "warte".
    bool laeuft() const { return m_laeuft; }

    /// Das Passwort hinterlegen. Die Ablage entsteht beim ersten Mal und ist an
    /// das Geräteschloss gebunden: DeviceLockVerifyLock heißt, dass sie mit dem
    /// Bildschirm zusperrt und erst nach einer Prüfung -- Fingerabdruck genügt,
    /// kein erneutes Tippen -- wieder aufgeht.
    ///
    /// Auch das läuft nebenher; das Ergebnis kommt als `gemerkt`.
    Q_INVOKABLE void merken(const QString &passwort)
    {
        if (!verfuegbar()) {
            emit gemerkt(false);
            return;
        }
        Sailfish::Secrets::CreateCollectionRequest *anlegen =
                new Sailfish::Secrets::CreateCollectionRequest(this);
        anlegen->setManager(&verwalter);
        anlegen->setCollectionName(ABLAGE);
        anlegen->setCollectionLockType(
                Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
        anlegen->setDeviceLockUnlockSemantic(
                Sailfish::Secrets::SecretManager::DeviceLockVerifyLock);
        anlegen->setAccessControlMode(
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
        anlegen->setStoragePluginName(
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName);
        anlegen->setEncryptionPluginName(
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName);
        anlegen->setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        m_passwort = passwort;
        setzeLaeuft(true);
        connect(anlegen, SIGNAL(statusChanged()), this, SLOT(ablageFertig()));
        anlegen->startRequest();
        m_frist.start();
    }

    /// Das Passwort holen. Hier fragt das Gerät nach -- Fingerabdruck oder
    /// Code --, und erst danach kommt es zurück. Die Antwort kommt als
    /// `gefunden` oder `fehlgeschlagen`, nie als Warten.
    Q_INVOKABLE void holen()
    {
        if (!verfuegbar()) {
            emit fehlgeschlagen();
            return;
        }
        if (m_laeuft)
            return;
        m_holen = new Sailfish::Secrets::StoredSecretRequest(this);
        m_holen->setManager(&verwalter);
        m_holen->setIdentifier(Sailfish::Secrets::Secret::Identifier(
                NAME, ABLAGE,
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        m_holen->setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        setzeLaeuft(true);
        connect(m_holen, SIGNAL(statusChanged()), this, SLOT(holenFertig()));
        m_holen->startRequest();
        m_frist.start();
    }

    /// Wieder wegnehmen -- beim Passwortwechsel und wenn der Benutzer es nicht
    /// mehr will. Das Wegnehmen fragt nicht nach, es darf also blockierend
    /// laufen; es dauert keine sichtbare Zeit.
    Q_INVOKABLE void vergessen()
    {
        if (!verfuegbar())
            return;
        Sailfish::Secrets::DeleteSecretRequest weg;
        weg.setManager(&verwalter);
        weg.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                NAME, ABLAGE,
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        weg.setUserInteractionMode(
                Sailfish::Secrets::SecretManager::PreventInteraction);
        weg.startRequest();
        weg.waitForFinished();
    }

signals:
    void laeuftChanged();
    /// Das Passwort ist da -- die Prüfung ist geglückt.
    void gefunden(const QString &passwort);
    /// Nichts hinterlegt, abgebrochen, oder die Frist ist abgelaufen.
    void fehlgeschlagen();
    void gemerkt(bool erfolg);

private slots:
    void ablageFertig()
    {
        Sailfish::Secrets::CreateCollectionRequest *anlegen =
                qobject_cast<Sailfish::Secrets::CreateCollectionRequest *>(sender());
        if (!anlegen || anlegen->status() != Sailfish::Secrets::Request::Finished)
            return;
        const bool schonDa = anlegen->result().errorCode()
                == Sailfish::Secrets::Result::CollectionAlreadyExistsError;
        const bool gut = anlegen->result().code()
                == Sailfish::Secrets::Result::Succeeded;
        anlegen->deleteLater();
        if (!gut && !schonDa) {
            fertig();
            emit gemerkt(false);
            return;
        }

        Sailfish::Secrets::Secret geheimnis(
                Sailfish::Secrets::Secret::Identifier(
                        NAME, ABLAGE,
                        Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        geheimnis.setData(m_passwort.toUtf8());
        geheimnis.setType(Sailfish::Secrets::Secret::TypeBlob);

        Sailfish::Secrets::StoreSecretRequest *legen =
                new Sailfish::Secrets::StoreSecretRequest(this);
        legen->setManager(&verwalter);
        legen->setSecretStorageType(
                Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
        legen->setSecret(geheimnis);
        legen->setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        connect(legen, SIGNAL(statusChanged()), this, SLOT(legenFertig()));
        legen->startRequest();
    }

    void legenFertig()
    {
        Sailfish::Secrets::StoreSecretRequest *legen =
                qobject_cast<Sailfish::Secrets::StoreSecretRequest *>(sender());
        if (!legen || legen->status() != Sailfish::Secrets::Request::Finished)
            return;
        const bool gut = legen->result().code()
                == Sailfish::Secrets::Result::Succeeded;
        legen->deleteLater();
        m_passwort.clear();
        fertig();
        emit gemerkt(gut);
    }

    void holenFertig()
    {
        if (!m_holen || m_holen->status() != Sailfish::Secrets::Request::Finished)
            return;
        const bool gut = m_holen->result().code()
                == Sailfish::Secrets::Result::Succeeded;
        const QString passwort = gut
                ? QString::fromUtf8(m_holen->secret().data())
                : QString();
        m_holen->deleteLater();
        m_holen = 0;
        fertig();
        if (gut && !passwort.isEmpty())
            emit gefunden(passwort);
        else
            emit fehlgeschlagen();
    }

    void fristAbgelaufen()
    {
        if (!m_laeuft)
            return;
        // Die Antwort des Dialogs läuft jetzt ins Leere. Wichtig ist nur, dass
        // die Oberfläche weiterkann.
        if (m_holen) {
            m_holen->deleteLater();
            m_holen = 0;
        }
        m_passwort.clear();
        fertig();
        emit fehlgeschlagen();
    }

private:
    void setzeLaeuft(bool wert)
    {
        if (m_laeuft == wert)
            return;
        m_laeuft = wert;
        emit laeuftChanged();
    }

    void fertig()
    {
        m_frist.stop();
        setzeLaeuft(false);
    }

    Sailfish::Secrets::SecretManager verwalter;
    Sailfish::Secrets::StoredSecretRequest *m_holen;
    QTimer m_frist;
    QString m_passwort;
    bool m_laeuft;
    // Eine eigene Ablage, damit nichts mit anderen Anwendungen kollidiert.
    const QString ABLAGE = QStringLiteral("harbour-briar");
    const QString NAME = QStringLiteral("kontopasswort");
};

#endif
