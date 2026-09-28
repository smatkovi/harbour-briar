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
// nach einem Neustart ist der Speicher versiegelt, und bisher half nur Tippen.
// Liegt das Passwort hier, genügt der Finger.
//
// Was das nicht ist: ein zweiter Ort, an dem das Passwort im Klartext liegt.
// Sailfish Secrets verschlüsselt es mit einem Schlüssel, den der Dienst hält,
// und gibt es nur an diese Anwendung heraus (OwnerOnlyMode), nachdem das
// Gerät den Benutzer erkannt hat.
//
// Alles daran ist freiwillig: fehlt der Dienst oder lehnt er ab, bleibt es beim
// Passwort, und die App merkt es nur daran, dass `verfuegbar` falsch ist.

#ifndef TRESORSECRETS_H
#define TRESORSECRETS_H

#include <QObject>
#include <QString>

#include <Sailfish/Secrets/createcollectionrequest.h>
#include <Sailfish/Secrets/deletesecretrequest.h>
#include <Sailfish/Secrets/secret.h>
#include <Sailfish/Secrets/secretmanager.h>
#include <Sailfish/Secrets/storedsecretrequest.h>
#include <Sailfish/Secrets/storesecretrequest.h>

class TresorSecrets : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool verfuegbar READ verfuegbar CONSTANT)

public:
    explicit TresorSecrets(QObject *parent = 0)
        : QObject(parent)
    {}

    /// Gibt es den Geheimnisdienst überhaupt? Ohne ihn bleibt alles beim
    /// Passwort -- das ist kein Fehler, nur ein Gerät ohne diese Ablage.
    bool verfuegbar() const
    {
        return verwalter.isInitialized();
    }

    /// Das Passwort hinterlegen. Die Ablage entsteht beim ersten Mal und ist an
    /// das Geräteschloss gebunden: DeviceLockVerifyLock heißt, dass sie mit dem
    /// Bildschirm zusperrt und erst nach einer Prüfung -- Fingerabdruck genügt,
    /// kein erneutes Tippen -- wieder aufgeht.
    Q_INVOKABLE bool merken(const QString &passwort)
    {
        if (!verfuegbar())
            return false;

        Sailfish::Secrets::CreateCollectionRequest anlegen;
        anlegen.setManager(&verwalter);
        anlegen.setCollectionName(ABLAGE);
        anlegen.setCollectionLockType(
                Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
        anlegen.setDeviceLockUnlockSemantic(
                Sailfish::Secrets::SecretManager::DeviceLockVerifyLock);
        anlegen.setAccessControlMode(
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
        anlegen.setStoragePluginName(
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName);
        anlegen.setEncryptionPluginName(
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName);
        anlegen.setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        anlegen.startRequest();
        anlegen.waitForFinished();
        // Ein zweites Anlegen scheitert mit "gibt es schon" -- das ist kein
        // Fehler, sondern der Normalfall ab dem zweiten Mal.
        const Sailfish::Secrets::Result::ResultCode angelegt =
                anlegen.result().code();
        if (angelegt == Sailfish::Secrets::Result::Failed
                && anlegen.result().errorCode()
                    != Sailfish::Secrets::Result::CollectionAlreadyExistsError) {
            return false;
        }

        Sailfish::Secrets::Secret geheimnis(
                Sailfish::Secrets::Secret::Identifier(
                        NAME, ABLAGE,
                        Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        geheimnis.setData(passwort.toUtf8());
        geheimnis.setType(Sailfish::Secrets::Secret::TypeBlob);

        Sailfish::Secrets::StoreSecretRequest legen;
        legen.setManager(&verwalter);
        legen.setSecretStorageType(
                Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
        legen.setSecret(geheimnis);
        legen.setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        legen.startRequest();
        legen.waitForFinished();
        return legen.result().code() == Sailfish::Secrets::Result::Succeeded;
    }

    /// Das Passwort holen. Hier fragt das Gerät nach -- Fingerabdruck oder
    /// Code --, und erst danach kommt es zurück. Leer heißt: nichts hinterlegt
    /// oder abgebrochen.
    Q_INVOKABLE QString holen()
    {
        if (!verfuegbar())
            return QString();

        Sailfish::Secrets::StoredSecretRequest holen;
        holen.setManager(&verwalter);
        holen.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                NAME, ABLAGE,
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        holen.setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        holen.startRequest();
        holen.waitForFinished();
        if (holen.result().code() != Sailfish::Secrets::Result::Succeeded)
            return QString();
        return QString::fromUtf8(holen.secret().data());
    }

    /// Wieder wegnehmen -- beim Passwortwechsel und wenn der Benutzer es nicht
    /// mehr will.
    Q_INVOKABLE bool vergessen()
    {
        if (!verfuegbar())
            return false;
        Sailfish::Secrets::DeleteSecretRequest weg;
        weg.setManager(&verwalter);
        weg.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                NAME, ABLAGE,
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName));
        weg.setUserInteractionMode(
                Sailfish::Secrets::SecretManager::SystemInteraction);
        weg.startRequest();
        weg.waitForFinished();
        return weg.result().code() == Sailfish::Secrets::Result::Succeeded;
    }

private:
    Sailfish::Secrets::SecretManager verwalter;
    // Eine eigene Ablage, damit nichts mit anderen Anwendungen kollidiert.
    const QString ABLAGE = QStringLiteral("harbour-briar");
    const QString NAME = QStringLiteral("kontopasswort");
};

#endif
