# Briar für Sailfish OS und MeeGo Harmattan

Briars Protokoll (Bramble) auf Geräten, auf denen Briar selbst nie laufen
wird: Briar ist Java und braucht Java 8, das Nokia N9/N950 hat kein JVM und
bekommt auch keines. Deshalb ist dies kein Port von Briars Code, sondern eine
Neuimplementierung seiner **Drahtformate** in Rust, mit zwei Oberflächen
darüber -- Silica auf Sailfish, `com.nokia.meego` auf Harmattan.

Beide Oberflächen sprechen denselben Dienst (`briard`) über eine kleine
HTTP-Schnittstelle auf `127.0.0.1:8105`, so wie es der WhatsApp-Port und
Fluesterwind auf diesen Geräten vormachen.

## Was Briars ist

Jede dieser Schichten ist gegen Referenzbytes geprüft, die aus Briars eigenem
`bramble-core` (Release 1.5.20) stammen -- siehe `vectors/`:

| Schicht | Datei | Prüfung |
|---|---|---|
| BLAKE2b-Ableitungen, Ed25519-Signaturen mit Etikett, X25519 | `kern/src/crypto.rs` | `hash`, `mac`, `derive_key`, `sign`, `agree_*` |
| Transportschlüssel, Marken, Zeitabschnitte | `kern/src/transport.rs` | `static_master_key`, `hs_*`, `rot_*`, `tag_v4_s3` |
| Stromverschlüsselung (XSalsa20-Poly1305, Rahmen) | `kern/src/stream.rs` | `stream` |
| BDF, das Datenformat | `kern/src/bdf.rs` | `bdf_simple`, `bdf_nested`, `bdf_text` |
| Kennungen (Autor, Gruppe, Nachricht) | `kern/src/ids.rs` | `author_id`, `group_id`, `message_id` |
| Handschlag 0.1 und Kontaktaustausch | `kern/src/handshake.rs`, `exchange.rs` | `hs_master_*`, `ex_*` |
| `briar://`-Links | `kern/src/ids.rs` | `link`, `link_pending_id` |
| Sync-Protokoll, Privatgruppen, Anhänge | `kern/src/sync.rs`, `groups.rs` | Format aus dem Quelltext |

`vectors/java/` ist das Programm, das diese Bytes erzeugt: es lädt die echten
Klassen aus Briars Fat-Jar und schreibt ihre Ausgaben als `schlüssel=hex`.
`cargo test` im Verzeichnis `kern` vergleicht die Rust-Seite damit.

## Was nicht Briars ist

* **Kein Tor-Rendezvous.** Briar findet einen neuen Kontakt über Tor. Hier
  trägt eine der beiden Seiten die Adresse der anderen von Hand ein -- im
  WLAN, über Bluetooth oder als Onion-Adresse. Danach tauschen die Geräte
  ihre Adressen selbst aus.
* **Kein SDP über Bluetooth.** Briar meldet pro Gerät eine UUID an und sucht
  den Kanal dazu. Ohne BlueZ-Anbindung nimmt dieser Port einen festen
  RFCOMM-Kanal (11).
* **Keine Foren, keine Blogs, kein Vorstellen von Kontakten
  (Introductions).**
* **QR-Code, aber nicht Briars BQP.** Briar tauscht über den QR-Code ein
  Handschlag-Geheimnis und baut daraus eine Verbindung auf. Hier steht im
  Code der briar://-Link mit den Adressen dahinter (`?lan=...&bt=...&tor=...`),
  die Gegenseite fotografiert ihn ab und hat alles ausgefüllt. Kodierer ist
  eigener Code (`src/qrencode.h`, gegen zbar geprüft), Dekodierer ist quirc
  (`src/quirc/`), weil keines der beiden Geräte eine QR-Bibliothek hat. Auf
  dem N9 wird ausgelöst und das Bild danach gelesen -- Qt 4.7 gibt QML keine
  laufenden Kamerabilder.
* **Adressen nach Briars Vorbild, nicht nach Briars Bauplan.** Briars
  Eigenschaften-Client meldet Adressen als eigene, versionierte Nachrichten;
  hier gehen sie in derselben Form (Transport, Version, Wörterbuch) durch den
  Ausgangskorb und werden wiederholt, bis die Gegenseite sie bestätigt. So
  erfährt auch ein Kontakt von vor Tor die Onion-Adresse.
* Der Speicher ist eine JSON-Datei, keine verschlüsselte H2-Datenbank. Das
  Format ist Briars Sache nicht -- nur die Leitung muss stimmen.

## Wege zum Kontakt

| Weg | Adresse | Voraussetzung |
|---|---|---|
| WLAN | `IP:Port`, z.B. `192.168.1.12:7327` | selbes Netz |
| Bluetooth | `40:98:4E:AD:BD:42` | gekoppelt, Bluetooth an |
| Tor | Onion-Adresse | keine -- ein statisches Tor liegt im Paket (`tools/build-tor.sh` baut es) |

Sind mehrere bekannt, wird der Reihe nach probiert: WLAN, Bluetooth, Tor.

## Aufbau

```
kern/       Dienst in Rust (briard), statisch gegen musl
  src/crypto.rs transport.rs stream.rs record.rs   Briars Unterbau
  src/handshake.rs exchange.rs sync.rs groups.rs   die Protokolle
  src/bt.rs tor.rs net.rs                          die Transporte
  src/store.rs api.rs                              Speicher und Schnittstelle
qml/        Silica-Oberfläche (Sailfish)
meego/      Qt-4.7-Oberfläche und Debian-Paket (Harmattan)
qml/Briar.js qml/Strings.js                        von beiden benutzt
src/imageprep.h                                    Bilder verkleinern (Qt 4 und 5)
vectors/    Referenzbytes aus bramble-core
tools/      Bauen, Paketieren, Installieren
```

## Bauen

```sh
tools/build.sh              # Dienst (aarch64 + armv7) und Harmattan-Oberfläche
tools/build-rpm.sh aarch64  # Sailfish-Paket -> ~/ps/rpms/briar/
tools/build-deb.sh 0.5      # Harmattan-Paket
tools/build-tor.sh          # statisches Tor für beide Architekturen
```

Gebaut wird auf dem Arch-Rechner (Rust, musl-Toolchains, Harmattan-SDK,
Sailfish-SDK-Container); `tools/buildhost.sh` findet ihn.

## Installieren

```sh
sudo rpm -Uvh ~/ps/rpms/briar/harbour-briar-0.5.0-1.aarch64.rpm
N9_HOST=192.168.1.15 tools/install-meego.sh briar_0.20_armel.deb
```

Auf Harmattan **`aegis-dpkg -i`**, nicht `dpkg -i`: sonst landen die Dateien
ohne registrierte Prüfsummen und lassen sich nicht starten ("Operation not
permitted").

## Sailfish: dieselben Griffe wie die anderen Apps

* **Benachrichtigungen** kommen aus dem Dienst (nicht aus der Oberfläche),
  also auch bei geschlossener App. Kategorie `x-nemo.messaging.im`, eine
  Benachrichtigung je Chat -- die nächste Nachricht ersetzt die vorige.
* **Antworten direkt in der Benachrichtigung**: die Fernaktion `reply` mit
  `x-nemo-remote-action-type-reply=input` ruft
  `harbour.briar.Backend.Reply(kontakt, text)` am Sitzungsbus. Der Dienst
  reicht den Text an seine eigene HTTP-Schnittstelle weiter, damit eine
  Antwort aus der Benachrichtigung genau denselben Weg nimmt wie eine aus
  der App.
* **Antippen öffnet den Chat**: Fernaktion `default` an
  `harbour.briar.Gui.openChat`; läuft die App nicht, startet sie der
  D-Bus-Dienst (`dbus/harbour.harbour-briar.service`).
* **Dienst im Hintergrund** (freiwillig): `harbour-briar-briard.service` als
  Benutzer-Einheit, ein Schalter unter „Mein Link" legt sie um
  (`systemctl --user enable --now`).
* **„Mit Briar senden"** im Teilen-Menü: `harbour-briar-share.desktop` mit
  `X-Share-Methods`, dazu das Objekt `/share/briar_share` in der App, das
  die Datei annimmt und nach dem Empfänger fragt.
* Der Dienst spricht D-Bus nur in der Sailfish-Ausgabe (`--features sfos`);
  Harmattan hat `org.freedesktop.Notifications` gar nicht.

## Wenn das Netz kommt und geht

Die Lauscher geben nicht mehr auf. Früher stieg der Bluetooth-Lauscher aus,
wenn beim Start nicht gebunden werden konnte -- war Bluetooth zu dem
Zeitpunkt aus, blieb es für die ganze Laufzeit stumm. Jetzt versuchen WLAN-
und Bluetooth-Lauscher es alle fünf Sekunden erneut (und melden das nur
einmal), und nach mehreren fehlgeschlagenen `accept` wird der Sockel
weggeworfen und neu gebunden. Die Tor-Steuerverbindung wird jede Minute
geprüft; reißt sie ab, wird der versteckte Dienst neu veröffentlicht --
mit demselben Schlüssel, also unter derselben Adresse.

Dazu ein Wächter am **Systembus**, der wartet statt zu fragen: ConnMan
(Sailfish), ICd2 (Harmattan) und BlueZ melden, wenn ein Netz kommt oder
geht. Erst dann wird nachgesehen, ob sich die eigenen Adressen geändert
haben, und gegebenenfalls sofort abgeglichen. Kein Takt, kein Aufwachen im
Ruhezustand -- geprüft: sechs Nachrichten an ein gesperrtes, schlafendes
Gerät kamen mit 0 s Verzug an, der eingehende Verbindungsaufbau weckt es
selbst.

## MeeGo: in der Nachrichten-App

Auf dem N9/N950 trägt die [Nachrichtenbrücke](../nachrichtenbruecke) Briar
in die eingebaute Nachrichten-App -- dieselbe Brücke, die schon WhatsApp,
Signal, Telegram und Matrix dorthin bringt. Sie brauchte dafür fast nichts:
der Dienst beantwortet zusätzlich die vier Wege, die sie von den anderen
Diensten kennt.

| Weg | Antwort |
|---|---|
| `GET /chats` | alle Kontakte und beigetretenen Gruppen |
| `GET /messages?jid=c3` | die Nachrichten eines Chats |
| `GET /send?to=c3&text=...` | senden |
| `GET /events?since=N` | lange Abfrage, kehrt bei Änderung zurück |

Eine Kennung ist `c<Kontaktnummer>` oder `g<Gruppenkennung>`. Die eigene
Oberfläche benutzt weiterhin `/messages?contact=` und `POST /send`; beides
steht nebeneinander.

## Sailfish ohne Sandkasten

Die Desktop-Datei setzt `Sandboxing=Disabled` im `[X-Sailjail]`-Abschnitt:
`Base.permission` erlaubt die Protokollfamilie `unix`, `Internet` fügt
`inet`, `inet6` und `netlink` hinzu, und **keine** Erlaubnis unter
`/etc/sailjail/permissions` nennt Bluetooth -- ein roher
`AF_BLUETOOTH`-Socket scheitert im Sandkasten mit Errno 95. Dazu endet der
Sandkasten mit dem Fenster, der Dienst soll aber weiterlaufen, damit
Nachrichten auch bei geschlossener App ankommen. Die Kennungen
(`OrganizationName`/`ApplicationName`) bleiben stehen, damit die App ihren
eigenen Platz für Einstellungen behält.

## Stand

Läuft und geprüft zwischen Jolla (Sailfish 5.2, aarch64), Nokia N9 und N950
(Harmattan, armv7):

* Handschlag und Kontaktaustausch über WLAN und über Bluetooth
* Nachrichten in beide Richtungen, mit Empfangsbestätigung
* Privatgruppen: anlegen, einladen, beitreten, schreiben -- Beiträge
  erreichen auch Mitglieder, die untereinander keine Kontakte sind
* Anhänge bis 32 KB (Bilder werden vorher verkleinert)
* Sprache: Englisch, im Menü auf Deutsch umschaltbar; die Wahl liegt im
  Dienst, also gilt sie auf beiden Oberflächen und übersteht den Neustart
* Tor: ein statisch gebautes Tor 0.4.8.14 liegt im Paket (aarch64 und
  armv7), der Dienst startet es, veröffentlicht einen versteckten Dienst und
  erreicht Gegenstellen über ihre Onion-Adresse. Auf dem N9 und N950 ist Tor
  anfangs aus (rund 30 MB Arbeitsspeicher), auf der Jolla an; Ausschalten
  beendet Tor wieder.

Der Tor-Weg ist zweimal geprüft: zwischen zwei Diensten auf einem Rechner
(beide nur über ihre Onion-Adresse) und zwischen Jolla und N950, indem dem
Kontakt WLAN und Bluetooth weggenommen wurden -- die Nachricht kam über den
versteckten Dienst an. Die Adressen melden sich seither von selbst: der N950
kennt die Onion-Adresse der Jolla, ohne dass sie jemand eingetragen hat.

Nicht geprüft: die MeeGo-Oberfläche wurde nur von Hand angesehen (ein
Bildschirmfoto war nicht zu bekommen, das Gerät schläft), und der Anhang-Weg
ist auf dem Rechner byteweise geprüft, auf den Geräten nur benutzt.
