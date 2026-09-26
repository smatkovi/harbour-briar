// Both front ends share this file. English unless German is chosen; the
// choice lives in the daemon, so both front ends and every restart keep it.
.pragma library

var lang = "en"

function language() {
    return lang
}

function setLanguage(code) {
    lang = (code && ("" + code).substring(0, 2) === "de") ? "de" : "en"
}

var table = {
    briar:            { de: "Briar",                       en: "Briar" },
    noIdentity:       { de: "noch keine Kennung",          en: "no identity yet" },
    name:             { de: "Name",                        en: "Name" },
    yourName:         { de: "Wie sollen dich Kontakte sehen?",
                        en: "How should contacts see you?" },
    createIdentity:   { de: "Kennung anlegen",             en: "Create identity" },
    create:           { de: "Anlegen",                     en: "Create" },
    contacts:         { de: "Kontakte",                    en: "Contacts" },
    noContacts:       { de: "Keine Kontakte",              en: "No contacts" },
    addContactHint:   { de: "Links tauschen und im Menü hinzufügen",
                        en: "Swap links and add one from the menu" },
    addContact:       { de: "Kontakt hinzufügen",          en: "Add contact" },
    myLink:           { de: "Mein Link",                   en: "My link" },
    connectNow:       { de: "Jetzt verbinden",             en: "Connect now" },
    connect:          { de: "Verbinden",                   en: "Connect" },
    about:            { de: "Über",                        en: "About" },
    remove:           { de: "Entfernen",                   en: "Remove" },
    waiting:          { de: "wartet",                      en: "waiting" },
    noAddress:        { de: "keine Adresse",               en: "no address" },
    message:          { de: "Nachricht",                   en: "Message" },
    send:             { de: "Senden",                      en: "Send" },
    copyLink:         { de: "In die Zwischenablage",       en: "Copy to clipboard" },
    linkOfContact:    { de: "briar://-Link des Kontakts",  en: "The contact's briar:// link" },
    nameFree:         { de: "Name (frei wählbar)",         en: "Name (your choice)" },
    lanAddress:       { de: "Adresse im WLAN, z.B. 192.168.1.12:7327",
                        en: "Address on the LAN, e.g. 192.168.1.12:7327" },
    btAddress:        { de: "Bluetooth-Adresse, z.B. 00:11:22:33:44:55",
                        en: "Bluetooth address, e.g. 00:11:22:33:44:55" },
    add:              { de: "Hinzufügen",                  en: "Add" },
    addHint:          { de: "Beide Seiten tragen den Link der anderen ein. Eine "
                          + "Seite gibt zusätzlich die Adresse an -- im WLAN oder "
                          + "über Bluetooth -- dann läuft Briars Handschlag.",
                        en: "Both sides enter the other's link. One side also gives "
                          + "an address -- on the LAN or over Bluetooth -- and then "
                          + "Briar's handshake runs." },
    linkHint:         { de: "Dieses Gerät hört auf Port ",
                        en: "This device listens on port " },
    btHere:           { de: "Bluetooth hier: ",            en: "Bluetooth here: " },
    groups:           { de: "Gruppen",                     en: "Groups" },
    group:            { de: "Gruppe",                      en: "Group" },
    newGroup:         { de: "Neue Gruppe",                 en: "New group" },
    groupName:        { de: "Name der Gruppe",             en: "Group name" },
    noGroups:         { de: "Keine Gruppen",               en: "No groups" },
    invitation:       { de: "Einladung",                   en: "Invitation" },
    invitedBy:        { de: "eingeladen von ",             en: "invited by " },
    join:             { de: "Beitreten",                   en: "Join" },
    joined:           { de: "beigetreten",                 en: "joined" },
    members:          { de: "Mitglieder",                  en: "members" },
    invite:           { de: "Einladen",                    en: "Invite" },
    inviteWho:        { de: "Wen einladen?",               en: "Whom to invite?" },
    onlyCreator:      { de: "Nur wer die Gruppe angelegt hat, kann einladen.",
                        en: "Only whoever created the group can invite." },
    joinFirst:        { de: "Erst beitreten",              en: "Join first" },
    attach:           { de: "Anhang",                      en: "Attachment" },
    pickFile:         { de: "Datei wählen",                en: "Choose a file" },
    tooBig:           { de: "Zu groß für eine Nachricht (max. 32 KB). Bilder "
                          + "werden verkleinert, anderes nicht.",
                        en: "Too big for one message (32 KB max). Images are "
                          + "scaled down, other files are not." },
    attachmentHint:   { de: "Briar legt einen Anhang in eine einzige Nachricht, "
                          + "darum passen nur 32 KB. Bilder werden vorher "
                          + "verkleinert.",
                        en: "Briar puts an attachment in a single message, so only "
                          + "32 KB fit. Images are scaled down first." },
    up:               { de: "Hinauf",                      en: "Up" },
    onionAddress:     { de: "Onion-Adresse (Tor), ohne .onion",
                        en: "Onion address (Tor), without .onion" },
    torHere:          { de: "Tor hier: ",                  en: "Tor here: " },
    attach:           { de: "Anhängen",                     en: "Attach" },
    fromGallery:      { de: "Bild aus der Galerie",         en: "Picture from the gallery" },
    fromFiles:        { de: "Datei",                        en: "File" },
    shareTitle:       { de: "An wen senden?",               en: "Send to whom?" },
    background:       { de: "Dienst im Hintergrund",        en: "Background service" },
    backgroundHint:   { de: "Nachrichten kommen auch an, wenn die App geschlossen ist, und melden sich als Benachrichtigung.",
                        en: "Messages keep arriving while the app is closed, and announce themselves as a notification." },
    scanQr:           { de: "QR-Code abfotografieren",      en: "Photograph a QR code" },
    scanLiveHint:     { de: "Den QR-Code des anderen Geräts vor die Kamera halten.",
                        en: "Hold the other device's QR code in front of the camera." },
    scanHint:         { de: "Den QR-Code des anderen Geräts formatfüllend aufnehmen.",
                        en: "Take a picture of the other device's QR code, filling the frame." },
    scanTake:         { de: "Aufnehmen",                    en: "Take the picture" },
    scanWithMeeScan:  { de: "Mit MeeScan scannen",          en: "Scan with MeeScan" },
    scanOpenCamera:   { de: "Kamera öffnen",                en: "Open the camera" },
    scanReadPhoto:    { de: "Letztes Foto lesen",           en: "Read the last photo" },
    scanNoPhoto:      { de: "Noch kein Foto aufgenommen.",  en: "No picture taken yet." },
    scanCameraHint:   { de: "Erst mit der Kamera aufnehmen, dann hier lesen lassen. Den Code formatfüllend und scharf aufnehmen.",
                        en: "Take the picture with the camera first, then read it here. Fill the frame and let it focus." },
    scanning:         { de: "wird gelesen ...",             en: "reading ..." },
    scanNothing:      { de: "Kein QR-Code zu erkennen -- näher heran, ruhig halten, mehr Licht.",
                        en: "No QR code found -- move closer, hold still, more light." },
    scanFailed:       { de: "Die Kamera hat kein Bild geliefert.",
                        en: "The camera gave no picture." },
    qrHint:           { de: "Dieser Code enthält den Link und die Adressen. Das andere Gerät fotografiert ihn ab.",
                        en: "This code holds the link and the addresses. The other device photographs it." },
    switchToGerman:   { de: "Sprache: Deutsch",             en: "Switch to German" },
    switchToEnglish:  { de: "Sprache: Englisch",            en: "Language: English" },
    torSwitch:        { de: "Tor", en: "Tor" },
    torSwitchHint:    { de: "Startet das mitgelieferte Tor und veröffentlicht einen versteckten Dienst. Braucht rund 30 MB.",
                        en: "Starts the bundled Tor and publishes a hidden service. Needs some 30 MB." },
    btSwitch:         { de: "Bluetooth", en: "Bluetooth" },
    torOff:           { de: "Tor läuft auf diesem Gerät nicht",
                        en: "No Tor is running on this device" },
    help:             { de: "Anleitung",                   en: "How it works" },
    helpText:         { de: "So funktioniert es\n\n1. Dein Name\nBeim ersten Start gibst du einen Namen ein. Unter dem sehen dich deine Kontakte, und er steht bei allem, was du schreibst. Es gibt keine Anmeldung, keine Nummer, keine E-Mail-Adresse: dein Gerät legt sich selbst einen Ausweis an, der nur hier liegt.\n\n2. Jemanden hinzufügen\nIhr müsst euch beide eintragen. Einer allein reicht nicht -- so wie ein Handschlag zu zweit geht.\n\nNebeneinander, mit der Kamera:\nDer eine öffnet \"Mein Link\". Dort steht ein QR-Code.\nDer andere wählt im Menü \"QR-Code abfotografieren\", hält den Code formatfüllend ins Bild und tippt auf Aufnehmen. Danach steht alles schon im Formular, und ein Tipp auf Hinzufügen genügt.\nDann tauscht ihr die Geräte und macht dasselbe in die andere Richtung.\nAm N9 und N950 wird ein Foto gemacht und danach gelesen -- also nah heran, ruhig halten, genug Licht.\n\nAus der Ferne, ohne Kamera:\nUnter \"Mein Link\" steht eine lange Zeile, die mit briar:// beginnt. Schick sie dem anderen über einen Weg, dem du traust, und lass sie dir ebenso schicken. Beide tragen dann den Link des anderen unter \"Kontakt hinzufügen\" ein.\nEiner von euch trägt zusätzlich eine Adresse ein, damit sein Gerät das andere anrufen kann. Welche das ist, steht im nächsten Abschnitt. Der andere braucht keine.\n\n3. Die drei Wege\nBriar kennt keinen Server in der Mitte. Zwei Geräte reden direkt miteinander, und dafür gibt es drei Wege. Du musst nichts auswählen: die App probiert der Reihe nach WLAN, Bluetooth, Tor.\n\nWLAN -- wenn beide im selben Netz sind, zu Hause oder im Büro. Schnell, kostet nichts, geht auch ohne Internetzugang. Die Adresse sieht so aus: 192.168.1.12:7327. Die eigene steht unter \"Mein Link\".\n\nBluetooth -- wenn kein Netz da ist und ihr im selben Raum seid, ein paar Meter weit. Die Geräte sollten in den Einstellungen einmal gekoppelt worden sein. Die Adresse sieht so aus: 40:98:4E:AD:BD:42, die eigene steht ebenfalls unter \"Mein Link\".\n\nTor -- für alles, was weiter weg ist. Tor ist ein Netz von Zwischenstationen im Internet: dein Gerät bekommt darin eine Adresse, unter der es erreichbar ist, ohne dass jemand erfährt, wo es steht. Das Programm dafür liegt bei, du musst nichts installieren -- unter \"Mein Link\" den Schalter \"Tor\" umlegen. Nach etwa einer Minute steht dort deine eigene Adresse, die auf .onion endet; die des anderen trägst du bei ihm ein (ohne .onion).\nAm N9 und N950 ist Tor anfangs aus, weil es rund 30 MB Arbeitsspeicher braucht -- an der Jolla ist es an. Ausschalten beendet es wieder.\n\nNach dem ersten Treffen merken sich die Geräte die Adressen des anderen von selbst und halten sie aktuell.\n\n4. Gruppen\nUnter \"Gruppen\" legst du oben eine neue an und gibst ihr einen Namen. Dann lädst du Kontakte ein: in der Gruppe auf Einladen tippen (am N9 lange auf die Gruppe tippen) und auswählen, wer dabei sein soll.\nEinladen kann nur, wer die Gruppe angelegt hat. Wer eingeladen wird, sieht sie als \"Einladung\" und tritt mit einem Tipp bei. Bei jedem Beitrag steht, von wem er ist.\n\nWie Beiträge in einer Gruppe reisen:\nEine Gruppe hat keine eigene Leitung. Ein Beitrag ist eine ganz normale Nachricht und nimmt denselben Weg: zu jedem Mitglied, das gerade dein Kontakt ist, über WLAN, Bluetooth oder Tor -- je nachdem, was diesen einen erreicht. In derselben Gruppe können also drei verschiedene Wege gleichzeitig benutzt werden.\nWer einen Beitrag bekommt, gibt ihn unverändert an die Mitglieder weiter, die er selbst erreicht. Der Name des Verfassers bleibt dabei stehen. So kommt ein Beitrag auch bei Leuten an, mit denen du selbst gar nicht verbunden bist -- es genügt, dass irgendeine Kette dazwischen liegt.\nNiemand muss gleichzeitig online sein. Was gerade nicht zugestellt werden kann, wartet auf dem Gerät und geht beim nächsten Treffen hinaus. Zwei Geräte im Flugmodus tauschen die Gruppe über Bluetooth aus, und sobald eines wieder im Netz ist, bekommt der Rest dasselbe über WLAN oder Tor.\n\n5. Dateien\nIm Chat der Knopf neben dem Eingabefeld: ein Bild aus der Galerie oder eine beliebige Datei. Es passen nur rund 32 KB in eine Nachricht -- Bilder werden vorher automatisch verkleinert, andere Dateien nicht. Ist eine Datei zu groß, sagt die App es und schickt nichts.\n\n6. Wenn nichts ankommt\nLäuft der Dienst? Bei \"Mein Link\" muss eine Zeile mit briar:// stehen; steht dort ein Fehler, startet die App ihn von selbst neu.\nHat der andere dich auch eingetragen? Das ist der häufigste Fall.\nStimmt die Adresse? Im WLAN ändert sie sich, wenn das Gerät das Netz wechselt -- nach dem ersten Treffen richtet sich das von selbst.\nBluetooth: an beiden Geräten eingeschaltet und einmal gekoppelt?\nTor: eingeschaltet, und die erste Minute abgewartet?\n\n7. Was diese App nicht kann\nKeine Foren, keine Blogs, keine Anrufe. Nachrichten verschwinden nicht von selbst. Und sie kann nicht mit dem Briar auf Android sprechen, wenn es ums Hinzufügen geht: dort läuft das über einen Treffpunkt im Tor-Netz, hier über Link und Adresse.",
                        en: "How it works\n\n1. Your name\nWhen you start the app the first time, you enter a name. That is how your contacts see you, and it stands under everything you write. There is no sign-up, no number, no e-mail address: your device makes its own identity, and it stays here.\n\n2. Adding someone\nBoth of you have to add the other. One side alone is not enough -- a handshake takes two.\n\nSide by side, with the camera:\nOne of you opens \"My link\", where a QR code is shown.\nThe other picks \"Photograph a QR code\" from the menu, fills the frame with it and takes the picture. Everything is then filled in already, and one tap on Add finishes it.\nNow swap the devices and do the same the other way round.\nOn the N9 and N950 a picture is taken and read afterwards -- so move close, hold still, enough light.\n\nFrom a distance, without a camera:\nUnder \"My link\" there is a long line starting with briar://. Send it to the other person over a channel you trust, and have them send you theirs. Each of you enters the other's link under \"Add contact\".\nOne of you also enters an address, so that their device can call the other. Which address, see the next section. The other side needs none.\n\n3. The three routes\nBriar has no server in the middle. Two devices talk to each other directly, and there are three ways to do it. You do not have to choose: the app tries LAN, Bluetooth and Tor in turn.\n\nLAN -- when both are on the same network, at home or at work. Fast, free, and it works without internet access. An address looks like this: 192.168.1.12:7327. Yours is shown under \"My link\".\n\nBluetooth -- when there is no network and you are in the same room, a few metres apart. The devices should have been paired once in the system settings. An address looks like this: 40:98:4E:AD:BD:42, and yours is under \"My link\" as well.\n\nTor -- for everything further away. Tor is a network of relays on the internet: your device gets an address there that others can reach without learning where it is. The program for it comes with the app, you install nothing -- just turn on the \"Tor\" switch under \"My link\". After about a minute your own address appears, ending in .onion; the other person enters that one on their side (without .onion).\nOn the N9 and N950 Tor starts switched off, because it needs some 30 MB of memory -- on the Jolla it is on. Switching it off stops it again.\n\nAfter the first meeting the devices remember each other's addresses and keep them up to date by themselves.\n\n4. Groups\nUnder \"Groups\" you create one at the top and give it a name. Then you invite contacts: tap Invite inside the group (on the N9, press and hold the group) and pick who should be in it.\nOnly whoever created the group can invite. Those invited see it as an \"Invitation\" and join with one tap. Every post says who wrote it.\n\nHow posts travel in a group:\nA group has no line of its own. A post is an ordinary message and takes the same route: to every member who is a contact of yours, over LAN, Bluetooth or Tor -- whichever reaches that one person. So three different routes can be in use in the same group at the same time.\nWhoever receives a post passes it on unchanged to the members they can reach. The author's name stays with it. That is how a post also reaches people you are not connected to at all -- it is enough that some chain of contacts lies in between.\nNobody has to be online at the same time. What cannot be delivered waits on the device and goes out at the next meeting. Two devices in flight mode exchange the group over Bluetooth, and as soon as one is back on a network the rest get the same posts over LAN or Tor.\n\n5. Files\nIn a chat, the button beside the input field: a picture from the gallery, or any file. Only about 32 KB fit into one message -- pictures are scaled down first, other files are not. If a file is too big, the app says so and sends nothing.\n\n6. When nothing arrives\nIs the service running? \"My link\" has to show a line starting with briar://; if there is an error instead, the app restarts it by itself.\nHas the other person added you too? That is the most common reason.\nIs the address right? On a network it changes when the device joins another one -- after the first meeting this sorts itself out.\nBluetooth: switched on at both ends, and paired once?\nTor: switched on, and did you wait out the first minute?\n\n7. What this app cannot do\nNo forums, no blogs, no calls. Messages do not disappear by themselves. And it cannot add a contact together with Briar on Android: there, adding runs through a meeting point in the Tor network, here through a link and an address." },
    aboutText:        { de: "Briars Protokoll (Bramble), neu geschrieben in Rust für "
                          + "Geräte ohne Java: Sailfish OS und MeeGo Harmattan.\n\n"
                          + "Die Verschlüsselung und alles, was über die Leitung geht, "
                          + "ist dieselbe wie bei Briar -- Schicht für Schicht gegen "
                          + "die Originalbytes geprüft. Nachrichten sind Ende zu Ende "
                          + "verschlüsselt und werden unterschrieben, Gruppenbeiträge "
                          + "auch.\n\n"
                          + "Wege: WLAN, Bluetooth und Tor -- ein Tor ist mitgeliefert.\n\n"
                          + "Anders als bei Briar: Kontakte werden über ihren Link und "
                          + "eine Adresse hinzugefügt, nicht über Briars Treffpunkt. "
                          + "Keine Foren, keine Blogs.",
                        en: "Briar's protocol (Bramble), rewritten in Rust for devices "
                          + "without Java: Sailfish OS and MeeGo Harmattan.\n\n"
                          + "The encryption and everything that goes over the wire is the "
                          + "same as Briar's -- every layer checked against the "
                          + "original bytes. Messages are end-to-end encrypted and "
                          + "signed, group posts too.\n\n"
                          + "Routes: LAN, Bluetooth and Tor -- a Tor is bundled.\n\n"
                          + "Different from Briar: contacts are added by their link plus "
                          + "an address rather than through Briar's rendezvous. No "
                          + "forums, no blogs." }
}

// `revision` is only there to tie a binding to app.languageRevision, so the
// text is recomputed when the language changes.
function tr(key, revision) {
    return t(key)
}

function t(key) {
    var entry = table[key]
    if (!entry)
        return key
    return entry[lang] !== undefined ? entry[lang] : entry.en
}

/** Milliseconds since the epoch as a short local time. */
function shortTime(ms) {
    var d = new Date(ms)
    var hh = d.getHours()
    var mm = d.getMinutes()
    return (hh < 10 ? "0" : "") + hh + ":" + (mm < 10 ? "0" : "") + mm
}
