// The daemon's local HTTP interface. Both front ends -- Silica on Sailfish
// and com.nokia.meego on Harmattan -- use this same file, because the only
// thing they share is the daemon.
.pragma library

// Nur noch der Rueckfall ohne Bruecke, siehe anfrage().
var base = "http://127.0.0.1:8105"

// Qt 4.7's QML engine on Harmattan has no JSON object. Both front ends share
// this file, so both paths live here.
function parse(text) {
    if (typeof JSON !== "undefined")
        return JSON.parse(text)
    return eval("(" + text + ")")
}

function stringify(value) {
    if (typeof JSON !== "undefined")
        return JSON.stringify(value)
    if (value === null || value === undefined)
        return "null"
    if (typeof value === "number")
        return "" + value
    if (typeof value === "boolean")
        return value ? "true" : "false"
    if (typeof value === "string") {
        var out = ""
        for (var i = 0; i < value.length; ++i) {
            var c = value.charAt(i)
            var code = value.charCodeAt(i)
            if (c === '"' || c === "\\")
                out += "\\" + c
            else if (code < 0x20 || code > 0x7e)
                out += "\\u" + ("000" + code.toString(16)).slice(-4)
            else
                out += c
        }
        return '"' + out + '"'
    }
    var parts = []
    for (var key in value) {
        if (value.hasOwnProperty(key))
            parts.push(stringify("" + key) + ":" + stringify(value[key]))
    }
    return "{" + parts.join(",") + "}"
}

// Wie lange auf eine Antwort gewartet wird, bevor der Rueckruf mit einem
// Fehler kommt. Grosszuegig, weil das Aufsperren am N9 einen scrypt-Lauf ueber
// 16 MB kostet -- aber eben nicht unbegrenzt: ohne Grenze bleibt eine Seite,
// die auf den Rueckruf wartet, fuer immer im "wird geprueft" stehen, und der
// Knopf laesst sich nicht mehr druecken. Genau das ist am N9 passiert.
var ZEITGRENZE = 90000

// Das Geheimnis der Schnittstelle. Der Dienst legt es bei jedem Start neben
// die state.json (api-token, nur fuer den Benutzer lesbar); ohne diesen Kopf
// gibt er nichts heraus -- so bleibt eine Webseite im Browser oder eine App
// eines anderen Kontos draussen (Sicherheitsbefund K1). Woher die
// Oberflaeche es liest, sagt ihr die QML-Wurzel ueber geheimnisQuelleSetzen;
// nach einem 401 wird es einmal neu gelesen, denn der Dienst wuerfelt bei
// jedem Start ein neues.
var geheimnis = ""
var geheimnisQuelle = null

function geheimnisQuelleSetzen(quelle) {
    geheimnisQuelle = quelle
    geheimnis = ""
    return true
}

function geheimnisHolen() {
    if (geheimnis === "" && geheimnisQuelle) {
        try {
            geheimnis = "" + (geheimnisQuelle() || "")
        } catch (e) {
            geheimnis = ""
        }
    }
    return geheimnis
}

// Seit 0.42.0 lauscht der Dienst auf einem Unix-Sockel (api.sock neben der
// state.json), nicht mehr auf 127.0.0.1:8105 -- den erreichte jede Webseite
// im Browser. XMLHttpRequest kann keinen Sockel, also schickt die C++-Seite
// die Anfrage (Daemon.anfrage / dienst.anfrage) und meldet die Antwort als
// Signal zurueck, das die QML-Wurzel an antwortErhalten weitergibt. Gesetzt
// wird die Bruecke wie die Geheimnisquelle als Eigenschafts-Bindung der
// Wurzel. Ohne Bruecke (Werkzeuge, qmlscene) geht es wie frueher ueber
// XMLHttpRequest an base -- das braucht einen Dienst mit --api-port.
var bruecke = null
// Die Rueckrufe der laufenden Anfragen, nach ihrer Nummer.
var offen = {}
var naechsteId = 1

function brueckeSetzen(obj) {
    bruecke = obj
    return true
}

/** Von der Wurzel gerufen, wenn die Bruecke eine Antwort meldet. */
function antwortErhalten(nummer, code, rumpf) {
    var auswerten = offen[nummer]
    if (!auswerten)
        return
    delete offen[nummer]
    auswerten(code, rumpf)
}

function request(method, path, body, callback) {
    anfrage(method, path, body, callback, true)
}

function anfrage(method, path, body, callback, nochmal) {
    // Der Rueckruf muss genau einmal kommen -- auch wenn Zeitgrenze und
    // Antwort sich ueberholen.
    var erledigt = false
    function fertig(antwort) {
        if (erledigt)
            return
        erledigt = true
        callback(antwort)
    }
    // Fuer beide Wege gleich: Status und Text der Antwort.
    function auswerten(status, text) {
        if (status === 200) {
            var answer = {}
            try {
                answer = parse(text)
            } catch (e) {
                answer = { error: "the daemon sent nonsense: " + text }
            }
            fertig(answer)
        } else if (status === 401 && nochmal) {
            // Ein neuer Dienst, ein neues Geheimnis: einmal frisch lesen und
            // die Anfrage wiederholen. Kommt wieder 401, war es das.
            if (erledigt)
                return
            erledigt = true
            geheimnis = ""
            anfrage(method, path, body, callback, false)
        } else {
            // Kommt gar nichts (Status 0), ist der Dienst weg oder neu -- das
            // Geheimnis dann lieber neu lesen, denn Qt 4.7 meldet womoeglich
            // auch ein 401 als 0. Die Bruecke meldet 0 auch nach ihrer
            // Zeitgrenze (90 s wie ZEITGRENZE).
            if (status === 0)
                geheimnis = ""
            fertig({ error: status === 0
                      ? "der Dienst antwortet nicht"
                      : (status === 401
                         ? "die Oberflaeche hat kein Geheimnis fuer den Dienst"
                         : "Fehler " + status) })
        }
    }

    var g = geheimnisHolen()
    var rumpf = body === null ? "" : stringify(body)
    if (bruecke) {
        var id = naechsteId++
        // Erst merken, dann schicken: die Antwort darf nie vor dem Eintrag
        // da sein.
        offen[id] = auswerten
        bruecke.anfrage(id, method, path, rumpf, g)
        return
    }

    var xhr = new XMLHttpRequest()
    xhr.open(method, base + path)
    xhr.setRequestHeader("Content-Type", "application/json")
    if (g !== "") {
        // Zwei Schreibweisen: Qt 4.7 laesst nicht jeden Kopf durch.
        xhr.setRequestHeader("Authorization", "Bearer " + g)
        xhr.setRequestHeader("X-Briar-Geheimnis", g)
    }
    // Qt 5 kennt beides; Qt 4.7 (Harmattan) ignoriert es stillschweigend,
    // dort haengt die Zeitgrenze am Zeitgeber der jeweiligen Seite.
    xhr.timeout = ZEITGRENZE
    xhr.ontimeout = function() {
        fertig({ error: "der Dienst antwortet nicht" })
    }
    xhr.onreadystatechange = function() {
        if (xhr.readyState !== 4)
            return
        auswerten(xhr.status, xhr.responseText)
    }
    xhr.send(rumpf)
}

function status(callback) {
    request("GET", "/status", null, callback)
}

// Antworten des Dienstes, die einem Menschen nichts sagen, in etwas
// uebersetzen, das weiterhilft. "unknown request" heisst in der Praxis
// immer dasselbe: der Dienst laeuft noch in einer aelteren Fassung als die
// Oberflaeche und muss neu gestartet werden.
function klartext(fehler) {
    if (!fehler)
        return ""
    if (fehler.indexOf("unknown request") >= 0)
        return "Der Dienst ist älter als die Oberfläche — bitte neu starten."
    return fehler
}

// Entsperren. Der Dienst unterscheidet nach aussen nicht, ob das Passwort
// falsch oder die Datei beschaedigt ist -- der Grund steht in seinem
// Protokoll. Fuer die Oberflaeche ist beides "so nicht".
// Bevor ein Passwort ueber die Leitung geht, muss der Dienst sich frisch
// ausgewiesen haben: das Geheimnis wird neu geholt, und die Quelle gibt es
// nur heraus, wenn der Dienst auf dem Sockel den Nachweis darueber liefert
// (Daemon.token / dienst.token). Ein Fremder am Sockel bekommt so weder
// Geheimnis noch Passwort.
function ausgewiesen(callback) {
    geheimnis = ""
    if (geheimnisHolen() !== "")
        return true
    callback({ error: "der Dienst weist sich nicht aus" })
    return false
}

function unlock(password, callback) {
    if (!ausgewiesen(callback))
        return
    request("POST", "/unlock", { password: password }, callback)
}

/** Aufsperren mit der Marke vom Zusperren -- nach Fingerabdruck oder Code. */
function unlock2(token, callback) {
    if (!ausgewiesen(callback))
        return
    request("POST", "/unlock", { token: token }, callback)
}

/** Zusperren wie Briars Bildschirmsperre: der Abgleich laeuft weiter. */
function lock(callback) {
    request("POST", "/lock", {}, callback)
}

/** Nach wie vielen Minuten ohne Regung von selbst zugesperrt wird, 0 = nie. */
function lockAfter(minutes, callback) {
    request("POST", "/lockafter", { minutes: minutes }, callback)
}

/** Alles loeschen und von vorn anfangen. Auch der Weg bei vergessenem Passwort. */
function deleteAccount(callback) {
    request("POST", "/account/delete", {}, callback)
}

/** Eine Nachricht oder das ganze Gespraech loeschen -- nur hier, nicht drueben. */
function deleteMessage(contact, id, callback) {
    request("POST", "/message/delete", { contact: contact, id: id }, callback)
}

function deleteAllMessages(contact, callback) {
    request("POST", "/message/delete", { contact: contact, all: true }, callback)
}

/** Mehrere auf einmal -- Briars Auswahlmodus. */
function deleteMessages(contact, ids, callback) {
    request("POST", "/message/delete", { contact: contact, ids: ids }, callback)
}

// Briars Staerkemass, eins zu eins: die Zahl der VERSCHIEDENEN Zeichen
// geteilt durch zwoelf, gedeckelt bei 1 (PasswordStrengthEstimatorImpl,
// STRONG_UNIQUE_CHARS = 12). Die Schwellen dort: 0 keins, 0,25 schwach,
// 0,5 eher schwach, 0,75 eher stark, 1 stark. Briar laesst ein Passwort ab
// 0,5 zu -- also ab sechs verschiedenen Zeichen.
function passwordStrength(password) {
    if (!password)
        return 0
    var gesehen = {}
    var verschieden = 0
    for (var i = 0; i < password.length; i++) {
        var z = password.charAt(i)
        if (!gesehen[z]) {
            gesehen[z] = true
            verschieden++
        }
    }
    return Math.min(1, verschieden / 12)
}

// Ab hier laesst Briar ein Passwort zu (QUITE_WEAK).
var PASSWORD_MIN_STRENGTH = 0.5

// Passwort setzen, aendern oder -- mit leerer Zeichenkette -- entfernen.
// Ist schon eines gesetzt, muss das alte mitkommen: sonst koennte jeder, der
// kurz an das entsperrte Geraet kommt, den Besitzer aussperren.
function setPassword(oldPassword, password, callback) {
    if (!ausgewiesen(callback))
        return
    request("POST", "/password",
            { old: oldPassword, password: password }, callback)
}

function createIdentity(name, callback) {
    request("POST", "/identity", { name: name }, callback)
}

function addPending(link, alias, address, bluetooth, onion, callback) {
    var body = { link: link, alias: alias }
    if (address && address.length > 0)
        body.address = address
    if (bluetooth && bluetooth.length > 0)
        body.bluetooth = bluetooth
    if (onion && onion.length > 0)
        body.onion = onion
    request("POST", "/pending", body, callback)
}

function messages(contact, callback) {
    request("GET", "/messages?contact=" + contact, null, callback)
}

function send(contact, text, callback) {
    request("POST", "/send", { contact: contact, text: text }, callback)
}

/** A message with a file attached, in Briar's attachment format. */
function sendFile(contact, text, path, contentType, callback) {
    request("POST", "/send", { contact: contact, text: text,
                               file: path, contentType: contentType }, callback)
}

function connectContact(contact, address, bluetooth, callback) {
    var body = { contact: contact }
    if (address && address.length > 0)
        body.address = address
    if (bluetooth && bluetooth.length > 0)
        body.bluetooth = bluetooth
    request("POST", "/connect", body, callback)
}

// What goes into the QR code: the link, and the addresses behind it, so one
// photograph is enough to add someone.
function qrPayload(status) {
    if (!status || !status.link)
        return ""
    var text = status.link
    var parts = []
    if (status.lanAddress)
        parts.push("lan=" + status.lanAddress)
    if (status.bluetoothAddress)
        parts.push("bt=" + status.bluetoothAddress)
    if (status.onion)
        parts.push("tor=" + status.onion)
    return parts.length ? text + "?" + parts.join("&") : text
}

// The other direction: what a photographed code holds.
//
// Nur ein Kontaktlink kommt hierher: briar:// und 53 Zeichen Base32, wie
// HandshakeLinkConstants.java:27 (LINK_REGEX) und qrPayload oben ihn
// schreiben. Der zweite Code, den es gibt -- der zum Treffen (BQP) --, ist
// kein Text; wo die Bytes vorliegen, erkennen die ScanPages ihn vorher
// (istBqp). MeeScan auf dem N9 liefert nur Text -- dort faellt er hier
// durch, wie jeder fremde Code.
// Alles andere gibt einen leeren Link, und die Seiten sagen "kein
// Briar-Code", statt beliebigen Text in AddContactPage zu tragen.
function qrParse(text) {
    var result = { link: "", address: "", bluetooth: "", onion: "" }
    if (!text)
        return result
    text = ("" + text).trim()
    var cut = text.indexOf("?")
    var link = (cut < 0 ? text : text.substring(0, cut)).trim()
    if (!/^briar:\/\/[a-z2-7]{53}$/i.test(link))
        return result
    result.link = link
    if (cut >= 0) {
        var pairs = text.substring(cut + 1).split("&")
        for (var i = 0; i < pairs.length; i++) {
            var kv = pairs[i].split("=")
            if (kv[0] === "bt") result.bluetooth = kv[1]
            else if (kv[0] === "tor") result.onion = kv[1]
            else if (kv[0] === "lan") result.address = kv[1]
        }
    }
    return result
}

// Sagt dem Dienst, dass dieser Chat gerade gelesen wird -- damit
// verschwindet auch seine Benachrichtigung.
function markRead(what, callback) {
    request("POST", "/read", what, callback)
}

function setLanguage(language, callback) {
    request("POST", "/language", {language: language}, callback)
}

function setTor(enabled, callback) {
    request("POST", "/tor", {enabled: enabled}, callback)
}

function setBluetooth(enabled, callback) {
    request("POST", "/bluetooth", {enabled: enabled}, callback)
}

function poll(callback) {
    request("POST", "/poll", {}, callback)
}

// Einen Wartenden streichen. Er hat noch keine Nummer -- die bekommt er
// erst mit dem Handschlag --, also geht es ueber seinen Schluessel.
function removePending(publicKey, callback) {
    request("POST", "/pending/remove", { publicKey: publicKey }, callback)
}

function removeContact(contact, callback) {
    request("POST", "/remove", { contact: contact }, callback)
}

function groups(callback) {
    request("GET", "/groups", null, callback)
}

function createGroup(name, callback) {
    request("POST", "/group", { name: name }, callback)
}

function inviteToGroup(group, contact, callback) {
    request("POST", "/group/invite", { group: group, contact: contact }, callback)
}

function joinGroup(group, callback) {
    request("POST", "/group/join", { group: group }, callback)
}

function groupMessages(group, callback) {
    request("GET", "/group/messages?group=" + group, null, callback)
}

function sendToGroup(group, text, callback) {
    request("POST", "/group/send", { group: group, text: text }, callback)
}

function removeGroup(group, callback) {
    request("POST", "/group/remove", { group: group }, callback)
}

// BQP -- zwei Geraete nebeneinander. Briar nennt es "Kontakt in der Naehe
// hinzufuegen": jedes Geraet zeigt einen Code und liest den des anderen,
// danach steht der Kontakt, ohne dass ein Link durch fremde Haende geht.
function bqpStart(callback) {
    request("POST", "/bqp/start", {}, callback)
}

function bqpScan(payloadHex, callback) {
    request("POST", "/bqp/scan", { payload: payloadHex }, callback)
}

function bqpStop(callback) {
    request("POST", "/bqp/stop", {}, callback)
}

// Ein gelesener Code, als Hex. Das erste Byte sagt, was es ist: 0x04 ist ein
// BQP-Rumpf (Briars Fassung 4), alles andere ist Schrift -- unser Link.
/// Was ZXing zurueckgibt, in rohe Bytes zurueckrechnen.
///
/// Der Filter der Kamera-App liefert einen QString, und ZXing schreibt darin
/// nicht druckbare Bytes als lesbare Namen aus -- nachgemessen am eigenen
/// BQP-Code ueber den zxing-daemon:
///
///   0x04 -> "<EOT>"   (C0-Steuerzeichen beim Namen genannt)
///   0x82 -> "<U+82>"  (0x80..0x9F, in Latin-1 die C1-Steuerzeichen)
///
/// Beides laesst sich umkehren. Der Beweis war der eigene Treffen-Code: 36
/// Bytes, und sie zerlegen sich restlos in Kennzeichen, 16-Byte-Verpflichtung
/// und einen WLAN-Beschreiber mit der richtigen Adresse und dem richtigen
/// Port. Ohne diese Umkehr kaeme aus dem schnellen Leser fuer BQP nur Unsinn.
///
/// Eine Unschaerfe bleibt und soll hier stehen: enthielte die Nutzlast selbst
/// die Zeichen "<EOT>", waere sie von einem echten 0x04 nicht zu
/// unterscheiden. Bei einer Verpflichtung aus Zufallsbytes ist das sehr
/// unwahrscheinlich, und wenn es doch geschieht, passt die Verpflichtung
/// nicht zum Schluessel und der Handschlag bricht ab -- also nichts
/// Gefaehrliches, nur ein Versuch, der nichts wird.
function zxingZuHex(text) {
    if (!text)
        return ""
    var namen = { NUL: 0, SOH: 1, STX: 2, ETX: 3, EOT: 4, ENQ: 5, ACK: 6,
                  BEL: 7, BS: 8, HT: 9, LF: 10, VT: 11, FF: 12, CR: 13,
                  SO: 14, SI: 15, DLE: 16, DC1: 17, DC2: 18, DC3: 19,
                  DC4: 20, NAK: 21, SYN: 22, ETB: 23, CAN: 24, EM: 25,
                  SUB: 26, ESC: 27, FS: 28, GS: 29, RS: 30, US: 31, DEL: 127 }
    var hex = ""
    var i = 0
    while (i < text.length) {
        var wert = -1
        var weiter = 1
        if (text.charAt(i) === "<") {
            var zu = text.indexOf(">", i + 1)
            if (zu > i && zu - i <= 9) {
                var innen = text.substring(i + 1, zu)
                if (innen.substring(0, 2) === "U+") {
                    var z = parseInt(innen.substring(2), 16)
                    if (!isNaN(z) && z >= 0 && z <= 255) {
                        wert = z
                        weiter = zu - i + 1
                    }
                } else if (namen.hasOwnProperty(innen)) {
                    wert = namen[innen]
                    weiter = zu - i + 1
                }
            }
        }
        if (wert < 0) {
            wert = text.charCodeAt(i)
            // Ueber 255 heisst: der Leser hat die Bytes als etwas anderes
            // gedeutet, und dann ist hier nichts mehr zu retten.
            if (wert > 255)
                return null
        }
        hex += (wert < 16 ? "0" : "") + wert.toString(16)
        i += weiter
    }
    return hex
}

/// Der strenge Riegel fuer den schnellen Leser: Kennzeichen, Listenanfang,
/// und eine Verpflichtung von genau 16 rohen Bytes. Ein Code, den die
/// Rueckrechnung oben verdorben haette, faellt hier fast sicher durch. Der
/// Fotoweg benutzt weiter istBqp() -- der liest die Bytes roh und braucht
/// keinen Riegel.
function istBqpStreng(hex) {
    return !!hex && hex.length > 40 && hex.substring(0, 8) === "04605110"
}

/// Die Beziehung in einer Gruppe zeigen -- Briars "Kontakte zeigen".
/// Wem gegenueber das geht, sagt der Dienst mit der Gruppe ("revealable").
function reveal(group, contact, callback) {
    request("POST", "/group/reveal", { group: group, contact: contact }, callback)
}

function istBqp(hex) {
    return !!hex && hex.length > 2 && hex.substring(0, 2) === "04"
}

// Hex zu Schrift. Der Leser gibt immer Bytes zurueck; wer Schrift erwartet,
// setzt sie hier zusammen. Mehr als ASCII steht in unseren Links nicht.
/// Der Rueckweg: Text zu Hex, Zeichen fuer Zeichen nach ISO-8859-1.
///
/// Genau die Abbildung, die Briar auf Android benutzt: ZXing liest einen
/// QR-Code im Byte-Modus ohne ECI als ISO-8859-1, jedes Byte wird ein
/// Zeichen. Steht ein Zeichen ueber 255, hat der Leser die Bytes als etwas
/// anderes gedeutet und dabei verdorben -- dann ist hier nichts zu retten,
/// und wir geben null zurueck, statt Unsinn weiterzureichen.
function textZuHex(text) {
    if (!text)
        return ""
    var hex = ""
    for (var i = 0; i < text.length; ++i) {
        var c = text.charCodeAt(i)
        if (c > 255)
            return null
        hex += (c < 16 ? "0" : "") + c.toString(16)
    }
    return hex
}

function hexZuText(hex) {
    if (!hex)
        return ""
    var text = ""
    for (var i = 0; i + 1 < hex.length; i += 2) {
        var b = parseInt(hex.substring(i, i + 2), 16)
        if (isNaN(b) || b === 0)
            return text
        text += String.fromCharCode(b)
    }
    return text
}

// Verschwindende Nachrichten: die Dauer in Millisekunden, -1 schaltet sie ab.
// Sie geht nicht als eigene Nachricht hinaus, sondern faehrt in der naechsten
// Nachricht mit -- so macht es Briar auch.
function setAutoDelete(contact, timer, callback) {
    request("POST", "/autodelete", { contact: contact, timer: timer }, callback)
}

// Die Dauer als Wort. Nur die vier Stufen, die die Oberflaeche anbietet --
// alles andere kaeme von der Gegenseite und wird in Minuten gezeigt.
function autoDeleteName(ms, tr) {
    if (!ms || ms < 0)
        return tr("autoDeleteOff")
    if (ms === 60000) return tr("autoDelete1Min")
    if (ms === 3600000) return tr("autoDelete1Hour")
    if (ms === 86400000) return tr("autoDelete1Day")
    if (ms === 604800000) return tr("autoDelete1Week")
    return Math.round(ms / 60000) + " min"
}

// Die Anhaenge einer Nachricht als Liste -- gleich, ob der Dienst schon die
// neue Liste liefert oder nur die vier alten Einzelfelder. Briar haengt bis
// zu zehn Bilder an eine Nachricht; bis 0.29.2 kam davon nur das erste an.
function attachmentsOf(message) {
    if (!message)
        return []
    if (message.attachments && message.attachments.length > 0)
        return message.attachments
    if (message.attachmentPath)
        return [{ "id": message.attachment,
                  "type": message.attachmentType,
                  "path": message.attachmentPath,
                  "size": message.attachmentSize }]
    return []
}

function isImage(anhang) {
    return !!anhang && ("" + anhang.type).indexOf("image/") === 0
}
