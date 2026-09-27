// The daemon's local HTTP interface. Both front ends -- Silica on Sailfish
// and com.nokia.meego on Harmattan -- use this same file, because the only
// thing they share is the daemon.
.pragma library

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

function request(method, path, body, callback) {
    var xhr = new XMLHttpRequest()
    xhr.open(method, base + path)
    xhr.setRequestHeader("Content-Type", "application/json")
    xhr.onreadystatechange = function() {
        if (xhr.readyState !== 4)
            return
        if (xhr.status === 200) {
            var answer = {}
            try {
                answer = parse(xhr.responseText)
            } catch (e) {
                answer = { error: "the daemon sent nonsense: " + xhr.responseText }
            }
            callback(answer)
        } else {
            // status 0 means the daemon is not up yet
            callback({ error: xhr.status === 0
                      ? "der Dienst antwortet nicht"
                      : "Fehler " + xhr.status })
        }
    }
    xhr.send(body === null ? "" : stringify(body))
}

function status(callback) {
    request("GET", "/status", null, callback)
}

// Entsperren. Der Dienst unterscheidet nach aussen nicht, ob das Passwort
// falsch oder die Datei beschaedigt ist -- der Grund steht in seinem
// Protokoll. Fuer die Oberflaeche ist beides "so nicht".
function unlock(password, callback) {
    request("POST", "/unlock", { password: password }, callback)
}

// Passwort setzen, aendern oder -- mit leerer Zeichenkette -- entfernen.
function setPassword(password, callback) {
    request("POST", "/password", { password: password }, callback)
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
function qrParse(text) {
    var result = { link: "", address: "", bluetooth: "", onion: "" }
    if (!text)
        return result
    var cut = text.indexOf("?")
    result.link = (cut < 0 ? text : text.substring(0, cut)).trim()
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
