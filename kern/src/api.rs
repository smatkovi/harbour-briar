//! The local HTTP interface the user interfaces talk to. Same shape as the
//! WhatsApp and Fluesterwind backends: a small JSON API on 127.0.0.1, so the
//! Silica and Qt 4 front ends can both use it unchanged.

use crate::groups;
use crate::net::{self, Node, Shared};
use crate::store::{key_from_hex, GroupPost, OutMessage, PendingContact, PrivateGroup, Store};
use crate::transport::{BLUETOOTH_TRANSPORT_ID, LAN_TRANSPORT_ID, TOR_TRANSPORT_ID};
use crate::util::{from_hex, now_ms, to_hex};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

#[cfg(feature = "sfos")]
fn close_notification(key: &str) {
    crate::notify::close(key);
}

#[cfg(not(feature = "sfos"))]
fn close_notification(_key: &str) {}

pub fn run(store: Shared, port: u16) {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            net::log(&format!("cannot bind the API to port {}: {}", port, e));
            return;
        }
    };
    net::log(&format!("API on 127.0.0.1:{}", port));
    for socket in listener.incoming() {
        match socket {
            Ok(socket) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    if let Err(e) = serve(store, socket) {
                        net::log(&format!("API request failed: {}", e));
                    }
                });
            }
            Err(e) => net::log(&format!("API accept failed: {}", e)),
        }
    }
}

fn serve(store: Shared, socket: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    let mut raw = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut raw)?;
    }
    let body: Value = if raw.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&raw).unwrap_or_else(|_| json!({}))
    };

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let response = handle(store, &method, &path, &query, &body);
    let text = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
    let mut socket = socket;
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        text.as_bytes().len(),
        text
    )?;
    socket.flush()
}

fn query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn spawn_poll(store: &Shared) {
    let store = Arc::clone(store);
    std::thread::spawn(move || {
        let node = Node::new(store);
        node.poll();
    });
}

/// Die Oberflaeche ist zugesperrt. Das ist Briars Bildschirmsperre, nicht das
/// Siegel des Speichers: der Schluessel bleibt im Dienst, der Abgleich laeuft
/// weiter und Nachrichten kommen an -- nur herzeigen tut die App nichts mehr,
/// bis das Passwort wieder da ist. Genau so haelt es Briar (pref_key_lock).
///
/// Absichtlich nicht gespeichert: nach einem Neustart des Dienstes ist der
/// Speicher ohnehin versiegelt, und dann fragt entsperren.rs.
static GESPERRT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Die Marke, mit der die Oberflaeche wieder aufsperren darf, ohne das
/// Passwort zu kennen.
///
/// Gedacht fuer den Fingerabdruck: an der Jolla sperrt Briar auf Android mit
/// dem Bildschirmschloss des Telefons auf, nicht mit dem Briar-Passwort. Das
/// geht hier auch (org.nemomobile.devicelock), nur weiss der Dienst nichts
/// davon, ob jemand seinen Finger aufgelegt hat -- also bekommt die App beim
/// Zusperren eine einmalige Marke, die sie nach geglueckter Pruefung
/// zurueckgibt.
///
/// Sie liegt nur im Arbeitsspeicher, gilt nur fuer dieses eine Zusperren und
/// ist nach dem Aufsperren verbraucht. Mit ihr laesst sich die Datei nicht
/// entschluesseln: sie oeffnet nur die Oberflaeche, die der Dienst ohnehin
/// schon offen haelt.
static MARKE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// Wann zuletzt etwas ueber die Schnittstelle kam -- fuer die Sperre nach Zeit.
static LETZTE_REGUNG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn ist_gesperrt() -> bool {
    GESPERRT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn sperren() {
    GESPERRT.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::net::log("die Oberflaeche ist zugesperrt");
}

/// Beim Zusperren von selbst gibt es keine Marke: niemand steht davor, der sie
/// entgegennehmen koennte. Dann hilft nur das Passwort -- so wie bei Briar,
/// wo nach der Frist ebenfalls das Bildschirmschloss verlangt wird.
fn marke_verwerfen() {
    *MARKE.lock().unwrap() = None;
}

fn regung_vermerken() {
    LETZTE_REGUNG.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
}

/// Der Waechter fuer die Sperre nach Zeit. Er schaut jede halbe Minute nach;
/// genauer muss es nicht sein, und haeufiger waere auf dem N9 Strom fuer
/// nichts.
pub fn sperrwaechter(store: Shared) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let frist = {
            let locked = match store.lock() {
                Ok(l) => l,
                Err(_) => continue,
            };
            locked.state.sperre_nach_minuten
        };
        if frist == 0 || ist_gesperrt() {
            continue;
        }
        let zuletzt = LETZTE_REGUNG.load(std::sync::atomic::Ordering::Relaxed);
        if zuletzt > 0 && now_ms().saturating_sub(zuletzt) > frist * 60_000 {
            marke_verwerfen();
            sperren();
        }
    });
}

/// Alles loeschen, was zu diesem Konto gehoert, und den Dienst beenden.
///
/// Beim naechsten Start findet er keine Datei und faengt bei null an -- ohne
/// Passwort, ohne Kontakte. Das ist auch der Weg heraus, wenn jemand sein
/// Passwort vergessen hat: dort gibt es sonst keinen.
pub fn konto_loeschen(pfad: &std::path::Path) {
    let ordner = pfad.parent().map(|p| p.to_path_buf());
    let _ = std::fs::remove_file(pfad);
    if let Some(ordner) = ordner {
        let _ = std::fs::remove_dir_all(ordner.join("attachments"));
        let _ = std::fs::remove_dir_all(ordner.join("tor"));
    }
    crate::net::log("das Konto wurde geloescht -- der Dienst beendet sich");
    // Nicht bloss den Speicher leeren: die Schluessel liegen auch im
    // Arbeitsspeicher, und der Tor-Dienst laeuft noch. Ein Ende raeumt beides.
    std::process::exit(0);
}

fn handle(store: Shared, method: &str, path: &str, query: &str, body: &Value) -> Value {
    regung_vermerken();
    // Solange zugesperrt ist, geht nur das Noetigste: nachsehen, aufsperren,
    // und das Konto loeschen (fuer den Fall eines vergessenen Passworts).
    if ist_gesperrt()
        && !matches!(
            (method, path),
            ("GET", "/status") | ("POST", "/unlock") | ("POST", "/account/delete")
        )
    {
        return json!({"error": "gesperrt", "locked": true});
    }
    match (method, path) {
        ("GET", "/status") => status(&store),

        // Zusperren wie Briars Bildschirmsperre: der Abgleich laeuft weiter,
        // die Oberflaeche zeigt nichts mehr.
        ("POST", "/lock") => {
            let verschluesselt = store.lock().unwrap().verschluesselt();
            if !verschluesselt {
                // Ohne Passwort waere die Sperre eine Tuer ohne Schloss: jeder
                // Aufruf von /unlock ohne Passwort wuerde sie oeffnen.
                return json!({"error": "set a password first"});
            }
            sperren();
            let marke = to_hex(&crate::util::random(16));
            *MARKE.lock().unwrap() = Some(marke.clone());
            json!({"ok": true, "locked": true, "token": marke})
        }

        // Aufsperren, wenn nur die Oberflaeche zu ist. Ist der Speicher selbst
        // versiegelt, laeuft dieser Dienst gar nicht -- dann antwortet
        // entsperren.rs auf denselben Weg.
        ("POST", "/unlock") => {
            // Zwei Wege herein: das Passwort, oder die Marke vom Zusperren --
            // die gibt die Oberflaeche erst zurueck, wenn das Telefon selbst
            // den Benutzer erkannt hat (Fingerabdruck oder Gerätecode).
            let marke = body["token"].as_str().unwrap_or("");
            let stimmt = if !marke.is_empty() {
                let mut gemerkt = MARKE.lock().unwrap();
                let passt = gemerkt.as_deref() == Some(marke) && !marke.is_empty();
                if passt {
                    // Einmalig: verbraucht ist verbraucht.
                    *gemerkt = None;
                }
                passt
            } else {
                let passwort = body["password"].as_str().unwrap_or("");
                let locked = store.lock().unwrap();
                locked.passwort_stimmt(passwort)
            };
            if !stimmt {
                return json!({"error": "falsches Passwort"});
            }
            GESPERRT.store(false, std::sync::atomic::Ordering::Relaxed);
            regung_vermerken();
            crate::net::log("aufgesperrt");
            json!({"ok": true, "locked": false})
        }

        // Wie lange ohne Regung, bis von selbst zugesperrt wird. 0 heisst nie.
        ("POST", "/lockafter") => {
            let minuten = body["minutes"].as_u64().unwrap_or(0);
            let mut locked = store.lock().unwrap();
            locked.state.sperre_nach_minuten = minuten;
            let _ = locked.save();
            json!({"ok": true, "minutes": minuten})
        }

        // Nachrichten loeschen -- eine einzelne oder das ganze Gespraech.
        // Rein oertlich: die Gegenseite behaelt ihre Kopie, wie bei Briar
        // ("delete messages" loescht nur hier). Der Anhang geht mit, sonst
        // bliebe das Bild auf der Platte, das man gerade weghaben wollte.
        ("POST", "/message/delete") => {
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let alle = body["all"].as_bool().unwrap_or(false);
            let kennung = body["id"].as_str().unwrap_or("").to_string();
            // Mehrere auf einmal, wie Briars Auswahlmodus: eine Liste von
            // Kennungen. Einzeln geht weiter ueber "id".
            let liste: std::collections::BTreeSet<String> = body["ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let mut locked = store.lock().unwrap();
            // Je Nachricht ihre Kennung und ALLE ihre Anhaenge -- bis 0.29.2
            // blieb alles ausser dem ersten als verwaiste Datei liegen.
            let betroffen: Vec<(String, Vec<String>)> = match locked.contact(contact_id) {
                Some(c) => c
                    .messages
                    .iter()
                    .filter(|m| alle || m.id == kennung || liste.contains(&m.id))
                    .map(|m| {
                        let mut anhaenge: Vec<String> =
                            m.anhaenge.iter().map(|k| k.id.clone()).collect();
                        if anhaenge.is_empty() {
                            if let Some(a) = &m.attachment {
                                anhaenge.push(a.clone());
                            }
                        }
                        (m.id.clone(), anhaenge)
                    })
                    .collect(),
                None => return json!({"error": "no such contact"}),
            };
            if betroffen.is_empty() {
                return json!({"error": "no such message"});
            }
            let ids: std::collections::BTreeSet<String> =
                betroffen.iter().map(|(id, _)| id.clone()).collect();
            // Erst die Anhaenge, dann die Eintraege: nach dem Streichen wuesste
            // niemand mehr, welche Datei gemeint war.
            for (_, anhaenge) in &betroffen {
                for anhang in anhaenge {
                    locked.anhang_loeschen(anhang);
                }
            }
            if let Some(c) = locked.contact_mut(contact_id) {
                c.messages.retain(|m| !ids.contains(&m.id));
                // Was noch nicht hinaus ist, geht auch nicht mehr hinaus.
                c.outbox.retain(|m| !ids.contains(&m.id));
            }
            let _ = locked.save();
            json!({"ok": true, "removed": ids.len()})
        }

        // Nebeneinander hinzufuegen, wie Briar es tut (BQP).
        //
        // Zwei Schritte: erst den eigenen Code zeigen -- dabei entsteht ein
        // fluechtiges Schluesselpaar und ein Lauscher --, dann den Code der
        // Gegenseite lesen. Beide Geraete tun beides; wer zuerst durchkommt,
        // gewinnt, der andere Versuch laeuft ins Leere.
        ("POST", "/bqp/start") => {
            let node = net::Node::new(Arc::clone(&store));
            match node.bqp_start() {
                Ok(rumpf) => json!({"ok": true, "payload": to_hex(&rumpf)}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/bqp/scan") => {
            let rumpf = match from_hex(body["payload"].as_str().unwrap_or("")) {
                Some(r) => r,
                None => return json!({"error": "der Code ist nicht lesbar"}),
            };
            let node = net::Node::new(Arc::clone(&store));
            // Nebenher: das Anwaehlen kann bis zu einer Minute dauern, und die
            // Oberflaeche soll derweil weiterlaufen. Ob es geglueckt ist, sagt
            // die naechste Statusabfrage -- der Kontakt steht dann in der Liste.
            std::thread::spawn(move || match node.bqp_gelesen(rumpf) {
                Ok(id) => crate::net::log(&format!("BQP: Kontakt {} steht", id)),
                Err(e) => crate::net::log(&format!("BQP: gescheitert: {}", e)),
            });
            json!({"ok": true})
        }

        // Verschwindende Nachrichten fuer einen Kontakt einstellen. Die
        // Dauer steht in Millisekunden; 0 oder -1 schaltet sie ab. Sie geht
        // nicht als eigene Nachricht hinaus, sondern faehrt in der naechsten
        // Privatnachricht mit -- so macht es Briar auch.
        ("POST", "/autodelete") => {
            let Some(id) = body["contact"].as_u64() else {
                return json!({"error": "no contact given"});
            };
            let dauer = body["timer"].as_i64().unwrap_or(-1);
            let dauer = if dauer <= 0 {
                crate::store::kein_timer()
            } else if !(crate::store::MIN_LOESCHDAUER_MS..=crate::store::MAX_LOESCHDAUER_MS)
                .contains(&dauer)
            {
                return json!({"error": "the timer must be between a minute and a year"});
            } else {
                dauer
            };
            let mut locked = store.lock().unwrap();
            match locked.contact_mut(id as u32) {
                Some(contact) => {
                    if contact.loesch_timer != dauer {
                        // Die vorige Dauer merken, solange die Aenderung noch
                        // in keiner Nachricht draussen war -- daran entscheidet
                        // sich, wessen Aenderung gilt, wenn beide gleichzeitig
                        // umstellen.
                        contact.loesch_vorher = contact.loesch_timer;
                        contact.loesch_timer = dauer;
                    }
                    let _ = locked.save();
                    json!({"ok": true, "timer": dauer})
                }
                None => json!({"error": "no such contact"}),
            }
        }

        ("POST", "/bqp/stop") => {
            net::Node::bqp_stop();
            json!({"ok": true})
        }

        ("POST", "/account/delete") => {
            let pfad = store.lock().unwrap().path.clone();
            konto_loeschen(&pfad);
            json!({"ok": true})
        }

        // Die vier Wege der Nachrichtenbrücke (siehe unten).
        ("GET", "/chats") => {
            let locked = store.lock().unwrap();
            let mut chats: Vec<Value> = locked
                .state
                .contacts
                .iter()
                .map(|c| {
                    let last = c.messages.last();
                    json!({
                        "jid": format!("c{}", c.id),
                        "name": c.name,
                        "isGroup": false,
                        "lastMessage": last.map(|m| m.text.clone()).unwrap_or_default(),
                        "lastTime": last.map(|m| m.timestamp).unwrap_or(0),
                        "fromMe": last.map(|m| m.outgoing).unwrap_or(false),
                    })
                })
                .collect();
            for group in locked.state.groups.iter().filter(|g| g.joined) {
                let last = group.messages.iter().filter(|m| !m.join).last();
                chats.push(json!({
                    "jid": format!("g{}", group.id),
                    "name": group.name,
                    "isGroup": true,
                    "lastMessage": last.map(|m| m.text.clone()).unwrap_or_default(),
                    "lastTime": last.map(|m| m.timestamp).unwrap_or(0),
                    "fromMe": false,
                }));
            }
            Value::Array(chats)
        }

        // Dieselben Pfade wie bei den anderen Diensten: die Brücke fragt
        // /messages?jid=... und /send?to=...&text=... ab (GET), die eigene
        // Oberfläche /messages?contact=... und POST /send.
        ("GET", "/send") => {
            let to = query_value(query, "to").unwrap_or_default();
            let text = query_value(query, "text").unwrap_or_default();
            bridge_send(&store, &to, &text)
        }

        ("GET", "/events") => {
            // Lange Abfrage: kehrt zurück, sobald sich am Zustand etwas
            // getan hat -- die Brücke hängt daran statt zu pollen.
            let since = query_value(query, "since")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut revision = store.lock().unwrap().state.revision;
            for _ in 0..70 {
                if revision != since {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                revision = store.lock().unwrap().state.revision;
            }
            json!({"seq": revision})
        }

        ("POST", "/identity") => {
            let name = body["name"].as_str().unwrap_or("").trim().to_string();
            // In UTF-8-Bytes, nicht in Zeichen -- Briar misst so, und ein
            // Name mit Umlauten ist sonst laenger als er aussieht.
            if name.len() > crate::sync::MAX_AUTHOR_NAME_LEN {
                return json!({"error": format!(
                    "the name is {} bytes long, at most {} are allowed -- it is part of your identifier and cannot be changed later",
                    name.len(), crate::sync::MAX_AUTHOR_NAME_LEN)});
            }
            if name.is_empty() {
                return json!({"error": "name is empty"});
            }
            let mut locked = store.lock().unwrap();
            if locked.identity().is_some() {
                return json!({"error": "identity already exists"});
            }
            match locked.create_identity(&name) {
                Ok(_) => {
                    drop(locked);
                    status(&store)
                }
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/pending") => {
            let link = body["link"].as_str().unwrap_or("").to_string();
            let alias = body["alias"].as_str().unwrap_or("").to_string();
            let address = body["address"]
                .as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let bluetooth = body["bluetooth"]
                .as_str()
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty());
            let onion = body["onion"]
                .as_str()
                .map(|s| s.trim().trim_end_matches(".onion").to_lowercase())
                .filter(|s| !s.is_empty());
            let public_key = match crate::ids::parse_handshake_link(&link) {
                Some(k) => k,
                None => return json!({"error": "not a briar:// link"}),
            };
            {
                let mut locked = store.lock().unwrap();
                if locked.identity().is_none() {
                    return json!({"error": "create an identity first"});
                }
                let own = locked
                    .identity()
                    .map(|i| key_from_hex(&i.handshake_public))
                    .unwrap_or([0u8; 32]);
                if own == public_key {
                    return json!({"error": "that is your own link"});
                }
                let hex = to_hex(&public_key);
                if locked.state.pending.iter().any(|p| p.public_key == hex)
                    || locked
                        .state
                        .contacts
                        .iter()
                        .any(|c| c.handshake_public.as_deref() == Some(hex.as_str()))
                {
                    return json!({"error": "that contact is already known"});
                }
                locked.state.pending.push(PendingContact {
                    public_key: hex,
                    alias,
                    address,
                    bluetooth,
                    onion,
                    added: now_ms(),
                    last_error: None,
                    transports: BTreeMap::new(),
                });
                if let Err(e) = locked.save() {
                    return json!({"error": e.to_string()});
                }
            }
            spawn_poll(&store);
            status(&store)
        }

        ("POST", "/send") => {
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let text = body["text"].as_str().unwrap_or("").to_string();
            if text.len() > crate::sync::MAX_PRIVATE_MESSAGE_TEXT_LEN {
                return json!({"error": format!(
                    "the message is {} bytes long, at most {} are allowed",
                    text.len(), crate::sync::MAX_PRIVATE_MESSAGE_TEXT_LEN)});
            }
            let file = body["file"].as_str().map(|s| s.to_string());
            if text.trim().is_empty() && file.is_none() {
                return json!({"error": "message is empty"});
            }
            {
                let mut locked = store.lock().unwrap();
                let group = match net::messaging_group_for(&locked, contact_id) {
                    Some(g) => g,
                    None => return json!({"error": "no such contact"}),
                };
                let mut attachments: Vec<(crate::crypto::SecretKey, String)> = Vec::new();
                if let Some(path) = file {
                    let data = match std::fs::read(&path) {
                        Ok(d) => d,
                        Err(e) => return json!({"error": format!("{}: {}", path, e)}),
                    };
                    let content_type = body["contentType"]
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| guess_content_type(&path));
                    let capacity = crate::sync::attachment_capacity(&content_type);
                    if data.len() > capacity {
                        // Briar puts an attachment in a single message, and a
                        // message body cannot grow past 32 KiB. That is why
                        // Briar compresses images before sending them.
                        return json!({
                            "error": format!(
                                "the file is {} bytes, at most {} fit in one message",
                                data.len(), capacity),
                            "maxSize": capacity,
                        });
                    }
                    let attachment_body = crate::sync::attachment_body(&content_type, &data);
                    let timestamp = now_ms();
                    let attachment_id =
                        crate::ids::message_id(&group, timestamp, &attachment_body);
                    let hex = to_hex(&attachment_id);
                    if let Err(e) = locked.store_attachment(&hex, &content_type, &data) {
                        return json!({"error": e.to_string()});
                    }
                    locked.queue(
                        contact_id,
                        OutMessage {
                            id: hex,
                            group: to_hex(&group),
                            timestamp,
                            body: to_hex(&attachment_body),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    attachments.push((attachment_id, content_type));
                }
                // Der Zeitstempel muss ueber dem liegen, den die Gegenseite
                // zuletzt von uns gesehen hat -- sonst zaehlt unsere
                // Zuenddauer drueben nicht.
                //
                // Briar verwirft eine gemeldete Dauer, deren Zeitstempel nicht
                // groesser ist als der zuletzt gespeicherte
                // (AutoDeleteManagerImpl.receiveAutoDeleteTimer: "if (timestamp
                // <= oldTimestamp) return"). Geht unsere Uhr nach -- auf N9 und
                // N950 laeuft sie ohne Zeitdienst --, traegt jede Nachricht
                // einen kleineren Stempel als die vorige der Gegenseite, und
                // unsere Einstellung kaeme drueben nie an. Die Uhr wird dafuer
                // nicht verstellt, nur dieser eine Wert vorgerueckt.
                let timestamp = {
                    let zuletzt = locked
                        .contact(contact_id)
                        .map(|c| c.loesch_stempel)
                        .unwrap_or(0);
                    now_ms().max(zuletzt.saturating_add(1))
                };
                // Die Zuenddauer faehrt mit -- ausser die Gegenseite hat
                // ausdruecklich eine aeltere Nebenfassung angesagt. Wir sagen
                // 3 an, also erwartet Briar sie von uns; eine dreigliedrige
                // Nachricht liest es als "keine Dauer" und spiegelt sie
                // zurueck.
                let dauer = {
                    let kann = locked
                        .contact(contact_id)
                        .map(|c| c.darf_zuenddauer_bekommen())
                        .unwrap_or(false);
                    let t = locked.contact(contact_id).map(|c| c.loesch_timer).unwrap_or(-1);
                    if kann && t > 0 {
                        Some(t as u64)
                    } else {
                        None
                    }
                };
                if let Some(c) = locked.contact_mut(contact_id) {
                    // Die Aenderung ist jetzt draussen.
                    c.loesch_stempel = timestamp;
                    c.loesch_vorher = crate::store::keine_vorige();
                }
                let message_body = crate::sync::private_message_body_with(
                    if text.trim().is_empty() { None } else { Some(text.trim()) },
                    &attachments,
                    dauer,
                );
                let message_id = crate::ids::message_id(&group, timestamp, &message_body);
                let hex = to_hex(&message_id);
                locked.add_message(
                    contact_id,
                    crate::store::Message {
                        id: hex.clone(),
                        timestamp,
                        text: text.trim().to_string(),
                        outgoing: true,
                        acked: false,
                        attachment: attachments.first().map(|(id, _)| to_hex(id)),
                        attachment_type: attachments.first().map(|(_, t)| t.clone()),
                        anhaenge: attachments
                            .iter()
                            .map(|(id, t)| crate::store::Anhangskopf {
                                id: to_hex(id),
                                content_type: Some(t.clone()),
                            })
                            .collect(),
                        loesch_dauer: dauer,
                        loesch_frist: None,
                    },
                );
                locked.queue(
                    contact_id,
                    OutMessage {
                        id: hex,
                        group: to_hex(&group),
                        timestamp,
                        body: to_hex(&message_body),
                        acked: false,
                        intern: false,
                        loesch_dauer: dauer,
                    },
                );
                if let Err(e) = locked.save() {
                    return json!({"error": e.to_string()});
                }
            }
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                if let Err(e) = node.reach_contact(contact_id) {
                    net::log(&format!("sending to contact {} failed: {}", contact_id, e));
                }
            });
            json!({"ok": true})
        }

        ("GET", "/messages") if query_value(query, "jid").is_some() => {
            bridge_messages(&store, query)
        }

        ("GET", "/messages") => {
            let contact_id = query_value(query, "contact")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let locked = store.lock().unwrap();
            match locked.contact(contact_id) {
                Some(contact) => json!({
                    "contact": contact.id,
                    "name": contact.name,
                    "messages": contact.messages.iter().map(|m| {
                        let attachment = m.attachment.as_ref()
                            .and_then(|id| locked.attachment(id));
                        // Alle Anhaenge -- die vier Felder darueber nennen
                        // weiterhin den ersten, damit eine aeltere Oberflaeche
                        // unveraendert weiterlaeuft.
                        let anhaenge: Vec<Value> = m.anhaenge.iter().map(|kopf| {
                            let datei = locked.attachment(&kopf.id);
                            json!({
                                "id": kopf.id,
                                "type": kopf.content_type,
                                "path": datei.map(|a| a.path.clone()),
                                "size": datei.map(|a| a.size),
                            })
                        }).collect();
                        json!({
                            "id": m.id,
                            "timestamp": m.timestamp,
                            "text": m.text,
                            "outgoing": m.outgoing,
                            "acked": m.acked,
                            "attachment": m.attachment,
                            "attachmentType": m.attachment_type,
                            "attachmentPath": attachment.map(|a| a.path.clone()),
                            "attachmentSize": attachment.map(|a| a.size),
                            "attachments": anhaenge,
                            // Verschwindende Nachricht: die Dauer und, wenn
                            // die Uhr schon laeuft, der Zeitpunkt.
                            "autoDelete": m.loesch_dauer,
                            "deleteAt": m.loesch_frist,
                        })
                    }).collect::<Vec<Value>>(),
                    "autoDelete": contact.loesch_timer,
                    "autoDeleteReady": contact.zuenddauer_bestaetigt(),
                }),
                None => json!({"error": "no such contact"}),
            }
        }

        ("POST", "/connect") => {
            let contact_id = body["contact"].as_u64().map(|v| v as u32);
            let address = body["address"].as_str().map(|s| s.trim().to_string());
            let bluetooth = body["bluetooth"].as_str().map(|s| s.trim().to_uppercase());
            if let Some(id) = contact_id {
                let mut locked = store.lock().unwrap();
                if let Some(contact) = locked.contact_mut(id) {
                    if let Some(address) = address.filter(|a| !a.is_empty()) {
                        contact.transport_mut(LAN_TRANSPORT_ID).address = Some(address);
                    }
                    if let Some(address) = bluetooth.filter(|a| !a.is_empty()) {
                        contact.transport_mut(BLUETOOTH_TRANSPORT_ID).address = Some(address);
                    }
                    if let Some(address) = body["onion"].as_str().map(|s| s.trim().to_string())
                        .filter(|a| !a.is_empty())
                    {
                        contact.transport_mut(TOR_TRANSPORT_ID).address = Some(address);
                    }
                }
                let _ = locked.save();
            }
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                match contact_id {
                    Some(id) => {
                        if let Err(e) = node.reach_contact(id) {
                            net::log(&format!("connecting to contact {} failed: {}", id, e));
                        }
                    }
                    None => {
                        node.poll();
                    }
                }
            });
            json!({"ok": true})
        }

        ("POST", "/poll") => {
            spawn_poll(&store);
            json!({"ok": true})
        }

        // Einen wartenden Kontakt streichen -- eigener Weg, nicht /remove: dort
        // steht eine Kontaktnummer, hier der oeffentliche Schluessel, denn
        // eine Nummer bekommt ein Wartender erst mit dem Handschlag.
        ("POST", "/pending/remove") => {
            let public_key = body["publicKey"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if public_key.is_empty() {
                return json!({"error": "no publicKey given"});
            }
            let mut locked = store.lock().unwrap();
            let vorher = locked.state.pending.len();
            locked.state.pending.retain(|p| p.public_key != public_key);
            let entfernt = locked.state.pending.len() < vorher;
            if entfernt {
                let _ = locked.save();
            }
            drop(locked);
            // Den Treffpunkt raeumt run_rendezvous von selbst ab: es leitet
            // sein Soll in jeder Runde neu aus den Wartenden ab und nimmt
            // herunter, was daraus verschwunden ist.
            //
            // Kein Fehler, wenn nichts da war: dann ist der Handschlag
            // wahrscheinlich gerade geglueckt, und der Eintrag steht schon
            // als Kontakt in derselben Antwort.
            let mut antwort = status(&store);
            antwort["removed"] = json!(entfernt);
            antwort
        }

        ("POST", "/remove") => {
            let contact_id = match body["contact"].as_u64() {
                Some(id) => id as u32,
                None => return json!({"error": "no contact given"}),
            };
            let mut locked = store.lock().unwrap();
            locked.state.contacts.retain(|c| c.id != contact_id);
            for group in locked.state.groups.iter_mut() {
                group.contacts.retain(|c| *c != contact_id);
            }
            let _ = locked.save();
            drop(locked);
            status(&store)
        }

        ("POST", "/tor") => {
            let on = body["enabled"].as_bool().unwrap_or(true);
            let mut locked = store.lock().unwrap();
            locked.state.tor = on;
            if !on {
                // The address stops being reachable the moment Tor goes.
                locked.state.tor_onion = None;
            }
            let _ = locked.save();
            drop(locked);
            // No restart needed: the supervisor picks the switch up within
            // a few seconds, and stops Tor again when it is switched off.
            status(&store)
        }

        ("POST", "/read") => {
            let mut locked = store.lock().unwrap();
            let now = now_ms();
            if let Some(id) = body["contact"].as_u64() {
                let id = id as u32;
                if let Some(contact) = locked.contact_mut(id) {
                    contact.last_read = now;
                    // Gelesen heisst: die Uhr einer verschwindenden Nachricht
                    // laeuft. Briar macht es an derselben Stelle
                    // (ConversationManagerImpl.setReadFlag).
                    for m in contact.messages.iter_mut() {
                        if !m.outgoing {
                            net::loeschuhr_starten(m, now);
                        }
                    }
                }
                let _ = locked.save();
                drop(locked);
                close_notification(&id.to_string());
            } else if let Some(group) = body["group"].as_str() {
                let group = group.to_string();
                if let Some(entry) = locked.group_mut(&group) {
                    entry.last_read = now;
                    // Die Antwort der Gegenseite ist gesehen, sobald die Gruppe
                    // offen war. Sonst stuende "hat abgelehnt" fuer immer in der
                    // Liste und verdeckte den letzten Beitrag.
                    entry.letztes_ereignis = None;
                }
                let _ = locked.save();
                drop(locked);
                close_notification(&group);
            } else {
                drop(locked);
            }
            status(&store)
        }

        // Passwort setzen, aendern oder entfernen. Ein leeres Passwort hebt
        // die Verschluesselung auf -- das soll gehen, sonst waere ein
        // vergessenes Passwort bei noch laufendem Dienst eine Sackgasse.
        ("POST", "/password") => {
            let alt = body["old"].as_str();
            let passwort = body["password"].as_str().unwrap_or("");
            let mut locked = store.lock().unwrap();
            match locked.passwort_setzen(alt, passwort) {
                Ok(()) => json!({"ok": true, "encrypted": locked.verschluesselt()}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/language") => {
            let language = body["language"].as_str().unwrap_or("en");
            let mut locked = store.lock().unwrap();
            locked.state.language = Some(if language.starts_with("de") {
                "de".to_string()
            } else {
                "en".to_string()
            });
            let _ = locked.save();
            drop(locked);
            status(&store)
        }

        ("POST", "/bluetooth") => {
            let on = body["enabled"].as_bool().unwrap_or(true);
            let mut locked = store.lock().unwrap();
            locked.state.bluetooth = on;
            let _ = locked.save();
            json!({"ok": true, "restart": true})
        }

        // --- private groups ------------------------------------------------
        ("GET", "/groups") => {
            let locked = store.lock().unwrap();
            json!({"groups": locked
                .state
                .groups
                .iter()
                .map(|g| group_json(&locked, g))
                .collect::<Vec<Value>>()})
        }

        ("POST", "/group") => {
            let name = body["name"].as_str().unwrap_or("").trim().to_string();
            if name.len() > crate::sync::MAX_GROUP_NAME_LEN {
                return json!({"error": format!(
                    "the group name is {} bytes long, at most {} are allowed",
                    name.len(), crate::sync::MAX_GROUP_NAME_LEN)});
            }
            if name.is_empty() {
                return json!({"error": "the group needs a name"});
            }
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let salt = crate::util::random(groups::SALT_LEN);
            let group_id = groups::group_id(&author, &name, &salt);
            let group_hex = to_hex(&group_id);
            let author_id = to_hex(&author.id());
            let mut member_names = BTreeMap::new();
            member_names.insert(author_id.clone(), author.name.clone());
            let mut group = PrivateGroup {
                id: group_hex.clone(),
                name: name.clone(),
                salt: to_hex(&salt),
                creator_name: author.name.clone(),
                creator_public: to_hex(&author.public_key),
                creator_author_id: author_id.clone(),
                joined: true,
                invited_by: None,
                invite_timestamp: None,
                invite_signature: None,
                member_names,
                last_read: 0,
                messages: Vec::new(),
                our_previous: None,
                einladungen: BTreeMap::new(),
                einladung_previous: None,
                aufgeloest: false,
                letztes_ereignis: None,
                contacts: Vec::new(),
            };
            // The creator's own join message starts its chain.
            let timestamp = now_ms();
            let join = groups::join_body(&group_id, timestamp, &author, &seed, None);
            let join_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &join));
            group.messages.push(GroupPost {
                id: join_id.clone(),
                author_id,
                author_name: author.name.clone(),
                timestamp,
                text: String::new(),
                body: to_hex(&join),
                join: true,
            });
            group.our_previous = Some(join_id);
            locked.state.groups.push(group);
            let _ = locked.save();
            drop(locked);
            json!({"ok": true, "group": group_hex})
        }

        ("POST", "/group/invite") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let our_author_id = author.id();
            let (group_id, name, salt, creator_author_id, is_creator) =
                match locked.group(&group_hex) {
                    Some(g) => (
                        key_from_hex(&g.id),
                        g.name.clone(),
                        from_hex(&g.salt).unwrap_or_default(),
                        key_from_hex(&g.creator_author_id),
                        g.creator_author_id == to_hex(&our_author_id),
                    ),
                    None => return json!({"error": "no such group"}),
                };
            if !is_creator {
                // Briar lets only the creator invite, and a member's join
                // message has to carry the creator's signature.
                return json!({"error": "only the group's creator can invite"});
            }
            let their_author_id = match locked.contact(contact_id) {
                Some(c) => c.author_id_bytes(),
                None => return json!({"error": "no such contact"}),
            };
            // Zweimal einladen ist in Briar ein Zustandsfehler (onInviteAction
            // wirft in INVITED, JOINED und LEFT). Hier kostet es mehr als dort:
            // die zweite Einladung traegt eine andere Kennung, die Gegenseite
            // hat die Gruppe schon und wirft sie weg -- der Benutzer sieht
            // nichts und tippt weiter. Das ist auch der Grund, warum wir eine
            // doppelte Einladung beim Empfaenger NICHT abbrechen: hier ist der
            // Ort, wo sie gar nicht entsteht.
            let (schon_drin, sitzungszustand) = match locked.group(&group_hex) {
                Some(g) => (
                    g.messages
                        .iter()
                        .any(|m| m.join && m.author_id == to_hex(&their_author_id)),
                    g.einladungen.get(&contact_id).map(|s| s.zustand),
                ),
                None => (false, None),
            };
            if schon_drin || sitzungszustand == Some(crate::store::Sitzungszustand::Beigetreten) {
                return json!({"error": "the contact is already in this group"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Eingeladen) {
                return json!({"error": "an invitation is already on its way"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Fehler) {
                // In ERROR nimmt Briar nichts mehr an; eine Einladung ginge in
                // eine Sitzung, die auf beiden Seiten abgebrochen ist.
                return json!({"error": "the invitation session with this contact has failed"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Gegangen) {
                // Seine Beitrittsnachricht steht noch in der Gruppe. Ein
                // zweiter Beitritt wuerde seine Kette gabeln, und die Gruppe
                // prueft genau die.
                return json!({"error": "the contact has left this group"});
            }
            // Echt spaeter als alles, was in dieser Sitzung schon lief.
            let timestamp = locked
                .sitzung(&group_hex, contact_id)
                .map(|s| s.naechster_zeitstempel())
                .unwrap_or_else(now_ms);
            let signature = groups::invite_signature(
                &seed,
                &creator_author_id,
                &their_author_id,
                &group_id,
                timestamp,
            );
            let invite = groups::invite_body(&author, &name, &salt, None, &signature);
            let invite_group = groups::invite_group_id(&our_author_id, &their_author_id);
            let invite_id = crate::ids::message_id(&invite_group, timestamp, &invite);
            locked.queue(
                contact_id,
                OutMessage {
                    id: to_hex(&invite_id),
                    group: to_hex(&invite_group),
                    timestamp,
                    body: to_hex(&invite),
                    acked: false,
                    intern: false,
                    loesch_dauer: None,
                },
            );
            // Die Kennung DIESER INVITE ist der erste Anker der Kette zu
            // DIESEM Kontakt: unser spaeteres JOIN nennt sie als vorige
            // Nachricht (CreatorProtocolEngine.onRemoteAccept ->
            // sendJoinMessage mit s.getLastLocalMessageId()). Bisher wurde sie
            // berechnet und weggeworfen, und damit war die Kette kopflos.
            if let Some(s) = locked.sitzung_mut(&group_hex, contact_id) {
                s.letzte_eigene = Some(to_hex(&invite_id));
                s.eigener_zeitstempel = timestamp;
                s.einladungs_zeitstempel = timestamp;
                s.zustand = crate::store::Sitzungszustand::Eingeladen;
            }
            // Den Verlauf der Gruppe bekommt die Eingeladene NICHT schon jetzt,
            // sondern erst mit ihrer Zusage (net.rs, receive_einladung_join).
            //
            // Vorher ging er sofort hinaus. Bei einem echten Briar existiert die
            // Gruppe vor der Zusage aber gar nicht, sie gilt als unsichtbar --
            // und in einer unsichtbaren Gruppe wird jede Nachricht verworfen UND
            // nicht quittiert. Der Korb haette also den ganzen Verlauf in jeder
            // Runde erneut geschickt, bis sie zusagt, und fuer immer, wenn sie
            // nie antwortet.
            if let Some(group) = locked.group_mut(&group_hex) {
                if !group.contacts.contains(&contact_id) {
                    group.contacts.push(contact_id);
                }
            }
            let _ = locked.save();
            drop(locked);
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                let _ = node.reach_contact(contact_id);
            });
            json!({"ok": true})
        }

        ("POST", "/group/join") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let (group_id, invite, contacts, already) = match locked.group(&group_hex) {
                Some(g) => {
                    let invite = match (g.invite_timestamp, g.invite_signature.clone()) {
                        (Some(t), Some(s)) => Some((t, from_hex(&s).unwrap_or_default())),
                        _ => None,
                    };
                    (key_from_hex(&g.id), invite, g.contacts.clone(), g.joined)
                }
                None => return json!({"error": "no such group"}),
            };
            if already {
                return json!({"error": "already joined"});
            }
            // Eine Einladung, die nicht mehr gilt: der Ersteller ist gegangen
            // (Briars onRemoteLeaveWhenNotSubscribed macht sie unbeantwortbar)
            // oder die Sitzung ist zerrissen. Beitreten wuerde eine Gruppe
            // anlegen, die niemand mehr haelt, und ein JOIN an jemanden
            // schicken, der uns nicht mehr zuhoert.
            let hinfaellig = match locked.group(&group_hex) {
                Some(g) => {
                    g.aufgeloest
                        || g.invited_by
                            .and_then(|c| g.einladungen.get(&c))
                            .map(|s| s.zustand == crate::store::Sitzungszustand::Fehler)
                            .unwrap_or(false)
                }
                None => false,
            };
            if hinfaellig {
                return json!({"error": "this invitation is no longer valid"});
            }
            // Das JOIN muss echt hinter der Einladung liegen. Sonst erklaert
            // Briars GroupMessageValidator es fuer ungueltig, und die Sitzung
            // des Einladenden bricht bei unserer Antwort in der
            // Einladungsgruppe ab, statt die Gruppe zu teilen -- wir waeren
            // formal beigetreten und bekaemen doch nie einen Beitrag. Die Uhr
            // des N9 geht gern nach, dann liegt eine Einladung von der Jolla
            // in unserer Zukunft.
            let einladung_zeit = invite.as_ref().map(|(t, _)| *t).unwrap_or(0);
            let timestamp = groups::vorgerueckt(now_ms(), einladung_zeit);
            let join = groups::join_body(&group_id, timestamp, &author, &seed, invite);
            let join_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &join));
            let author_id = to_hex(&author.id());
            if let Some(group) = locked.group_mut(&group_hex) {
                group.joined = true;
                group.our_previous = Some(join_id.clone());
                group
                    .member_names
                    .insert(author_id.clone(), author.name.clone());
                group.messages.push(GroupPost {
                    id: join_id.clone(),
                    author_id,
                    author_name: author.name.clone(),
                    timestamp,
                    text: String::new(),
                    body: to_hex(&join),
                    join: true,
                });
            }
            for contact in &contacts {
                locked.queue(
                    *contact,
                    OutMessage {
                        id: join_id.clone(),
                        group: group_hex.clone(),
                        timestamp,
                        body: to_hex(&join),
                        acked: false,
                        intern: false,
                        loesch_dauer: None,
                    },
                );
            }
            // Und die Antwort an den Einladenden, in SEINE Einladungsgruppe.
            // Ohne sie teilt er die Gruppe nie: seine Sitzung wartet auf
            // genau diese Nachricht und bliebe sonst ewig im Zustand
            // INVITED -- wir bekaemen die Beitraege der anderen Mitglieder
            // nicht, obwohl wir formal beigetreten sind.
            if let Some(einladender) = locked.group(&group_hex).and_then(|g| g.invited_by) {
                let ihre_kennung = locked
                    .contact(einladender)
                    .map(|c| c.author_id_bytes());
                let vorige = locked
                    .sitzung(&group_hex, einladender)
                    .and_then(|s| s.letzte_eigene.clone());
                if let Some(ihre) = ihre_kennung {
                    let einladungsgruppe = groups::invite_group_id(&author.id(), &ihre);
                    let rumpf = groups::einladung_join_body(
                        &group_id,
                        vorige.as_deref().and_then(|v| from_hex(v)).as_deref(),
                    );
                    let kennung = to_hex(&crate::ids::message_id(
                        &einladungsgruppe,
                        timestamp,
                        &rumpf,
                    ));
                    locked.queue(
                        einladender,
                        OutMessage {
                            id: kennung.clone(),
                            group: to_hex(&einladungsgruppe),
                            timestamp,
                            body: to_hex(&rumpf),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    // Fortschreiben in DER Sitzung, aus der die Kette kommt --
                    // nicht an der Gruppe, wo sie sich mit anderen Kontakten
                    // vermischt.
                    if let Some(s) = locked.sitzung_mut(&group_hex, einladender) {
                        s.letzte_eigene = Some(kennung);
                        s.eigener_zeitstempel = timestamp;
                        // Gleich Beigetreten, nicht ein Wartezustand: unser
                        // Beitritt in der Gruppe geht im selben Aufruf hinaus,
                        // wir teilen also sofort. Briars Eingeladener geht nach
                        // ACCEPTED und wartet auf das JOIN des Erstellers, aber
                        // nur, weil dort die Sichtbarkeit daran haengt.
                        s.zustand = crate::store::Sitzungszustand::Beigetreten;
                    }
                }
            }
            let _ = locked.save();
            drop(locked);
            spawn_poll(&store);
            json!({"ok": true})
        }

        ("POST", "/group/send") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let text = body["text"].as_str().unwrap_or("").trim().to_string();
            if text.is_empty() {
                return json!({"error": "message is empty"});
            }
            // Dieselbe Falle wie bei /send, nur mit einer anderen Zahl: ein zu
            // langer Beitrag reisst bei der Gegenseite nicht die Nachricht ab,
            // sondern die Verbindung -- und weil der Ausgangskorb Unquittiertes
            // behaelt, stolpert danach jede weitere Runde daran.
            if text.len() > crate::sync::MAX_GROUP_POST_TEXT_LEN {
                return json!({"error": format!(
                    "the post is {} bytes long, at most {} are allowed",
                    text.len(), crate::sync::MAX_GROUP_POST_TEXT_LEN)});
            }
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let (group_id, previous, vorher, contacts, joined, aufgeloest) =
                match locked.group(&group_hex) {
                    Some(g) => (
                        key_from_hex(&g.id),
                        g.our_previous.clone(),
                        g.vorgaenger_zeit(),
                        g.contacts.clone(),
                        g.joined,
                        g.aufgeloest,
                    ),
                    None => return json!({"error": "no such group"}),
                };
            if !joined {
                return json!({"error": "join the group first"});
            }
            // In eine aufgeloeste Gruppe laesst Briar nichts mehr schreiben
            // (isDissolved). Der Verlauf bleibt lesbar und Entfernen bleibt
            // moeglich -- nur hinaus geht nichts mehr, denn der Ersteller, an
            // dem die Gruppe haengt, ist weg.
            if aufgeloest {
                return json!({"error": "this group has been dissolved"});
            }
            let previous = match previous {
                Some(p) => key_from_hex(&p),
                None => return json!({"error": "no join message yet"}),
            };
            // Zwei Beitraege in derselben Millisekunde, oder eine
            // zurueckgestellte Uhr, und Briar wirft den zweiten beim Zustellen
            // weg: er muss echt hinter unserer vorigen eigenen Nachricht
            // liegen (PrivateGroupManagerImpl.handleGroupMessage, Zeile 588).
            // Nach einem vorgeruecktem JOIN ist das sogar der Normalfall --
            // dessen Zeitstempel kann vor der Uhr liegen.
            let timestamp = groups::vorgerueckt(now_ms(), vorher);
            let post = groups::post_body(
                &group_id,
                timestamp,
                &author,
                &seed,
                None,
                &previous,
                &text,
            );
            let post_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &post));
            let author_id = to_hex(&author.id());
            if let Some(group) = locked.group_mut(&group_hex) {
                group.messages.push(GroupPost {
                    id: post_id.clone(),
                    author_id,
                    author_name: author.name.clone(),
                    timestamp,
                    text: text.clone(),
                    body: to_hex(&post),
                    join: false,
                });
                group.our_previous = Some(post_id.clone());
            }
            for contact in &contacts {
                locked.queue(
                    *contact,
                    OutMessage {
                        id: post_id.clone(),
                        group: group_hex.clone(),
                        timestamp,
                        body: to_hex(&post),
                        acked: false,
                        intern: false,
                        loesch_dauer: None,
                    },
                );
            }
            let _ = locked.save();
            drop(locked);
            for contact in contacts {
                let node_store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let node = Node::new(node_store);
                    let _ = node.reach_contact(contact);
                });
            }
            json!({"ok": true})
        }

        ("GET", "/group/messages") => {
            let group_hex = query_value(query, "group").unwrap_or_default();
            let locked = store.lock().unwrap();
            // Wem gegenueber sich die Beziehung in dieser Gruppe noch zeigen
            // laesst -- Briars "Kontakte zeigen". Die Regeln stehen in
            // net::zeigbarkeit; hier wird nur gefragt.
            let kontaktnummern: Vec<u32> = locked.state.contacts.iter().map(|c| c.id).collect();
            let zeigbar: Vec<Value> = kontaktnummern
                .iter()
                .filter(|id| net::zeigbarkeit(&locked, &group_hex, **id).is_ok())
                .filter_map(|id| {
                    locked
                        .contact(*id)
                        .map(|c| json!({"id": c.id, "name": c.name}))
                })
                .collect();
            // Und wem gegenueber es schon geschehen ist: eine eigene
            // Nachricht in einer Sitzung, in der wir weder eingeladen haben
            // noch eingeladen wurden.
            let gezeigt: Vec<Value> = kontaktnummern
                .iter()
                .filter(|id| {
                    matches!(
                        net::zeigbarkeit(&locked, &group_hex, **id),
                        Err("schon gezeigt")
                    )
                })
                .filter_map(|id| {
                    locked
                        .contact(*id)
                        .map(|c| json!({"id": c.id, "name": c.name}))
                })
                .collect();
            match locked.group(&group_hex) {
                Some(group) => json!({
                    "revealable": zeigbar,
                    "revealed": gezeigt,
                    "group": group.id,
                    "name": group.name,
                    "joined": group.joined,
                    "dissolved": group.aufgeloest,
                    "messages": group.messages.iter().filter(|m| !m.join).map(|m| json!({
                        "id": m.id,
                        "timestamp": m.timestamp,
                        "text": m.text,
                        "author": m.author_name,
                        "authorId": m.author_id,
                    })).collect::<Vec<Value>>(),
                    "members": group.member_names.values().collect::<Vec<&String>>(),
                }),
                None => json!({"error": "no such group"}),
            }
        }

        // Die Beziehung in einer Gruppe zeigen -- Briars "Kontakte zeigen".
        // Es ist ein JOIN in der Einladungsgruppe dieses Kontakts, mehr nicht;
        // was es bewirkt, steht bei Node::beziehung_zeigen.
        ("POST", "/group/reveal") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let kontakt = body["contact"].as_u64().unwrap_or(0) as u32;
            let mut locked = store.lock().unwrap();
            let node = Node::new(Arc::clone(&store));
            match node.beziehung_zeigen(&mut locked, kontakt, &group_hex) {
                Ok(()) => {
                    let _ = locked.save();
                    drop(locked);
                    // Gleich hinausschicken, nicht erst beim naechsten
                    // Abgleich -- sonst sieht es aus, als sei nichts geschehen.
                    let node_store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        let node = Node::new(node_store);
                        let _ = node.reach_contact(kontakt);
                    });
                    json!({"ok": true})
                }
                Err(grund) => json!({"error": grund}),
            }
        }

        ("POST", "/group/remove") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let mut locked = store.lock().unwrap();
            // Erst den Mitgliedern sagen, dass wir gehen, dann gehen. Ohne
            // LEAVE haelt die Gegenseite uns fuer immer fuer ein Mitglied und
            // schickt weiter Beitraege an jemanden, der nicht mehr zuhoert.
            let (gruppen_id, kontakte, eigene) = match locked.group(&group_hex) {
                Some(g) => (
                    key_from_hex(&g.id),
                    g.contacts.clone(),
                    locked.identity().map(|i| key_from_hex(&i.author_id)),
                ),
                None => (key_from_hex(&group_hex), Vec::new(), None),
            };
            if let Some(unsere) = eigene {
                // Das LEAVE muss hinter der Einladung liegen, sonst bricht die
                // Sitzung der Gegenseite ab statt unser Gehen zu verbuchen
                // (CreatorProtocolEngine.onRemoteDecline) -- und wir gelten
                // dort weiter als Mitglied, genau das, was der Kommentar oben
                // verhindern will. Eine selbst angelegte Gruppe hat keine
                // Einladung, dann bleibt es bei der Uhr.
                let einladung_zeit = locked
                    .group(&group_hex)
                    .and_then(|g| g.invite_timestamp)
                    .unwrap_or(0);
                for kontakt in &kontakte {
                    let ihre = match locked.contact(*kontakt) {
                        Some(c) => c.author_id_bytes(),
                        None => continue,
                    };
                    let einladungsgruppe = groups::invite_group_id(&unsere, &ihre);
                    // Jede Sitzung hat ihre eigene Kette und ihren eigenen
                    // Zeitstempel. Vorher nahmen alle LEAVE dieselbe vorige
                    // Nachricht -- sie stammte aus der Sitzung mit dem
                    // Einladenden und kommt in der Kontaktgruppe der anderen
                    // nicht vor. Briars Pruefer macht die vorige Nachricht zur
                    // Vorbedingung (GroupInvitationValidator.validateLeave),
                    // und die trifft dort nie ein: das LEAVE bliebe fuer immer
                    // liegen.
                    let (vorige, timestamp) = match locked.sitzung(&group_hex, *kontakt) {
                        Some(s) => (s.letzte_eigene.clone(), s.naechster_zeitstempel()),
                        None => (
                            None,
                            groups::vorgerueckt(crate::util::now_ms(), einladung_zeit),
                        ),
                    };
                    let rumpf = groups::einladung_leave_body(
                        &gruppen_id,
                        vorige.as_deref().and_then(|v| from_hex(v)).as_deref(),
                    );
                    let kennung = to_hex(&crate::ids::message_id(
                        &einladungsgruppe,
                        timestamp,
                        &rumpf,
                    ));
                    locked.queue(
                        *kontakt,
                        OutMessage {
                            id: kennung.clone(),
                            group: to_hex(&einladungsgruppe),
                            timestamp,
                            body: to_hex(&rumpf),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    // Die Kette fortschreiben -- das LEAVE ist ab jetzt unsere
                    // letzte eigene Nachricht in dieser Sitzung.
                    //
                    // Ohne diese Zeile stand hier fuer eine nie angenommene
                    // Einladung weiterhin None. Briars Ersteller merkt sich
                    // dagegen die Kennung unseres LEAVE (CreatorProtocolEngine
                    // onRemoteDecline) und macht sie zur Vorbedingung des
                    // naechsten JOIN (isValidDependency). Unser JOIN nach einer
                    // zweiten Einladung nannte also die falsche vorige
                    // Nachricht, Briar brach die Sitzung ab (ABORT) und stellte
                    // die Gruppe fuer uns auf unsichtbar: jeder weitere Beitrag
                    // von uns wurde dort weder gespeichert noch quittiert, und
                    // von drueben kam nichts mehr. Ein Weg zurueck gab es
                    // nicht. Der Kommentar darunter beschrieb die Regel schon,
                    // der Code hielt sie nur nicht ein.
                    if let Some(s) = locked.sitzung_mut(&group_hex, *kontakt) {
                        s.letzte_eigene = Some(kennung);
                        s.eigener_zeitstempel = timestamp;
                    }
                }
            }
            // Die Sitzungen ueberleben die Gruppe. Entfernen ist auf der
            // Leitung eine Ablehnung -- Briar verbucht unser LEAVE als solche,
            // geht nach START und darf neu einladen. Kommt diese neue Einladung,
            // muss unser JOIN die Kette fortsetzen: Briar erwartet als vorige
            // Nachricht unser LEAVE (isValidDependency) und bricht sonst ab.
            if let Some(g) = locked.group(&group_hex) {
                let sitzungen = g.einladungen.clone();
                if !sitzungen.is_empty() {
                    locked
                        .state
                        .verlassene_einladungen
                        .insert(group_hex.clone(), sitzungen);
                }
            }
            // Und die eigene Gruppenpost aus dem Korb: wir gehen, also wird sie
            // niemand mehr annehmen. Bei einem echten Briar bliebe ein vorher
            // abgewiesener Beitrag sonst fuer immer unquittiert liegen und
            // stuende dauerhaft im Zaehler am Kontakt. Das LEAVE selbst liegt in
            // der Einladungsgruppe und bleibt davon unberuehrt.
            for kontakt in &kontakte {
                locked.verwerfe_gruppenpost(*kontakt, &group_hex);
            }
            locked.state.groups.retain(|g| g.id != group_hex);
            let _ = locked.save();
            drop(locked);
            spawn_poll(&store);
            json!({"ok": true})
        }

        _ => json!({"error": "unknown request"}),
    }
}

/// A content type from the file's ending, for the common cases.
fn guess_content_type(path: &str) -> String {
    let lower = path.to_lowercase();
    let kind = if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".txt") {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    kind.to_string()
}

fn group_json(store: &Store, group: &PrivateGroup) -> Value {
    let our_author = store
        .identity()
        .map(|i| i.author_id.clone())
        .unwrap_or_default();
    json!({
        "id": group.id,
        "name": group.name,
        "joined": group.joined,
        "creator": group.creator_name,
        "isCreator": group.creator_author_id == our_author,
        "invitedBy": group.invited_by,
        "members": group.member_names.len(),
        "messages": group.messages.iter().filter(|m| !m.join).count(),
        "lastText": group.messages.iter().filter(|m| !m.join).last().map(|m| m.text.clone()),
        "contacts": group.contacts,
        "dissolved": group.aufgeloest,
        // Nur die Art und der Name, nicht der Satz: die Worte macht die
        // Oberflaeche, sonst stuende deutsche Schrift im Dienst und die
        // Sprachumschaltung griffe hier nicht.
        "event": group.letztes_ereignis.as_ref().map(|e| json!({
            "kind": match e.art {
                crate::store::Ereignisart::Angenommen => "accepted",
                crate::store::Ereignisart::Abgelehnt => "declined",
                crate::store::Ereignisart::Gegangen => "left",
                crate::store::Ereignisart::Aufgeloest => "dissolved",
                crate::store::Ereignisart::Abgebrochen => "aborted",
            },
            "who": e.wer,
            "at": e.wann,
        })),
    })
}

fn status(store: &Shared) -> Value {
    let locked = store.lock().unwrap();
    let identity = locked.identity().map(|i| {
        json!({
            "name": i.name,
            "authorId": i.author_id,
        })
    });
    let contacts: Vec<Value> = locked
        .state
        .contacts
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "address": c.address(LAN_TRANSPORT_ID),
                "bluetooth": c.address(BLUETOOTH_TRANSPORT_ID),
                "onion": c.address(TOR_TRANSPORT_ID),
                "unread": c.messages.iter()
                    .filter(|m| !m.outgoing && m.timestamp > c.last_read)
                    .count(),
                "lastSeen": c.last_seen,
                "messages": c.messages.len(),
                // Haushaltskram zaehlt nicht mit: Adressmeldung und
                // Versionsansage liegen im selben Korb, sind aber nichts, was
                // der Benutzer geschrieben hat.
                "unsent": c.outbox.iter().filter(|m| !m.acked && !m.intern).count(),
                "lastText": c.messages.last().map(|m| m.text.clone()),
                // Verschwindende Nachrichten: die Dauer in Millisekunden,
                // -1 heisst aus. "autoDeleteReady" sagt, ob die Gegenseite
                // sie ueberhaupt liest.
                "autoDelete": c.loesch_timer,
                "autoDeleteReady": c.zuenddauer_bestaetigt(),
            })
        })
        .collect();
    let pending: Vec<Value> = locked
        .state
        .pending
        .iter()
        .map(|p| {
            json!({
                "publicKey": p.public_key,
                "alias": p.alias,
                "address": p.address,
                "bluetooth": p.bluetooth,
                "onion": p.onion,
                "added": p.added,
                "lastError": p.last_error,
            })
        })
        .collect();
    let groups: Vec<Value> = locked
        .state
        .groups
        .iter()
        .map(|g| group_json(&locked, g))
        .collect();
    // Alle Netze, durch Komma getrennt. Daraus baut die Oberflaeche den
    // briar://-Link und damit den QR-Code -- stuende hier nur eine Adresse,
    // waere jede Kopplung wieder an ein einziges Netz genagelt.
    let lan_port = locked.state.listen_port;
    let lan_addresses = {
        // Aus dem Gedaechtnis, nicht aus den gerade vorhandenen Adressen:
        // hier muss genau das stehen, was die Kontakte gemeldet bekommen,
        // sonst traegt der QR-Code etwas anderes als der Ausgangskorb.
        let list = if locked.state.lan_recent.is_empty() {
            crate::net::local_ips()
                .iter()
                .map(|ip| format!("{}:{}", ip, lan_port))
                .collect::<Vec<_>>()
                .join(",")
        } else {
            locked.state.lan_recent.join(",")
        };
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    };
    json!({
        "identity": identity,
        "link": locked.link(),
        "port": locked.state.listen_port,
        "bluetooth": locked.state.bluetooth,
        "language": locked.state.language.clone().unwrap_or_else(|| "en".to_string()),
        "bluetoothAddress": crate::bt::local_address(),
        // Our own address on this network, so the QR code can carry it.
        "unread": locked
            .state
            .contacts
            .iter()
            .map(|c| c.messages.iter()
                .filter(|m| !m.outgoing && m.timestamp > c.last_read)
                .count())
            .sum::<usize>(),
        // Alle Netze, durch Komma getrennt. Daraus baut die Oberflaeche den
        // briar://-Link und damit den QR-Code -- stuende hier nur eine
        // Adresse, waere jede Kopplung wieder an ein einziges Netz genagelt.
        "lanAddress": lan_addresses,
        "locked": ist_gesperrt(),
        "encrypted": locked.verschluesselt(),
        "lockAfter": locked.state.sperre_nach_minuten,
        "tor": locked.state.tor,
        "onion": locked.state.tor_onion,
        "revision": locked.state.revision,
        // Steht die Uhr dieses Geraets erkennbar falsch? Dann kommt nichts an,
        // ohne dass es jemand merkt: Briar verwirft eine Nachricht, deren
        // Zeitstempel mehr als einen Tag in seiner Zukunft liegt -- quittiert
        // sie aber vorher, also gilt sie bei uns als zugestellt. Und ein
        // Kontaktaustausch mit einer Uhr vor 2021 scheitert drueben ganz.
        // N9 und N950 haben keinen Zeitdienst; eine leere Pufferbatterie
        // setzt sie auf 1970.
        "clockWrong": net::uhr_steht_falsch(),
        "contacts": contacts,
        "pending": pending,
        "groups": groups,
    })
}

// --- Die Sprechweise der Nachrichtenbrücke -------------------------------
//
// Die Brücke auf dem N9 (Telepathy-Verbindungsmanager, ~/ps/nachrichtenbruecke)
// spricht mit den Diensten von WhatsApp und Flüsterwind über eine kleine
// HTTP-Schnittstelle: /chats, /messages?jid=, /send?to=&text=, /events?since=.
// Damit Briar in der Nachrichten-App des Geräts auftaucht, muss der Dienst
// nur dieselben vier Wege können -- die Brücke selbst braucht dann keinen
// eigenen Briar-Code, nur einen Eintrag mehr.
//
// Eine Kennung ("jid") ist hier c<Kontaktnummer> oder g<Gruppenkennung>.

/// Zerlegt eine Brücken-Kennung: "c3" -> Kontakt 3, "gab12..." -> Gruppe.
fn bridge_target(jid: &str) -> Option<(bool, String)> {
    let mut chars = jid.chars();
    let kind = chars.next()?;
    let rest: String = chars.collect();
    match kind {
        'c' => Some((false, rest)),
        'g' => Some((true, rest)),
        _ => None,
    }
}

/// Die Nachrichten eines Chats in der Form, die die Brücke erwartet.
fn bridge_messages(store: &Shared, query: &str) -> Value {
    let jid = query_value(query, "jid").unwrap_or_default();
    let Some((group, rest)) = bridge_target(&jid) else {
        return Value::Array(Vec::new());
    };
    let locked = store.lock().unwrap();
    let own_name = locked
        .identity()
        .map(|i| i.name.clone())
        .unwrap_or_default();
    if group {
        let Some(entry) = locked.group(&rest) else {
            return Value::Array(Vec::new());
        };
        let messages: Vec<Value> = entry
            .messages
            .iter()
            .filter(|m| !m.join)
            .map(|m| {
                json!({
                    "id": m.id,
                    "chatJid": jid,
                    "sender": m.author_name,
                    "text": m.text,
                    "fromMe": m.author_name == own_name,
                    "timestamp": m.timestamp,
                    "mediaType": "",
                    "fileName": "",
                })
            })
            .collect();
        return Value::Array(messages);
    }
    let Ok(contact_id) = rest.parse::<u32>() else {
        return Value::Array(Vec::new());
    };
    let Some(contact) = locked.contact(contact_id) else {
        return Value::Array(Vec::new());
    };
    let messages: Vec<Value> = contact
        .messages
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "chatJid": jid,
                "sender": if m.outgoing { own_name.clone() } else { contact.name.clone() },
                "text": m.text,
                "fromMe": m.outgoing,
                "timestamp": m.timestamp,
                "mediaType": m.attachment_type.clone().unwrap_or_default(),
                "fileName": "",
            })
        })
        .collect();
    Value::Array(messages)
}

/// Senden über die Brücken-Kennung. Der Weg dahinter ist derselbe wie bei
/// der eigenen Oberfläche: die Nachricht geht durch POST /send bzw.
/// /group/send, damit es nur eine Stelle gibt, die Nachrichten erzeugt.
fn bridge_send(store: &Shared, to: &str, text: &str) -> Value {
    let Some((group, rest)) = bridge_target(to) else {
        return json!({"error": "unknown chat"});
    };
    if text.trim().is_empty() {
        return json!({"error": "empty message"});
    }
    if group {
        handle(
            Arc::clone(store),
            "POST",
            "/group/send",
            "",
            &json!({"group": rest, "text": text}),
        )
    } else {
        let Ok(contact_id) = rest.parse::<u32>() else {
            return json!({"error": "unknown chat"});
        };
        handle(
            Arc::clone(store),
            "POST",
            "/send",
            "",
            &json!({"contact": contact_id, "text": text}),
        )
    }
}

#[cfg(test)]
mod gruppenablehnung_tests {
    use super::*;
    use crate::store::{Einladungssitzung, PrivateGroup, Sitzungszustand};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const IHR: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const GRUPPE: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn speicher() -> Shared {
        let mut p = std::env::temp_dir();
        p.push("briar-gruppenablehnung.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(crate::store::Contact {
            id: 1,
            name: "Einladende".to_string(),
            author_id: IHR.to_string(),
            signature_public: IHR.to_string(),
            handshake_public: Some(IHR.to_string()),
            master_key: IHR.to_string(),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
        });
        let mut einladungen = BTreeMap::new();
        einladungen.insert(
            1u32,
            Einladungssitzung {
                letzte_eigene: None,
                letzte_fremde: Some("ff01".to_string()),
                eigener_zeitstempel: 1_700_000_000_000,
                einladungs_zeitstempel: 1_700_000_000_000,
                zustand: Sitzungszustand::Eingeladen,
            },
        );
        store.state.groups.push(PrivateGroup {
            id: GRUPPE.to_string(),
            name: "Testgruppe".to_string(),
            salt: "44".to_string(),
            creator_name: "Einladende".to_string(),
            creator_public: IHR.to_string(),
            creator_author_id: IHR.to_string(),
            joined: false,
            invited_by: Some(1),
            invite_timestamp: Some(1_700_000_000_000),
            invite_signature: None,
            member_names: BTreeMap::new(),
            last_read: 0,
            messages: Vec::new(),
            our_previous: None,
            einladungen,
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: vec![1],
        });
        Arc::new(Mutex::new(store))
    }

    /// Eine Einladung abzulehnen heisst hier, die Gruppe zu entfernen -- auf
    /// der Leitung ist das ein LEAVE. Dessen Kennung MUSS in der Sitzung
    /// stehenbleiben: Briars Ersteller macht sie zur Vorbedingung des
    /// naechsten JOIN (isValidDependency). Stand dort weiter None, brach Briar
    /// die Sitzung nach einer zweiten Einladung ab und stellte die Gruppe fuer
    /// uns auf unsichtbar -- ohne Weg zurueck.
    #[test]
    fn ablehnen_merkt_sich_die_kennung_des_leave() {
        let store = speicher();
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/group/remove",
            "",
            &json!({"group": GRUPPE}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let sitzung = locked
            .state
            .verlassene_einladungen
            .get(GRUPPE)
            .and_then(|m| m.get(&1))
            .expect("die Sitzung ueberlebt die Gruppe");
        let kennung = sitzung
            .letzte_eigene
            .clone()
            .expect("das LEAVE steht als letzte eigene Nachricht");

        // Und es ist wirklich die Kennung der Nachricht, die hinausgeht.
        let korb = &locked.state.contacts[0].outbox;
        assert!(
            korb.iter().any(|m| m.id == kennung),
            "die gemerkte Kennung liegt so auch im Korb: {:?}",
            korb.iter().map(|m| m.id.clone()).collect::<Vec<_>>()
        );
        assert_eq!(sitzung.eigener_zeitstempel, korb.iter().find(|m| m.id == kennung).unwrap().timestamp);
    }
}

#[cfg(test)]
mod zeitstempel_tests {
    use super::*;
    use std::sync::Mutex;

    /// Der Zeitstempel einer Privatnachricht rueckt ueber den zuletzt an diese
    /// Gegenseite gemeldeten hinaus. Sonst verwirft Briar unsere Zuenddauer,
    /// weil sie nicht neuer ist als die zuletzt gesehene.
    #[test]
    fn zeitstempel_rueckt_ueber_den_zuletzt_gemeldeten() {
        let mut p = std::env::temp_dir();
        p.push("briar-zeitstempel-test.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(crate::store::Contact {
            id: 1,
            name: "Gegenueber".to_string(),
            author_id: "22".to_string(),
            signature_public: "22".to_string(),
            handshake_public: None,
            master_key: "22".to_string(),
            alice: true,
            creation_period: 0,
            transports: Default::default(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: 60_000,
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
        });
        // Die Gegenseite hat zuletzt einen Stempel weit in der Zukunft
        // gesehen -- so sieht es aus, wenn unsere eigene Uhr nachgeht.
        let weit = now_ms() + 3_600_000;
        store.contact_mut(1).unwrap().loesch_stempel = weit;
        let store: Shared = Arc::new(Mutex::new(store));

        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/send",
            "",
            &json!({"contact": 1, "text": "hallo"}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let nachricht = locked.state.contacts[0]
            .messages
            .last()
            .expect("die Nachricht steht im Verlauf");
        assert!(
            nachricht.timestamp > weit,
            "{} muss ueber {} liegen",
            nachricht.timestamp,
            weit
        );
        assert_eq!(locked.state.contacts[0].loesch_stempel, nachricht.timestamp);
        assert_eq!(nachricht.loesch_dauer, Some(60_000));
    }
}

#[cfg(test)]
mod zeigen_tests {
    use super::*;
    use crate::store::{Contact, Einladungssitzung, PrivateGroup, Sitzungszustand};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const EINLADENDE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const MITGLIED: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const FREMDE: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const GRUPPE: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn kontakt(id: u32, name: &str, autor: &str) -> Contact {
        Contact {
            id,
            name: name.to_string(),
            author_id: autor.to_string(),
            signature_public: autor.to_string(),
            handshake_public: Some(autor.to_string()),
            master_key: autor.to_string(),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
        }
    }

    /// Wir sind eingeladen worden von Kontakt 1. Kontakt 2 ist auch in der
    /// Gruppe, hat uns aber nicht eingeladen -- das ist die PEER-Rolle, und
    /// nur dort gibt es etwas zu zeigen. Kontakt 3 ist gar nicht drin.
    /// Je Pruefung eine eigene Datei: sie laufen nebeneinander, und drei
    /// Pruefungen auf demselben Pfad loeschen einander die Datei unter den
    /// Fuessen weg.
    fn speicher(wer: &str) -> Shared {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-zeigen-{}.json", wer));
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(kontakt(1, "Einladende", EINLADENDE));
        store.state.contacts.push(kontakt(2, "Mitglied", MITGLIED));
        store.state.contacts.push(kontakt(3, "Fremde", FREMDE));

        let mut einladungen = BTreeMap::new();
        einladungen.insert(
            1u32,
            Einladungssitzung {
                letzte_eigene: Some("aa01".to_string()),
                letzte_fremde: Some("ff01".to_string()),
                eigener_zeitstempel: 1_700_000_000_000,
                einladungs_zeitstempel: 1_700_000_000_000,
                zustand: Sitzungszustand::Beigetreten,
            },
        );
        let mut mitglieder = BTreeMap::new();
        mitglieder.insert(EINLADENDE.to_string(), "Einladende".to_string());
        mitglieder.insert(MITGLIED.to_string(), "Mitglied".to_string());

        store.state.groups.push(PrivateGroup {
            id: GRUPPE.to_string(),
            name: "Testgruppe".to_string(),
            salt: "44".to_string(),
            creator_name: "Einladende".to_string(),
            creator_public: EINLADENDE.to_string(),
            creator_author_id: EINLADENDE.to_string(),
            joined: true,
            invited_by: Some(1),
            invite_timestamp: Some(1_700_000_000_000),
            invite_signature: None,
            member_names: mitglieder,
            last_read: 0,
            messages: Vec::new(),
            our_previous: Some("aa02".to_string()),
            einladungen,
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: vec![1, 2],
        });
        Arc::new(Mutex::new(store))
    }

    #[test]
    fn nur_die_peer_rolle_laesst_sich_zeigen() {
        let store = speicher("rolle");
        let locked = store.lock().unwrap();
        // Kontakt 1 hat uns eingeladen -- das laeuft ueber die INVITEE-Rolle.
        assert!(net::zeigbarkeit(&locked, GRUPPE, 1).is_err());
        // Kontakt 2 ist Mitglied, ohne dass einer den anderen eingeladen hat.
        assert_eq!(net::zeigbarkeit(&locked, GRUPPE, 2), Ok(()));
        // Kontakt 3 ist gar nicht in der Gruppe.
        assert!(net::zeigbarkeit(&locked, GRUPPE, 3).is_err());
    }

    #[test]
    fn die_liste_nennt_genau_den_einen() {
        let store = speicher("liste");
        let antwort = handle(
            Arc::clone(&store),
            "GET",
            "/group/messages",
            &format!("group={}", GRUPPE),
            &json!({}),
        );
        let zeigbar = antwort["revealable"].as_array().unwrap();
        assert_eq!(zeigbar.len(), 1, "{}", antwort);
        assert_eq!(zeigbar[0]["id"], 2);
        assert!(antwort["revealed"].as_array().unwrap().is_empty());
    }

    /// Nach dem Zeigen liegt eine eigene Nachricht in der Sitzung -- und ein
    /// zweites Mal geht nicht mehr, sonst gabelte es die Kette.
    #[test]
    fn zeigen_schickt_ein_join_und_zaehlt_danach_als_gezeigt() {
        let store = speicher("join");
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/group/reveal",
            "",
            &json!({"group": GRUPPE, "contact": 2}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let sitzung = locked.sitzung(GRUPPE, 2).expect("die Sitzung steht");
        assert!(
            sitzung.letzte_eigene.is_some(),
            "das JOIN muss in der Sitzung stehen"
        );
        assert!(
            locked
                .state
                .contacts
                .iter()
                .any(|c| c.id == 2 && !c.outbox.is_empty()),
            "das JOIN muss in der Ausgangspost liegen"
        );
        assert_eq!(net::zeigbarkeit(&locked, GRUPPE, 2), Err("schon gezeigt"));
    }
}
