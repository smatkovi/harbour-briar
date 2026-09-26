//! Notifications on Sailfish, with a reply field in the notification.
//!
//! Only built for the Sailfish package (`--features sfos`): Harmattan has no
//! org.freedesktop.Notifications, and its own notification system is a
//! different animal.
//!
//! Two directions:
//!   out -- a message arrives, the daemon raises a notification. Tapping it
//!          opens the chat in the app; the reply field sends straight back.
//!   in  -- lipstick calls harbour.briar.Backend.Reply(contact, text) when
//!          the user types into that field. We hand it to our own HTTP API,
//!          so the reply goes exactly the way a reply from the app goes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Mutex;

use zbus::zvariant::Value;

/// The identifiers of the notifications we raised, per chat, so a second
/// message replaces the first instead of stacking up.
static IDS: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// The name lipstick shows and groups by.
const APP_NAME: &str = "harbour-briar";
const ICON: &str = "harbour-briar";

/// A QString as nemo's notification plugin encodes call arguments:
/// QDataStream QVariant (type 10), then UTF-16BE, the whole thing base64.
fn qvariant_b64(text: &str) -> String {
    let utf16: Vec<u16> = text.encode_utf16().collect();
    let mut buffer = Vec::with_capacity(9 + 2 * utf16.len());
    buffer.extend_from_slice(&[0, 0, 0, 10]); // QVariant::String
    buffer.push(0); // not null
    let length = (2 * utf16.len()) as u32;
    buffer.extend_from_slice(&length.to_be_bytes());
    for unit in utf16 {
        buffer.extend_from_slice(&unit.to_be_bytes());
    }
    base64(&buffer)
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Raises (or replaces) the notification for one chat.
///
/// `key` is what we remember it under, `argument` the chat's identifier as
/// the remote actions need it -- a contact number, or a group's identifier.
pub fn message(key: &str, summary: &str, body: &str, argument: &str, group: bool, reply_label: &str) {
    let connection = match zbus::blocking::Connection::session() {
        Ok(c) => c,
        Err(_) => return,
    };
    let replaces = {
        let guard = IDS.lock().unwrap();
        guard
            .as_ref()
            .and_then(|map| map.get(key).copied())
            .unwrap_or(0)
    };

    let reply_method = if group { "ReplyGroup" } else { "Reply" };
    let open_method = if group { "openGroup" } else { "openChat" };
    let encoded = qvariant_b64(argument);
    let reply_action = format!(
        "harbour.briar.backend / harbour.briar.Backend {} {}",
        reply_method, encoded
    );
    let open_action = format!(
        "harbour.harbour-briar / harbour.briar.Gui {} {}",
        open_method, encoded
    );

    let mut hints: HashMap<&str, Value> = HashMap::new();
    hints.insert("category", Value::from("x-nemo.messaging.im"));
    // Without this lipstick looks the icon up by process name and complains
    // that briard has no desktop entry.
    hints.insert("desktop_entry", Value::from("harbour-briar"));
    hints.insert("x-nemo-preview-summary", Value::from(summary));
    hints.insert("x-nemo-preview-body", Value::from(body));
    hints.insert("x-nemo-feedback", Value::from("chat_exists"));
    hints.insert("x-nemo-remote-action-default", Value::from(open_action.as_str()));
    hints.insert("x-nemo-remote-action-reply", Value::from(reply_action.as_str()));
    // type=input is what makes lipstick draw a text field instead of a button
    hints.insert("x-nemo-remote-action-type-reply", Value::from("input"));

    let actions: Vec<&str> = vec!["default", "", "reply", reply_label];
    let answer = connection.call_method(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        Some("org.freedesktop.Notifications"),
        "Notify",
        &(APP_NAME, replaces, ICON, summary, body, actions, hints, -1i32),
    );
    if let Ok(answer) = answer {
        if let Ok(id) = answer.body().deserialize::<u32>() {
            let mut guard = IDS.lock().unwrap();
            guard.get_or_insert_with(HashMap::new).insert(key.to_string(), id);
        }
    }
}

/// Takes the notification for a chat away again -- when it has been read.
pub fn close(key: &str) {
    let id = {
        let mut guard = IDS.lock().unwrap();
        guard.as_mut().and_then(|map| map.remove(key))
    };
    let id = match id {
        Some(id) if id != 0 => id,
        _ => return,
    };
    if let Ok(connection) = zbus::blocking::Connection::session() {
        let _ = connection.call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "CloseNotification",
            &(id,),
        );
    }
}

/// The other direction: the interface lipstick calls when someone types into
/// the notification's reply field.
struct Backend {
    api_port: u16,
}

#[zbus::interface(name = "harbour.briar.Backend")]
impl Backend {
    fn reply(&self, contact: String, text: String) {
        let contact_id: u32 = contact.trim().parse().unwrap_or(0);
        if contact_id == 0 || text.trim().is_empty() {
            return;
        }
        let body = format!(
            "{{\"contact\":{},\"text\":{}}}",
            contact_id,
            json_string(text.trim())
        );
        post(self.api_port, "/send", &body);
    }

    fn reply_group(&self, group: String, text: String) {
        if group.trim().is_empty() || text.trim().is_empty() {
            return;
        }
        let body = format!(
            "{{\"group\":{},\"text\":{}}}",
            json_string(group.trim()),
            json_string(text.trim())
        );
        post(self.api_port, "/group/send", &body);
    }
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Our own HTTP interface, so a reply from the notification takes exactly
/// the same path as one typed in the app.
fn post(port: u16, path: &str, body: &str) {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    if let Ok(mut socket) = std::net::TcpStream::connect(("127.0.0.1", port)) {
        let _ = socket.write_all(request.as_bytes());
        let mut answer = Vec::new();
        let _ = socket.read_to_end(&mut answer);
    }
}

/// Holds the name on the session bus for as long as the daemon runs.
pub fn serve(api_port: u16) {
    std::thread::spawn(move || {
        let built = zbus::blocking::connection::Builder::session()
            .and_then(|builder| builder.name("harbour.briar.backend"))
            .and_then(|builder| builder.serve_at("/", Backend { api_port }))
            .and_then(|builder| builder.build());
        match built {
            Ok(_connection) => {
                crate::net::log("replying from the notification is ready");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
            Err(e) => crate::net::log(&format!("no notification replies: {}", e)),
        }
    });
}
