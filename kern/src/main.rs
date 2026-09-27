//! briard -- the Briar daemon behind the Sailfish and Harmattan front ends.
//!
//!   briard [--state <file>] [--api-port <port>] [--lan-port <port>]
//!          [--tor-port <port>]

use briarkern::net::{self, Node};
use briarkern::store::Store;
use briarkern::transport::DEFAULT_PORT;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_API_PORT: u16 = 8105;
// Der Taktgeber holt nicht immer gleich oft nach. Kommt keine Verbindung
// zustande, waechst der Abstand von 60 s mit Faktor 1,2 bis hoechstens 600 s;
// nach einer geglueckten Verbindung faellt er zurueck auf 60 s, und der
// Netzwaechter setzt ihn ebenfalls zurueck. Briar macht es genauso
// (LanTcpPluginFactory, backoff.reset() in TcpPlugin). Auf dem N9 ist das
// kein Feinschliff, sondern Strom: ein Geraet ohne Gegenueber in Reichweite
// weckt sich sonst jede Minute.
const POLL_INTERVAL: Duration = Duration::from_secs(60);
const POLL_INTERVAL_MAX: Duration = Duration::from_secs(600);
const POLL_BACKOFF: f64 = 1.2;

fn default_state_path() -> PathBuf {
    if let Ok(dir) = std::env::var("BRIAR_STATE_DIR") {
        return PathBuf::from(dir).join("state.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    // Sailfish keeps application data here; on Harmattan the directory is
    // just as good a place, and both are on the user's own partition.
    PathBuf::from(home)
        .join(".local/share/harbour-briar")
        .join("state.json")
}

fn main() {
    let mut state_path = default_state_path();
    let mut api_port = DEFAULT_API_PORT;
    let mut lan_port = None;
    // The local port the hidden service points at. Only worth setting when
    // two daemons share one machine, as in the Tor tests.
    let mut tor_port = briarkern::transport::DEFAULT_TOR_PORT;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state" if i + 1 < args.len() => {
                state_path = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            "--api-port" if i + 1 < args.len() => {
                api_port = args[i + 1].parse().unwrap_or(DEFAULT_API_PORT);
                i += 1;
            }
            "--lan-port" if i + 1 < args.len() => {
                lan_port = args[i + 1].parse::<u16>().ok();
                i += 1;
            }
            "--tor-port" if i + 1 < args.len() => {
                tor_port = args[i + 1].parse().unwrap_or(tor_port);
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "briard [--state <file>] [--api-port <port>] [--lan-port <port>] \
                     [--tor-port <port>]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                return;
            }
        }
        i += 1;
    }

    let mut store = match Store::open(&state_path, DEFAULT_PORT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open {}: {}", state_path.display(), e);
            std::process::exit(1);
        }
    };
    if let Some(port) = lan_port {
        store.state.listen_port = port;
    }
    net::log(&format!("state in {}", state_path.display()));
    let shared = Arc::new(Mutex::new(store));

    let api_store = Arc::clone(&shared);
    std::thread::spawn(move || briarkern::api::run(api_store, api_port));

    // Replying straight from the notification: lipstick calls us on the
    // session bus, and we hand the text to our own interface.
    #[cfg(feature = "sfos")]
    briarkern::notify::serve(api_port);

    // Bluetooth is a second listener: Briar's own transport identifier, so
    // its keys and tags differ from the LAN ones, on a fixed RFCOMM channel.
    // Unter einem Aufseher, genau wie Tor: wird Bluetooth erst spaeter
    // eingeschaltet, faengt der Lauscher dann an -- frueher blieb er bis
    // zum naechsten Start des Dienstes stumm.
    let bt_store = Arc::clone(&shared);
    std::thread::spawn(move || loop {
        if bt_store.lock().unwrap().state.bluetooth {
            let node = Node::new(Arc::clone(&bt_store));
            node.run_bluetooth_listener();
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    // Tor, when one is running on the device: the daemon publishes a hidden
    // service through its control port and listens on the port behind it.
    // Started and stopped with the switch, not once at launch: a Tor
    // process costs about 30 MB, and on Harmattan that is real money.
    let tor_store = Arc::clone(&shared);
    std::thread::spawn(move || loop {
        if tor_store.lock().unwrap().state.tor {
            let node = Node::new(Arc::clone(&tor_store));
            node.run_tor_listener(tor_port);
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    let poll_store = Arc::clone(&shared);
    let takt = Arc::new(std::sync::Mutex::new(POLL_INTERVAL));
    let takt_poller = Arc::clone(&takt);
    std::thread::spawn(move || loop {
        let abstand = *takt_poller.lock().unwrap();
        std::thread::sleep(abstand);
        let node = Node::new(Arc::clone(&poll_store));
        let erreicht = node.poll();
        let mut abstand = takt_poller.lock().unwrap();
        *abstand = if erreicht {
            POLL_INTERVAL
        } else {
            let naechster = abstand.as_secs_f64() * POLL_BACKOFF;
            Duration::from_secs_f64(naechster).min(POLL_INTERVAL_MAX)
        };
    });

    // Der Netzwaechter. Er fragt nicht nach, er wartet: der Systembus
    // meldet, wenn WLAN, mobile Daten oder Bluetooth kommen oder gehen
    // (ConnMan auf Sailfish, ICd2 auf Harmattan, BlueZ auf beiden). Dann
    // wird sofort abgeglichen, statt bis zu einer Minute auf die naechste
    // Runde zu warten -- und im Ruhezustand kostet es nichts, weil kein
    // Faden aufwacht, solange sich nichts tut.
    #[cfg(feature = "dbus")]
    {
        let watch_store = Arc::clone(&shared);
        let takt_waechter = Arc::clone(&takt);
        // Alle Adressen, nicht nur die vorderste: kommt das Tethering dazu,
        // aendert sich die vorderste vielleicht gar nicht, die Liste aber
        // schon -- und genau die wollen wir neu melden.
        let letzte = std::sync::Mutex::new((
            briarkern::net::local_ips(),
            briarkern::bt::local_address(),
        ));
        briarkern::netwatch::beobachten(move || {
            let jetzt = (briarkern::net::local_ips(), briarkern::bt::local_address());
            let mut gemerkt = letzte.lock().unwrap();
            if *gemerkt == jetzt {
                // ConnMan meldet auch Dinge, die uns nichts angehen
                // (Signalstaerke, Zaehlerstaende). Nur eine wirklich andere
                // Adresse ist ein Grund, etwas zu tun.
                return;
            }
            briarkern::net::log(&format!(
                "the network changed ({} / {}) -- syncing now",
                if jetzt.0.is_empty() {
                    "no address".to_string()
                } else {
                    jetzt.0.join(", ")
                },
                jetzt.1.clone().unwrap_or_else(|| "no Bluetooth".to_string())
            ));
            *gemerkt = jetzt;
            drop(gemerkt);
            // Das neue Netz sofort ins Adressgedaechtnis, damit die naechste
            // Runde es schon melden kann.
            {
                let mut store = watch_store.lock().unwrap();
                let v4 = briarkern::net::note_local_addresses(&mut store.state);
                let v6 = briarkern::net::note_local_addresses6(&mut store.state);
                if v4 || v6 {
                    let _ = store.save();
                }
            }
            // Ein Netzwechsel ist der beste Grund, es sofort wieder zu
            // versuchen: der Abstand faellt auf den Anfangswert zurueck.
            *takt_waechter.lock().unwrap() = POLL_INTERVAL;
            let node = Node::new(Arc::clone(&watch_store));
            node.poll();
        });
    }

    // Der IPv6-Lauscher laeuft daneben: link-lokal, eigener Faden, und wenn
    // das Geraet kein IPv6 hat, meldet er das einmal und schweigt danach.
    let v6_store = Arc::clone(&shared);
    let v6_port = v6_store.lock().unwrap().state.listen_port;
    std::thread::spawn(move || {
        let node = Node::new(v6_store);
        node.run_listener6(v6_port);
    });

    let node = Node::new(shared);
    node.run_listener();
}
