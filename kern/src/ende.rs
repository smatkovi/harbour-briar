//! Sauber gehen, wenn der Dienst beendet wird.
//!
//! `%post`, stopDaemon und systemd beenden den Dienst mit SIGTERM. Ohne
//! eigene Behandlung starb er sofort, und die entschluesselten Kopien der
//! Anhaenge blieben im Laufzeitordner liegen, bis zum naechsten Start
//! (Gegenpruefung 7b, C4). Auf dem N9 liegt der unter /tmp, und ob das ein
//! tmpfs ist, ist ungeprueft.
//!
//! In einem Signalhandler ist fast nichts erlaubt -- kein Speicher, kein
//! Schloss, kein Protokoll. Darum der alte Kniff mit der Pipe: der Handler
//! schreibt ein Byte (write ist async-signal-sicher), und ein gewoehnlicher
//! Faden, der darauf wartet, raeumt auf und beendet den Prozess.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

/// Das Schreibende der Pipe; -1, solange keine eingerichtet ist.
static SCHREIBENDE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn bei_sigterm(_signal: libc::c_int) {
    let fd = SCHREIBENDE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // Sicher: ein Byte aus dem Stapel an einen offenen Deskriptor. Das
        // Ergebnis ist egal -- ist die Pipe voll, steht schon ein Byte darin.
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

/// Was vor dem Ende geschieht: der Laufzeitordner wird geleert, und das
/// Protokoll bekommt seine letzte Zeile.
pub fn aufraeumen(laufzeit: &Path) {
    crate::store::anhang_kopien_leeren(laufzeit);
    crate::net::log("stopping");
}

/// Richtet die Behandlung von SIGTERM ein: ein Faden wartet auf das Byte aus
/// dem Handler, raeumt `laufzeit` auf und ruft `exit(0)`.
///
/// Einmal in main.rs, nach der Instanzsperre -- ein Dienst, der dort noch
/// auf den ersten wartet, soll dessen Laufzeitordner nicht leeren und stirbt
/// weiter wie gewohnt.
pub fn einrichten(laufzeit: PathBuf) -> std::io::Result<()> {
    let mut fds = [0 as libc::c_int; 2];
    // Sicher: fds hat Platz fuer die zwei Deskriptoren. O_CLOEXEC, damit Tor
    // sie nicht erbt.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (lesen, schreiben) = (fds[0], fds[1]);
    SCHREIBENDE.store(schreiben, Ordering::Relaxed);
    std::thread::spawn(move || {
        let mut byte = 0u8;
        loop {
            // Sicher: ein Byte in den eigenen Puffer.
            let n = unsafe { libc::read(lesen, &mut byte as *mut u8 as *mut libc::c_void, 1) };
            if n == 1 {
                break;
            }
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Die Pipe ist kaputt -- dann wenigstens wieder so sterben wie
            // vorher, statt SIGTERM zu schlucken.
            // Sicher: SIG_DFL ist immer ein gueltiger Handler.
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
            }
            crate::net::log("SIGTERM handling failed -- back to the default");
            return;
        }
        aufraeumen(&laufzeit);
        std::process::exit(0);
    });
    // Sicher: sa ist vollstaendig belegt (zeroed + Handler + leere Maske).
    let ergebnis = unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = bei_sigterm as extern "C" fn(libc::c_int) as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut())
    };
    if ergebnis != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aufraeumen_leert_den_laufzeitordner() {
        let ordner = std::env::temp_dir().join(format!("briar-ende-{}", std::process::id()));
        std::fs::create_dir_all(ordner.join("tiefer")).unwrap();
        std::fs::write(ordner.join("a1.png"), b"klartext").unwrap();
        std::fs::write(ordner.join("tiefer").join("a2.jpg"), b"klartext").unwrap();
        aufraeumen(&ordner);
        assert!(!ordner.exists(), "die Kopien muessen weg sein");
    }

    #[test]
    fn aufraeumen_ohne_ordner_ist_kein_fehler() {
        let ordner = std::env::temp_dir().join(format!("briar-ende-leer-{}", std::process::id()));
        aufraeumen(&ordner);
        assert!(!ordner.exists());
    }
}
