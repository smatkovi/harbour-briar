Name:       harbour-briar
Summary:    Briar for Sailfish OS
Version:    0.42.1
Release:    1
License:    GPLv3
URL:        https://github.com/smatkovi/harbour-briar
Source0:    %{name}-%{version}.tar.bz2
Requires:   sailfishsilica-qt5 >= 0.10.9
BuildRequires:  pkgconfig(sailfishapp) >= 1.0.2
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Qml)
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Gui)
BuildRequires:  pkgconfig(Qt5Network)
# Das Geraeteschloss als Schluesselbund: darin liegt das Kontopasswort, damit
# der Fingerabdruck auch einen versiegelten Dienst aufsperrt.
BuildRequires:  pkgconfig(sailfishsecrets)
BuildRequires:  desktop-file-utils

%description
Briar's Bramble protocols, reimplemented in Rust for devices without a JVM.
Handshake, key derivation, stream encryption, the BDF data format,
identifiers and the sync protocol are Briar's own and are checked against
reference bytes taken from bramble-core.

Without Tor: contacts meet on the same LAN, one side enters the other's
briar:// link and address.

%prep
%setup -q -n %{name}-%{version}

%build
# Die Fassung ins Programm reichen: die App vergleicht sie mit der, die der
# laufende Dienst meldet, und ersetzt ihn, wenn sie auseinandergehen.
%qmake5 "BRIARVER=%{version}"
%make_build

%install
%qmake5_install

%post
# Den alten Dienst beenden. Er ist ein eigener, langlebiger Prozess: die App
# startet ihn nur, wenn keiner laeuft, und nach einer Aktualisierung liefe
# sonst der alte weiter -- mit dem alten Verhalten, waehrend die neue
# Binaerdatei danebenliegt. Das hat schon mehrere Fehlersuchen gekostet.
# Beim naechsten Oeffnen der App startet der neue; das Passwort wird dabei
# einmal wieder gebraucht, weil der Speicher versiegelt.
# Ueber /proc, nicht ueber pkill: Linux kuerzt den Prozessnamen auf 15
# Zeichen, "harbour-briar-briard" hat 20 -- `pkill -x` mit dem vollen Namen
# findet nie etwas. Nachgemessen: /proc/<pid>/comm sagt "harbour-briar-b".
# Genau daran lief auf der Jolla stundenlang ein veralteter Dienst weiter,
# waehrend jede Reparatur danebenlag.
# Nur das ERSTE Wort der Befehlszeile zaehlt. Ein Muster ueber die ganze
# Zeile traf auch die Shell, die gerade `strings .../harbour-briar-briard`
# aufrief -- und beendete sie mit.
for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    erstes=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -n 1)
    [ "$erstes" = "/usr/bin/harbour-briar-briard" ] && kill "${d#/proc/}" 2>/dev/null || :
done
exit 0

%files
%defattr(-,root,root,-)
# One line for all three: the interface, the daemon, and the Tor that only
# ships when it has been built.
%{_bindir}/%{name}*
%{_datadir}/%{name}
%{_datadir}/applications/%{name}.desktop
%{_datadir}/applications/%{name}-share.desktop
%{_datadir}/dbus-1/services/harbour.harbour-briar.service
%{_prefix}/lib/systemd/user/%{name}-briard.service
%{_datadir}/icons/hicolor/*/apps/%{name}.png
