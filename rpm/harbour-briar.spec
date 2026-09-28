Name:       harbour-briar
Summary:    Briar for Sailfish OS
Version:    0.33.0
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
%qmake5
%make_build

%install
%qmake5_install

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
