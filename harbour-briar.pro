TARGET = harbour-briar
CONFIG += sailfishapp c++11
QT += core gui qml quick network
LIBS += -lsailfishapp

SOURCES += src/harbour-briar.cpp \
    src/quirc/quirc.c \
    src/quirc/decode.c \
    src/quirc/identify.c \
    src/quirc/version_db.c
HEADERS += src/imageprep.h src/qrcode.h src/qrencode.h src/quirc/quirc.h

DISTFILES += \
    qml/harbour-briar.qml \
    qml/Briar.js \
    qml/Strings.js \
    qml/pages/GroupsPage.qml \
    qml/pages/GroupChatPage.qml \
    qml/pages/InvitePage.qml \
    qml/pages/FilePage.qml \
    qml/pages/HelpPage.qml \
    qml/pages/MainPage.qml \
    qml/pages/ChatPage.qml \
    qml/pages/AddContactPage.qml \
    qml/pages/LinkPage.qml \
    qml/pages/ScanPage.qml \
    qml/pages/AboutPage.qml \
    qml/pages/UnlockPage.qml \
    qml/pages/PasswordPage.qml \
    qml/pages/SetupPasswordPage.qml \
    qml/cover/CoverPage.qml \
    rpm/harbour-briar.spec \
    harbour-briar.desktop \
    harbour-briar-share.desktop \
    harbour-briar-briard.service

# The daemon is built separately (kern/, cross-compiled for the device) and
# copied in by tools/build-rpm.sh.
daemon.files = build/harbour-briar-briard
daemon.path = /usr/bin
INSTALLS += daemon

# Tor comes with the package when it has been built: Sailfish has none in
# its repositories, and without one the Tor transport stays off.
exists(build/harbour-briar-tor) {
    tor.files = build/harbour-briar-tor
    tor.path = /usr/bin
    INSTALLS += tor
}

# The pieces that make the app part of the system: an optional background
# service, the entry in the share menu, and D-Bus activation so that tapping
# a notification starts the app when it is closed.
service.files = harbour-briar-briard.service
service.path = /usr/lib/systemd/user
INSTALLS += service

sharedesktop.files = harbour-briar-share.desktop
sharedesktop.path = /usr/share/applications
INSTALLS += sharedesktop

dbusservice.files = dbus/harbour.harbour-briar.service
dbusservice.path = /usr/share/dbus-1/services
INSTALLS += dbusservice

icon86.files = icons/86x86/harbour-briar.png
icon86.path = /usr/share/icons/hicolor/86x86/apps
icon108.files = icons/108x108/harbour-briar.png
icon108.path = /usr/share/icons/hicolor/108x108/apps
icon128.files = icons/128x128/harbour-briar.png
icon128.path = /usr/share/icons/hicolor/128x128/apps
icon172.files = icons/172x172/harbour-briar.png
icon172.path = /usr/share/icons/hicolor/172x172/apps
icon256.files = icons/256x256/harbour-briar.png
icon256.path = /usr/share/icons/hicolor/256x256/apps
INSTALLS += icon86 icon108 icon128 icon172 icon256
