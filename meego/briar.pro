TEMPLATE = app
TARGET = briar
QT += declarative network dbus
CONFIG += qt

HEADERS += geraeteschloss.h ../src/imageprep.h ../src/qrcode.h
SOURCES += main.cpp

target.path = /opt/briar/bin
INSTALLS += target
