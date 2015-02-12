#-------------------------------------------------
#
# Project created by QtCreator 2014-09-21T15:21:49
#
#-------------------------------------------------

QT       += core
CONFIG += c++14 console

TARGET = CryptFileDeviceExample
TEMPLATE = app

SRCPATH = $$PWD/../../src

INCLUDEPATH += $$SRCPATH

SOURCES += main.cpp \
    $$SRCPATH/cryptfiledevice.cpp

HEADERS  += \
    $$SRCPATH/cryptfiledevice.h

#openssl
win32 {
INCLUDEPATH += c:/OpenSSL-Win32/include
LIBS += -Lc:/OpenSSL-Win32/bin -llibeay32
}

linux|macx {
LIBS += -lcrypto
}

