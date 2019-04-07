#-------------------------------------------------
#
# Project created by QtCreator 2014-10-02T10:48:35
#
#-------------------------------------------------

QT       += core gui webenginewidgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = WebViewWithCryptDevice
TEMPLATE = app
CONFIG += c++11

SRCPATH = $$PWD/../../src

INCLUDEPATH += $$SRCPATH

SOURCES += main.cpp \
    mainwindow.cpp \
    $$SRCPATH/cryptfiledevice.cpp \
    schemehandler.cpp

HEADERS  += mainwindow.h \
    $$SRCPATH/cryptfiledevice.h \
    schemehandler.h

FORMS    += mainwindow.ui

#openssl
win32 {
INCLUDEPATH += c:/OpenSSL-Win32/include
LIBS += -Lc:/OpenSSL-Win32/bin -llibeay32
}

linux|macx {
LIBS += -lcrypto
}

