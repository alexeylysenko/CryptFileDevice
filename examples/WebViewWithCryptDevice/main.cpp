#include "mainwindow.h"

#include <QApplication>

#include <QWebEngineProfile>

#include "schemehandler.h"

int main(int argc, char *argv[])
{
    SchemeHandler::registerUrlScheme();

    QApplication a(argc, argv);

    SchemeHandler schemeHandler;
    QWebEngineProfile::defaultProfile()->installUrlSchemeHandler(SchemeHandler::schemeName,
                                                                 &schemeHandler);

    MainWindow w;
    w.show();

    return a.exec();
}
