#ifndef SCHEMEHANDLER_H
#define SCHEMEHANDLER_H

#include <QWebEngineUrlSchemeHandler>

class SchemeHandler : public QWebEngineUrlSchemeHandler
{
    Q_OBJECT
public:
    explicit SchemeHandler(QObject *parent = nullptr);

    void requestStarted(QWebEngineUrlRequestJob *job) override;

    static void registerUrlScheme();

    static const QByteArray schemeName;
};

#endif // SCHEMEHANDLER_H
