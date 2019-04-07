#include "schemehandler.h"

#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlScheme>

#include "cryptfiledevice.h"

const QByteArray SchemeHandler::schemeName = QByteArrayLiteral("cd");

SchemeHandler::SchemeHandler(QObject *parent)
    : QWebEngineUrlSchemeHandler(parent)
{
}

void SchemeHandler::requestStarted(QWebEngineUrlRequestJob *job)
{
    QByteArray method = job->requestMethod();
    QString urlPath = job->requestUrl().path();

    if (method == QByteArrayLiteral("GET") && urlPath.endsWith(".enc"))
    {
        auto file = new CryptFileDevice(urlPath,
                                        QByteArrayLiteral("alex_password"),
                                        QByteArrayLiteral("alex_salt"),
                                        job);
        file->open(QIODevice::ReadOnly);
        job->reply(QByteArrayLiteral("image/*"), file);
    }
    else
    {
        job->fail(QWebEngineUrlRequestJob::UrlInvalid);
    }
}

void SchemeHandler::registerUrlScheme()
{
    QWebEngineUrlScheme scheme(schemeName);
    scheme.setFlags(QWebEngineUrlScheme::SecureScheme |
                    QWebEngineUrlScheme::LocalScheme |
                    QWebEngineUrlScheme::LocalAccessAllowed);
    QWebEngineUrlScheme::registerScheme(scheme);
}
