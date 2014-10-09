#include "networkaccessmanager.h"

#include "cryptfiledevice.h"

#include <QFile>

NetworkAccessManager::NetworkAccessManager(QObject *parent) :
    QNetworkAccessManager(parent)
{
}

QNetworkReply *NetworkAccessManager::createRequest(Operation op, const QNetworkRequest &req, QIODevice *outgoingData)
{
    if (!req.url().isLocalFile())
        return QNetworkAccessManager::createRequest(op, req, outgoingData);

    QString filePath = req.url().toLocalFile();
    if (!filePath.endsWith(".enc"))
        return QNetworkAccessManager::createRequest(op, req, outgoingData);

    filePath.chop(4);
    if (!QFile::exists(filePath))
        return QNetworkAccessManager::createRequest(op, req, outgoingData);

    NetworkReply *networkReply = new NetworkReply(this);
    networkReply->setRequestInfo(op, req);
    return networkReply;
}



NetworkReply::NetworkReply(QObject *parent) :
    QNetworkReply(parent)
{
}

NetworkReply::~NetworkReply()
{
    closeFile();
}

qint64 NetworkReply::bytesAvailable() const
{
    return m_cryptFileDevice->size() - m_cryptFileDevice->pos();
}

bool NetworkReply::isSequential() const
{
    return true;
}

void NetworkReply::abort()
{
    closeFile();
}

void NetworkReply::setRequestInfo(QNetworkAccessManager::Operation op, const QNetworkRequest &req)
{
    setRequest(req);
    setOperation(op);
    setUrl(req.url());

    open(QIODevice::ReadOnly);

    QString fileName = url().toLocalFile();
    closeFile();
    m_cryptFileDevice = new CryptFileDevice;
    m_cryptFileDevice->setFileName(fileName);
    m_cryptFileDevice->setPassword("alex_password");
    m_cryptFileDevice->setSalt("alex_salt");
    if (!m_cryptFileDevice->open(QIODevice::ReadOnly))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot open cryptfiledevice: " + fileName.toLocal8Bit());
    }

    setHeader(QNetworkRequest::LastModifiedHeader, QDateTime::currentDateTime());
    setHeader(QNetworkRequest::ContentLengthHeader, m_cryptFileDevice->size());

    QMetaObject::invokeMethod(this, "metaDataChanged", Qt::QueuedConnection);
    QMetaObject::invokeMethod(this, "readyRead", Qt::QueuedConnection);
    QMetaObject::invokeMethod(this, "finished", Qt::QueuedConnection);
}

qint64 NetworkReply::readData(char *buffer, qint64 maxlen)
{
    qint64 result = m_cryptFileDevice->read(buffer, maxlen);
    QMetaObject::invokeMethod(this,
                              "downloadProgress",
                              Qt::QueuedConnection,
                              Q_ARG(qint64, m_cryptFileDevice->pos()),
                              Q_ARG(qint64, m_cryptFileDevice->size()));
    return result;
}

void NetworkReply::closeFile()
{
    if (m_cryptFileDevice != nullptr)
    {
        m_cryptFileDevice->close();
        delete m_cryptFileDevice;
        m_cryptFileDevice = nullptr;
    }
}
